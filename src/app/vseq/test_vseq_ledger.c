/* test_vseq_ledger checks the segmented ledger: sealing, reopening,
   spans, pruning, recovery from the files a crash can leave, and a
   read-only follower keeping up with a writer. */

#define _GNU_SOURCE
#include "vseq_ledger.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define PAYLOAD_MAX (512UL)
#define PROOF_MAX   (64UL)
#define SEG_BYTES   (4096UL)
#define BLOCK_MAX   (400UL)

static ag_block_id_t chain[ BLOCK_MAX ];  /* chain[i] is block i */
static ulong         chain_slot0;

static void
append_n( vseq_ledger_t * l,
          ulong           from,
          ulong           to,
          ag_block_id_t   parent ) {
  uchar payload[ PAYLOAD_MAX ];
  uchar proof  [ PROOF_MAX ];
  for( ulong i=from; i<to; i++ ) {
    vseq_block_t b = {0};
    b.slot       = chain_slot0 + i*2UL + 1UL; /* skipped slots in between */
    b.parent     = i ? chain[ i-1UL ] : parent;
    b.payload_sz = 50UL + (i*37UL)%300UL;
    for( ulong j=0UL; j<b.payload_sz; j++ ) payload[j] = (uchar)(i+j);
    b.payload    = payload;
    ag_block_hash_t hash;
    vseq_block_hash( b.slot, &b.parent, payload, b.payload_sz, hash );
    ulong proof_sz = i%3UL==2UL ? 40UL : 0UL; /* every third block has certs */
    memset( proof, 0xc5, proof_sz );
    vseq_ledger_append( l, &b, hash, proof, proof_sz );
    chain[i] = ag_block_id( b.slot, hash );
  }
}

static void
check_all( vseq_ledger_t * l ) {
  ulong first = vseq_ledger_first_idx( l ), cnt = vseq_ledger_cnt( l );
  ag_block_id_t prev = vseq_ledger_base( l );
  for( ulong i=first; i<cnt; i++ ) {
    vseq_ledger_rec_t rec;
    FD_TEST( !vseq_ledger_read( l, i, &rec ) );
    FD_TEST( rec.block.slot==chain[i].slot && !memcmp( rec.hash, chain[i].hash, 32UL ) );
    FD_TEST( ag_block_id_eq( &rec.block.parent, &prev ) );
    prev = chain[i];
    FD_TEST( vseq_ledger_first_after( l, rec.block.slot-1UL )==i );
    FD_TEST( vseq_ledger_first_after( l, rec.block.slot     )==i+1UL );
  }
}

/* Every span is a contiguous run of records ending with one that has
   certs. */

static void
check_spans( vseq_ledger_t * l ) {
  static uchar buf[ 1UL<<20 ];
  ulong first = vseq_ledger_first_idx( l ), cnt = vseq_ledger_cnt( l );
  for( ulong i=first; i<cnt; i++ ) {
    ulong n, sz = vseq_ledger_read_span( l, i, 1UL, 0UL, buf, sizeof(buf), &n );
    if( !n ) { FD_TEST( !sz ); continue; } /* trailing records not yet followed by certs */
    ulong off = 0UL, proof_sz = 0UL;
    for( ulong k=0UL; k<n; k++ ) {
      ulong rec_sz = FD_LOAD( uint, buf+off );
      FD_TEST( FD_LOAD( ulong, buf+off+4UL )==chain[ i+k ].slot );
      ulong payload_sz = FD_LOAD( uint, buf+off+148UL );
      proof_sz = FD_LOAD( uint, buf+off+152UL+payload_sz );
      off += 4UL+rec_sz;
    }
    FD_TEST( off==sz && proof_sz );
  }
}

static char dir[ 256 ];

static void
path_of( ulong        seq,
         char const * ext,
         char *       out ) {
  sprintf( out, "%s/%010lu.%s", dir, seq, ext );
}

static int
exists( char const * p ) {
  struct stat st;
  return !stat( p, &st );
}

static ulong
last_seq( void ) {
  char p[ 512 ];
  ulong s = 0UL;
  for( ulong i=0UL; i<10000UL; i++ ) { path_of( i, "seg", p ); if( exists( p ) ) s = i; }
  return s;
}

static ulong
first_seq( void ) {
  char p[ 512 ];
  for( ulong i=0UL; i<10000UL; i++ ) { path_of( i, "seg", p ); if( exists( p ) ) return i; }
  return ULONG_MAX;
}

static vseq_ledger_t *
reopen( vseq_ledger_t * l ) {
  vseq_ledger_close( l );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  FD_TEST( l );
  return l;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  strcpy( dir, "/tmp/test_vseq_ledger_XXXXXX" );
  FD_TEST( mkdtemp( dir ) );
  strcat( dir, "/ledger" );
  ag_block_id_t genesis = ag_block_id( 0UL, ag_block_hash_null );

  /* Fresh ledger, sealing */
  vseq_ledger_t * l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  FD_TEST( l && !vseq_ledger_cnt( l ) && ag_block_id_eq( (ag_block_id_t[]){ vseq_ledger_base( l ) }, &genesis ) );
  append_n( l, 0UL, 200UL, genesis );
  vseq_ledger_stats_t st = vseq_ledger_stats( l );
  FD_TEST( st.segments>5UL && st.sealed==st.segments-1UL );
  FD_LOG_NOTICE(( "200 blocks in %lu segments, %lu bytes", st.segments, st.bytes ));
  check_all( l );
  check_spans( l );

  /* Reopen loads sealed indexes and rescans the active segment */
  l = reopen( l );
  FD_TEST( vseq_ledger_cnt( l )==200UL );
  check_all( l );
  check_spans( l );

  /* Prune: whole sealed segments below the slot, never the active one */
  ulong segs = vseq_ledger_stats( l ).segments;
  ulong removed = vseq_ledger_prune( l, chain[100].slot );
  FD_TEST( removed>0UL && vseq_ledger_stats( l ).segments==segs-removed );
  ulong first = vseq_ledger_first_idx( l );
  FD_TEST( first>0UL && first<=100UL );
  FD_TEST( ag_block_id_eq( (ag_block_id_t[]){ vseq_ledger_base( l ) }, &chain[ first-1UL ] ) );
  FD_TEST( vseq_ledger_first_after( l, 0UL )==first ); /* below the base: callers must check */
  check_all( l );
  l = reopen( l );
  FD_TEST( vseq_ledger_first_idx( l )==first && vseq_ledger_cnt( l )==200UL );
  check_all( l );
  FD_TEST( !vseq_ledger_prune( l, ULONG_MAX-1UL ) || vseq_ledger_stats( l ).segments>=1UL );
  l = reopen( l );
  check_all( l );
  first = vseq_ledger_first_idx( l );

  /* More blocks, then a torn tail in the active segment */
  append_n( l, 200UL, 260UL, genesis );
  char p[ 512 ];
  path_of( last_seq(), "seg", p );
  struct stat sst; FD_TEST( !stat( p, &sst ) );
  if( sst.st_size>64 ) {
    vseq_ledger_close( l );
    FD_TEST( !truncate( p, sst.st_size-7 ) );
    l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
    FD_TEST( l && vseq_ledger_cnt( l )==259UL );
    check_all( l );
  }
  append_n( l, 259UL, 300UL, genesis );
  check_all( l );

  /* A sealed segment's index missing, then corrupt: rebuilt */
  ulong mid = first_seq()+1UL;
  path_of( mid, "idx", p );
  vseq_ledger_close( l );
  FD_TEST( !unlink( p ) );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  FD_TEST( l && vseq_ledger_cnt( l )==300UL && exists( p ) );
  check_all( l );
  vseq_ledger_close( l );
  FILE * f = fopen( p, "r+" ); FD_TEST( f ); fseek( f, 80, SEEK_SET ); fputc( 0x55, f ); fclose( f );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  FD_TEST( l && vseq_ledger_cnt( l )==300UL );
  check_all( l );
  check_spans( l );

  /* Interrupted prune: the oldest .seg is gone but its .idx remains */
  ulong old = first_seq();
  vseq_ledger_close( l );
  path_of( old, "seg", p ); FD_TEST( !unlink( p ) );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  path_of( old, "idx", p );
  FD_TEST( l && !exists( p ) && vseq_ledger_first_idx( l )>first );
  check_all( l );

  /* Crash right after sealing: the new active segment never made it */
  while( vseq_ledger_stats( l ).sealed==0UL ) append_n( l, vseq_ledger_cnt( l ), vseq_ledger_cnt( l )+1UL, genesis );
  ulong cnt = vseq_ledger_cnt( l );
  vseq_ledger_close( l );
  path_of( last_seq(), "seg", p );
  FD_TEST( !stat( p, &sst ) && sst.st_size==64 && !unlink( p ) );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  FD_TEST( l && vseq_ledger_cnt( l )==cnt );
  append_n( l, cnt, cnt+5UL, genesis );
  check_all( l );
  vseq_ledger_close( l );

  /* A missing segment in the middle must refuse to open */
  path_of( first_seq()+1UL, "seg", p ); FD_TEST( !unlink( p ) );
  pid_t pid = fork();
  if( !pid ) {
    fd_log_level_stderr_set( 5 );
    vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
    _exit( 0 );
  }
  int status; FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( !( WIFEXITED( status ) && WEXITSTATUS( status )==0 ) );

  /* Starting after a peer's base instead of genesis */
  strcat( dir, "2" );
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  ag_block_id_t base = ag_block_id( 1001UL, (uchar const *)"0123456789abcdef0123456789abcdef" );
  FD_TEST( !vseq_ledger_set_base( l, &base ) );
  chain_slot0 = 2000UL;
  append_n( l, 0UL, 30UL, base );
  FD_TEST( vseq_ledger_set_base( l, &genesis )==-1 ); /* not empty */
  l = reopen( l );
  FD_TEST( ag_block_id_eq( (ag_block_id_t[]){ vseq_ledger_base( l ) }, &base ) && vseq_ledger_cnt( l )==30UL );
  check_all( l );
  vseq_ledger_close( l );

  /* A follower sees what the writer appends, seals and prunes */
  strcat( dir, "3" );
  FD_TEST( !vseq_ledger_follow( dir, PAYLOAD_MAX, PROOF_MAX ) ); /* no ledger yet */
  l = vseq_ledger_open( dir, PAYLOAD_MAX, PROOF_MAX, SEG_BYTES );
  vseq_ledger_t * fl = vseq_ledger_follow( dir, PAYLOAD_MAX, PROOF_MAX );
  FD_TEST( fl && !vseq_ledger_cnt( fl ) );
  base        = ag_block_id( 3001UL, (uchar const *)"abcdef0123456789abcdef0123456789" );
  chain_slot0 = 4000UL;
  FD_TEST( !vseq_ledger_set_base( l, &base ) );
  for( ulong n=0UL; n<120UL; n+=7UL ) {
    append_n( l, n, n+7UL, base );
    FD_TEST( !vseq_ledger_refresh( fl ) );
    FD_TEST( vseq_ledger_cnt( fl )==vseq_ledger_cnt( l ) );
    check_all( fl );
  }
  FD_TEST( vseq_ledger_stats( fl ).segments>3UL );

  /* A record still being written is not seen until it is complete */
  path_of( last_seq(), "seg", p );
  int fd = open( p, O_WRONLY|O_APPEND );
  FD_TEST( fd>=0 && write( fd, "\x40\x01\0\0partial", 11 )==11 );
  FD_TEST( !vseq_ledger_refresh( fl ) && vseq_ledger_cnt( fl )==vseq_ledger_cnt( l ) );
  FD_TEST( !stat( p, &sst ) && !ftruncate( fd, sst.st_size-11 ) );
  close( fd );

  FD_TEST( vseq_ledger_prune( l, chain[ 60 ].slot ) );
  FD_TEST( !vseq_ledger_refresh( fl ) );
  FD_TEST( vseq_ledger_first_idx( fl )==vseq_ledger_first_idx( l ) );
  FD_TEST( ag_block_id_eq( (ag_block_id_t[]){ vseq_ledger_base( fl ) }, (ag_block_id_t[]){ vseq_ledger_base( l ) } ) );
  check_all( fl );

  /* Opening a follower on a pruned ledger, then the ledger replaced */
  vseq_ledger_close( fl );
  fl = vseq_ledger_follow( dir, PAYLOAD_MAX, PROOF_MAX );
  FD_TEST( fl && vseq_ledger_cnt( fl )==vseq_ledger_cnt( l ) );
  check_all( fl );
  vseq_ledger_close( l );
  char cmd[ 300 ];
  FD_TEST( fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "rm -rf %s", dir ) && !system( cmd ) );
  FD_TEST( vseq_ledger_refresh( fl )==-1 );
  vseq_ledger_close( fl );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
