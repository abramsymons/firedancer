#include "vseq_client.h"
#include "vseq_ledger.h"
#include "vseq_node.h"
#include "vseq_proof.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

struct vseq_client {
  vseq_sched_t * sched;
  ushort         network_id;
  ag_cert_t      cert;  /* scratch, too big for some callers' stacks */
};

/* The library may be loaded into any process (Python), so it boots
   fd_util itself, quietly. */

static void
boot_once( void ) {
  static int booted = 0;
  if( FD_LIKELY( booted ) ) return;
  booted = 1;
  int    argc   = 1;
  char * argv[] = { (char *)"vseq_client", NULL };
  char ** pargv = argv;
  if( !getenv( "FD_LOG_PATH" ) ) setenv( "FD_LOG_PATH", "", 1 );
  fd_log_enable_unclean_exit();

  /* fd_boot always reports the log destination on stderr; keep the
     host program's stderr clean. */
  int saved = dup( STDERR_FILENO );
  int null  = open( "/dev/null", O_WRONLY|O_CLOEXEC );
  if( saved>=0 && null>=0 ) dup2( null, STDERR_FILENO );
  fd_boot( &argc, &pargv );
  if( saved>=0 && null>=0 ) dup2( saved, STDERR_FILENO );
  if( saved>=0 ) close( saved );
  if( null >=0 ) close( null  );
  fd_log_level_stderr_set( 4 );
}

vseq_client_t *
vseq_client_new( uchar const * validators,
                 ulong         cnt,
                 uint          network_id,
                 ulong         epoch_slots ) {
  boot_once();
  if( FD_UNLIKELY( !validators || !cnt || !network_id || network_id>USHORT_MAX ) ) return NULL;

  vseq_member_t * members = malloc( cnt*sizeof(vseq_member_t) );
  FD_TEST( members );
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * v = validators + i*VSEQ_CLIENT_VALIDATOR_SZ;
    members[i].v.stake     = FD_LOAD( ulong, v );
    memcpy( members[i].v.id_key,  v+ 8UL, 32UL );
    memcpy( members[i].v.bls_key, v+40UL, 48UL );
    members[i].from_epoch  = FD_LOAD( ulong, v+88UL );
    members[i].until_epoch = FD_LOAD( ulong, v+96UL );
  }
  vseq_sched_t * sched = vseq_sched_new( members, cnt, epoch_slots, (ushort)network_id );
  free( members );
  if( FD_UNLIKELY( !sched ) ) return NULL;

  vseq_client_t * client = aligned_alloc( alignof(vseq_client_t), fd_ulong_align_up( sizeof(vseq_client_t), alignof(vseq_client_t) ) );
  FD_TEST( client );
  client->sched      = sched;
  client->network_id = (ushort)network_id;
  return client;
}

void
vseq_client_delete( vseq_client_t * client ) {
  if( FD_UNLIKELY( !client ) ) return;
  vseq_sched_delete( client->sched );
  free( client );
}

ulong
vseq_client_leader( vseq_client_t const * client,
                    ulong                 slot ) {
  vseq_set_t const * set = vseq_sched_set( client->sched, slot );
  return set->member_of_rank[ ag_epoch_info_leader( set->epoch, slot )->id ];
}

int
vseq_client_verify( vseq_client_t * client,
                    ulong           slot,
                    uchar const *   hash,
                    uchar const *   certs,
                    ulong           certs_sz ) {
  return vseq_proof_verify( vseq_sched_set( client->sched, slot )->epoch, client->network_id, slot, hash, certs, certs_sz, &client->cert );
}

#define LEDGER_PAYLOAD_MAX (16UL<<20) /* the largest payload_max a cluster can set */
#define BLOCKS_HDR_SZ      (20UL)

vseq_ledger_t *
vseq_client_ledger_follow( char const * dir ) {
  boot_once();
  return vseq_ledger_follow( dir, LEDGER_PAYLOAD_MAX, VSEQ_PROOF_MAX );
}

long
vseq_client_ledger_read( vseq_ledger_t * ledger,
                         ulong           after,
                         uchar *         out,
                         ulong           out_max ) {
  if( FD_UNLIKELY( out_max<BLOCKS_HDR_SZ ) ) return -3L;
  if( FD_UNLIKELY( vseq_ledger_refresh( ledger ) ) ) return -1L;
  if( FD_UNLIKELY( after<vseq_ledger_base( ledger ).slot ) ) return -2L;
  ulong first = vseq_ledger_first_after( ledger, after );
  ulong cnt;
  ulong sz    = vseq_ledger_read_span( ledger, first, ULONG_MAX, ULONG_MAX, out+BLOCKS_HDR_SZ, out_max-BLOCKS_HDR_SZ, &cnt );
  if( FD_UNLIKELY( !cnt && first<vseq_ledger_cnt( ledger ) ) ) return -3L;
  memcpy( out, "VSQB\1\0\0\0", 8UL );
  FD_STORE( ulong, out+ 8UL, 0UL ); /* finalized slot: not tracked here */
  FD_STORE( uint,  out+16UL, (uint)cnt );
  return (long)( BLOCKS_HDR_SZ+sz );
}

void
vseq_client_ledger_close( vseq_ledger_t * ledger ) {
  vseq_ledger_close( ledger );
}
