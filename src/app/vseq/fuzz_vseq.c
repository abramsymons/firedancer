/* fuzz_vseq feeds untrusted bytes to everything vseq parses from the
   network: block wire bytes, ledger records (SYNC_BLOCK and /blocks),
   finality proofs (certs), and the consensus messages a peer can send
   a running node (votes, certs, blocks, repair requests).  A real node
   with a four validator set receives the messages, so the whole path
   through the pool and votor runs, not just the parsers.

   The first byte picks the target.  The rest is the input.

   Build and run (see config/everything.mk for the fuzz targets):

     make -j BUILDDIR=clang-fuzz-asan CC=clang EXTRAS="fuzz asan" fuzz_vseq
     FUZZ_VSEQ_SEED_DIR=corpus/fuzz_vseq build/clang-fuzz-asan/fuzz-test/fuzz_vseq -runs=0
     build/clang-fuzz-asan/fuzz-test/fuzz_vseq corpus/fuzz_vseq

   With FUZZ_VSEQ_SEED_DIR set, init writes a validly signed vote,
   block, repair request and ledger record there, so the fuzzer starts
   from inputs that pass the signature checks. */

#include "vseq_node.h"
#include "vseq_ledger.h"
#include "vseq_proof.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdio.h>
#include <stdlib.h>

#define N          (4UL)
#define SLOT_MAX   (32UL)
#define NETWORK_ID ((ushort)0x5e5e)
#define PAYLOAD_MAX (4096UL)

static vseq_sched_t * sched;
static vseq_node_t *  node;
static ulong          own;         /* peer index of the node */
static long           now;
static fd_sha512_t    sha[1];
static ag_cert_t      cert;        /* scratch for proof verification */
static fd_bls_sec_t   bls_sec[ N ];
static uchar          id_sec [ N ][ 32 ];
static vseq_member_t  members[ N ];

static void
no_send( void * ctx, ulong dst, uchar const * buf, ulong sz ) {
  (void)ctx; (void)dst; (void)buf; (void)sz;
}

static void
no_finalized( void * ctx, vseq_block_t const * block, uchar const hash[ 32 ], uchar const * proof, ulong proof_sz ) {
  (void)ctx; (void)block; (void)hash; (void)proof; (void)proof_sz;
}

static void
no_persist_vote( void * ctx, ulong slot, uchar const * vote, ulong vote_sz, uchar const * block, ulong block_sz ) {
  (void)ctx; (void)slot; (void)vote; (void)vote_sz; (void)block; (void)block_sz;
}

static void
no_persist_block( void * ctx, ulong slot ) {
  (void)ctx; (void)slot;
}

static void
sign( void * ctx, fd_bls_sig_t * sig, uchar const * public_key, uchar const * payload, ulong payload_sz ) {
  (void)public_key;
  fd_bls_sec_sign( (fd_bls_sec_t const *)ctx, payload, payload_sz, sig );
}

static void
seed_write( char const * dir, char const * name, uchar const * buf, ulong sz ) {
  char path[ 4096 ];
  snprintf( path, sizeof(path), "%s/%s", dir, name );
  FILE * f = fopen( path, "wb" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "fopen(%s) failed", path ));
  FD_TEST( fwrite( buf, 1UL, sz, f )==sz );
  fclose( f );
}

/* seeds writes valid messages from member 1 (peer `from`) to dir. */

static void
seeds( char const * dir ) {
  vseq_set_t const * set  = &sched->sets[0];
  ulong              from = sched->member_peer[1];
  ulong              rank = set->rank_of_peer[ from ];
  uchar              buf[ 1UL+VSEQ_BLOCK_HDR_SZ+PAYLOAD_MAX+256UL ];

  /* A skip vote on slot 1 */
  ag_vote_t vote = ag_vote_construct_skip( sign, &bls_sec[1], members[1].v.bls_key, 1UL, (ushort)rank, NETWORK_ID );
  buf[0] = 3; buf[1] = (uchar)from; buf[2] = VSEQ_MSG_VOTE;
  ulong sz = ag_vote_ser( &vote, buf+3UL );
  seed_write( dir, "vote", buf, 3UL+sz );

  /* A block for the first slot member 1 leads, on genesis */
  ulong slot = 1UL;
  while( set->member_of_rank[ ag_epoch_info_leader( set->epoch, slot )->id ]!=1UL ) slot++;
  ag_block_id_t   parent = ag_block_id( 0UL, ag_block_hash_null );
  ag_block_hash_t hash;
  uchar           payload[ 16 ] = "fuzz-seed";
  uchar           wire[ VSEQ_BLOCK_HDR_SZ+sizeof(payload) ];
  sz = vseq_block_build( wire, slot, &parent, payload, sizeof(payload), members[1].v.id_key, id_sec[1], sha, hash );
  buf[0] = 3; buf[1] = (uchar)from; buf[2] = VSEQ_MSG_BLOCK;
  memcpy( buf+3UL, wire, sz );
  seed_write( dir, "block", buf, 3UL+sz );
  buf[0] = 0;
  memcpy( buf+1UL, wire, sz );
  seed_write( dir, "block_wire", buf, 1UL+sz );

  /* The same block as a ledger record without certs */
  uchar * r = buf+1UL;
  FD_STORE( uint,  r,       (uint)(152UL+sizeof(payload)) );
  FD_STORE( ulong, r+ 4UL,  slot );
  FD_STORE( ulong, r+12UL,  parent.slot );
  memcpy( r+20UL, parent.hash, 32UL );
  memcpy( r+52UL, hash,        32UL );
  memcpy( r+84UL, wire+48UL,   64UL );
  FD_STORE( uint, r+148UL, (uint)sizeof(payload) );
  memcpy( r+152UL, payload, sizeof(payload) );
  FD_STORE( uint, r+152UL+sizeof(payload), 0U );
  buf[0] = 1;
  seed_write( dir, "ledger_rec", buf, 1UL+156UL+sizeof(payload) );

  /* A repair request for that block */
  buf[0] = 3; buf[1] = (uchar)from; buf[2] = VSEQ_MSG_REPAIR;
  FD_STORE( ulong, buf+3UL, slot );
  memcpy( buf+11UL, hash, 32UL );
  seed_write( dir, "repair", buf, 43UL );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 1 );
  fd_log_level_logfile_set( 4 ); /* the node warns about every bad message */
  fd_log_level_stderr_set ( 4 );

  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<N; i++ ) {
    uchar ikm[ 32 ] = {0}; FD_STORE( ulong, ikm, 0xf022UL+i );
    fd_bls_sec_derive( &bls_sec[i], ikm, sizeof(ikm) );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &bls_sec[i], &pub );
    blst_p1_compress( members[i].v.bls_key, &pub );
    memset( id_sec[i], (int)(0x40+i), 32UL );
    fd_ed25519_public_from_private( members[i].v.id_key, id_sec[i], sha );
    members[i].v.stake     = 10UL-i;
    members[i].from_epoch  = 0UL;
    members[i].until_epoch = ULONG_MAX;
  }
  sched = vseq_sched_new( members, N, 1024UL, NETWORK_ID );
  FD_TEST( sched );
  own = sched->member_peer[0];

  vseq_node_cfg_t cfg = {
    .sched         = sched,
    .own_peer      = own,
    .bls_sec       = bls_sec[0],
    .ns_per_slot   = 400L*1000L*1000L,
    .network_id    = NETWORK_ID,
    .slot_max      = SLOT_MAX,
    .payload_max   = PAYLOAD_MAX,
    .txq_max       = 65536UL,
    .retain_slots  = SLOT_MAX,
    .seed          = 7UL,
    .send          = no_send,
    .finalized     = no_finalized,
    .persist_vote  = no_persist_vote,
    .persist_block = no_persist_block,
  };
  memcpy( cfg.id_sec, id_sec[0], 32UL );
  now  = 1000L*1000L*1000L;
  node = vseq_node_create( &cfg, now );
  FD_TEST( node );

  char const * seed_dir = getenv( "FUZZ_VSEQ_SEED_DIR" );
  if( seed_dir ) seeds( seed_dir );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  if( !size ) return 0;
  uchar const * in = data+1UL;
  ulong         sz = size-1UL;

  switch( data[0]&3 ) {

  case 0: { /* block wire bytes, as a leader signs them */
    vseq_block_t    block;
    ag_block_hash_t hash;
    if( vseq_block_parse( &block, in, sz ) ) return 0;
    vseq_set_t const * set = vseq_sched_set( sched, block.slot );
    ulong member = set->member_of_rank[ ag_epoch_info_leader( set->epoch, block.slot )->id ];
    vseq_block_verify( &block, members[ member ].v.id_key, sha, hash );
    return 0;
  }

  case 1: { /* a ledger record, as SYNC_BLOCK and /blocks carry it */
    vseq_ledger_rec_t rec;
    ag_block_hash_t   hash;
    if( vseq_ledger_rec_parse( in, sz, &rec ) ) return 0;
    vseq_block_hash( rec.block.slot, &rec.block.parent, rec.block.payload, rec.block.payload_sz, hash );
    if( rec.proof_sz ) vseq_proof_verify( vseq_sched_set( sched, rec.block.slot )->epoch, NETWORK_ID, rec.block.slot, hash, rec.proof, rec.proof_sz, &cert );
    return 0;
  }

  case 2: { /* bare certs, as the client library verifies them */
    if( sz<8UL+32UL ) return 0;
    ulong slot = FD_LOAD( ulong, in );
    vseq_proof_verify( vseq_sched_set( sched, slot )->epoch, NETWORK_ID, slot, in+8UL, in+40UL, sz-40UL, &cert );
    return 0;
  }

  default: { /* a peer's message to the node: vote, cert, block or repair */
    if( sz<2UL ) return 0;
    ulong from = in[0];
    now += 1000L*1000L; /* a millisecond per message, so timeouts fire too */
    vseq_node_recv( node, now, from, in+1UL, sz-1UL );
    vseq_node_service( node, now );
    return 0;
  }
  }
}
