/* vseqd is the vseq node daemon: a consensus-only node that orders
   opaque txs with Alpenglow votor and never executes them.

   Commands:

     vseqd keygen --out node.toml
         Writes a new node key file and prints the public keys.

     vseqd gen-cluster --dir DIR [--nodes 20] [--host 127.0.0.1]
                       [--base-port 9000] [--api-base-port 8000]
                       [--blocks-base-port 8500]
                       [--distinct-hosts] [--api-host HOST]
                       [--genesis-delay-s 5]
         Writes DIR/cluster.toml and DIR/node-<i>.toml for a test cluster.
         Node i listens on host:base-port+i, or with --distinct-hosts on
         (host+i):base-port, e.g. one container per node.  Each
         validator's api URL is http://api-host:api-base-port+i and its
         blocks URL http://api-host:blocks-base-port+i, where api-host
         defaults to host (or 127.0.0.1 with --distinct-hosts).
         Genesis is set genesis-delay-s from now; start the nodes before.

     vseqd api-key --name NAME [--txs-bytes-per-s 0] [--requests-per-s 0]
         Prints a new API key for a dApp and its entry for the API keys
         file.  Limits of 0 mean no limit.

     vseqd run --cluster cluster.toml --key node.toml --ledger FILE
               [--api-keys FILE] [--api-port 8000] [--slot-max 64]
               [--ledger-segment-kb 262144] [--ledger-retain-slots 0]
               [--history recent|full]
         Runs a node.

     vseqd blocks --cluster cluster.toml --ledger FILE [--api-keys FILE]
                  [--port 8500]
         Serves /blocks from a node's ledger files, as a separate
         process so readers never slow down consensus.  It only reads
         the files: run it next to the node, start and restart either
         one in any order.

   Cluster config (TOML):

     network_id      = 24158          # 1-65535, votes from other networks are rejected
     slot_ms         = 400
     payload_max     = 1048576        # max block payload bytes
     genesis_time_ms = 1767225600000  # unix ms; consensus starts here on every node
     epoch_slots     = 9000           # validator sets change only at epoch boundaries

     [[validator]]
     stake    = 1
     identity = "<hex ed25519 public key>"
     bls      = "<hex compressed BLS12-381 public key>"
     host     = "127.0.0.1"
     port     = 9000
     api      = "http://127.0.0.1:8000"   # optional, used by clients: /txs, /status
     blocks   = "http://127.0.0.1:8500"   # optional, used by clients: /blocks
     from_epoch  = 0                      # optional: a validator from this epoch
     until_epoch = 120                    # optional: up to, not including, this epoch

   The validator set of epoch E is every entry with from_epoch <= E <
   until_epoch (vseq_sched.h).  The file is part of the release: every
   node and client must use the same one.  To change the set, publish a
   file that starts or ends entries at a future epoch, and keep old
   entries so history stays verifiable.  To change a validator's stake,
   end its entry and add one with the new stake.  Nodes connect only to
   validators of the previous, current and next epoch, and drop peers
   whose set for the current epoch differs from theirs.

   Node key file (TOML):

     identity_secret = "<hex 32 bytes>"
     bls_secret      = "<hex 32 bytes>"

   Files next to --ledger FILE:

     FILE/         finalized blocks with their proofs, in append-only
                   segment files (vseq_ledger.h).  With
                   --ledger-retain-slots N, whole segments more than N
                   slots behind the finalized slot are pruned.
     FILE.votes    the vote history (vseq_history.h): every vote this
                   node sent and the blocks it voted notar for, made
                   durable before the vote is sent.  On restart they go
                   back into consensus so the node cannot contradict
                   itself.  Losing it while keeping the ledger is
                   refused: the node could double vote.  So is the
                   other way round, a ledger that ends more than
                   --slot-max minus 8 slots below the last vote in the
                   file (an old copy restored by hand): the node could
                   not replay those votes and might contradict them.
                   Restore the ledger that goes with the vote history,
                   or start over with neither.

   Durability: a finalized block was voted for by at least 60% of
   stake, and each voter made its vote and the block durable first, so
   even if every node loses power the network finalizes the same block
   again.  The ledger is not synced per block: it is synced every
   slot_max/2 finalized slots, when a segment is sealed, and right
   before the vote history drops what the ledger holds (on open, when
   consensus starts, and every COMPACT_SLOTS).  So a block is always on
   disk in one of the two, and the ledger is never more than slot_max/2
   slots behind the vote history, which is what a restart can replay
   (votor tracks slot_max slots above the root). A ledger further
   behind, e.g. restored from an old copy, is refused at startup.

   Restart: run the same command again.  The node reopens the ledger,
   catches up from peers if it is behind (blocks are checked against
   their certs), and resumes consensus at its last finalized block.

   A node with an empty ledger does not need history to take part in
   consensus.  With --history recent (the default) it asks a peer for
   its latest finalized block, checks that block's certs against the
   validator set, starts its ledger there and joins consensus.  With
   --history full (for nodes that serve history) it first fetches
   everything its peers keep, from genesis or from their oldest kept
   block.  A node whose ledger ends before
   every peer's oldest kept block cannot catch up: it says so and waits
   (restore older segments, or start it with an empty ledger but the
   same vote history file).

   API keys file (TOML), the same on every node:

     [[dapp]]
     name            = "kv-store"
     key_sha256      = "<hex SHA-256 of the key>"
     txs_bytes_per_s = 262144         # optional, 0 for no limit
     requests_per_s  = 100            # optional, 0 for no limit

   With --api-keys every API call needs ?api-key=KEY: unknown keys get
   403, calls over a limit get 400 {"error":"rate limit"}.  Limits are per node and allow a
   burst of one second, so txs_bytes_per_s must be at least the
   largest /txs body a dApp sends.  Nodes store only key hashes, so the file is
   not secret.  Without --api-keys the API is open to everyone.

   HTTP API of vseqd run:

     GET  /status                       node and consensus state (JSON)
     POST /txs                          body is txs framed as (uint sz, tx)

   HTTP API of vseqd blocks:

     GET  /blocks?after=SLOT&limit=N    finalized blocks after SLOT

   Errors other than 403 and 404 are 400 with {"error":...}, because
   fd_http_server only sends a body with 200, 204 and 400.

   /blocks answers 400 with {"error":"pruned","base_slot":B} when SLOT is
   below B, the block the oldest kept record builds on.

   /blocks (Content-Type application/x-vseq-blocks-v1) is a header and
   then ledger records exactly as stored (vseq_ledger.h), so serving it
   is one file read and a copy:

     uchar magic[4]      "VSQB"
     uchar version       1
     uchar reserved[3]
     ulong finalized     the node's finalized slot
     uint  count         records that follow

   The last record always has its own certs, so a client can verify
   everything it got: check the certs on the last block, then follow
   parent hashes back. */

#define _GNU_SOURCE
#include "vseq_node.h"
#include "vseq_mesh.h"
#include "vseq_ledger.h"
#include "vseq_proof.h"
#include "vseq_history.h"
#include "../../ballet/toml/fd_toml.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#define POD_SZ          (4UL<<20)
#define PAYLOAD_MAX_DEFAULT (1UL<<20) /* 1 MiB blocks: ~50 MB/s leader upload with 20 nodes */
#define DAPP_MAX        (4096UL)
#define MEMBER_MAX      (4096UL)      /* [[validator]] entries */
#define EPOCH_SLOTS_DEFAULT (9000UL)  /* 1 hour of 400 ms slots */
#define TOML_SCRATCH_SZ (1UL<<16)
#define FILE_MAX        (4UL<<20)
#define RESP_MAX        (8UL<<20)   /* /blocks stops adding blocks past this */
#define BLOCKS_BIN_MAX  (1024UL)      /* /blocks */
#define SPAN_MAX        (12UL<<20)    /* /blocks hard size cap */
#define BLOCKS_HDR_SZ   (20UL)
#define STATUS_LOG_NS   (10L*1000L*1000L*1000L)
#define SEC_NS          (1000L*1000L*1000L)
#define SYNC_BATCH      (32UL)        /* blocks per sync request */
#define SYNC_TIP        (ULONG_MAX)   /* SYNC_REQ after_slot asking for the peer's latest finalized block */
#define SYNC_NEAR       (16UL)        /* close enough to the peer's tip to start consensus */
#define SYNC_TIMEOUT_NS (3L*SEC_NS)   /* ask the next peer */
#define SYNC_GIVEUP_NS  (15L*SEC_NS)  /* no peer answers: start consensus anyway */
#define LATE_JOIN_NS    (5L*SEC_NS)   /* empty ledger this long after genesis: sync first */
#define PROBE_NS        (15L*SEC_NS)  /* no finalization this long: ask a peer how far ahead it is */
#define COMPACT_SLOTS   (512UL)       /* compact the vote history this often */

/* Files and keys *****************************************************/

static ulong
read_file( char const * path,
           uchar *      buf,
           ulong        max ) {
  FILE * f = fopen( path, "rb" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "cannot open %s (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  ulong sz = fread( buf, 1UL, max, f );
  if( FD_UNLIKELY( sz==max ) ) FD_LOG_ERR(( "%s is too large", path ));
  fclose( f );
  return sz;
}

static uchar *
parse_toml( char const * path ) {
  static uchar file   [ FILE_MAX        ];
  static uchar scratch[ TOML_SCRATCH_SZ ];
  uchar * pod = fd_pod_join( fd_pod_new( malloc( POD_SZ ), POD_SZ ) );
  FD_TEST( pod );
  ulong              sz = read_file( path, file, sizeof(file) );
  fd_toml_err_info_t err;
  int                rc = fd_toml_parse( file, sz, pod, scratch, sizeof(scratch), &err );
  if( FD_UNLIKELY( rc ) ) FD_LOG_ERR(( "%s:%lu: %s", path, err.line, fd_toml_strerror( rc ) ));
  return pod;
}

static void
hex_field( uchar const * pod,
           char const *  path,
           char const *  key,
           uchar *       out,
           ulong         sz ) {
  char const * s = fd_pod_query_cstr( pod, key, NULL );
  if( FD_UNLIKELY( !s ) ) FD_LOG_ERR(( "%s: missing %s", path, key ));
  if( FD_UNLIKELY( strlen( s )!=2UL*sz || fd_hex_decode( out, s, sz )!=sz ) ) FD_LOG_ERR(( "%s: %s must be %lu hex bytes", path, key, sz ));
}

static void
put_hex( FILE *        f,
         char const *  key,
         uchar const * b,
         ulong         sz ) {
  char s[ 2UL*256UL+1UL ];
  FD_TEST( sz<=256UL );
  fd_hex_encode( s, b, sz );
  s[ 2UL*sz ] = '\0';
  fprintf( f, "%s = \"%s\"\n", key, s );
}

struct node_key {
  uchar        id_sec[ 32 ];
  uchar        id_pub[ 32 ];
  fd_bls_sec_t bls_sec;
  ag_bls_key_t bls_pub;
};
typedef struct node_key node_key_t;

static void
key_derive_pub( node_key_t * k ) {
  fd_sha512_t sha_mem[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( sha_mem ) );
  fd_ed25519_public_from_private( k->id_pub, k->id_sec, sha );
  fd_bls_pub_t pub;
  fd_bls_sec_to_pub( &k->bls_sec, &pub );
  blst_p1_compress( k->bls_pub, &pub );
}

static void
key_generate( node_key_t * k ) {
  uchar ikm[ 32 ];
  FD_TEST( fd_rng_secure( k->id_sec, 32UL ) );
  FD_TEST( fd_rng_secure( ikm, sizeof(ikm) ) );
  fd_bls_sec_derive( &k->bls_sec, ikm, sizeof(ikm) );
  fd_memzero_explicit( ikm, sizeof(ikm) );
  key_derive_pub( k );
}

static void
key_write( node_key_t const * k,
           char const *       path ) {
  FILE * f = fopen( path, "w" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "cannot write %s (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  fchmod( fileno( f ), 0600 );
  fprintf( f, "# vseq node key.  Keep secret.\n" );
  put_hex( f, "identity_secret", k->id_sec,       32UL );
  put_hex( f, "bls_secret",      k->bls_sec.b,    32UL );
  fprintf( f, "\n# public, for the cluster config\n" );
  put_hex( f, "# identity", k->id_pub,  32UL );
  put_hex( f, "# bls",      k->bls_pub, sizeof(ag_bls_key_t) );
  fclose( f );
}

static void
key_read( node_key_t * k,
          char const * path ) {
  uchar * pod = parse_toml( path );
  hex_field( pod, path, "identity_secret", k->id_sec,    32UL );
  hex_field( pod, path, "bls_secret",      k->bls_sec.b, 32UL );
  free( fd_pod_delete( fd_pod_leave( pod ) ) );
  key_derive_pub( k );
}

/* Cluster config *****************************************************/

struct cluster {
  ushort           network_id;
  long             slot_ns;
  long             genesis_ns;  /* unix ns, 0 to start right away */
  ulong            payload_max;
  ulong            cnt;         /* [[validator]] entries */
  vseq_member_t    members[ MEMBER_MAX ];
  vseq_mesh_peer_t addrs  [ MEMBER_MAX ];
  vseq_sched_t *   sched;
};
typedef struct cluster cluster_t;

static void
cluster_read( cluster_t *  c,
              char const * path ) {
  uchar * pod = parse_toml( path );
  long network_id = fd_pod_query_long( pod, "network_id",  0L      );
  long slot_ms    = fd_pod_query_long( pod, "slot_ms",     400L    );
  long payload    = fd_pod_query_long( pod, "payload_max", (long)PAYLOAD_MAX_DEFAULT );
  long genesis_ms = fd_pod_query_long( pod, "genesis_time_ms", 0L  );
  long epoch_slots = fd_pod_query_long( pod, "epoch_slots", (long)EPOCH_SLOTS_DEFAULT );
  if( FD_UNLIKELY( epoch_slots<=0L ) ) FD_LOG_ERR(( "%s: epoch_slots must be positive", path ));
  if( FD_UNLIKELY( genesis_ms<0L ) ) FD_LOG_ERR(( "%s: genesis_time_ms must not be negative", path ));
  c->genesis_ns   = genesis_ms*1000000L;
  if( FD_UNLIKELY( network_id<1L || network_id>65535L ) ) FD_LOG_ERR(( "%s: network_id must be in [1,65535]", path ));
  if( FD_UNLIKELY( slot_ms<50L || slot_ms>60000L      ) ) FD_LOG_ERR(( "%s: slot_ms must be in [50,60000]", path ));
  if( FD_UNLIKELY( payload<1024L || payload>(16L<<20) ) ) FD_LOG_ERR(( "%s: payload_max must be in [1024,16777216]", path ));
  c->network_id  = (ushort)network_id;
  c->slot_ns     = slot_ms*1000L*1000L;
  c->payload_max = (ulong)payload;

  c->cnt = 0UL;
  for( ulong i=0UL; ; i++ ) {
    char key[ 64 ];
    FD_TEST( fd_cstr_printf_check( key, sizeof(key), NULL, "validator.%lu", i ) );
    uchar const * v = fd_pod_query_subpod( pod, key );
    if( !v ) break;
    if( FD_UNLIKELY( i>=MEMBER_MAX ) ) FD_LOG_ERR(( "%s: more than %lu validator entries", path, MEMBER_MAX ));

    char where[ 4200 ];
    fd_cstr_printf( where, sizeof(where), NULL, "%s validator %lu", path, i );
    long         stake = fd_pod_query_long( v, "stake", 0L );
    char const * host  = fd_pod_query_cstr( v, "host", NULL );
    long         port  = fd_pod_query_long( v, "port", 0L );
    long         from  = fd_pod_query_long( v, "from_epoch",   0L );
    long         until = fd_pod_query_long( v, "until_epoch", -1L );
    if( FD_UNLIKELY( stake<=0L                      ) ) FD_LOG_ERR(( "%s: stake must be positive", where ));
    if( FD_UNLIKELY( from<0L || until<-1L           ) ) FD_LOG_ERR(( "%s: bad from_epoch or until_epoch", where ));
    if( FD_UNLIKELY( !host || !fd_cstr_to_ip4_addr( host, &c->addrs[i].ip4 ) ) ) FD_LOG_ERR(( "%s: host must be an IPv4 address", where ));
    if( FD_UNLIKELY( port<1L || port>65535L         ) ) FD_LOG_ERR(( "%s: bad port", where ));
    vseq_member_t * m = &c->members[i];
    m->v.stake        = (ulong)stake;
    m->from_epoch     = (ulong)from;
    m->until_epoch    = until<0L ? ULONG_MAX : (ulong)until;
    c->addrs[i].port  = (ushort)port;
    hex_field( v, where, "identity", m->v.id_key,  32UL                 );
    hex_field( v, where, "bls",      m->v.bls_key, sizeof(ag_bls_key_t) );
    memcpy( c->addrs[i].id_pub, m->v.id_key, 32UL );
    c->cnt++;
  }
  if( FD_UNLIKELY( !c->cnt ) ) FD_LOG_ERR(( "%s: no [[validator]] entries", path ));
  free( fd_pod_delete( fd_pod_leave( pod ) ) );

  c->sched = vseq_sched_new( c->members, c->cnt, (ulong)epoch_slots, c->network_id );
  if( FD_UNLIKELY( !c->sched ) ) FD_LOG_ERR(( "%s: bad validator schedule", path ));
  for( ulong i=0UL; i<c->cnt; i++ ) {
    for( ulong j=0UL; j<i; j++ ) {
      if( c->sched->member_peer[i]==c->sched->member_peer[j] &&
          ( c->addrs[i].ip4!=c->addrs[j].ip4 || c->addrs[i].port!=c->addrs[j].port ) ) {
        FD_LOG_ERR(( "%s: validator entries %lu and %lu have the same identity but different addresses", path, j, i ));
      }
    }
  }
}

/* API keys ***********************************************************/

struct dapp {
  char  name[ 64 ];
  uchar key_hash[ 32 ];  /* SHA-256 of the key string */
  ulong rate[ 2 ];       /* txs bytes, requests per second; 0 for no limit */
  ulong tokens[ 2 ];
  long  refill;          /* last refill, wallclock ns */
};
typedef struct dapp dapp_t;

static dapp_t *
dapps_read( char const * path,
            ulong *      cnt ) {
  uchar *  pod   = parse_toml( path );
  dapp_t * dapps = calloc( DAPP_MAX, sizeof(dapp_t) );
  FD_TEST( dapps );
  ulong i = 0UL;
  for( ;; i++ ) {
    char key[ 64 ];
    FD_TEST( fd_cstr_printf_check( key, sizeof(key), NULL, "dapp.%lu", i ) );
    uchar const * v = fd_pod_query_subpod( pod, key );
    if( !v ) break;
    if( FD_UNLIKELY( i>=DAPP_MAX ) ) FD_LOG_ERR(( "%s: more than %lu dapps", path, DAPP_MAX ));
    char where[ 4200 ];
    fd_cstr_printf( where, sizeof(where), NULL, "%s dapp %lu", path, i );
    dapp_t *     a    = &dapps[i];
    char const * name = fd_pod_query_cstr( v, "name", "" );
    long         txs  = fd_pod_query_long( v, "txs_bytes_per_s", 0L );
    long         reqs = fd_pod_query_long( v, "requests_per_s",  0L );
    if( FD_UNLIKELY( txs<0L || reqs<0L || txs>(1L<<32) || reqs>(1L<<32) ) ) FD_LOG_ERR(( "%s: limits must be in [0,2^32]", where ));
    fd_cstr_ncpy( a->name, name, sizeof(a->name) );
    hex_field( v, where, "key_sha256", a->key_hash, 32UL );
    for( ulong j=0UL; j<i; j++ ) if( FD_UNLIKELY( !memcmp( dapps[j].key_hash, a->key_hash, 32UL ) ) ) FD_LOG_ERR(( "%s: same key as dapp %lu", where, j ));
    a->rate[0] = a->tokens[0] = (ulong)txs;
    a->rate[1] = a->tokens[1] = (ulong)reqs;
  }
  if( FD_UNLIKELY( !i ) ) FD_LOG_ERR(( "%s: no [[dapp]] entries", path ));
  free( fd_pod_delete( fd_pod_leave( pod ) ) );
  *cnt = i;
  return dapps;
}

/* dapp_charge takes cost[j] tokens from each bucket, refilled at
   rate[j] per second up to one second's worth.  Returns 0 and takes
   nothing if any bucket is short. */

static int
dapp_charge( dapp_t *    a,
             long        now,
             ulong const cost[ 2 ] ) {
  ulong dt = (ulong)fd_long_min( fd_long_max( now-a->refill, 0L ), SEC_NS );
  a->refill = now;
  for( ulong j=0UL; j<2UL; j++ ) a->tokens[j] = fd_ulong_min( a->tokens[j] + a->rate[j]*dt/(ulong)SEC_NS, a->rate[j] );
  for( ulong j=0UL; j<2UL; j++ ) if( a->rate[j] && cost[j]>a->tokens[j] ) return 0;
  for( ulong j=0UL; j<2UL; j++ ) if( a->rate[j] ) a->tokens[j] -= cost[j];
  return 1;
}

/* HTTP API, shared by run and blocks *********************************/

struct api {
  fd_http_server_t * http;
  int                ep;       /* epoll fd */
  dapp_t *           dapps;    /* NULL: the API is open */
  ulong              dapp_cnt;
  long               now;
};
typedef struct api api_t;

static void
api_open( api_t *                    api,
          char const *               keys_path,
          ushort                     port,
          ulong                      request_max,
          ulong                      out_sz,
          fd_http_server_callbacks_t callbacks,
          void *                     ctx ) {
  if( keys_path ) {
    api->dapps = dapps_read( keys_path, &api->dapp_cnt );
    FD_LOG_NOTICE(( "API open to %lu dapps from %s", api->dapp_cnt, keys_path ));
  } else {
    FD_LOG_WARNING(( "no --api-keys: the API is open to everyone" ));
  }
  fd_http_server_params_t params = {
    .max_connection_cnt    = 64UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = request_max,
    .max_ws_recv_frame_len = request_max,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = out_sz,
  };
  void * mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( fd_http_server_footprint( params ), fd_http_server_align() ) );
  FD_TEST( mem );
  api->http = fd_http_server_join( fd_http_server_new( mem, params, callbacks, ctx ) );
  api->ep   = epoll_create1( EPOLL_CLOEXEC );
  FD_TEST( api->http && api->ep>=0 );
  fd_http_server_listen( api->http, api->ep, 0U, port );
}

/* api_poll serves at most a few requests, so a flood of them cannot
   hold up the caller's loop. */

static void
api_poll( api_t * api,
          long    now ) {
  api->now = now;
  fd_http_server_epoll_poll( api->http, 16UL );
}

/* Commands: keygen, api-key, gen-cluster *****************************/

static int
cmd_keygen( int     argc,
            char ** argv ) {
  char const * out = fd_env_strip_cmdline_cstr( &argc, &argv, "--out", NULL, NULL );
  if( FD_UNLIKELY( !out ) ) FD_LOG_ERR(( "usage: vseqd keygen --out node.toml" ));
  struct stat st;
  if( FD_UNLIKELY( !stat( out, &st ) ) ) FD_LOG_ERR(( "%s exists, not overwriting", out ));
  node_key_t k;
  key_generate( &k );
  key_write( &k, out );
  char id[ 65 ], bls[ 97 ];
  fd_hex_encode( id,  k.id_pub,  32UL );                 id [ 64 ] = '\0';
  fd_hex_encode( bls, k.bls_pub, sizeof(ag_bls_key_t) ); bls[ 96 ] = '\0';
  printf( "identity = \"%s\"\nbls      = \"%s\"\n", id, bls );
  return 0;
}

static int
cmd_api_key( int     argc,
             char ** argv ) {
  char const * name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--name",            NULL, NULL );
  ulong        txs  = fd_env_strip_cmdline_ulong( &argc, &argv, "--txs-bytes-per-s", NULL, 0UL  );
  ulong        reqs = fd_env_strip_cmdline_ulong( &argc, &argv, "--requests-per-s",  NULL, 0UL  );
  if( FD_UNLIKELY( !name || strchr( name, '"' ) || strchr( name, '\\' ) ) ) FD_LOG_ERR(( "usage: vseqd api-key --name NAME" ));
  uchar raw[ 32 ], hash[ 32 ];
  char  key[ 65 ];
  FD_TEST( fd_rng_secure( raw, sizeof(raw) ) );
  fd_hex_encode( key, raw, 32UL ); key[ 64 ] = '\0';
  fd_sha256_hash( key, 64UL, hash );
  printf( "# give this key to %s only:\n# %s\n\n[[dapp]]\nname            = \"%s\"\n", name, key, name );
  put_hex( stdout, "key_sha256     ", hash, 32UL );
  printf( "txs_bytes_per_s = %lu\nrequests_per_s  = %lu\n", txs, reqs );
  return 0;
}

static int
cmd_gen_cluster( int     argc,
                 char ** argv ) {
  ulong        n         = fd_env_strip_cmdline_ulong ( &argc, &argv, "--nodes",         NULL, 20UL         );
  char const * dir       = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--dir",           NULL, NULL         );
  char const * host      = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--host",          NULL, "127.0.0.1"  );
  ushort       base_port = fd_env_strip_cmdline_ushort( &argc, &argv, "--base-port",     NULL, (ushort)9000 );
  ushort       api_base  = fd_env_strip_cmdline_ushort( &argc, &argv, "--api-base-port", NULL, (ushort)8000 );
  ushort       blk_base  = fd_env_strip_cmdline_ushort( &argc, &argv, "--blocks-base-port", NULL, (ushort)8500 );
  int          distinct  = fd_env_strip_cmdline_contains( &argc, &argv, "--distinct-hosts" );
  char const * api_host  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--api-host",      NULL, NULL         );
  ulong        delay_s   = fd_env_strip_cmdline_ulong ( &argc, &argv, "--genesis-delay-s", NULL, 5UL         );
  if( FD_UNLIKELY( !dir || !n || n>AG_VAT_MAX ) ) FD_LOG_ERR(( "usage: vseqd gen-cluster --nodes N --dir DIR" ));
  uint host_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( host, &host_ip ) ) ) FD_LOG_ERR(( "--host must be an IPv4 address" ));
  if( !api_host ) api_host = distinct ? "127.0.0.1" : host;
  if( FD_UNLIKELY( mkdir( dir, 0700 ) && errno!=EEXIST ) ) FD_LOG_ERR(( "mkdir %s failed (%i-%s)", dir, errno, fd_io_strerror( errno ) ));

  uint network_id;
  FD_TEST( fd_rng_secure( &network_id, sizeof(network_id) ) );
  network_id = 1U + network_id%65535U;

  char path[ 4096 ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/cluster.toml", dir ) );
  FILE * f = fopen( path, "w" );
  if( FD_UNLIKELY( !f ) ) FD_LOG_ERR(( "cannot write %s", path ));
  fprintf( f, "network_id      = %u\nslot_ms         = 400\npayload_max     = %lu\ngenesis_time_ms = %ld\nepoch_slots     = %lu\n",
           network_id, PAYLOAD_MAX_DEFAULT, fd_log_wallclock()/1000000L + (long)delay_s*1000L, EPOCH_SLOTS_DEFAULT );

  for( ulong i=0UL; i<n; i++ ) {
    node_key_t k;
    key_generate( &k );
    char key_path[ 4096 ];
    FD_TEST( fd_cstr_printf_check( key_path, sizeof(key_path), NULL, "%s/node-%lu.toml", dir, i ) );
    key_write( &k, key_path );
    fprintf( f, "\n[[validator]]\nstake    = 1\n" );
    put_hex( f, "identity", k.id_pub,  32UL );
    put_hex( f, "bls     ", k.bls_pub, sizeof(ag_bls_key_t) );
    uint ip = distinct ? fd_uint_bswap( fd_uint_bswap( host_ip )+(uint)i ) : host_ip;
    fprintf( f, "host     = \"" FD_IP4_ADDR_FMT "\"\nport     = %lu\n", FD_IP4_ADDR_FMT_ARGS( ip ), distinct ? (ulong)base_port : (ulong)base_port+i );
    fprintf( f, "api      = \"http://%s:%lu\"\n", api_host, (ulong)api_base+i );
    fprintf( f, "blocks   = \"http://%s:%lu\"\n", api_host, (ulong)blk_base+i );
  }
  fclose( f );

  printf( "wrote %s and %lu node keys.  Start each node and its blocks server with:\n", path, n );
  for( ulong i=0UL; i<n; i++ ) {
    printf( "  vseqd run --cluster %s/cluster.toml --key %s/node-%lu.toml --ledger %s/ledger-%lu --api-port %lu\n"
            "  vseqd blocks --cluster %s/cluster.toml --ledger %s/ledger-%lu --port %lu\n",
            dir, dir, i, dir, i, (ulong)api_base+i, dir, dir, i, (ulong)blk_base+i );
  }
  return 0;
}

/* Command: run *******************************************************/

struct sync_blk {
  uchar * rec;      /* a ledger record from the peer */
  ulong   sz;
};
typedef struct sync_blk sync_blk_t;

struct daemon {
  vseq_node_t *      node;     /* NULL before genesis and while syncing */
  vseq_mesh_t *      mesh;
  vseq_ledger_t *    ledger;
  api_t              api;
  cluster_t const *  cluster;
  vseq_sched_t const * sched;
  vseq_node_cfg_t *  cfg;      /* template for (re)creating the node */
  ulong              own;      /* our peer index */
  ulong              wall_epoch;  /* epoch by the clock, ULONG_MAX before the first peers_tick */
  uchar *            hello_sent;  /* by peer: we sent our set hash on this connection */
  uchar *            hello_ok;    /* by peer: its set hash matches ours */
  ulong *            hello_gen;   /* by peer: the connection (vseq_mesh_peer_conn_gen) hello_sent and hello_ok are about */
  long               now;
  uchar *            span;     /* sync records */
  uchar *            msg;      /* outgoing sync message */
  ag_cert_t *        cert;     /* proof check scratch */

  vseq_history_t *   history;
  ulong              compact_root;
  ulong              ledger_synced; /* delivered slot at the last ledger sync */
  ulong              retain_slots; /* prune ledger segments this far behind, 0 keeps all */
  int                history_full; /* an empty ledger fetches all history peers keep */

  struct {
    int           active;      /* consensus stopped, catching up */
    int           probing;     /* consensus running, asked a peer how far ahead it is */
    int           from_tip;    /* empty ledger: start at a peer's latest finalized block */
    ulong         peer;        /* rank asked, ULONG_MAX if none */
    ulong         next_peer;
    long          deadline;
    long          giveup;
    ag_block_id_t anchor;      /* last block in the ledger */
    sync_blk_t    pending[ SYNC_BATCH+1UL ]; /* received, not yet covered by certs */
    ulong         pending_cnt;
    ag_block_id_t pending_last;
    ulong         blocks;      /* appended by sync, total */
    ulong         gap_peers;   /* peers this round that pruned past our ledger */
    long          gap_log;     /* next time to complain about a history gap */
    long          last_progress;
    ulong         last_delivered;
  } sync;
};
typedef struct daemon daemon_t;

static volatile int stop = 0;

static void
on_signal( int sig ) {
  (void)sig;
  stop = 1;
}

static void
node_send( void *        ctx,
           ulong         dst,
           uchar const * buf,
           ulong         sz ) {
  daemon_t * d = ctx;
  vseq_mesh_send( d->mesh, dst==VSEQ_DST_ALL ? VSEQ_MESH_DST_ALL : dst, buf, sz );
}

static void hello_recv( daemon_t * d, ulong from, uchar const * body, ulong sz );
static ulong peers_ok( daemon_t const * d );
static void sync_serve( daemon_t * d, ulong from, uchar const * body, ulong sz );
static void sync_block( daemon_t * d, uchar const * body, ulong sz );
static void sync_end  ( daemon_t * d, uchar const * body, ulong sz );

static void
mesh_recv( void *        ctx,
           ulong         from,
           uchar const * msg,
           ulong         sz ) {
  daemon_t * d = ctx;
  if( msg[0]==VSEQ_MSG_HELLO ) { hello_recv( d, from, msg+1UL, sz-1UL ); return; }
  if( FD_UNLIKELY( !d->hello_ok[ from ] ) ) return; /* not known to share our validator set yet */
  switch( msg[0] ) {
  case VSEQ_MSG_SYNC_REQ:   sync_serve( d, from, msg+1UL, sz-1UL ); return;
  case VSEQ_MSG_SYNC_BLOCK: if( d->sync.active && from==d->sync.peer ) sync_block( d, msg+1UL, sz-1UL ); return;
  case VSEQ_MSG_SYNC_END:   if( ( d->sync.active || d->sync.probing ) && from==d->sync.peer ) sync_end( d, msg+1UL, sz-1UL ); return;
  default: break;
  }
  if( FD_UNLIKELY( !d->node ) ) return; /* before genesis or while syncing */
  vseq_node_recv( d->node, d->now, from, msg, sz );
}

static void
node_finalized( void *               ctx,
                vseq_block_t const * block,
                uchar const          hash[ 32 ],
                uchar const *        proof,
                ulong                proof_sz ) {
  daemon_t * d = ctx;
  vseq_ledger_append( d->ledger, block, hash, proof, proof_sz );
}

/* Vote history ******************************************************/

static void
node_persist_vote( void *        ctx,
                   ulong         slot,
                   uchar const * vote,
                   ulong         vote_sz,
                   uchar const * block,
                   ulong         block_sz ) {
  daemon_t * d = ctx;
  vseq_history_add_vote( d->history, slot, vote, vote_sz, block, block_sz );
}

static void
node_persist_block( void * ctx,
                    ulong  slot ) {
  daemon_t * d = ctx;
  vseq_history_add_block_floor( d->history, slot );
}

/* Consensus start ****************************************************/

static ag_block_id_t
ledger_tip( daemon_t *          d,
            vseq_ledger_rec_t * rec ) {
  ulong cnt = vseq_ledger_cnt( d->ledger );
  if( !cnt ) { rec->proof_sz = 0UL; return ag_block_id( 0UL, ag_block_hash_null ); }
  if( FD_UNLIKELY( vseq_ledger_read( d->ledger, cnt-1UL, rec ) ) ) FD_LOG_ERR(( "ledger read failed" ));
  return ag_block_id( rec->block.slot, rec->hash );
}

static void
start_node( daemon_t * d ) {
  vseq_ledger_rec_t rec;
  ag_block_id_t     root = ledger_tip( d, &rec );
  if( FD_UNLIKELY( root.slot && !rec.proof_sz ) ) FD_LOG_ERR(( "the last ledger block (slot %lu) has no certs", root.slot ));
  d->cfg->root_slot     = root.slot;
  memcpy( d->cfg->root_hash, root.hash, sizeof(ag_block_hash_t) );
  d->cfg->root_proof    = rec.proof;
  d->cfg->root_proof_sz = rec.proof_sz;
  vseq_ledger_sync( d->ledger ); /* the history forgets what the ledger has */
  vseq_history_compact( d->history, root.slot );
  d->cfg->prior_votes   = vseq_history_prior_votes ( d->history, &d->cfg->prior_votes_sz  );
  d->cfg->prior_blocks  = vseq_history_prior_blocks( d->history, &d->cfg->prior_blocks_sz );
  d->cfg->block_floor   = vseq_history_block_floor ( d->history );
  d->compact_root       = root.slot;
  d->ledger_synced      = root.slot;
  d->node = vseq_node_create( d->cfg, d->now );
  if( FD_UNLIKELY( !d->node ) ) FD_LOG_ERR(( "cannot start consensus at slot %lu", root.slot ));
  d->sync.active         = 0;
  d->sync.probing        = 0;
  d->sync.last_progress  = d->now;
  d->sync.last_delivered = root.slot;
  FD_LOG_NOTICE(( "consensus started at slot %lu, %lu peers connected", root.slot, peers_ok( d ) ));
}

/* Peers **************************************************************/

/* Peers agree on the validator set before they work together: after
   connecting, and again at every epoch, each sends HELLO with the hash
   of its set for its current epoch (by the clock).  A peer whose set
   differs is disconnected; until its HELLO matches, its messages are
   dropped.  Hello state is per connection: a peer that reconnects
   (even replacing a connection that still looked alive on our side)
   gets a fresh HELLO and must send its own again. */

static ulong
wall_epoch( daemon_t const * d ) {
  long t = d->now - d->cluster->genesis_ns;
  return t<=0L ? 0UL : (ulong)( t/d->cluster->slot_ns )/d->sched->epoch_slots;
}

static vseq_set_t const *
set_of_epoch( daemon_t const * d,
              ulong            epoch ) {
  return vseq_sched_set( d->sched, fd_ulong_sat_mul( epoch, d->sched->epoch_slots ) );
}

static void
hello_recv( daemon_t *    d,
            ulong         from,
            uchar const * body,
            ulong         sz ) {
  if( FD_UNLIKELY( sz!=40UL ) ) { vseq_mesh_close( d->mesh, from, "bad hello" ); return; }
  ulong gen = vseq_mesh_peer_conn_gen( d->mesh, from );
  if( gen!=d->hello_gen[ from ] ) { d->hello_gen[ from ] = gen; d->hello_sent[ from ] = 0; } /* its HELLO may beat peers_tick to the new connection */
  ulong epoch = FD_LOAD( ulong, body );
  if( FD_UNLIKELY( memcmp( set_of_epoch( d, epoch )->hash, body+8UL, 32UL ) ) ) {
    FD_LOG_WARNING(( "peer %lu has another validator set for epoch %lu: its cluster.toml differs from ours", from, epoch ));
    d->hello_ok[ from ] = 0;
    vseq_mesh_close( d->mesh, from, "different validator set" );
    return;
  }
  d->hello_ok[ from ] = 1;
}

/* peers_tick connects to the validators of the previous, current and
   next epoch and says hello on new connections and new epochs. */

static void
peers_tick( daemon_t * d ) {
  ulong epoch = wall_epoch( d );
  if( FD_UNLIKELY( epoch!=d->wall_epoch ) ) {
    d->wall_epoch = epoch;
    vseq_set_t const * sets[3] = { set_of_epoch( d, epoch ? epoch-1UL : 0UL ), set_of_epoch( d, epoch ), set_of_epoch( d, epoch+1UL ) };
    for( ulong p=0UL; p<d->sched->peer_cnt; p++ ) {
      int active = 0;
      for( ulong k=0UL; k<3UL; k++ ) active |= sets[k]->rank_of_peer[p]!=ULONG_MAX;
      vseq_mesh_set_active( d->mesh, p, active );
      d->hello_sent[p] = 0;
    }
  }
  vseq_set_t const * set = set_of_epoch( d, epoch );
  for( ulong p=0UL; p<d->sched->peer_cnt; p++ ) {
    if( p==d->own ) continue;
    if( !vseq_mesh_peer_connected( d->mesh, p ) ) { d->hello_sent[p] = d->hello_ok[p] = 0; continue; }
    ulong gen = vseq_mesh_peer_conn_gen( d->mesh, p );
    if( gen!=d->hello_gen[p] ) { d->hello_gen[p] = gen; d->hello_sent[p] = d->hello_ok[p] = 0; }
    if( d->hello_sent[p] ) continue;
    d->msg[0] = VSEQ_MSG_HELLO;
    FD_STORE( ulong, d->msg+1UL, epoch );
    memcpy( d->msg+9UL, set->hash, 32UL );
    vseq_mesh_send( d->mesh, p, d->msg, 41UL );
    d->hello_sent[p] = 1;
  }
}

static ulong
peers_ok( daemon_t const * d ) {
  ulong cnt = 0UL;
  for( ulong p=0UL; p<d->sched->peer_cnt; p++ ) cnt += d->hello_ok[p];
  return cnt;
}

/* Sync ***************************************************************/

static void
sync_clear_pending( daemon_t * d ) {
  for( ulong i=0UL; i<d->sync.pending_cnt; i++ ) free( d->sync.pending[i].rec );
  d->sync.pending_cnt = 0UL;
}

/* sync_after is what to ask peers for next. */

static ulong
sync_after( daemon_t const * d ) {
  return d->sync.from_tip ? SYNC_TIP : d->sync.anchor.slot;
}

/* sync_ask sends SYNC_REQ to the next connected peer (max 0 just asks
   for its tip). */

static void
sync_ask( daemon_t * d,
          ulong      after,
          ulong      max,
          int        next ) {
  ulong cnt = d->sched->peer_cnt;
  if( next || d->sync.peer==ULONG_MAX ) {
    d->sync.peer = ULONG_MAX;
    for( ulong i=0UL; i<cnt; i++ ) {
      ulong r = ( d->sync.next_peer+i ) % cnt;
      if( r==d->own || !d->hello_ok[r] ) continue;
      d->sync.peer      = r;
      d->sync.next_peer = r+1UL;
      break;
    }
  }
  sync_clear_pending( d );
  if( d->sync.peer==ULONG_MAX ) { d->sync.deadline = d->now + SEC_NS/5L; return; } /* nobody connected yet */
  d->msg[0] = VSEQ_MSG_SYNC_REQ;
  FD_STORE( ulong, d->msg+1UL, after );
  FD_STORE( ulong, d->msg+9UL, max   );
  vseq_mesh_send( d->mesh, d->sync.peer, d->msg, 17UL );
  d->sync.deadline = d->now + SYNC_TIMEOUT_NS;
}

static void
sync_start( daemon_t * d ) {
  vseq_ledger_rec_t rec;
  d->sync.active      = 1;
  d->sync.probing     = 0;
  d->sync.anchor      = ledger_tip( d, &rec );
  d->sync.peer        = ULONG_MAX;
  d->sync.giveup      = d->now + SYNC_GIVEUP_NS;
  d->sync.gap_peers   = 0UL;
  d->sync.from_tip    = !d->history_full && vseq_ledger_cnt( d->ledger )==vseq_ledger_first_idx( d->ledger );
  if( d->sync.from_tip ) FD_LOG_NOTICE(( "empty ledger: starting from a peer's latest finalized block" ));
  else                   FD_LOG_NOTICE(( "catching up from peers, ledger ends at slot %lu", d->sync.anchor.slot ));
  sync_ask( d, sync_after( d ), SYNC_BATCH, 1 );
}

/* sync_serve answers a peer's SYNC_REQ from our ledger, one record
   per SYNC_BLOCK, then SYNC_END with our tip and base. */

static void
sync_serve( daemon_t *    d,
            ulong         from,
            uchar const * body,
            ulong         sz ) {
  if( FD_UNLIKELY( sz!=16UL ) ) return;
  ulong         after = FD_LOAD( ulong, body );
  ulong         max   = fd_ulong_min( FD_LOAD( ulong, body+8UL ), SYNC_BATCH );
  ulong         cnt   = vseq_ledger_cnt( d->ledger );
  ag_block_id_t base  = vseq_ledger_base( d->ledger );
  ulong         first = vseq_ledger_first_after( d->ledger, after );
  if( after==SYNC_TIP ) first = cnt>vseq_ledger_first_idx( d->ledger ) ? cnt-1UL : cnt; /* has its certs */
  if( after<base.slot ) max = 0UL; /* pruned: the peer learns our base from SYNC_END */

  ulong n, span = max ? vseq_ledger_read_span( d->ledger, first, max, 0UL, d->span, SPAN_MAX, &n ) : 0UL;
  for( ulong off=0UL; off<span; ) {
    ulong rec_sz = sizeof(uint)+FD_LOAD( uint, d->span+off );
    d->msg[0] = VSEQ_MSG_SYNC_BLOCK;
    memcpy( d->msg+1UL, d->span+off, rec_sz );
    vseq_mesh_send( d->mesh, from, d->msg, 1UL+rec_sz );
    off += rec_sz;
  }
  vseq_ledger_rec_t rec;
  ag_block_id_t     tip = ledger_tip( d, &rec );
  d->msg[0] = VSEQ_MSG_SYNC_END;
  FD_STORE( ulong, d->msg+ 1UL, tip.slot  );
  FD_STORE( ulong, d->msg+ 9UL, base.slot );
  memcpy( d->msg+17UL, base.hash, 32UL );
  vseq_mesh_send( d->mesh, from, d->msg, 49UL );
}

/* sync_block checks one record from the peer.  Records queue until one
   carries certs; once those verify, the queue is appended to the
   ledger.  With an empty ledger and from_tip, the first record (the
   peer's latest finalized block) starts the ledger on its own certs.
   Anything wrong drops the batch and moves to the next peer. */

static void
sync_block( daemon_t *    d,
            uchar const * rec_buf,
            ulong         sz ) {
  vseq_ledger_rec_t rec;
  ag_block_hash_t   hash;
  if( FD_UNLIKELY( vseq_ledger_rec_parse( rec_buf, sz, &rec ) || d->sync.pending_cnt>SYNC_BATCH ) ) goto bad;
  vseq_block_hash( rec.block.slot, &rec.block.parent, rec.block.payload, rec.block.payload_sz, hash );
  if( FD_UNLIKELY( memcmp( hash, rec.hash, sizeof(ag_block_hash_t) ) ) ) goto bad;
  int proved = rec.proof_sz && !vseq_proof_verify( vseq_sched_set( d->sched, rec.block.slot )->epoch, d->cluster->network_id, rec.block.slot, hash, rec.proof, rec.proof_sz, d->cert );
  if( FD_UNLIKELY( rec.proof_sz && !proved ) ) goto bad;

  if( d->sync.from_tip ) {
    if( FD_UNLIKELY( !proved || vseq_ledger_set_base( d->ledger, &rec.block.parent ) ) ) goto bad;
    vseq_ledger_append( d->ledger, &rec.block, hash, rec.proof, rec.proof_sz );
    d->sync.anchor   = ag_block_id( rec.block.slot, hash );
    d->sync.from_tip = 0;
    d->sync.blocks++;
    FD_LOG_NOTICE(( "starting the ledger at peer %lu's finalized slot %lu, without the history before it", d->sync.peer, rec.block.slot ));
    return;
  }

  ag_block_id_t prev = d->sync.pending_cnt ? d->sync.pending_last : d->sync.anchor;
  if( FD_UNLIKELY( !ag_block_id_eq( &rec.block.parent, &prev ) ) ) goto bad;
  sync_blk_t * p = &d->sync.pending[ d->sync.pending_cnt++ ];
  p->rec = malloc( sz );
  p->sz  = sz;
  FD_TEST( p->rec );
  memcpy( p->rec, rec_buf, sz );
  d->sync.pending_last = ag_block_id( rec.block.slot, hash );
  if( !proved ) return;

  for( ulong i=0UL; i<d->sync.pending_cnt; i++ ) {
    FD_TEST( !vseq_ledger_rec_parse( d->sync.pending[i].rec, d->sync.pending[i].sz, &rec ) );
    vseq_ledger_append( d->ledger, &rec.block, rec.hash, rec.proof, rec.proof_sz );
  }
  d->sync.blocks += d->sync.pending_cnt;
  d->sync.anchor  = d->sync.pending_last;
  sync_clear_pending( d );
  return;

bad:
  FD_LOG_WARNING(( "sync: bad block from peer %lu, asking another peer", d->sync.peer ));
  sync_ask( d, sync_after( d ), SYNC_BATCH, 1 );
}

/* sync_end handles a peer's tip and base (the block its oldest kept
   record builds on).  While syncing: if the peer pruned past our
   ledger, start an empty ledger at its base or try another peer;
   otherwise start consensus once near its tip, or ask for more.  While
   probing: if the peer is further ahead than consensus can repair,
   stop consensus and sync. */

static void
sync_end( daemon_t *    d,
          uchar const * body,
          ulong         sz ) {
  if( FD_UNLIKELY( sz!=48UL ) ) return;
  ulong         tip  = FD_LOAD( ulong, body );
  ag_block_id_t base = ag_block_id( FD_LOAD( ulong, body+8UL ), body+16UL );
  if( d->sync.active ) {
    sync_clear_pending( d ); /* blocks after the last certified one */
    if( d->sync.anchor.slot<base.slot ) {
      int empty = vseq_ledger_cnt( d->ledger )==vseq_ledger_first_idx( d->ledger );
      if( empty && !vseq_ledger_set_base( d->ledger, &base ) ) {
        /* Nothing to lose: start after the peer's oldest kept block.
           The certs at the end of each batch prove what follows. */
        FD_LOG_NOTICE(( "peer %lu pruned history before slot %lu; starting the ledger there", d->sync.peer, base.slot ));
        d->sync.anchor = base;
        sync_ask( d, sync_after( d ), SYNC_BATCH, 0 );
        return;
      }
      d->sync.gap_peers++;
      if( d->sync.gap_peers>=vseq_mesh_connected_cnt( d->mesh ) && d->now>=d->sync.gap_log ) {
        FD_LOG_WARNING(( "history gap: the ledger ends at slot %lu but every connected peer pruned history before it (peer %lu keeps from slot %lu). "
                         "Restore older segments, or restart with an empty ledger and the same vote history file.",
                         d->sync.anchor.slot, d->sync.peer, base.slot ));
        d->sync.gap_log = d->now + 30L*SEC_NS;
      }
      sync_ask( d, sync_after( d ), SYNC_BATCH, 1 );
      return;
    }
    d->sync.gap_peers = 0UL;
    if( tip<=d->sync.anchor.slot+SYNC_NEAR ) {
      FD_LOG_NOTICE(( "caught up: %lu blocks from peers, peer at slot %lu", d->sync.blocks, tip ));
      start_node( d );
    } else {
      sync_ask( d, sync_after( d ), SYNC_BATCH, 0 );
    }
  } else if( d->sync.probing ) {
    d->sync.probing = 0;
    ulong delivered = vseq_node_delivered_slot( d->node );
    if( tip>delivered+d->cfg->slot_max/2UL ) {
      FD_LOG_WARNING(( "fell behind: finalized slot %lu, peer %lu is at %lu; restarting consensus after catching up", delivered, d->sync.peer, tip ));
      vseq_node_destroy( d->node );
      d->node = NULL;
      sync_start( d );
    }
  }
}

static void
sync_tick( daemon_t * d ) {
  if( d->sync.active ) {
    if( d->now>=d->sync.giveup && !d->sync.gap_peers ) {
      FD_LOG_WARNING(( "sync: no peer answered, starting consensus at slot %lu", d->sync.anchor.slot ));
      sync_clear_pending( d );
      start_node( d );
      return;
    }
    if( d->now>=d->sync.deadline ) sync_ask( d, sync_after( d ), SYNC_BATCH, 1 );
    return;
  }

  /* Consensus running: if finalization stalls, check whether peers are
     ahead of what the pool can accept. */
  ulong delivered = vseq_node_delivered_slot( d->node );
  if( delivered!=d->sync.last_delivered ) { d->sync.last_delivered = delivered; d->sync.last_progress = d->now; }
  if( d->sync.probing && d->now>=d->sync.deadline ) d->sync.probing = 0;
  if( !d->sync.probing && d->now-d->sync.last_progress>=PROBE_NS ) {
    d->sync.probing       = 1;
    d->sync.last_progress = d->now;
    sync_ask( d, delivered, 0UL, 1 );
  }
}

/* query_val returns the value of key in path's query string and sets
   *len, or NULL if it is not there. */

static char const *
query_val( char const * path,
           char const * key,
           ulong *      len ) {
  char const * p = strchr( path, '?' );
  ulong key_len = strlen( key );
  for( ; p; p = strchr( p, '&' ) ) {
    p++;
    if( !strncmp( p, key, key_len ) && p[ key_len ]=='=' ) {
      p  += key_len+1UL;
      *len = strcspn( p, "&" );
      return p;
    }
  }
  return NULL;
}

static ulong
query_ulong( char const * path,
             char const * key,
             ulong        def ) {
  ulong        len;
  char const * v = query_val( path, key, &len );
  return v ? strtoul( v, NULL, 10 ) : def;
}

static int
path_is( char const * path,
         char const * route ) {
  ulong n = strlen( route );
  return !strncmp( path, route, n ) && ( path[n]=='\0' || path[n]=='?' );
}

static fd_http_server_response_t
respond( fd_http_server_t * http,
         ulong              status ) {
  fd_http_server_response_t res = { .status = status, .content_type = "application/json", .access_control_allow_origin = "*" };
  if( FD_UNLIKELY( fd_http_server_stage_body( http, &res ) ) ) {
    fd_http_server_response_t err = { .status = 500 };
    return err;
  }
  return res;
}

static fd_http_server_response_t
api_status( daemon_t * d ) {
  static vseq_node_metrics_t const none = {0};
  vseq_node_metrics_t const * m  = d->node ? vseq_node_metrics( d->node ) : &none;
  vseq_ledger_rec_t           rec;
  ulong                       finalized = d->node ? vseq_node_delivered_slot( d->node ) : ledger_tip( d, &rec ).slot;
  char const *                state     = d->node ? "running" : d->sync.active ? "syncing" : "waiting_for_genesis";
  vseq_ledger_stats_t         ls        = vseq_ledger_stats( d->ledger );
  vseq_mesh_metrics_t const * mm = vseq_mesh_metrics( d->mesh );
  vseq_set_t const *          set = vseq_sched_set( d->sched, finalized );
  ulong                       rank = set->rank_of_peer[ d->own ];
  char id[ 65 ];
  fd_hex_encode( id, d->sched->peer_id[ d->own ], 32UL ); id[64] = '\0';
  fd_http_server_printf( d->api.http,
      "{\"state\":\"%s\",\"peer\":%lu,\"rank\":%ld,\"set_epoch\":%lu,\"identity\":\"%s\",\"network_id\":%u,\"slot_ms\":%ld,\"validators\":%lu,"
      "\"peers_connected\":%lu,\"finalized_slot\":%lu,\"ledger_blocks\":%lu,"
      "\"vote_history_bytes\":%lu,\"no_blocks_until\":%lu,\"synced_blocks\":%lu,"
      "\"ledger_base_slot\":%lu,\"ledger_segments\":%lu,\"ledger_bytes\":%lu,\"ledger_pruned_segments\":%lu,\"history\":\"%s\","
      "\"metrics\":{\"blocks_built\":%lu,\"blocks_finalized\":%lu,\"fast_final_certs\":%lu,\"final_certs\":%lu,"
      "\"skip_certs\":%lu,\"standstills\":%lu,\"repair_reqs_sent\":%lu,\"bans\":%lu,"
      "\"votes_restored\":%lu,\"votes_withheld\":%lu,\"blocks_withheld\":%lu,\"blocks_refused\":%lu,"
      "\"frames_dropped\":%lu,\"disconnects\":%lu}}\n",
      state, d->own, rank==ULONG_MAX ? -1L : (long)rank, set->first_epoch, id, (uint)d->cluster->network_id, d->cluster->slot_ns/1000000L, set->epoch->validator_cnt,
      peers_ok( d ), finalized, vseq_ledger_cnt( d->ledger ),
      vseq_history_size( d->history ), d->node ? vseq_node_quiet_until( d->node ) : 0UL, d->sync.blocks,
      vseq_ledger_base( d->ledger ).slot, ls.segments, ls.bytes, ls.pruned, d->history_full ? "full" : "recent",
      m->blocks_built, m->blocks_finalized, m->fast_final_certs, m->final_certs,
      m->skip_certs, m->standstills, m->repair_reqs_sent, m->bans,
      m->votes_restored, m->votes_withheld, m->blocks_withheld, m->blocks_refused,
      mm->frames_dropped, mm->disconnects );
  return respond( d->api.http, 200 );
}

/* api_auth finds the caller's dapp and charges the call to it.
   Returns 0 if the call may go on, 403 for a bad key, or 400 if it is
   over its limits. */

static ulong
api_auth( api_t *                          api,
          fd_http_server_request_t const * req ) {
  if( !api->dapps ) return 0UL;
  ulong        len;
  char const * key = query_val( req->path, "api-key", &len );
  if( FD_UNLIKELY( !key ) ) return 403UL;
  uchar hash[ 32 ];
  fd_sha256_hash( key, len, hash );
  for( ulong i=0UL; i<api->dapp_cnt; i++ ) {
    if( memcmp( api->dapps[i].key_hash, hash, 32UL ) ) continue;
    ulong cost[ 2 ] = { req->method==FD_HTTP_SERVER_METHOD_POST ? req->post.body_len : 0UL, 1UL };
    return dapp_charge( &api->dapps[i], api->now, cost ) ? 0UL : 400UL;
  }
  return 403UL;
}

/* api_denied answers a call api_auth refused. */

static fd_http_server_response_t
api_denied( api_t * api,
            ulong   status ) {
  fd_http_server_printf( api->http, "{\"error\":\"%s\"}\n", status==403UL ? "missing or unknown api-key" : "rate limit" );
  return respond( api->http, status );
}

static fd_http_server_response_t
api_request( fd_http_server_request_t const * req ) {
  daemon_t * d = req->ctx;
  ulong denied = api_auth( &d->api, req );
  if( FD_UNLIKELY( denied ) ) return api_denied( &d->api, denied );
  if( req->method==FD_HTTP_SERVER_METHOD_GET && path_is( req->path, "/status" ) ) return api_status( d );
  if( FD_UNLIKELY( !d->node && req->method==FD_HTTP_SERVER_METHOD_POST ) ) {
    fd_http_server_printf( d->api.http, "{\"ok\":false,\"error\":\"%s\"}\n", d->sync.active ? "syncing" : "waiting for genesis" );
    return respond( d->api.http, 400 );
  }
  if( req->method==FD_HTTP_SERVER_METHOD_POST && path_is( req->path, "/txs" ) ) {
    ulong off = 0UL, tx_sz, accepted = 0UL, refused = 0UL;
    for( uchar const * tx; (tx = vseq_payload_next( req->post.body, req->post.body_len, &off, &tx_sz )); ) {
      if( tx_sz && !vseq_node_submit_tx( d->node, tx, tx_sz ) ) accepted++;
      else                                                    refused++;
    }
    if( FD_UNLIKELY( off!=req->post.body_len ) ) {
      fd_http_server_printf( d->api.http, "{\"ok\":false,\"error\":\"body must be txs framed as (u32 le size, bytes)\",\"accepted\":%lu}\n", accepted );
      return respond( d->api.http, 400 );
    }
    fd_http_server_printf( d->api.http, "{\"ok\":%s,\"accepted\":%lu,\"refused\":%lu}\n", refused ? "false" : "true", accepted, refused );
    return respond( d->api.http, refused ? 400 : 200 );
  }
  fd_http_server_printf( d->api.http, "{\"error\":\"not found\"}\n" );
  return respond( d->api.http, 404 );
}

static int
cmd_run( int     argc,
         char ** argv ) {
  char const * cluster_path = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cluster",  NULL, NULL         );
  char const * key_path     = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--key",      NULL, NULL         );
  char const * ledger_path  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--ledger",   NULL, NULL         );
  ushort       api_port     = fd_env_strip_cmdline_ushort( &argc, &argv, "--api-port", NULL, (ushort)8000 );
  ulong        slot_max     = fd_env_strip_cmdline_ulong ( &argc, &argv, "--slot-max", NULL, 64UL         );
  ulong        seg_kb       = fd_env_strip_cmdline_ulong ( &argc, &argv, "--ledger-segment-kb",   NULL, 256UL*1024UL );
  ulong        retain_slots = fd_env_strip_cmdline_ulong ( &argc, &argv, "--ledger-retain-slots", NULL, 0UL          );
  char const * history      = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--history",             NULL, "recent"     );
  char const * keys_path    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--api-keys",            NULL, NULL         );
  if( FD_UNLIKELY( strcmp( history, "recent" ) && strcmp( history, "full" ) ) ) FD_LOG_ERR(( "--history must be recent or full" ));
  if( FD_UNLIKELY( !cluster_path || !key_path || !ledger_path ) ) FD_LOG_ERR(( "usage: vseqd run --cluster cluster.toml --key node.toml --ledger DIR [--api-port 8000]" ));
  if( FD_UNLIKELY( slot_max<32UL ) ) FD_LOG_ERR(( "--slot-max must be at least 32" ));
  /* Keep at least what consensus may still ask peers to repair */
  if( FD_UNLIKELY( retain_slots && retain_slots<2UL*slot_max ) ) FD_LOG_ERR(( "--ledger-retain-slots must be 0 or at least %lu", 2UL*slot_max ));

  static cluster_t cluster;
  cluster_read( &cluster, cluster_path );
  vseq_sched_t const * sched = cluster.sched;
  node_key_t key;
  key_read( &key, key_path );

  ulong              own   = vseq_sched_peer( sched, key.id_pub );
  vseq_mesh_peer_t * peers = malloc( sched->peer_cnt*sizeof(vseq_mesh_peer_t) );
  FD_TEST( peers );
  if( FD_UNLIKELY( own==ULONG_MAX ) ) FD_LOG_ERR(( "identity in %s is not in %s", key_path, cluster_path ));
  for( ulong i=0UL; i<cluster.cnt; i++ ) {
    peers[ sched->member_peer[i] ] = cluster.addrs[i];
    if( sched->member_peer[i]==own && FD_UNLIKELY( memcmp( cluster.members[i].v.bls_key, key.bls_pub, sizeof(ag_bls_key_t) ) ) ) {
      FD_LOG_ERR(( "bls key in %s does not match validator entry %lu of the cluster config", key_path, i ));
    }
  }
  if( FD_UNLIKELY( sched->epoch_slots<slot_max ) ) FD_LOG_ERR(( "%s: epoch_slots must be at least --slot-max (%lu)", cluster_path, slot_max ));

  static daemon_t d;
  d.cluster    = &cluster;
  d.sched      = sched;
  d.own        = own;
  d.wall_epoch = ULONG_MAX;
  d.hello_sent = calloc( sched->peer_cnt, 1UL );
  d.hello_ok   = calloc( sched->peer_cnt, 1UL );
  d.hello_gen  = calloc( sched->peer_cnt, sizeof(ulong) );
  FD_TEST( d.hello_sent && d.hello_ok && d.hello_gen );
  d.now     = fd_log_wallclock();
  ulong frame_max = 1UL+VSEQ_LEDGER_REC_SZ( cluster.payload_max, VSEQ_PROOF_MAX ); /* SYNC_BLOCK is the largest */
  d.msg     = malloc( frame_max );
  d.span    = malloc( SPAN_MAX );
  d.cert    = aligned_alloc( alignof(ag_cert_t), fd_ulong_align_up( sizeof(ag_cert_t), alignof(ag_cert_t) ) );
  d.sync.peer = ULONG_MAX;
  FD_TEST( d.msg && d.cert && d.span );

  d.retain_slots = retain_slots;
  d.history_full = !strcmp( history, "full" );
  d.ledger = vseq_ledger_open( ledger_path, cluster.payload_max, VSEQ_PROOF_MAX, seg_kb*1024UL );
  if( FD_UNLIKELY( !d.ledger ) ) FD_LOG_ERR(( "cannot open ledger %s", ledger_path ));
  {
    char              history_path[ 4200 ];
    vseq_ledger_rec_t rec;
    ulong             root = ledger_tip( &d, &rec ).slot;
    int               existed;
    fd_cstr_printf( history_path, sizeof(history_path), NULL, "%s.votes", ledger_path );
    vseq_ledger_sync( d.ledger ); /* opening drops history the ledger has */
    d.history = vseq_history_open( history_path, root, VSEQ_BLOCK_HDR_SZ+cluster.payload_max, &existed );
    if( FD_UNLIKELY( !d.history ) ) FD_LOG_ERR(( "cannot open the vote history %s", history_path ));
    if( FD_UNLIKELY( !existed && vseq_ledger_cnt( d.ledger ) ) ) {
      FD_LOG_ERR(( "%s is missing but the ledger has blocks: this node may have voted and could double vote.  "
                   "Restore the file, or start over with neither ledger nor vote history.", history_path ));
    }
    if( vseq_ledger_cnt( d.ledger ) ) {
      ulong votes_sz, blocks_sz;
      vseq_history_prior_votes ( d.history, &votes_sz  );
      vseq_history_prior_blocks( d.history, &blocks_sz );
      FD_LOG_NOTICE(( "restarting: ledger has %lu blocks up to slot %lu; vote history above it: %lu bytes of votes, %lu of blocks, block floor %lu",
                      vseq_ledger_cnt( d.ledger ), root, votes_sz, blocks_sz, vseq_history_block_floor( d.history ) ));
    }
  }

  d.mesh = vseq_mesh_create( peers, sched->peer_cnt, own, key.id_sec, frame_max, 64UL*frame_max, mesh_recv, &d, d.now );
  if( FD_UNLIKELY( !d.mesh ) ) FD_LOG_ERR(( "cannot start the peer mesh" ));

  static vseq_node_cfg_t cfg;
  cfg = (vseq_node_cfg_t){
    .sched        = sched,
    .own_peer     = own,
    .bls_sec      = key.bls_sec,
    .ns_per_slot  = cluster.slot_ns,
    .network_id   = cluster.network_id,
    .slot_max     = slot_max,
    .payload_max  = cluster.payload_max,
    .txq_max      = 64UL*cluster.payload_max,
    .retain_slots = 256UL,
    .seed         = (ulong)d.now,
    .send           = node_send,
    .finalized      = node_finalized,
    .persist_vote   = node_persist_vote,
    .persist_block  = node_persist_block,
    .cb_ctx         = &d,
  };
  memcpy( cfg.id_sec, key.id_sec, 32UL );
  fd_memzero_explicit( &key, sizeof(key) );
  d.cfg = &cfg;

  api_open( &d.api, keys_path, api_port, cluster.payload_max+8192UL, 1UL<<20,
            (fd_http_server_callbacks_t){ .request = api_request }, &d );

  signal( SIGINT,  on_signal );
  signal( SIGTERM, on_signal );
  FD_LOG_NOTICE(( "peer %lu of %lu, peer port %hu, api port %hu, network %u, %ld ms slots, %lu validator sets, epochs of %lu slots",
                  own, sched->peer_cnt, peers[ own ].port, api_port, (uint)cluster.network_id, cluster.slot_ns/1000000L,
                  sched->set_cnt, sched->epoch_slots ));
  if( d.now<cluster.genesis_ns ) FD_LOG_NOTICE(( "consensus starts at genesis in %ld ms", (cluster.genesis_ns-d.now)/1000000L ));

  long next_status = d.now + STATUS_LOG_NS;
  long deadline    = d.now;
  while( !stop ) {
    d.now = fd_log_wallclock();
    long wait_ns = fd_long_max( 0L, fd_long_min( deadline-d.now, 50L*1000L*1000L ) );
    struct pollfd   fds[2] = { { .fd = vseq_mesh_fd( d.mesh ), .events = POLLIN }, { .fd = d.api.ep, .events = POLLIN } };
    struct timespec ts     = { .tv_sec = wait_ns/1000000000L, .tv_nsec = wait_ns%1000000000L };
    if( FD_UNLIKELY( ppoll( fds, 2UL, &ts, NULL )<0 && errno!=EINTR ) ) FD_LOG_ERR(( "ppoll failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    d.now = fd_log_wallclock();
    long mesh_next = vseq_mesh_service( d.mesh, d.now );
    peers_tick( &d );
    api_poll( &d.api, d.now );

    /* A fresh node starts consensus at genesis, so all clocks line up.
       A node with a ledger, or one joining well after genesis, first
       catches up from peers.  While running, sync_tick checks whether a
       stall means peers are far ahead. */

    if( FD_UNLIKELY( !d.node && !d.sync.active ) ) {
      if( d.now<cluster.genesis_ns ) { deadline = fd_long_min( cluster.genesis_ns, mesh_next ); continue; }
      if( vseq_ledger_cnt( d.ledger ) || d.now>=cluster.genesis_ns+LATE_JOIN_NS ) sync_start( &d );
      else                                                                       start_node( &d );
    }
    sync_tick( &d );
    if( FD_UNLIKELY( !d.node ) ) {
      deadline = fd_long_min( fd_long_min( d.sync.deadline, d.sync.giveup ), mesh_next );
      continue;
    }
    deadline = fd_long_min( vseq_node_service( d.node, d.now ), mesh_next );

    ulong delivered = vseq_node_delivered_slot( d.node );
    if( FD_UNLIKELY( delivered>=d.ledger_synced+slot_max/2UL ) ) {
      vseq_ledger_sync( d.ledger ); /* keep the ledger within what a restart can replay */
      d.ledger_synced = delivered;
    }
    if( FD_UNLIKELY( delivered>=d.compact_root+COMPACT_SLOTS ) ) {
      vseq_ledger_sync( d.ledger );
      vseq_history_compact( d.history, delivered );
      d.compact_root  = delivered;
      d.ledger_synced = delivered;
    }
    if( d.retain_slots && delivered>d.retain_slots ) {
      ulong removed = vseq_ledger_prune( d.ledger, delivered-d.retain_slots );
      if( FD_UNLIKELY( removed ) ) FD_LOG_INFO(( "pruned %lu ledger segments, history now starts after slot %lu", removed, vseq_ledger_base( d.ledger ).slot ));
    }

    if( FD_UNLIKELY( d.now>=next_status && d.node ) ) {
      vseq_node_metrics_t const * m = vseq_node_metrics( d.node );
      FD_LOG_NOTICE(( "finalized slot %lu, peers %lu, blocks built %lu, certs fast %lu final %lu skip %lu, standstills %lu",
                      vseq_node_delivered_slot( d.node ), peers_ok( &d ),
                      m->blocks_built, m->fast_final_certs, m->final_certs, m->skip_certs, m->standstills ));
      next_status = d.now + STATUS_LOG_NS;
    }
  }

  if( d.node ) FD_LOG_NOTICE(( "stopping at finalized slot %lu", vseq_node_delivered_slot( d.node ) ));
  fd_memzero_explicit( &cfg, sizeof(cfg) );
  vseq_node_destroy( d.node );
  vseq_mesh_destroy( d.mesh );
  vseq_ledger_close( d.ledger );
  vseq_history_close( d.history );
  return 0;
}

/* Command: blocks ****************************************************/

struct reader {
  api_t           api;
  vseq_ledger_t * ledger;   /* NULL until the node has created it */
  uchar *         span;     /* response */
};
typedef struct reader reader_t;

static fd_http_server_response_t
blocks_get( reader_t *   r,
            char const * path ) {
  ulong         after = query_ulong( path, "after", 0UL );
  ag_block_id_t base  = vseq_ledger_base( r->ledger );
  if( FD_UNLIKELY( after<base.slot ) ) {
    fd_http_server_printf( r->api.http, "{\"error\":\"pruned\",\"base_slot\":%lu}\n", base.slot );
    return respond( r->api.http, 400 );
  }
  ulong             limit = fd_ulong_max( fd_ulong_min( query_ulong( path, "limit", 256UL ), BLOCKS_BIN_MAX ), 1UL );
  ulong             cnt   = vseq_ledger_cnt( r->ledger );
  vseq_ledger_rec_t tip;
  ulong finalized = cnt>vseq_ledger_first_idx( r->ledger ) && !vseq_ledger_read( r->ledger, cnt-1UL, &tip ) ? tip.block.slot : base.slot;

  ulong sz = vseq_ledger_read_span( r->ledger, vseq_ledger_first_after( r->ledger, after ), limit, RESP_MAX,
                                    r->span+BLOCKS_HDR_SZ, SPAN_MAX-BLOCKS_HDR_SZ, &cnt );
  memcpy( r->span, "VSQB\1\0\0\0", 8UL );
  FD_STORE( ulong, r->span+ 8UL, finalized );
  FD_STORE( uint,  r->span+16UL, (uint)cnt );
  fd_http_server_memcpy( r->api.http, r->span, BLOCKS_HDR_SZ+sz );
  fd_http_server_response_t res = { .status = 200, .content_type = "application/x-vseq-blocks-v1", .access_control_allow_origin = "*" };
  if( FD_UNLIKELY( fd_http_server_stage_body( r->api.http, &res ) ) ) return (fd_http_server_response_t){ .status = 500 };
  return res;
}

static fd_http_server_response_t
blocks_request( fd_http_server_request_t const * req ) {
  reader_t * r = req->ctx;
  ulong denied = api_auth( &r->api, req );
  if( FD_UNLIKELY( denied ) ) return api_denied( &r->api, denied );
  if( req->method!=FD_HTTP_SERVER_METHOD_GET || !path_is( req->path, "/blocks" ) ) {
    fd_http_server_printf( r->api.http, "{\"error\":\"not found\"}\n" );
    return respond( r->api.http, 404 );
  }
  if( FD_UNLIKELY( !r->ledger ) ) {
    fd_http_server_printf( r->api.http, "{\"error\":\"no ledger yet\"}\n" );
    return respond( r->api.http, 400 );
  }
  return blocks_get( r, req->path );
}

static int
cmd_blocks( int     argc,
            char ** argv ) {
  char const * cluster_path = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--cluster",  NULL, NULL         );
  char const * ledger_path  = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--ledger",   NULL, NULL         );
  char const * keys_path    = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--api-keys", NULL, NULL         );
  ushort       port         = fd_env_strip_cmdline_ushort( &argc, &argv, "--port",     NULL, (ushort)8500 );
  if( FD_UNLIKELY( !cluster_path || !ledger_path ) ) FD_LOG_ERR(( "usage: vseqd blocks --cluster cluster.toml --ledger DIR [--port 8500]" ));
  static cluster_t cluster;
  cluster_read( &cluster, cluster_path );

  static reader_t r;
  r.span = malloc( SPAN_MAX );
  FD_TEST( r.span );
  api_open( &r.api, keys_path, port, 8192UL, 4UL*RESP_MAX, (fd_http_server_callbacks_t){ .request = blocks_request }, &r );
  signal( SIGINT,  on_signal );
  signal( SIGTERM, on_signal );
  FD_LOG_NOTICE(( "serving /blocks from %s on port %hu", ledger_path, port ));

  long next_open = 0L;
  while( !stop ) {
    struct pollfd   fds[1] = { { .fd = r.api.ep, .events = POLLIN } };
    struct timespec ts     = { .tv_sec = 0L, .tv_nsec = 20L*1000L*1000L };
    if( FD_UNLIKELY( ppoll( fds, 1UL, &ts, NULL )<0 && errno!=EINTR ) ) FD_LOG_ERR(( "ppoll failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    long now = fd_log_wallclock();
    if( r.ledger && FD_UNLIKELY( vseq_ledger_refresh( r.ledger ) ) ) {
      FD_LOG_WARNING(( "%s was replaced, reopening it", ledger_path ));
      vseq_ledger_close( r.ledger );
      r.ledger = NULL;
    }
    if( !r.ledger && now>=next_open ) {
      r.ledger  = vseq_ledger_follow( ledger_path, cluster.payload_max, VSEQ_PROOF_MAX );
      next_open = now + SEC_NS;
      if( r.ledger ) FD_LOG_NOTICE(( "following %s from slot %lu", ledger_path, vseq_ledger_base( r.ledger ).slot ));
    }
    api_poll( &r.api, now );
  }
  vseq_ledger_close( r.ledger );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "usage: vseqd {keygen|api-key|gen-cluster|run|blocks} ..." ));
  char const * cmd = argv[1];
  argc--; argv++;
  int rc;
  if     ( !strcmp( cmd, "keygen"      ) ) rc = cmd_keygen     ( argc, argv );
  else if( !strcmp( cmd, "api-key"     ) ) rc = cmd_api_key    ( argc, argv );
  else if( !strcmp( cmd, "gen-cluster" ) ) rc = cmd_gen_cluster( argc, argv );
  else if( !strcmp( cmd, "run"         ) ) rc = cmd_run        ( argc, argv );
  else if( !strcmp( cmd, "blocks"      ) ) rc = cmd_blocks     ( argc, argv );
  else FD_LOG_ERR(( "unknown command %s, expected keygen, api-key, gen-cluster, run or blocks", cmd ));
  fd_halt();
  return rc;
}
