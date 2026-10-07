/* test_vseq_sim runs several vseq nodes in one process on a simulated
   network and clock, and checks:

     safety:   every node finalizes the same block in every slot, and
               each node's finalized blocks form one chain
     liveness: finalization keeps moving, up to a per-scenario minimum

   The network delivers each message after a uniform random delay and
   may drop it.  Nodes marked down never run, so their leader windows
   are skipped.  A client injects txs at a fixed rate and sends each to
   the leaders of the next three windows, as the SDK would; the report
   shows how long txs take to finalize.

   Every vote and block a node sends is checked against what that node
   sent before in the same slot: two notar votes for different blocks,
   notar and skip, final and skip, or two different blocks from an
   honest leader fail the run.  This is what restart safety must
   prevent.

   Restarting nodes crash (the node is destroyed, messages to it are
   lost) and come back from their finalized log, the certs of the last
   logged block, the votes they persisted and their block floor, as
   vseqd does from its ledger and vote history file.  With lost_tail,
   the crash also drops that many blocks from the end of the log, like
   a power loss taking the part of the ledger not yet synced; the run
   then checks that every lost block is finalized again, unchanged.

   An equivocating leader sends a second, differently signed version of
   each of its blocks (one extra tx) to the ranks in equiv_dst_mask,
   including in repair responses.  This drives votor's notar-fallback
   and safe-to-notar paths and repair by block hash.  With flood, it
   also sends everyone that many signed junk blocks for each slot it
   leads in the next slot_max, every time it builds a block: a leader
   can sign anything for its own slots, and the nodes' block store must
   not fill up with it.

   A scenario can change the validator set at epoch change_epoch: nodes
   in leave_mask leave it and nodes in join_mask join (both by node
   index, the others by rank in the first set).  Joining nodes run from
   genesis and follow consensus before they may vote.

   Usage: test_vseq_sim [--scenario name] [--duration-s secs] */

#include "vseq_node.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#include <stdlib.h>

#define NODE_MAX     (16UL)
#define MSGQ_MAX     (1UL<<20)
#define TX_MAX       (1UL<<20)
#define LOG_MAX      (1UL<<16)
#define TX_SZ        (64UL)
#define SEC          (1000L*1000L*1000L)
#define MS           (1000L*1000L)
#define PAYLOAD_MAX  (64UL*1024UL)
#define TRACK_MAX    (1UL<<14)   /* slots of sent votes and blocks remembered per node */

struct sim_msg {
  long    timeout; /* delivery time, fd_prq key */
  ulong   src;
  ulong   dst;
  uchar * buf;
  ulong   sz;
};
typedef struct sim_msg sim_msg_t;

#define PRQ_NAME msgq
#define PRQ_T    sim_msg_t
#include "../../util/tmpl/fd_prq.c"

struct scenario {
  char const * name;
  ulong        node_cnt;
  ulong        stake[ NODE_MAX ];  /* by node index, 0 means 1 */
  ulong        down_mask;          /* by rank */
  ulong        equiv_mask;         /* ranks that equivocate as leader */
  ulong        equiv_dst_mask;     /* ranks that get the other version */
  ulong        flood;              /* junk blocks per future slot from equivocating leaders */
  long         lat_min;
  long         lat_max;
  float        drop;
  long         duration;
  ulong        tx_per_sec;
  ulong        min_delivered;      /* every up node must reach this slot */
  ulong        restart_mask;       /* ranks that crash at crash_at and restart at restart_at */
  long         crash_at;
  long         restart_at;
  int          no_history;         /* restart without the vote history (unsafe, for comparison) */
  ulong        inject_skips;       /* add signed skip votes for this many slots ahead of the crash to the history */
  ulong        epoch_slots;        /* 0 for 1024 */
  ulong        change_epoch;
  ulong        leave_mask;         /* by node index */
  ulong        join_mask;          /* by node index */
  ulong        crash_idx_mask;     /* by node index: crash at crash_at, like restart_mask */
  ulong        lost_tail;          /* finalized log entries lost at the crash (an unsynced ledger tail) */
};
typedef struct scenario scenario_t;

/* What one node sent in one slot */

struct track {
  ulong           slot_p1;
  uchar           notar, skip, final, block;
  ag_block_hash_t notar_hash;
  ag_block_hash_t block_hash;
};
typedef struct track track_t;

typedef struct sim sim_t;

struct sim_node {
  sim_t *         sim;
  ulong           peer;
  int             down;
  vseq_node_t *   node;
  long            deadline;
  int             dirty;
  ag_block_id_t   last;
  ulong *         log_slot;
  ag_block_hash_t * log_hash;
  ulong           log_cnt;
  uchar **        log_proof;    /* per entry, so a truncated log still ends with certs */
  ulong *         log_proof_sz;
  ulong *         lost_slot;    /* entries dropped by lost_tail */
  ag_block_hash_t * lost_hash;
  ulong           lost_cnt;
  uchar           id_sec[ 32 ];
  uchar           id_pub[ 32 ];
  ag_bls_key_t    bls_pub;
  vseq_node_cfg_t cfg;          /* to restart the node */
  uchar *         votes;        /* persisted votes, (uint sz, bytes), as vseqd's vote history file */
  ulong           votes_sz;
  ulong           votes_max;
  uchar *         blocks;       /* persisted blocks of notar votes, same framing */
  ulong           blocks_sz;
  ulong           blocks_max;
  ulong           block_floor;
  uchar           last_proof[ VSEQ_PROOF_MAX ];
  ulong           last_proof_sz;
  track_t *       track;        /* TRACK_MAX entries */
};
typedef struct sim_node sim_node_t;

struct sim {
  fd_sha512_t        sha[1];
  uchar              alt[ 1UL+VSEQ_BLOCK_HDR_SZ+PAYLOAD_MAX+sizeof(uint)+TX_SZ ];
  scenario_t const * sc;
  ulong              n;
  sim_node_t         nodes[ NODE_MAX ];  /* by peer index */
  vseq_sched_t *     sched;
  ulong              down_mask;          /* the scenario's masks, by peer index */
  ulong              equiv_mask;
  ulong              equiv_dst_mask;
  ulong              restart_mask;
  fd_rng_t           rng[1];
  sim_msg_t *        msgq;
  long               now;

  ulong              msgs_sent;
  ulong              msgs_dropped;
  ulong              bytes_sent;

  ulong              tx_cnt;
  long *             tx_submit_ts;
  uchar *            tx_final;
  long *             tx_lat;
  ulong              tx_lat_cnt;
  ulong              proved;    /* finalized blocks with their own certs, summed over nodes */

  ulong              conflicts;
  int                fail;
};

/* equivocate writes the other version of a block message into sim->alt:
   the same slot and parent, plus one extra tx, signed by the leader.
   Returns its size. */

static ulong
equivocate( sim_t *            sim,
            sim_node_t const * leader,
            uchar const *      buf,
            ulong              sz ) {
  vseq_block_t block;
  FD_TEST( !vseq_block_parse( &block, buf+1UL, sz-1UL ) );
  static uchar payload[ PAYLOAD_MAX+sizeof(uint)+TX_SZ ];
  memcpy( payload, block.payload, block.payload_sz );
  FD_STORE( uint, payload+block.payload_sz, (uint)TX_SZ );
  memset( payload+block.payload_sz+sizeof(uint), 0, TX_SZ ); /* tx 0 again; finalized txs are deduplicated */

  ag_block_hash_t hash;
  sim->alt[0] = VSEQ_MSG_BLOCK;
  return 1UL + vseq_block_build( sim->alt+1UL, block.slot, &block.parent, payload, block.payload_sz+sizeof(uint)+TX_SZ,
                                 leader->id_pub, leader->id_sec, sim->sha, hash );
}

static void
conflict( sim_t *      sim,
          ulong        peer,
          ulong        slot,
          char const * what ) {
  if( sim->conflicts++<10UL ) FD_LOG_WARNING(( "CONFLICT: peer %lu sent %s in slot %lu", peer, what, slot ));
}

static track_t *
track_slot( sim_node_t * sn,
            ulong        slot ) {
  track_t * t = &sn->track[ slot%TRACK_MAX ];
  if( t->slot_p1!=slot+1UL ) { memset( t, 0, sizeof(track_t) ); t->slot_p1 = slot+1UL; }
  return t;
}

static void
track_sent( sim_node_t *  sn,
            uchar const * buf,
            ulong         sz ) {
  sim_t * sim = sn->sim;
  if( buf[0]==VSEQ_MSG_VOTE ) {
    ag_vote_t vote;
    if( FD_UNLIKELY( ag_vote_de( &vote, buf+1UL, sz-1UL ) ) ) { sim->fail = 1; return; }
    ulong     slot = ag_vote_slot( &vote );
    track_t * t    = track_slot( sn, slot );
    switch( vote.kind ) {
    case AG_VOTE_KIND_NOTAR:
      if( t->notar && memcmp( t->notar_hash, vote.notar.block_hash, 32UL ) ) conflict( sim, sn->peer, slot, "notar votes for two blocks" );
      if( t->skip                                                         ) conflict( sim, sn->peer, slot, "notar and skip votes" );
      t->notar = 1; memcpy( t->notar_hash, vote.notar.block_hash, 32UL );
      break;
    case AG_VOTE_KIND_SKIP:
      if( t->notar || t->final ) conflict( sim, sn->peer, slot, "skip and notar/final votes" );
      t->skip = 1;
      break;
    case AG_VOTE_KIND_FINAL:
      if( t->skip ) conflict( sim, sn->peer, slot, "final and skip votes" );
      t->final = 1;
      break;
    default:
      break;
    }
  } else if( buf[0]==VSEQ_MSG_BLOCK && !( sim->equiv_mask & (1UL<<sn->peer) ) ) {
    vseq_block_t block;
    if( FD_UNLIKELY( vseq_block_parse( &block, buf+1UL, sz-1UL ) ) ) { sim->fail = 1; return; }
    if( vseq_sched_leader( sim->sched, block.slot )!=sn->peer ) return; /* a repair response */
    ag_block_hash_t hash;
    vseq_block_hash( block.slot, &block.parent, block.payload, block.payload_sz, hash );
    track_t * t = track_slot( sn, block.slot );
    if( t->block && memcmp( t->block_hash, hash, 32UL ) ) conflict( sim, sn->peer, block.slot, "two different blocks" );
    t->block = 1; memcpy( t->block_hash, hash, 32UL );
  }
}

static void
append( uchar **      buf,
        ulong *       buf_sz,
        ulong *       buf_max,
        uchar const * data,
        ulong         sz ) {
  if( FD_UNLIKELY( *buf_sz+sizeof(uint)+sz>*buf_max ) ) {
    *buf_max = 2UL**buf_max + sizeof(uint)+sz;
    *buf     = realloc( *buf, *buf_max );
    FD_TEST( *buf );
  }
  FD_STORE( uint, *buf+*buf_sz, (uint)sz );
  memcpy( *buf+*buf_sz+sizeof(uint), data, sz );
  *buf_sz += sizeof(uint)+sz;
}

static void
sim_persist_vote( void *        ctx,
                  ulong         slot,
                  uchar const * vote,
                  ulong         sz,
                  uchar const * block,
                  ulong         block_sz ) {
  (void)slot;
  sim_node_t * sn = ctx;
  if( block ) append( &sn->blocks, &sn->blocks_sz, &sn->blocks_max, block, block_sz );
  append( &sn->votes, &sn->votes_sz, &sn->votes_max, vote, sz );
}

static void
sim_sign( void *         ctx,
          fd_bls_sig_t * sig,
          uchar const *  public_key,
          uchar const *  payload,
          ulong          payload_sz ) {
  (void)public_key;
  fd_bls_sec_sign( (fd_bls_sec_t const *)ctx, payload, payload_sz, sig );
}

static void
sim_persist_block( void * ctx,
                   ulong  slot ) {
  sim_node_t * sn = ctx;
  sn->block_floor = slot;
}

static void sim_deliver( sim_t * sim, sim_node_t const * from, ulong dst, uchar const * buf, ulong sz );

/* flood sends every other node sc->flood distinct signed blocks for
   each slot from leads in the slot_max slots after block. */

static void
flood( sim_t *            sim,
       sim_node_t const * from,
       vseq_block_t const * block ) {
  uchar msg[ 1UL+VSEQ_BLOCK_HDR_SZ+sizeof(ulong) ];
  for( ulong s=block->slot+1UL; s<block->slot+from->cfg.slot_max; s++ ) {
    if( vseq_sched_leader( sim->sched, s )!=from->peer ) continue;
    for( ulong v=0UL; v<sim->sc->flood; v++ ) {
      uchar           payload[ 8 ]; FD_STORE( ulong, payload, v );
      ag_block_hash_t hash;
      msg[0] = VSEQ_MSG_BLOCK;
      ulong sz = 1UL + vseq_block_build( msg+1UL, s, &block->parent, payload, sizeof(payload), from->id_pub, from->id_sec, sim->sha, hash );
      sim_deliver( sim, from, VSEQ_DST_ALL, msg, sz );
    }
  }
}

static void
sim_send( void *        ctx,
          ulong         dst,
          uchar const * buf,
          ulong         sz ) {
  sim_node_t * from = ctx;
  sim_t *      sim  = from->sim;
  track_sent( from, buf, sz );
  sim_deliver( sim, from, dst, buf, sz );

  if( FD_UNLIKELY( sim->sc->flood && ( sim->equiv_mask & (1UL<<from->peer) ) && buf[0]==VSEQ_MSG_BLOCK && dst==VSEQ_DST_ALL ) ) {
    vseq_block_t block;
    FD_TEST( !vseq_block_parse( &block, buf+1UL, sz-1UL ) );
    flood( sim, from, &block );
  }
}

static void
sim_deliver( sim_t *            sim,
             sim_node_t const * from,
             ulong              dst,
             uchar const *      buf,
             ulong              sz ) {

  uchar const * alt    = NULL;
  ulong         alt_sz = 0UL;
  if( FD_UNLIKELY( ( sim->equiv_mask & (1UL<<from->peer) ) && buf[0]==VSEQ_MSG_BLOCK ) ) {
    alt_sz = equivocate( sim, from, buf, sz );
    alt    = sim->alt;
  }

  uchar const * orig    = buf;
  ulong         orig_sz = sz;
  for( ulong r=0UL; r<sim->n; r++ ) {
    if( r==from->peer || ( dst!=VSEQ_DST_ALL && r!=dst ) ) continue;
    buf = orig; sz = orig_sz;
    if( alt && ( sim->equiv_dst_mask & (1UL<<r) ) ) { buf = alt; sz = alt_sz; }
    sim->msgs_sent++;
    sim->bytes_sent += sz;
    if( sim->sc->drop>0.f && fd_rng_float_c0( sim->rng )<sim->sc->drop ) { sim->msgs_dropped++; continue; }
    FD_TEST( msgq_cnt( sim->msgq )<msgq_max( sim->msgq ) );
    long      jitter = sim->sc->lat_max>sim->sc->lat_min ? (long)( fd_rng_ulong( sim->rng ) % (ulong)( sim->sc->lat_max-sim->sc->lat_min ) ) : 0L;
    sim_msg_t msg    = { .timeout = sim->now + sim->sc->lat_min + jitter, .src = from->peer, .dst = r, .buf = malloc( sz ), .sz = sz };
    FD_TEST( msg.buf );
    memcpy( msg.buf, buf, sz );
    msgq_insert( sim->msgq, &msg );
  }
}

static void
sim_finalized( void *               ctx,
               vseq_block_t const * block,
               uchar const          hash[ 32 ],
               uchar const *        proof,
               ulong                proof_sz ) {
  sim_node_t * sn  = ctx;
  sim_t *      sim = sn->sim;
  sim->proved += !!proof_sz;
  memcpy( sn->last_proof, proof, proof_sz );
  sn->last_proof_sz = proof_sz;

  if( FD_UNLIKELY( !ag_block_id_eq( &block->parent, &sn->last ) ) ) {
    FD_LOG_WARNING(( "peer %lu: finalized slot %lu does not extend slot %lu", sn->peer, block->slot, sn->last.slot ));
    sim->fail = 1;
  }
  sn->last = ag_block_id( block->slot, hash );

  FD_TEST( sn->log_cnt<LOG_MAX );
  sn->log_slot[ sn->log_cnt ] = block->slot;
  memcpy( sn->log_hash[ sn->log_cnt ], hash, sizeof(ag_block_hash_t) );
  sn->log_proof[ sn->log_cnt ] = realloc( sn->log_proof[ sn->log_cnt ], VSEQ_PROOF_MAX );
  FD_TEST( sn->log_proof[ sn->log_cnt ] );
  memcpy( sn->log_proof[ sn->log_cnt ], proof, proof_sz );
  sn->log_proof_sz[ sn->log_cnt ] = proof_sz;
  sn->log_cnt++;

  ulong off = 0UL, tx_sz;
  for( uchar const * tx; (tx = vseq_payload_next( block->payload, block->payload_sz, &off, &tx_sz )); ) {
    if( FD_UNLIKELY( tx_sz!=TX_SZ ) ) { sim->fail = 1; continue; }
    ulong id = FD_LOAD( ulong, tx );
    if( FD_UNLIKELY( id>=sim->tx_cnt ) ) { sim->fail = 1; continue; }
    if( sim->tx_final[ id ] ) continue; /* duplicate, or another node got here first */
    sim->tx_final[ id ] = 1;
    sim->tx_lat[ sim->tx_lat_cnt++ ] = sim->now - sim->tx_submit_ts[ id ];
  }
}

/* inject_tx plays the SDK: read the current slot from some node, then
   send the tx to the leaders of the next three windows. */

static void
inject_tx( sim_t * sim ) {
  if( FD_UNLIKELY( sim->tx_cnt>=TX_MAX ) ) return;
  ulong id = sim->tx_cnt++;
  sim->tx_submit_ts[ id ] = sim->now;

  uchar tx[ TX_SZ ] = {0};
  FD_STORE( ulong, tx,     id       );
  FD_STORE( long,  tx+8UL, sim->now );

  sim_node_t const * any = NULL;
  for( ulong tries=0UL; tries<4UL*sim->n && !any; tries++ ) {
    sim_node_t const * sn = &sim->nodes[ fd_rng_ulong( sim->rng ) % sim->n ];
    if( !sn->down ) any = sn;
  }
  if( FD_UNLIKELY( !any ) ) return;
  ulong slot = vseq_node_delivered_slot( any->node )+1UL;

  ulong sent[ 3 ]; ulong sent_cnt = 0UL;
  for( ulong w=0UL; w<3UL; w++ ) {
    ulong leader = vseq_sched_leader( sim->sched, slot+w*AG_SLOTS_PER_WINDOW );
    int   dup    = 0;
    for( ulong i=0UL; i<sent_cnt; i++ ) dup |= sent[i]==leader;
    if( dup ) continue;
    sent[ sent_cnt++ ] = leader;
    if( !sim->nodes[ leader ].down ) vseq_node_submit_tx( sim->nodes[ leader ].node, tx, TX_SZ );
  }
}

/* lose_tail drops the last sc->lost_tail entries of sn's log, and then
   any more without their own certs, so the log still ends with a block
   that has them, as a ledger does. */

static void
lose_tail( sim_t *      sim,
           sim_node_t * sn ) {
  ulong keep = fd_ulong_sat_sub( sn->log_cnt, sim->sc->lost_tail );
  while( keep && !sn->log_proof_sz[ keep-1UL ] ) keep--;
  for( ulong i=keep; i<sn->log_cnt; i++ ) {
    sn->lost_slot[ sn->lost_cnt ] = sn->log_slot[i];
    memcpy( sn->lost_hash[ sn->lost_cnt ], sn->log_hash[i], sizeof(ag_block_hash_t) );
    sn->lost_cnt++;
  }
  sn->log_cnt = keep;
  if( keep ) {
    sn->last_proof_sz = sn->log_proof_sz[ keep-1UL ];
    memcpy( sn->last_proof, sn->log_proof[ keep-1UL ], sn->last_proof_sz );
    sn->last = ag_block_id( sn->log_slot[ keep-1UL ], sn->log_hash[ keep-1UL ] );
  } else {
    sn->last_proof_sz = 0UL;
    sn->last          = ag_block_id( 0UL, ag_block_hash_null );
  }
  FD_LOG_NOTICE(( "[%s]   peer %lu loses the last %lu finalized blocks, its log now ends at slot %lu", sim->sc->name, sn->peer, sn->lost_cnt, sn->last.slot ));
}

/* node_start creates sn's node from genesis, or after a crash from its
   log tip (root) and last signed slot, as vseqd does on restart. */

static void
node_start( sim_t *      sim,
            sim_node_t * sn ) {
  vseq_node_cfg_t cfg = sn->cfg;
  if( sn->log_cnt ) {
    FD_TEST( sn->last_proof_sz ); /* the last finalized block always has certs */
    cfg.root_slot     = sn->log_slot[ sn->log_cnt-1UL ];
    memcpy( cfg.root_hash, sn->log_hash[ sn->log_cnt-1UL ], sizeof(ag_block_hash_t) );
    cfg.root_proof    = sn->last_proof;
    cfg.root_proof_sz = sn->last_proof_sz;
    if( !sim->sc->no_history ) {
      cfg.prior_votes     = sn->votes;
      cfg.prior_votes_sz  = sn->votes_sz;
      cfg.prior_blocks    = sn->blocks;
      cfg.prior_blocks_sz = sn->blocks_sz;
      cfg.block_floor    = sn->block_floor;
    }
  }
  sn->node = vseq_node_create( &cfg, sim->now );
  FD_TEST( sn->node );
  sn->deadline = vseq_node_service( sn->node, sim->now );
}

static int
cmp_long( void const * a,
          void const * b ) {
  long x = *(long const *)a, y = *(long const *)b;
  return (x>y) - (x<y);
}

static int
run( scenario_t const * sc,
     long               duration ) {
  static sim_t sim_mem;
  sim_t * sim = &sim_mem;
  memset( sim, 0, sizeof(sim_t) );
  sim->sc = sc;
  sim->n  = sc->node_cnt;
  FD_TEST( sim->n>=1UL && sim->n<=NODE_MAX );
  FD_TEST( fd_rng_join( fd_rng_new( sim->rng, 1234U, 0UL ) ) );

  void * msgq_mem = aligned_alloc( msgq_align(), fd_ulong_align_up( msgq_footprint( MSGQ_MAX ), msgq_align() ) );
  sim->msgq = msgq_join( msgq_new( msgq_mem, MSGQ_MAX ) );
  sim->tx_submit_ts = malloc( TX_MAX*sizeof(long) );
  sim->tx_lat       = malloc( TX_MAX*sizeof(long) );
  sim->tx_final     = calloc( TX_MAX, 1UL );
  FD_TEST( sim->msgq && sim->tx_submit_ts && sim->tx_lat && sim->tx_final );

  /* Keys.  Node i derives its keys from i; ranks come from stake. */

  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( sim->sha ) );
  fd_bls_sec_t  bls_sec[ NODE_MAX ];
  uchar         id_sec [ NODE_MAX ][ 32 ];
  vseq_member_t members[ NODE_MAX ];
  for( ulong i=0UL; i<sim->n; i++ ) {
    uchar ikm[ 32 ] = {0}; FD_STORE( ulong, ikm, 0xb15UL+i );
    fd_bls_sec_derive( &bls_sec[i], ikm, sizeof(ikm) );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &bls_sec[i], &pub );
    blst_p1_compress( members[i].v.bls_key, &pub );
    for( ulong j=0UL; j<32UL; j++ ) id_sec[i][j] = fd_rng_uchar( sim->rng );
    fd_ed25519_public_from_private( members[i].v.id_key, id_sec[i], sha );
    members[i].v.stake     = sc->stake[i] ? sc->stake[i] : 1UL;
    members[i].from_epoch  = ( sc->join_mask  & (1UL<<i) ) ? sc->change_epoch : 0UL;
    members[i].until_epoch = ( sc->leave_mask & (1UL<<i) ) ? sc->change_epoch : ULONG_MAX;
  }
  sim->sched = vseq_sched_new( members, sim->n, sc->epoch_slots ? sc->epoch_slots : 1024UL, (ushort)0x5e5e );
  FD_TEST( sim->sched && sim->sched->peer_cnt==sim->n );

  /* Masks are by rank in the first set, so peer index them */
  vseq_set_t const * set0 = &sim->sched->sets[0];
  for( ulong r=0UL; r<set0->epoch->validator_cnt; r++ ) {
    ulong bit = 1UL<<set0->peer_of_rank[r];
    if( sc->down_mask      & (1UL<<r) ) sim->down_mask      |= bit;
    if( sc->equiv_mask     & (1UL<<r) ) sim->equiv_mask     |= bit;
    if( sc->equiv_dst_mask & (1UL<<r) ) sim->equiv_dst_mask |= bit;
    if( sc->restart_mask   & (1UL<<r) ) sim->restart_mask   |= bit;
  }
  for( ulong i=0UL; i<sim->n; i++ ) if( sc->crash_idx_mask & (1UL<<i) ) sim->restart_mask |= 1UL<<sim->sched->member_peer[i];

  sim->now = SEC;
  for( ulong i=0UL; i<sim->n; i++ ) {
    ulong        r  = sim->sched->member_peer[i];
    sim_node_t * sn = &sim->nodes[ r ];
    sn->sim      = sim;
    sn->peer     = r;
    sn->down     = !!( sim->down_mask & (1UL<<r) );
    sn->last     = ag_block_id( 0UL, ag_block_hash_null );
    sn->log_slot = malloc( LOG_MAX*sizeof(ulong) );
    sn->log_hash = malloc( LOG_MAX*sizeof(ag_block_hash_t) );
    sn->log_proof    = calloc( LOG_MAX, sizeof(uchar *) );
    sn->log_proof_sz = calloc( LOG_MAX, sizeof(ulong)   );
    sn->lost_slot    = malloc( LOG_MAX*sizeof(ulong)           );
    sn->lost_hash    = malloc( LOG_MAX*sizeof(ag_block_hash_t) );
    FD_TEST( sn->log_slot && sn->log_hash && sn->log_proof && sn->log_proof_sz && sn->lost_slot && sn->lost_hash );
    memcpy( sn->id_sec,  id_sec[i],            32UL );
    memcpy( sn->id_pub,  members[i].v.id_key,  32UL );
    memcpy( sn->bls_pub, members[i].v.bls_key, sizeof(ag_bls_key_t) );
    sn->track = calloc( TRACK_MAX, sizeof(track_t) );
    FD_TEST( sn->track );
    if( sn->down ) continue;

    sn->cfg = (vseq_node_cfg_t){
      .sched        = sim->sched,
      .own_peer     = r,
      .bls_sec      = bls_sec[i],
      .ns_per_slot  = 400L*MS,
      .network_id   = (ushort)0x5e5e,
      .slot_max     = 32UL,
      .payload_max  = PAYLOAD_MAX,
      .txq_max      = 1024UL*1024UL,
      .retain_slots = 32UL,
      .seed         = 42UL+r,
      .send         = sim_send,
      .finalized      = sim_finalized,
      .persist_vote   = sim_persist_vote,
      .persist_block  = sim_persist_block,
      .cb_ctx         = sn,
    };
    memcpy( sn->cfg.id_sec, id_sec[i], 32UL );
  }
  for( ulong r=0UL; r<sim->n; r++ ) if( !sim->nodes[r].down ) node_start( sim, &sim->nodes[r] );

  /* Event loop */

  long end     = SEC + duration;
  long tx_step = sc->tx_per_sec ? SEC/(long)sc->tx_per_sec : LONG_MAX;
  long next_tx = sc->tx_per_sec ? SEC : LONG_MAX;
  long crash   = sim->restart_mask ? SEC+sc->crash_at   : LONG_MAX;
  long restart = sim->restart_mask ? SEC+sc->restart_at : LONG_MAX;
  for(;;) {
    long t = fd_long_min( next_tx, fd_long_min( crash, restart ) );
    if( msgq_cnt( sim->msgq ) ) t = fd_long_min( t, sim->msgq[0].timeout );
    for( ulong r=0UL; r<sim->n; r++ ) if( !sim->nodes[r].down ) t = fd_long_min( t, sim->nodes[r].deadline );
    if( t>end ) break;
    sim->now = t;

    while( msgq_cnt( sim->msgq ) && sim->msgq[0].timeout<=sim->now ) {
      sim_msg_t msg = sim->msgq[0];
      msgq_remove_min( sim->msgq );
      sim_node_t * dst = &sim->nodes[ msg.dst ];
      if( !dst->down ) {
        vseq_node_recv( dst->node, sim->now, msg.src, msg.buf, msg.sz );
        dst->dirty = 1;
      }
      free( msg.buf );
    }
    while( next_tx<=sim->now ) { inject_tx( sim ); next_tx += tx_step; }
    if( FD_UNLIKELY( sim->now>=crash ) ) {
      for( ulong r=0UL; r<sim->n; r++ ) {
        sim_node_t * sn = &sim->nodes[r];
        if( !( sim->restart_mask & (1UL<<r) ) || sn->down ) continue;
        FD_LOG_NOTICE(( "[%s]   peer %lu crashes at finalized slot %lu, %lu bytes of votes persisted, block floor %lu",
                        sc->name, r, vseq_node_delivered_slot( sn->node ), sn->votes_sz, sn->block_floor ));
        /* Pretend it voted skip in slots it has not reached yet */
        for( ulong k=0UL; k<sc->inject_skips; k++ ) {
          ulong     slot = vseq_node_delivered_slot( sn->node )+6UL+k;
          ulong     rank = vseq_sched_set( sim->sched, slot )->rank_of_peer[r];
          ag_vote_t vote = ag_vote_construct_skip( sim_sign, &sn->cfg.bls_sec, sn->bls_pub, slot, (ushort)rank, sn->cfg.network_id );
          uchar     ser[ AG_VOTE_SER_MAX ];
          append( &sn->votes, &sn->votes_sz, &sn->votes_max, ser, ag_vote_ser( &vote, ser ) );
        }
        if( sc->lost_tail ) lose_tail( sim, sn );
        vseq_node_destroy( sn->node );
        sn->node = NULL;
        sn->down = 1;
      }
      crash = LONG_MAX;
    }
    if( FD_UNLIKELY( sim->now>=restart ) ) {
      for( ulong r=0UL; r<sim->n; r++ ) {
        sim_node_t * sn = &sim->nodes[r];
        if( !( sim->restart_mask & (1UL<<r) ) || !sn->down || ( sim->down_mask & (1UL<<r) ) ) continue;
        sn->down = 0;
        node_start( sim, sn );
        vseq_node_metrics_t const * m = vseq_node_metrics( sn->node );
        FD_LOG_NOTICE(( "[%s]   peer %lu restarts at finalized slot %lu, %lu votes restored, no blocks through slot %lu",
                        sc->name, r, vseq_node_delivered_slot( sn->node ), m->votes_restored, vseq_node_quiet_until( sn->node ) ));
      }
      restart = LONG_MAX;
    }
    for( ulong r=0UL; r<sim->n; r++ ) {
      sim_node_t * sn = &sim->nodes[r];
      if( sn->down || ( !sn->dirty && sn->deadline>sim->now ) ) continue;
      sn->deadline = fd_long_max( vseq_node_service( sn->node, sim->now ), sim->now+1L );
      sn->dirty    = 0;
    }
  }

  /* Safety: logs agree slot by slot */

  for( ulong a=0UL; a<sim->n; a++ ) {
    for( ulong b=a+1UL; b<sim->n; b++ ) {
      sim_node_t const * x = &sim->nodes[a];
      sim_node_t const * y = &sim->nodes[b];
      if( x->down || y->down ) continue;
      for( ulong i=0UL, j=0UL; i<x->log_cnt && j<y->log_cnt; ) {
        if     ( x->log_slot[i]<y->log_slot[j] ) i++;
        else if( x->log_slot[i]>y->log_slot[j] ) j++;
        else {
          if( FD_UNLIKELY( memcmp( x->log_hash[i], y->log_hash[j], sizeof(ag_block_hash_t) ) ) ) {
            FD_LOG_WARNING(( "SAFETY: peers %lu and %lu finalized different blocks in slot %lu", a, b, x->log_slot[i] ));
            sim->fail = 1;
          }
          i++; j++;
        }
      }
    }
  }

  /* Safety: blocks lost from a log were finalized again, unchanged */

  for( ulong r=0UL; r<sim->n; r++ ) {
    sim_node_t const * sn = &sim->nodes[r];
    ulong missing = 0UL, changed = 0UL;
    for( ulong i=0UL; i<sn->lost_cnt; i++ ) {
      int found = 0, same = 0;
      for( ulong j=0UL; j<sn->log_cnt && !found; j++ ) {
        if( sn->log_slot[j]!=sn->lost_slot[i] ) continue;
        found = 1;
        same  = !memcmp( sn->log_hash[j], sn->lost_hash[i], sizeof(ag_block_hash_t) );
      }
      missing += !found;
      changed += found && !same;
    }
    if( FD_UNLIKELY( missing || changed ) ) {
      FD_LOG_WARNING(( "[%s] SAFETY: peer %lu lost %lu finalized blocks; %lu were never finalized again and %lu were finalized as another block",
                       sc->name, r, sn->lost_cnt, missing, changed ));
      sim->fail = 1;
    }
  }

  /* Report */

  ulong min_delivered = ULONG_MAX, max_delivered = 0UL, up = 0UL;
  vseq_node_metrics_t sum = {0};
  for( ulong r=0UL; r<sim->n; r++ ) {
    sim_node_t const * sn = &sim->nodes[r];
    if( sn->down ) continue;
    up++;
    ulong d = vseq_node_delivered_slot( sn->node );
    min_delivered = fd_ulong_min( min_delivered, d );
    max_delivered = fd_ulong_max( max_delivered, d );
    ulong src[ sizeof(vseq_node_metrics_t)/sizeof(ulong) ];
    ulong acc[ sizeof(vseq_node_metrics_t)/sizeof(ulong) ];
    memcpy( src, vseq_node_metrics( sn->node ), sizeof(src) );
    memcpy( acc, &sum,                          sizeof(acc) );
    for( ulong k=0UL; k<sizeof(src)/sizeof(ulong); k++ ) acc[k] += src[k];
    memcpy( &sum, acc, sizeof(acc) );
  }
  ulong slots_total   = (ulong)( duration/(400L*MS) );
  ulong final_blocks  = sum.blocks_finalized/up;

  qsort( sim->tx_lat, sim->tx_lat_cnt, sizeof(long), cmp_long );
  double p50 = sim->tx_lat_cnt ? (double)sim->tx_lat[ sim->tx_lat_cnt/2UL         ]/1e6 : 0.;
  double p99 = sim->tx_lat_cnt ? (double)sim->tx_lat[ (sim->tx_lat_cnt*99UL)/100UL ]/1e6 : 0.;

  FD_LOG_NOTICE(( "[%s] %lu nodes (%lu up), %.0f s, latency %ld-%ld ms, drop %.0f%%",
                  sc->name, sim->n, up, (double)duration/1e9, sc->lat_min/MS, sc->lat_max/MS, (double)sc->drop*100. ));
  FD_LOG_NOTICE(( "[%s]   finalized slot %lu-%lu of ~%lu, %lu blocks finalized per node, %lu with their own certs",
                  sc->name, min_delivered, max_delivered, slots_total, final_blocks, sim->proved/up ));
  FD_LOG_NOTICE(( "[%s]   certs per node: fast-final %lu, final %lu, skip %lu; standstills %lu, repairs %lu, bans %lu",
                  sc->name, sum.fast_final_certs/up, sum.final_certs/up, sum.skip_certs/up, sum.standstills/up, sum.repair_reqs_sent/up, sum.bans ));
  FD_LOG_NOTICE(( "[%s]   network: %lu msgs (%lu dropped), %.1f MB",
                  sc->name, sim->msgs_sent, sim->msgs_dropped, (double)sim->bytes_sent/1e6 ));
  FD_LOG_NOTICE(( "[%s]   txs: %lu sent, %lu finalized, latency p50 %.0f ms, p99 %.0f ms",
                  sc->name, sim->tx_cnt, sim->tx_lat_cnt, p50, p99 ));
  for( ulong r=0UL; r<sim->n; r++ ) {
    sim_node_t const * sn = &sim->nodes[r];
    if( !( sim->restart_mask & (1UL<<r) ) || sn->down ) continue;
    vseq_node_metrics_t const * m = vseq_node_metrics( sn->node );
    FD_LOG_NOTICE(( "[%s]   restarted peer %lu: finalized slot %lu, after restart %lu votes restored, %lu withheld as conflicting, %lu blocks withheld",
                    sc->name, r, vseq_node_delivered_slot( sn->node ), m->votes_restored, m->votes_withheld, m->blocks_withheld ));
  }
  if( FD_UNLIKELY( sim->conflicts ) ) {
    FD_LOG_WARNING(( "[%s] SAFETY: %lu conflicting votes or blocks", sc->name, sim->conflicts ));
    sim->fail = 1;
  }

  if( FD_UNLIKELY( min_delivered<sc->min_delivered ) ) {
    FD_LOG_WARNING(( "[%s] LIVENESS: finalized slot %lu, expected at least %lu", sc->name, min_delivered, sc->min_delivered ));
    sim->fail = 1;
  }
  if( FD_UNLIKELY( sum.bans ) ) {
    FD_LOG_WARNING(( "[%s] honest nodes banned each other %lu times", sc->name, sum.bans ));
    sim->fail = 1;
  }

  /* Cleanup */

  while( msgq_cnt( sim->msgq ) ) { free( sim->msgq[0].buf ); msgq_remove_min( sim->msgq ); }
  for( ulong r=0UL; r<sim->n; r++ ) {
    vseq_node_destroy( sim->nodes[r].node );
    free( sim->nodes[r].log_slot );
    for( ulong i=0UL; i<LOG_MAX; i++ ) free( sim->nodes[r].log_proof[i] );
    free( sim->nodes[r].log_proof );
    free( sim->nodes[r].log_proof_sz );
    free( sim->nodes[r].lost_slot );
    free( sim->nodes[r].lost_hash );
    free( sim->nodes[r].track );
    free( sim->nodes[r].votes );
    free( sim->nodes[r].blocks );
    free( sim->nodes[r].log_hash );
  }
  free( sim->tx_final ); free( sim->tx_lat ); free( sim->tx_submit_ts );
  vseq_sched_delete( sim->sched );
  free( msgq_delete( msgq_leave( sim->msgq ) ) );
  return sim->fail;
}

/* Scenarios.  min_delivered is ~80% of what the run can reach (one
   slot per 400 ms), minus the skipped windows of down leaders. */

static scenario_t const scenarios[] = {
  { .name = "happy",   .node_cnt = 4, .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 120 },
  { .name = "crash",   .node_cnt = 5, .down_mask = 1UL<<4,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "lossy",   .node_cnt = 4, .lat_min = 20*MS,  .lat_max = 80*MS,  .drop = 0.05f,
                                                                            .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "slow",    .node_cnt = 4, .lat_min = 100*MS, .lat_max = 300*MS, .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "genesis-down", .node_cnt = 5, .down_mask = 1UL<<0, /* the genesis window's leader */
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "equivocate", .node_cnt = 5, .equiv_mask = 1UL<<4, .equiv_dst_mask = (1UL<<0)|(1UL<<1),
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "flood",      .node_cnt = 5, .equiv_mask = 1UL<<4, .flood = 16,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "restart",      .node_cnt = 5, .restart_mask = 1UL<<2, .crash_at = 20*SEC, .restart_at = 26*SEC,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "restart-fast", .node_cnt = 5, .restart_mask = 1UL<<2, .crash_at = 20*SEC, .restart_at = 20*SEC+300*MS,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "restart-conflict", .node_cnt = 5, .restart_mask = 1UL<<2, .crash_at = 20*SEC, .restart_at = 20*SEC+300*MS, .inject_skips = 8,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  { .name = "restart-all",  .node_cnt = 5, .restart_mask = 0x1fUL, .crash_at = 20*SEC, .restart_at = 21*SEC,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  /* Every node also loses the last slot_max/2 finalized blocks, the
     most vseqd lets the ledger fall behind the vote history */
  { .name = "restart-all-lost-tail", .node_cnt = 5, .restart_mask = 0x1fUL, .crash_at = 20*SEC, .restart_at = 21*SEC, .lost_tail = 16,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
  /* Node 0 leaves and node 5 joins at slot 64.  Then nodes 0-2 crash:
     the new set {1..5} keeps 60% only if node 5 votes. */
  { .name = "set-change", .node_cnt = 6, .epoch_slots = 32, .change_epoch = 2, .leave_mask = 1UL<<0, .join_mask = 1UL<<5,
                                      .crash_idx_mask = 0x7UL, .crash_at = 35*SEC, .restart_at = 1000*SEC,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 70*SEC, .tx_per_sec = 200, .min_delivered = 110 },
  { .name = "stake",   .node_cnt = 7, .stake = { 30, 20, 15, 10, 10, 10, 5 }, .down_mask = 1UL<<6,
                                      .lat_min = 20*MS,  .lat_max = 60*MS,  .duration = 60*SEC, .tx_per_sec = 200, .min_delivered = 100 },
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * only     = fd_env_strip_cmdline_cstr( &argc, &argv, "--scenario",   NULL, NULL );
  long         duration = fd_env_strip_cmdline_long( &argc, &argv, "--duration-s", NULL, 0L  )*SEC;

  int fail = 0;
  for( ulong i=0UL; i<sizeof(scenarios)/sizeof(scenarios[0]); i++ ) {
    scenario_t sc = scenarios[i];
    if( only && strcmp( only, sc.name ) ) continue;
    if( duration ) sc.min_delivered = (ulong)( (double)sc.min_delivered*(double)duration/(double)sc.duration );
    int f = run( &sc, duration ? duration : sc.duration );
    FD_LOG_NOTICE(( "[%s] %s", sc.name, f ? "FAIL" : "pass" ));
    fail |= f;
  }

  if( fail ) FD_LOG_ERR(( "FAIL" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
