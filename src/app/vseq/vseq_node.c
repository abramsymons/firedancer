#include "vseq_node.h"
#include "../../choreo/votor/ag_pool.h"
#include "../../choreo/votor/ag_votor.h"
#include "../../choreo/votor/ag_vote_serde.h"
#include "../../choreo/votor/ag_slot_state.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "vseq_proof.h"

#include <stdlib.h>

/* Input checks and constants follow the Firedancer votor tile
   (src/discof/votor/fd_votor_tile.c).  Keep them in sync. */

#define VOTE_LOOKAHEAD_MAX (40UL)                    /* slots past the highest ParentReady */
#define BAN_NS             (10L*1000L*1000L*1000L)   /* drop a peer's messages for 10 s */
#define REPAIR_MAX         (128UL)

/* A leader can sign any number of blocks for its slots, so the store
   keeps at most BLKS_PER_SLOT_MAX per slot: an honest leader makes one,
   and the fallback path settles on at most AG_NOTAR_FALLBACK_VOTE_MAX
   candidates.  One the pool asked to repair (votes or certs name it) is
   taken up to BLKS_PER_SLOT_WANTED, below the pool's own per-slot limit
   on block hashes.  Only the slot's leader can sign blocks for it, so
   the cap never keeps out another validator's block. */

#define BLKS_PER_SLOT_MAX    (4UL)
#define BLKS_PER_SLOT_WANTED (AG_EQVOC_BLOCK_HASH_MAX-1UL)
FD_STATIC_ASSERT( BLKS_PER_SLOT_MAX<BLKS_PER_SLOT_WANTED, per_slot_cap );
#define REPAIR_RETRY_NS    (100L*1000L*1000L)        /* ask the next peer after 100 ms */
#define REPAIR_BODY_SZ     (sizeof(ulong)+sizeof(ag_block_hash_t))
#define BODY_MAX           (AG_VOTE_SER_MAX>AG_CERT_SER_MAX ? AG_VOTE_SER_MAX : AG_CERT_SER_MAX)
#define MSG_MAX            (1UL+BODY_MAX)

/* Block store ********************************************************/

struct blk {
  ag_block_id_t id;
  ulong         next;      /* reserved for fd_pool, fd_map_chain */
  ag_block_id_t parent;
  int           complete;  /* every ancestor is stored, so votor has seen it */
  int           finalized;
  uchar *       wire;      /* VSEQ_MSG_BLOCK message, ready to resend */
  ulong         wire_sz;
};
typedef struct blk blk_t;

#define POOL_NAME blk_pool
#define POOL_T    blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blk_map
#define MAP_ELE_T              blk_t
#define MAP_KEY                id
#define MAP_KEY_T              ag_block_id_t
#define MAP_KEY_EQ(k0,k1)      ag_block_id_eq( (k0), (k1) )
#define MAP_KEY_HASH(key,seed) fd_hash( (seed), (key), sizeof(ag_block_id_t) )
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

/* Node ***************************************************************/

struct repair {
  ag_block_id_t id;
  long          next_ts;
  ulong         attempt;
};
typedef struct repair repair_t;

struct __attribute__((aligned(FD_SHA512_ALIGN))) vseq_node {
  fd_sha512_t             sha[1];

  vseq_node_cfg_t         cfg;
  vseq_sched_t const *    sched;
  ulong                   own;         /* our peer index */
  vseq_set_t const *      next_set;    /* the last set given to votor, NULL once all are */
  uchar                   id_pub[ 32 ];
  ag_bls_key_t            bls_pub;
  long                    now;

  void *                  pool_mem;
  ag_pool_t *             pool;
  void *                  votor_mem;
  ag_votor_t *            votor;

  void *                  blk_pool_mem;
  void *                  blk_map_mem;
  blk_t *                 blks;
  blk_map_t *             blk_map;
  ulong                   blk_max;
  blk_t **                blk_scratch; /* blk_max entries */

  ag_block_id_t           root;        /* where consensus started */
  ag_block_id_t           delivered;   /* last finalized block handed to the app */
  ulong                   quiet_until; /* restart: build no blocks at or below */
  ulong                   block_hi;    /* highest slot passed to persist_block */
  ulong                   last_final_slot;
  long                    last_final_ts;
  ulong                   highest_parent_ready_slot;

  ulong                   lead_window; /* window being built, or ULONG_MAX */
  ulong                   lead_idx;    /* next slot index in the window */
  long                    lead_t0;
  ag_block_id_t           lead_parent;
  ulong                   last_led_window;

  uchar *                 txq;         /* pending txs, framed as in a payload */
  ulong                   txq_sz;
  uchar *                 build_buf;   /* 1+VSEQ_BLOCK_HDR_SZ+payload_max */

  repair_t                repairs[ REPAIR_MAX ];
  ulong                   repair_cnt;

  long *                  banned_until; /* by peer */

  uchar                   msg[ MSG_MAX ];
  uchar                   proof[ VSEQ_PROOF_MAX ];
  fd_bls_set_t            bad[ fd_bls_set_word_cnt ];

  union {
    ag_vote_t          vote;
    ag_cert_t          cert;
    ag_pool_event_t    pool_event;
    ag_block_id_t      block_id;
  } scratch;

  vseq_node_metrics_t     metrics;
};

static void *
alloc_aligned( ulong align,
               ulong sz ) {
  return aligned_alloc( align, fd_ulong_align_up( fd_ulong_max( sz, 1UL ), align ) );
}

static void
sign_bls( void *         ctx,
          fd_bls_sig_t * sig,
          uchar const *  public_key,
          uchar const *  payload,
          ulong          payload_sz ) {
  (void)public_key;
  vseq_node_t * node = ctx;
  fd_bls_sec_sign( &node->cfg.bls_sec, payload, payload_sz, sig );
}

static vseq_set_t const *
set_of( vseq_node_t const * node,
        ulong               slot ) {
  return vseq_sched_set( node->sched, slot );
}

/* advance_epoch tells votor about the set starting at set->start_slot:
   our rank in it, and whether we vote (only with the BLS key the set
   lists for us). */

static ulong
own_rank( vseq_node_t const * node,
          vseq_set_t const *  set ) {
  ulong rank = set->rank_of_peer[ node->own ];
  return rank==ULONG_MAX ? USHORT_MAX : rank;
}

static void
advance_pool( vseq_node_t *      node,
              vseq_set_t const * set ) {
  ag_pool_advance_epoch( node->pool, set->epoch, own_rank( node, set ), set->start_slot );
}

static void
advance_votor( vseq_node_t *      node,
               vseq_set_t const * set ) {
  ulong         rank = own_rank( node, set );
  uchar const * bls  = rank!=USHORT_MAX ? set->epoch->validators[ rank ].bls_key : NULL;
  if( bls && memcmp( bls, node->bls_pub, sizeof(ag_bls_key_t) ) ) {
    FD_LOG_WARNING(( "the config lists another BLS key for us from slot %lu; not voting there", set->start_slot ));
    bls = NULL;
  }
  ag_votor_advance_epoch( node->votor, node->cfg.ns_per_slot, rank, set->start_slot, bls );
}

static void
send_msg( vseq_node_t * node,
          ulong         dst,
          uchar const * msg,
          ulong         sz ) {
  node->cfg.send( node->cfg.cb_ctx, dst, msg, sz );
}

static void
ban_peer( vseq_node_t * node,
          ulong         peer ) {
  if( FD_UNLIKELY( peer==node->own || peer>=node->sched->peer_cnt ) ) return;
  node->banned_until[ peer ] = node->now + BAN_NS;
  node->metrics.bans++;
}

/* ban_bad_ranks bans the signers votor found bad in slot's set. */

static void
ban_bad_ranks( vseq_node_t *        node,
               ulong                slot,
               fd_bls_set_t const * bad ) {
  if( FD_LIKELY( fd_bls_set_is_null( bad ) ) ) return;
  vseq_set_t const * set = set_of( node, slot );
  for( ulong rank = fd_bls_set_const_iter_init( bad );
                   !fd_bls_set_const_iter_done( rank );
             rank = fd_bls_set_const_iter_next( bad, rank ) ) {
    if( rank<set->epoch->validator_cnt ) ban_peer( node, set->peer_of_rank[ rank ] );
  }
}

static blk_t *
blk_query( vseq_node_t *         node,
           ag_block_id_t const * id ) {
  return blk_map_ele_query( node->blk_map, id, NULL, node->blks );
}

static ulong
blk_slot_cnt( vseq_node_t * node,
              ulong         slot ) {
  ulong cnt = 0UL;
  for( blk_map_iter_t iter = blk_map_iter_init( node->blk_map, node->blks );
                            !blk_map_iter_done( iter, node->blk_map, node->blks );
                      iter = blk_map_iter_next( iter, node->blk_map, node->blks ) ) {
    cnt += blk_map_iter_ele( iter, node->blk_map, node->blks )->id.slot==slot;
  }
  return cnt;
}

/* Repair *************************************************************/

static int
repair_wanted( vseq_node_t const *   node,
               ag_block_id_t const * id ) {
  for( ulong i=0UL; i<node->repair_cnt; i++ ) if( ag_block_id_eq( &node->repairs[i].id, id ) ) return 1;
  return 0;
}

static void
repair_request( vseq_node_t *         node,
                ag_block_id_t const * id ) {
  if( FD_UNLIKELY( id->slot<=node->delivered.slot ) ) return;
  if( FD_LIKELY( blk_query( node, id ) ) ) return;
  if( FD_UNLIKELY( repair_wanted( node, id ) ) ) return;
  if( FD_UNLIKELY( node->repair_cnt==REPAIR_MAX ) ) return; /* retried once others resolve */
  node->repairs[ node->repair_cnt++ ] = (repair_t){ .id = *id, .next_ts = node->now, .attempt = 0UL };
}

/* repair_tick asks for missing blocks, starting with the slot's leader
   and moving on to the next rank of the slot's set on each retry.
   Returns the next retry time. */

static long
repair_tick( vseq_node_t * node ) {
  long next = LONG_MAX;
  for( ulong i=0UL; i<node->repair_cnt; ) {
    repair_t *         r   = &node->repairs[i];
    vseq_set_t const * set = set_of( node, r->id.slot );
    ulong              cnt = set->epoch->validator_cnt;
    ulong              dst = set->peer_of_rank[ ( ag_epoch_info_leader( set->epoch, r->id.slot )->id + r->attempt ) % cnt ];
    if( dst==node->own ) dst = set->peer_of_rank[ ( ag_epoch_info_leader( set->epoch, r->id.slot )->id + r->attempt + 1UL ) % cnt ];
    if( FD_UNLIKELY( r->id.slot<=node->delivered.slot || blk_query( node, &r->id ) || dst==node->own ) ) {
      node->repairs[i] = node->repairs[ --node->repair_cnt ];
      continue;
    }
    if( node->now>=r->next_ts ) {
      r->attempt++;
      r->next_ts = node->now + REPAIR_RETRY_NS;

      node->msg[0] = VSEQ_MSG_REPAIR;
      FD_STORE( ulong, node->msg+1UL, r->id.slot );
      memcpy( node->msg+1UL+sizeof(ulong), r->id.hash, sizeof(ag_block_hash_t) );
      send_msg( node, dst, node->msg, 1UL+REPAIR_BODY_SZ );
      node->metrics.repair_reqs_sent++;
    }
    next = fd_long_min( next, r->next_ts );
    i++;
  }
  return next;
}

/* Restart safety *****************************************************/

/* note_block is called before a block for slot leaves the node.  The
   slot is made durable first, so a restart knows not to build another
   block in its window. */

static void
note_block( vseq_node_t * node,
            ulong         slot ) {
  if( FD_LIKELY( slot<=node->block_hi ) ) return;
  if( node->cfg.persist_block ) node->cfg.persist_block( node->cfg.cb_ctx, slot );
  node->block_hi = slot;
}

/* Blocks *************************************************************/

/* replay tells votor a block is available.  It plays the role of
   Firedancer's replay tile, minus execution.  Returns 0, or the pool
   error if the pool does not track the block's slot yet (too far above
   the root, or in a set it has not been given): votor is not told
   either, since its slot table is bounded the same way, and the caller
   retries once the root has advanced. */

static int
replay( vseq_node_t * node,
        blk_t const * blk ) {
  int err = ag_pool_add_block( node->pool, &blk->id, &blk->parent, node->bad );
  ban_bad_ranks( node, blk->id.slot, node->bad );
  if( FD_UNLIKELY( err ) ) return err;

  ag_block_info_t info = { .parent = blk->parent };
  memcpy( info.hash, blk->id.hash, sizeof(ag_block_hash_t) );
  ag_votor_process_replay( node->votor, blk->id.slot, &info );
  return 0;
}

/* try_complete marks blk complete once its parent is, then does the
   same for any stored descendants waiting on it.  Like replay, a block
   is only handed to votor after its whole chain is available. */

static void
try_complete( vseq_node_t * node,
              blk_t *       blk ) {
  blk_t ** stack = node->blk_scratch;
  ulong    cnt   = 0UL;
  stack[ cnt++ ] = blk;
  while( cnt ) {
    blk_t * b = stack[ --cnt ];
    if( FD_UNLIKELY( b->complete ) ) continue;

    int parent_ok = ag_block_id_eq( &b->parent, &node->delivered );
    if( !parent_ok ) {
      blk_t const * p = blk_query( node, &b->parent );
      if( p ) parent_ok = p->complete;
      else    repair_request( node, &b->parent );
    }
    if( !parent_ok ) continue;
    if( FD_UNLIKELY( replay( node, b ) ) ) continue; /* retried by retry_incomplete */

    b->complete = 1;

    for( blk_map_iter_t iter = blk_map_iter_init( node->blk_map, node->blks );
                              !blk_map_iter_done( iter, node->blk_map, node->blks );
                        iter = blk_map_iter_next( iter, node->blk_map, node->blks ) ) {
      blk_t * child = blk_map_iter_ele( iter, node->blk_map, node->blks );
      if( !child->complete && ag_block_id_eq( &child->parent, &b->id ) && cnt<node->blk_max ) stack[ cnt++ ] = child;
    }
  }
}

/* retry_incomplete gives every stored block that is not complete
   another chance, e.g. after the root advanced into its slot's range. */

static void
retry_incomplete( vseq_node_t * node ) {
  for( blk_map_iter_t iter = blk_map_iter_init( node->blk_map, node->blks );
                            !blk_map_iter_done( iter, node->blk_map, node->blks );
                      iter = blk_map_iter_next( iter, node->blk_map, node->blks ) ) {
    blk_t * b = blk_map_iter_ele( iter, node->blk_map, node->blks );
    if( !b->complete ) try_complete( node, b );
  }
}

/* on_block stores a block received from a peer, or built by us
   (own=1, signature not rechecked).  msg is the VSEQ_MSG_BLOCK
   message. */

static void
on_block( vseq_node_t * node,
          uchar const * msg,
          ulong         sz,
          int           own ) {
  vseq_block_t block;
  if( FD_UNLIKELY( vseq_block_parse( &block, msg+1UL, sz-1UL ) || block.payload_sz>node->cfg.payload_max ) ) return;
  if( FD_UNLIKELY( block.slot<=node->delivered.slot ) ) return;
  if( FD_UNLIKELY( block.slot>=node->delivered.slot+node->cfg.slot_max ) ) return; /* too far ahead; repaired later */

  ag_block_hash_t hash;
  if( own ) {
    vseq_block_hash( block.slot, &block.parent, block.payload, block.payload_sz, hash );
  } else {
    ag_validator_info_t const * leader = ag_epoch_info_leader( set_of( node, block.slot )->epoch, block.slot );
    if( FD_UNLIKELY( vseq_block_verify( &block, leader->id_key, node->sha, hash ) ) ) return;
  }

  ag_block_id_t id = ag_block_id( block.slot, hash );
  if( FD_UNLIKELY( blk_query( node, &id ) ) ) return;
  ulong slot_cnt = blk_slot_cnt( node, block.slot );
  if( FD_UNLIKELY( slot_cnt>=BLKS_PER_SLOT_MAX && !( slot_cnt<BLKS_PER_SLOT_WANTED && repair_wanted( node, &id ) ) ) ) {
    node->metrics.blocks_refused++;
    return;
  }
  if( FD_UNLIKELY( !blk_pool_free( node->blks ) ) ) {
    FD_LOG_WARNING(( "block store full, dropping block for slot %lu", block.slot ));
    return;
  }

  blk_t * blk     = blk_pool_ele_acquire( node->blks );
  blk->id         = id;
  blk->parent     = block.parent;
  blk->complete   = 0;
  blk->finalized  = 0;
  blk->wire       = malloc( sz );
  blk->wire_sz    = sz;
  FD_TEST( blk->wire );
  memcpy( blk->wire, msg, sz );
  blk_map_ele_insert( node->blk_map, blk, node->blks );

  try_complete( node, blk );
}

/* build_block turns pending txs into the block for slot and sends it to
   every node. */

static void
build_block( vseq_node_t * node,
             ulong         slot ) {
  ulong take = 0UL;
  while( take+sizeof(uint)<=node->txq_sz ) {
    ulong tx_sz = FD_LOAD( uint, node->txq+take );
    ulong end   = take+sizeof(uint)+tx_sz;
    if( FD_UNLIKELY( end>node->txq_sz || end>node->cfg.payload_max ) ) break;
    take = end;
  }

  note_block( node, slot );

  ag_block_hash_t hash;
  uchar *         msg = node->build_buf;
  msg[0] = VSEQ_MSG_BLOCK;
  ulong sz = 1UL + vseq_block_build( msg+1UL, slot, &node->lead_parent, node->txq, take, node->id_pub, node->cfg.id_sec, node->sha, hash );

  memmove( node->txq, node->txq+take, node->txq_sz-take );
  node->txq_sz     -= take;
  node->lead_parent = ag_block_id( slot, hash );
  node->metrics.blocks_built++;

  send_msg( node, VSEQ_DST_ALL, msg, sz );
  on_block( node, msg, sz, 1 );
}

static void
lead( vseq_node_t *         node,
      ulong                 window,
      ulong                 first_idx,
      ag_block_id_t const * parent ) {
  node->lead_window     = window;
  node->lead_idx        = first_idx;
  node->lead_t0         = node->now;
  node->lead_parent     = *parent;
  node->last_led_window = window;
}

/* leader_tick builds slot i of our window at lead_t0+(i+1)*ns_per_slot.
   Votor's skip timeout for that slot fires at
   ParentReady+AG_DELTA_TIMEOUT_NS+(i+1)*ns_per_slot, leaving
   AG_DELTA_TIMEOUT_NS for the block to reach the other nodes. */

static int
leader_tick( vseq_node_t * node ) {
  int busy = 0;
  while( node->lead_window!=ULONG_MAX && node->lead_idx<AG_SLOTS_PER_WINDOW &&
         node->now>=node->lead_t0+(long)(node->lead_idx+1UL)*node->cfg.ns_per_slot ) {
    ulong slot = node->lead_window+node->lead_idx;
    if( FD_UNLIKELY( slot<=node->quiet_until ) ) node->metrics.blocks_withheld++;
    else                                         build_block( node, slot );
    node->lead_idx++;
    busy = 1;
  }
  if( node->lead_idx>=AG_SLOTS_PER_WINDOW ) node->lead_window = ULONG_MAX;
  return busy;
}

static void
maybe_lead( vseq_node_t *         node,
            ulong                 slot,
            ag_block_id_t const * parent ) {
  if( vseq_sched_leader( node->sched, slot )!=node->own ) return;
  if( node->last_led_window!=ULONG_MAX && slot<=node->last_led_window ) return; /* first ParentReady wins */
  if( slot<=node->delivered.slot ) return;
  if( slot<=node->quiet_until ) { node->metrics.blocks_withheld += AG_SLOTS_PER_WINDOW; return; }
  lead( node, slot, 0UL, parent );
}

/* Finalization *******************************************************/

static void
prune( vseq_node_t * node ) {
  ulong     cnt  = 0UL;
  blk_t **  dead = node->blk_scratch;
  ulong     keep = fd_ulong_sat_sub( node->delivered.slot, node->cfg.retain_slots );
  for( blk_map_iter_t iter = blk_map_iter_init( node->blk_map, node->blks );
                            !blk_map_iter_done( iter, node->blk_map, node->blks );
                      iter = blk_map_iter_next( iter, node->blk_map, node->blks ) ) {
    blk_t * b = blk_map_iter_ele( iter, node->blk_map, node->blks );
    if( ( !b->finalized && b->id.slot<=node->delivered.slot ) || ( b->finalized && b->id.slot<keep ) ) dead[ cnt++ ] = b;
  }
  for( ulong i=0UL; i<cnt; i++ ) {
    blk_t * b = dead[i];
    blk_map_ele_remove( node->blk_map, &b->id, NULL, node->blks );
    free( b->wire );
    blk_pool_ele_release( node->blks, b );
  }
}

static ulong
proof_append( uchar *           out,
              ulong             off,
              ag_cert_t const * cert ) {
  ulong sz = ag_cert_ser( cert, out+off+sizeof(uint) );
  FD_STORE( uint, out+off, (uint)sz );
  return off+sizeof(uint)+sz;
}

/* build_proof writes the certs that finalize block id directly, see
   VSEQ_PROOF_MAX, and returns their size (0 if there are none). */

static ulong
build_proof( vseq_node_t *         node,
             ag_block_id_t const * id ) {
  ag_slot_state_t const * state = ag_pool_slot_state( node->pool, id->slot );
  if( FD_UNLIKELY( !state ) ) return 0UL;
  ag_slot_certs_t const * certs = &state->certs;
  ag_cert_t               cert;

  if( certs->fast_finalize.slot==id->slot && !memcmp( certs->fast_finalize.block_hash, id->hash, sizeof(ag_block_hash_t) ) ) {
    cert = (ag_cert_t){ .kind = AG_CERT_KIND_FAST_FINAL, .fast_final = certs->fast_finalize };
    return proof_append( node->proof, 0UL, &cert );
  }
  if( certs->finalize.slot==id->slot && certs->notar.slot==id->slot && !memcmp( certs->notar.block_hash, id->hash, sizeof(ag_block_hash_t) ) ) {
    cert = (ag_cert_t){ .kind = AG_CERT_KIND_FINAL, .final = certs->finalize };
    ulong off = proof_append( node->proof, 0UL, &cert );
    cert = (ag_cert_t){ .kind = AG_CERT_KIND_NOTAR, .notar = certs->notar };
    return proof_append( node->proof, off, &cert );
  }
  return 0UL;
}

/* deliver_finalized hands newly finalized blocks to the app, oldest
   first.  The pool's highest finalized block implies all its
   ancestors; missing ones are repaired before anything is delivered. */

static void
deliver_finalized( vseq_node_t * node ) {
  ulong         fin_slot = ag_pool_finalized_slot( node->pool );
  uchar const * fin_hash = ag_pool_finalized_block_hash( node->pool );
  if( FD_UNLIKELY( fin_slot==ULONG_MAX || !fin_hash || fin_slot<=node->delivered.slot ) ) return;

  blk_t **      chain = node->blk_scratch;
  ulong         cnt   = 0UL;
  ag_block_id_t cur   = ag_block_id( fin_slot, fin_hash );
  while( cur.slot>node->delivered.slot ) {
    blk_t * b = blk_query( node, &cur );
    if( FD_UNLIKELY( !b ) ) { repair_request( node, &cur ); return; }
    FD_TEST( cnt<node->blk_max );
    chain[ cnt++ ] = b;
    cur = b->parent;
  }
  if( FD_UNLIKELY( !ag_block_id_eq( &cur, &node->delivered ) ) ) {
    FD_LOG_CRIT(( "finalized block %lu does not descend from delivered block %lu", fin_slot, node->delivered.slot ));
  }

  while( cnt ) {
    blk_t *      b = chain[ --cnt ];
    vseq_block_t block;
    FD_TEST( !vseq_block_parse( &block, b->wire+1UL, b->wire_sz-1UL ) );
    b->finalized    = 1;
    node->delivered = b->id;
    node->metrics.blocks_finalized++;
    ulong proof_sz = build_proof( node, &b->id );
    node->cfg.finalized( node->cfg.cb_ctx, &block, b->id.hash, node->proof, proof_sz );
  }
  prune( node );
}

/* Events *************************************************************/

static void
handle_pool_event( vseq_node_t *           node,
                   ag_pool_event_t const * event ) {
  if( event->kind==AG_POOL_EVENT_IMPLICITLY_SKIPPED || event->kind==AG_POOL_EVENT_IMPLICITLY_FINALIZED ) return; /* not for votor */
  ag_votor_handle_pool_event( node->votor, event, node->now );
  switch( event->kind ) {
  case AG_POOL_EVENT_PARENT_READY:
    node->highest_parent_ready_slot = fd_ulong_max( node->highest_parent_ready_slot, event->parent_ready.slot );
    maybe_lead( node, event->parent_ready.slot, &event->parent_ready.parent );
    break;
  case AG_POOL_EVENT_CERT_CREATED:
    switch( event->cert_created.kind ) {
    case AG_CERT_KIND_FAST_FINAL: node->metrics.fast_final_certs++; break;
    case AG_CERT_KIND_FINAL:      node->metrics.final_certs++;      break;
    case AG_CERT_KIND_SKIP:       node->metrics.skip_certs++;       break;
    default:                                                         break;
    }
    break;
  default:
    break;
  }
}

/* handle_own_vote sends a vote votor made.  Our pool holds every vote
   we sent, in this run and (after a restart) earlier ones, so it is the
   check that we never contradict ourselves: a vote it calls slashable
   is withheld.  Votes are persisted before they leave. */

static void
handle_own_vote( vseq_node_t *     node,
                 ag_vote_t const * vote ) {
  uchar quorum_reached;
  int   err = ag_pool_add_vote( node->pool, vote, node->bad, &quorum_reached );
  ban_bad_ranks( node, ag_vote_slot( vote ), node->bad );
  if( FD_UNLIKELY( err && err!=AG_POOL_ERR_DUPLICATE ) ) {
    char cstr[ AG_VOTE_CSTR_MAX ];
    FD_LOG_INFO(( "withholding %s: %s", ag_vote_to_cstr( vote, cstr ), ag_pool_strerror( err ) ));
    node->metrics.votes_withheld++;
    return;
  }

  node->msg[0] = VSEQ_MSG_VOTE;
  ulong sz = 1UL + ag_vote_ser( vote, node->msg+1UL );
  if( FD_LIKELY( !err && node->cfg.persist_vote ) ) {
    blk_t const * blk = NULL;
    if( vote->kind==AG_VOTE_KIND_NOTAR ) {
      ag_block_id_t id = ag_block_id( vote->notar.slot, vote->notar.block_hash );
      blk = blk_query( node, &id );
      FD_TEST( blk ); /* votor only votes notar for blocks we replayed */
    }
    node->cfg.persist_vote( node->cfg.cb_ctx, ag_vote_slot( vote ), node->msg+1UL, sz-1UL,
                            blk ? blk->wire+1UL : NULL, blk ? blk->wire_sz-1UL : 0UL );
  }
  send_msg( node, VSEQ_DST_ALL, node->msg, sz );
}

static void
handle_own_cert( vseq_node_t *     node,
                 ag_cert_t const * cert ) {
  if( FD_UNLIKELY( ag_cert_slot( cert )<=node->root.slot ) ) return; /* root certs, rebroadcast by standstill recovery: peers have them */
  ag_pool_add_cert( node->pool, cert, node->bad );
  ban_bad_ranks( node, ag_cert_slot( cert ), node->bad );

  node->msg[0] = VSEQ_MSG_CERT;
  ulong sz = 1UL + ag_cert_ser( cert, node->msg+1UL );
  send_msg( node, VSEQ_DST_ALL, node->msg, sz );
}

static void
set_vote_rank( ag_vote_t * vote,
               ushort      rank ) {
  switch( vote->kind ) {
  case AG_VOTE_KIND_NOTAR:          vote->notar.rank          = rank; break;
  case AG_VOTE_KIND_FINAL:          vote->final.rank          = rank; break;
  case AG_VOTE_KIND_SKIP:           vote->skip.rank           = rank; break;
  case AG_VOTE_KIND_NOTAR_FALLBACK: vote->notar_fallback.rank = rank; break;
  case AG_VOTE_KIND_SKIP_FALLBACK:  vote->skip_fallback.rank  = rank; break;
  default:                          FD_LOG_CRIT(( "unreachable" ));
  }
}

/* Public API *********************************************************/

vseq_node_t *
vseq_node_create( vseq_node_cfg_t const * cfg,
                  long                    now ) {
  if( FD_UNLIKELY( !cfg->sched || !cfg->send || !cfg->finalized ) ) { FD_LOG_WARNING(( "missing schedule or callback" )); return NULL; }
  if( FD_UNLIKELY( cfg->own_peer>=cfg->sched->peer_cnt          ) ) { FD_LOG_WARNING(( "own_peer out of range"      )); return NULL; }
  if( FD_UNLIKELY( cfg->slot_max<32UL || !cfg->network_id       ) ) { FD_LOG_WARNING(( "bad slot_max or network_id" )); return NULL; }
  /* Votor knows the current and the next set, so a set must last
     longer than the slots it tracks */
  if( FD_UNLIKELY( cfg->sched->epoch_slots<cfg->slot_max        ) ) { FD_LOG_WARNING(( "epoch_slots must be at least slot_max" )); return NULL; }
  if( FD_UNLIKELY( cfg->ns_per_slot<=0L || !cfg->payload_max    ) ) { FD_LOG_WARNING(( "bad ns_per_slot or payload_max" )); return NULL; }

  vseq_node_t * node = alloc_aligned( alignof(vseq_node_t), sizeof(vseq_node_t) );
  if( FD_UNLIKELY( !node ) ) return NULL;
  memset( node, 0, sizeof(vseq_node_t) );
  node->cfg   = *cfg;
  node->sched = cfg->sched;
  node->own   = cfg->own_peer;
  node->now   = now;
  FD_TEST( fd_sha512_join( fd_sha512_new( node->sha ) ) );

  fd_ed25519_public_from_private( node->id_pub, cfg->id_sec, node->sha );
  if( FD_UNLIKELY( memcmp( node->id_pub, node->sched->peer_id[ node->own ], 32UL ) ) ) {
    FD_LOG_WARNING(( "identity key does not match peer %lu", node->own ));
    free( node );
    return NULL;
  }
  fd_bls_pub_t bls_pub;
  fd_bls_sec_to_pub( &cfg->bls_sec, &bls_pub );
  blst_p1_compress( node->bls_pub, &bls_pub );

  node->pool_mem  = alloc_aligned( ag_pool_align(),  ag_pool_footprint ( cfg->slot_max ) );
  node->votor_mem = alloc_aligned( ag_votor_align(), ag_votor_footprint( cfg->slot_max ) );
  node->blk_max   = cfg->slot_max*BLKS_PER_SLOT_WANTED + cfg->retain_slots;
  ulong chain_cnt = blk_map_chain_cnt_est( node->blk_max );
  node->blk_pool_mem = alloc_aligned( blk_pool_align(), blk_pool_footprint( node->blk_max ) );
  node->blk_map_mem  = alloc_aligned( blk_map_align(),  blk_map_footprint ( chain_cnt     ) );
  node->blk_scratch  = malloc( node->blk_max*sizeof(blk_t *) );
  node->txq          = malloc( fd_ulong_max( cfg->txq_max, 1UL ) );
  node->build_buf    = malloc( 1UL+VSEQ_BLOCK_HDR_SZ+cfg->payload_max );
  node->banned_until = calloc( node->sched->peer_cnt, sizeof(long) );
  FD_TEST( node->pool_mem && node->votor_mem && node->blk_pool_mem && node->blk_map_mem && node->blk_scratch && node->txq && node->build_buf && node->banned_until );

  node->pool    = ag_pool_join ( ag_pool_new ( node->pool_mem,  cfg->slot_max, cfg->seed ) );
  node->votor   = ag_votor_join( ag_votor_new( node->votor_mem, cfg->slot_max, cfg->seed ) );
  node->blks    = blk_pool_join( blk_pool_new( node->blk_pool_mem, node->blk_max ) );
  node->blk_map = blk_map_join ( blk_map_new ( node->blk_map_mem, chain_cnt, cfg->seed ) );
  FD_TEST( node->pool && node->votor && node->blks && node->blk_map );

  /* Votor and the pool get the root's set and the next one; the one
     after that once the root reaches the next (vseq_node_service).
     Genesis is slot 0 with the all-zero block hash. */

  node->root     = ag_block_id( cfg->root_slot, cfg->root_slot ? cfg->root_hash : ag_block_hash_null );
  vseq_set_t const * root_set = set_of( node, node->root.slot );
  node->next_set = vseq_sched_next( node->sched, root_set );
  advance_pool( node, root_set );
  if( node->next_set ) advance_pool( node, node->next_set );
  ag_pool_init( node->pool, &node->root );

  /* A root from the ledger must be finalized by its certs.  They go
     into the pool too, so standstill recovery can rebroadcast them. */

  ag_cert_t * cert = &node->scratch.cert;
  if( node->root.slot ) {
    int err = vseq_proof_verify( root_set->epoch, cfg->network_id, node->root.slot, node->root.hash, cfg->root_proof, cfg->root_proof_sz, cert );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "certs of root slot %lu do not verify (%d)", node->root.slot, err ));
      vseq_node_destroy( node );
      return NULL;
    }
    for( ulong off=0UL; off<cfg->root_proof_sz; ) {
      ulong sz = FD_LOAD( uint, cfg->root_proof+off ), bit_cnt;
      FD_TEST( !ag_cert_de( cert, &bit_cnt, cfg->root_proof+off+sizeof(uint), sz ) );
      FD_TEST( !ag_pool_add_verified_cert( node->pool, cert, node->bad ) );
      off += sizeof(uint)+sz;
    }
  }
  ag_votor_init( node->votor, &node->root, now, cfg->ns_per_slot, cfg->network_id, sign_bls, node );
  advance_votor( node, root_set );
  if( node->next_set ) advance_votor( node, node->next_set );

  node->delivered                 = node->root;
  node->quiet_until               = cfg->block_floor ? ag_first_slot_in_window( cfg->block_floor )+AG_SLOTS_PER_WINDOW-1UL : 0UL;
  node->block_hi                  = cfg->block_floor;
  node->last_final_slot           = node->root.slot;
  node->last_final_ts             = now;
  node->highest_parent_ready_slot = node->root.slot;
  node->lead_window               = ULONG_MAX;
  node->last_led_window           = ULONG_MAX;

  /* No ParentReady event is raised for the genesis window, so its
     leader builds slots 1-3 on top of genesis right away. */

  if( !node->root.slot && !node->quiet_until && vseq_sched_leader( node->sched, 0UL )==node->own ) lead( node, 0UL, 1UL, &node->delivered );
  if( node->quiet_until ) FD_LOG_NOTICE(( "restart: building no blocks at or below slot %lu", node->quiet_until ));

  /* Restore the blocks we voted for before the restart, then the votes
     (see cfg): votes into the pool as ours, and out again.  Anything
     above what the pool can hold would be forgotten, and the node
     could then contradict it, so that fails instead (the caller must
     restore the ledger tail, or raise slot_max). */

  ulong window_end = node->root.slot + cfg->slot_max - AG_REWARD_SLOT_DELTA; /* ag_pool_add_vote's bound */
  for( ulong off=0UL; off+sizeof(uint)<=cfg->prior_blocks_sz; ) {
    ulong sz = FD_LOAD( uint, cfg->prior_blocks+off );
    if( FD_UNLIKELY( off+sizeof(uint)+sz>cfg->prior_blocks_sz || sz>VSEQ_BLOCK_HDR_SZ+cfg->payload_max ) ) break;
    ulong slot = sz>=sizeof(ulong) ? FD_LOAD( ulong, cfg->prior_blocks+off+sizeof(uint) ) : 0UL;
    if( FD_UNLIKELY( slot>=window_end ) ) {
      FD_LOG_WARNING(( "the vote history has a block for slot %lu, more than slot_max-%lu slots above the root slot %lu: the ledger lost too much; restore it or raise slot_max",
                       slot, AG_REWARD_SLOT_DELTA, node->root.slot ));
      vseq_node_destroy( node );
      return NULL;
    }
    node->build_buf[0] = VSEQ_MSG_BLOCK;
    memcpy( node->build_buf+1UL, cfg->prior_blocks+off+sizeof(uint), sz );
    on_block( node, node->build_buf, 1UL+sz, 0 );
    off += sizeof(uint)+sz;
  }

  for( ulong off=0UL; off+sizeof(uint)<=cfg->prior_votes_sz; ) {
    ulong sz = FD_LOAD( uint, cfg->prior_votes+off );
    if( FD_UNLIKELY( off+sizeof(uint)+sz>cfg->prior_votes_sz ) ) break;
    uchar const * ser  = cfg->prior_votes+off+sizeof(uint);
    ag_vote_t *   vote = &node->scratch.vote;
    off += sizeof(uint)+sz;
    if( FD_UNLIKELY( ag_vote_de( vote, ser, sz ) || sz>BODY_MAX ) ) { FD_LOG_WARNING(( "skipping a malformed prior vote" )); continue; }
    if( ag_vote_slot( vote )<=node->root.slot ) continue;
    ulong rank = own_rank( node, set_of( node, ag_vote_slot( vote ) ) );
    if( FD_UNLIKELY( rank==USHORT_MAX ) ) continue;
    set_vote_rank( vote, (ushort)rank );
    uchar quorum_reached;
    int   err = ag_pool_add_vote( node->pool, vote, node->bad, &quorum_reached );
    if( FD_UNLIKELY( err==AG_POOL_ERR_DUPLICATE ) ) continue;
    if( FD_UNLIKELY( err ) ) {
      char cstr[ AG_VOTE_CSTR_MAX ];
      FD_LOG_WARNING(( "cannot restore prior vote %s (%s): the ledger lost too much since it was cast; restore it or raise slot_max",
                       ag_vote_to_cstr( vote, cstr ), ag_pool_strerror( err ) ));
      vseq_node_destroy( node );
      return NULL;
    }
    node->msg[0] = VSEQ_MSG_VOTE;
    memcpy( node->msg+1UL, ser, sz );
    send_msg( node, VSEQ_DST_ALL, node->msg, 1UL+sz );
    node->metrics.votes_restored++;
  }
  if( node->metrics.votes_restored ) FD_LOG_NOTICE(( "restart: restored %lu votes sent before the restart", node->metrics.votes_restored ));

  return node;
}

void
vseq_node_destroy( vseq_node_t * node ) {
  if( FD_UNLIKELY( !node ) ) return;
  for( blk_map_iter_t iter = blk_map_iter_init( node->blk_map, node->blks );
                            !blk_map_iter_done( iter, node->blk_map, node->blks );
                      iter = blk_map_iter_next( iter, node->blk_map, node->blks ) ) {
    free( blk_map_iter_ele( iter, node->blk_map, node->blks )->wire );
  }
  free( node->banned_until );
  free( node->build_buf );
  free( node->txq );
  free( node->blk_scratch );
  free( node->blk_map_mem );
  free( node->blk_pool_mem );
  free( node->votor_mem );
  free( node->pool_mem );
  free( node );
}

/* hash_set_full: adding hash to set would use its last entry */

static int
hash_set_full( ag_block_hash_set_t const * set,
               uchar const *               hash ) {
  if( set->cnt+1UL<AG_EQVOC_BLOCK_HASH_MAX ) return 0;
  for( ulong i=0UL; i<set->cnt; i++ ) if( !memcmp( set->hash[i], hash, sizeof(ag_block_hash_t) ) ) return 0;
  return 1;
}

static void
recv_vote( vseq_node_t * node,
           ulong         from,
           uchar const * body,
           ulong         sz ) {
  ag_vote_t * vote = &node->scratch.vote;
  if( FD_UNLIKELY( ag_vote_de( vote, body, sz ) ) ) return;
  ulong rank = set_of( node, ag_vote_slot( vote ) )->rank_of_peer[ from ];
  if( FD_UNLIKELY( rank==ULONG_MAX ) ) return; /* not a voter in that slot */
  set_vote_rank( vote, (ushort)rank );

  if( FD_UNLIKELY( ag_vote_shred_version( vote )!=node->cfg.network_id ) ) return;
  if( FD_UNLIKELY( blst_p2_is_inf( ag_vote_sig( vote ) ) ) ) { ban_peer( node, from ); return; } /* never a valid signature */
  uchar const * block_hash = ag_vote_block_hash( vote );
  if( FD_UNLIKELY( block_hash && !memcmp( block_hash, ag_block_hash_null, sizeof(ag_block_hash_t) ) ) ) return;
  ulong finalized = ag_pool_finalized_slot( node->pool );
  ulong horizon   = fd_ulong_max( finalized, node->highest_parent_ready_slot ) + VOTE_LOOKAHEAD_MAX;
  if( FD_UNLIKELY( ag_vote_slot( vote )>horizon ) ) return;
  /* The pool keeps slot state for a few slots at and below the
     finalized one too, and makes it before checking the signature.  A
     vote on the finalized slot itself would give it a slot state with
     no certs, which standstill recovery asserts against (fatal) when
     the root is genesis, so no vote at or below finalized goes in. */
  if( FD_UNLIKELY( ag_vote_slot( vote )<=finalized ) ) return;
  /* The pool tracks at most AG_EQVOC_BLOCK_HASH_MAX hashes per slot
     that 20% of stake voted notar on, and asserts (fatal) on more.
     Enough for honest voters and under 20% byzantine stake, but
     signatures are only checked once a quorum forms, and a voter whose
     signature then fails may vote again: colluding validators of 40%
     can leave a new unverified hash behind each round.  Leave the last
     slot free rather than let a peer abort the node. */
  if( vote->kind==AG_VOTE_KIND_NOTAR ) {
    ag_slot_state_t const * st = ag_pool_slot_state( node->pool, ag_vote_slot( vote ) );
    if( st && ( hash_set_full( &st->pending_safe_to_notar, block_hash ) || hash_set_full( &st->sent_safe_to_notar, block_hash ) ) ) {
      node->metrics.votes_refused++;
      return;
    }
  }

  uchar quorum_reached;
  ag_pool_add_vote( node->pool, vote, node->bad, &quorum_reached );
  ban_bad_ranks( node, ag_vote_slot( vote ), node->bad );
}

static void
recv_cert( vseq_node_t * node,
           ulong         from,
           uchar const * body,
           ulong         sz ) {
  ag_cert_t * cert = &node->scratch.cert;
  ulong       bit_cnt;
  if( FD_UNLIKELY( ag_cert_de( cert, &bit_cnt, body, sz ) ) ) return;
  ulong slot = ag_cert_slot( cert );
  if( FD_UNLIKELY( ag_cert_shred_version( cert )!=node->cfg.network_id || bit_cnt>set_of( node, slot )->epoch->validator_cnt ) ) return;
  if( FD_UNLIKELY( slot<=ag_pool_finalized_slot( node->pool ) ) ) return; /* as for votes */

  if( FD_UNLIKELY( ag_pool_add_cert( node->pool, cert, node->bad )==AG_POOL_ERR_CERT_VERIFY ) ) ban_peer( node, from );
  ban_bad_ranks( node, slot, node->bad );
}

static void
recv_repair( vseq_node_t * node,
             ulong         from,
             uchar const * body,
             ulong         sz ) {
  if( FD_UNLIKELY( sz!=REPAIR_BODY_SZ ) ) return;
  ag_block_id_t id = ag_block_id( FD_LOAD( ulong, body ), body+sizeof(ulong) );
  blk_t const * b  = blk_query( node, &id );
  if( FD_UNLIKELY( !b ) ) return;
  send_msg( node, from, b->wire, b->wire_sz );
}

void
vseq_node_recv( vseq_node_t * node,
                long          now,
                ulong         from,
                uchar const * buf,
                ulong         sz ) {
  node->now = now;
  if( FD_UNLIKELY( from>=node->sched->peer_cnt || from==node->own ) ) return;
  if( FD_UNLIKELY( now<node->banned_until[ from ] ) ) return;
  if( FD_UNLIKELY( !sz ) ) return;

  uchar const * body    = buf+1UL;
  ulong         body_sz = sz-1UL;
  switch( buf[0] ) {
  case VSEQ_MSG_VOTE:   recv_vote  ( node, from, body, body_sz ); break;
  case VSEQ_MSG_CERT:   recv_cert  ( node, from, body, body_sz ); break;
  case VSEQ_MSG_BLOCK:  on_block   ( node, buf, sz, 0 );          break;
  case VSEQ_MSG_REPAIR: recv_repair( node, from, body, body_sz ); break;
  default:                                                        break;
  }
}

long
vseq_node_service( vseq_node_t * node,
                   long          now ) {
  node->now = now;

  /* Section 4.1: no finalization for AG_DELTA_STANDSTILL_NS means
     messages were lost.  Rebroadcast our certs and votes, again every
     AG_DELTA_STANDSTILL_NS until finalization resumes. */

  if( FD_UNLIKELY( now-node->last_final_ts>=AG_DELTA_STANDSTILL_NS ) ) {
    ag_pool_recover_from_standstill( node->pool );
    node->last_final_ts = now;
    node->metrics.standstills++;
  }

  for(;;) {
    int busy = leader_tick( node );

    ulong timeout_slot;
    while( ag_votor_poll_skip_timeout( node->votor, now, &timeout_slot ) ) {
      ag_votor_handle_skip_timeout( node->votor, timeout_slot );
      busy = 1;
    }
    while( ag_pool_poll_pool_event( node->pool, &node->scratch.pool_event ) ) {
      handle_pool_event( node, &node->scratch.pool_event );
      busy = 1;
    }
    uchar reason;
    while( ag_votor_poll_vote( node->votor, &node->scratch.vote, &reason ) ) {
      handle_own_vote( node, &node->scratch.vote );
      busy = 1;
    }
    while( ag_votor_poll_cert( node->votor, &node->scratch.cert ) ) {
      handle_own_cert( node, &node->scratch.cert );
      busy = 1;
    }
    while( ag_pool_poll_repair_event( node->pool, &node->scratch.block_id ) ) {
      repair_request( node, &node->scratch.block_id );
      busy = 1;
    }
    if( !busy ) break;
  }

  ulong fin_slot = ag_pool_finalized_slot( node->pool );
  if( FD_LIKELY( fin_slot!=ULONG_MAX && fin_slot>node->last_final_slot ) ) {
    node->last_final_slot = fin_slot;
    node->last_final_ts   = now;
  }
  ulong delivered_before = node->delivered.slot;
  deliver_finalized( node );
  if( node->delivered.slot!=delivered_before ) retry_incomplete( node );

  /* Once the root is in the next set, give votor the one after */
  while( node->next_set && node->delivered.slot>=node->next_set->start_slot ) {
    node->next_set = vseq_sched_next( node->sched, node->next_set );
    if( !node->next_set ) break;
    advance_pool ( node, node->next_set );
    advance_votor( node, node->next_set );
  }

  long next = ag_votor_next_skip_timeout( node->votor );
  next = fd_long_min( next, repair_tick( node ) );
  next = fd_long_min( next, node->last_final_ts+AG_DELTA_STANDSTILL_NS );
  if( node->lead_window!=ULONG_MAX ) next = fd_long_min( next, node->lead_t0+(long)(node->lead_idx+1UL)*node->cfg.ns_per_slot );
  return next;
}

int
vseq_node_submit_tx( vseq_node_t * node,
                     uchar const * tx,
                     ulong         sz ) {
  if( FD_UNLIKELY( sizeof(uint)+sz>node->cfg.payload_max || node->txq_sz+sizeof(uint)+sz>node->cfg.txq_max ) ) return -1;
  FD_STORE( uint, node->txq+node->txq_sz, (uint)sz );
  memcpy( node->txq+node->txq_sz+sizeof(uint), tx, sz );
  node->txq_sz += sizeof(uint)+sz;
  return 0;
}

ulong
vseq_node_delivered_slot( vseq_node_t const * node ) {
  return node->delivered.slot;
}

ulong
vseq_node_quiet_until( vseq_node_t const * node ) {
  return node->quiet_until;
}

vseq_node_metrics_t const *
vseq_node_metrics( vseq_node_t const * node ) {
  return &node->metrics;
}

uchar const *
vseq_payload_next( uchar const * payload,
                   ulong         payload_sz,
                   ulong *       off,
                   ulong *       sz ) {
  if( *off+sizeof(uint)>payload_sz ) return NULL;
  ulong tx_sz = FD_LOAD( uint, payload+*off );
  if( *off+sizeof(uint)+tx_sz>payload_sz ) return NULL;
  uchar const * tx = payload+*off+sizeof(uint);
  *off += sizeof(uint)+tx_sz;
  *sz   = tx_sz;
  return tx;
}
