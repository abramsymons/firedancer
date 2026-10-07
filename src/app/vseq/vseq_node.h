#ifndef HEADER_fd_src_app_vseq_vseq_node_h
#define HEADER_fd_src_app_vseq_vseq_node_h

/* vseq_node is one consensus-only node: Firedancer's Alpenglow votor
   (ag_pool + ag_votor) plus a block store, a leader that batches
   submitted txs into blocks, direct block broadcast, block repair and
   standstill recovery.  It never executes blocks; finalized blocks are
   handed to the application in chain order.

   This is the only module that calls into choreo/votor.

   The node does no I/O.  The caller moves bytes between nodes with
   vseq_node_recv and the send callback, and drives time with
   vseq_node_service.  Nodes are addressed by peer index (vseq_sched.h).
   The transport must authenticate senders: a vote's signer is taken
   from the sending peer, because votor checks vote signatures lazily,
   in aggregate.

   The validator set can change at epoch boundaries (vseq_sched.h).  A
   node follows consensus whether or not it is in the current set, and
   votes and leads only in sets that list it.

   Not thread safe. */

#include "vseq_block.h"
#include "vseq_sched.h"
#include "../../choreo/votor/ag_cert_serde.h"

/* Message envelope: one type byte, then the body. */

#define VSEQ_MSG_VOTE   (1) /* ag_vote_ser bytes                   */
#define VSEQ_MSG_CERT   (2) /* ag_cert_ser bytes                   */
#define VSEQ_MSG_BLOCK  (3) /* vseq_block wire bytes               */
#define VSEQ_MSG_REPAIR (4) /* ulong slot, uchar hash[32]: send me */

/* Catch-up from a peer's ledger, handled by vseqd (vseq_node_recv
   ignores them).  A node that restarts, or falls too far behind for
   consensus to repair, fetches finalized blocks with their proofs. */

#define VSEQ_MSG_SYNC_REQ   (16) /* ulong after_slot, ulong max_blocks                        */
#define VSEQ_MSG_SYNC_BLOCK (17) /* one ledger record (vseq_ledger.h)                          */
#define VSEQ_MSG_SYNC_END   (18) /* ulong last finalized slot, ulong base_slot, uchar base[32] */
#define VSEQ_MSG_HELLO      (19) /* ulong epoch, uchar validator set hash[32] (vseqd)          */

#define VSEQ_DST_ALL (ULONG_MAX)

typedef void
(* vseq_send_fn)( void *        ctx,
                  ulong         dst_peer, /* or VSEQ_DST_ALL, never self */
                  uchar const * buf,
                  ulong         sz );

/* A finality proof is the certs that finalize a block directly, as a
   sequence of (uint sz, uchar cert[sz]) in ag_cert_ser format:

     fast finalized:  one FastFinal cert on (slot, hash)
     finalized:       one Final cert on slot, then one Notar cert on
                      (slot, hash), since Final does not name the hash

   A block finalized only because a descendant was has an empty proof:
   the descendant's proof covers it through parent hashes. */

#define VSEQ_PROOF_MAX (2UL*(sizeof(uint)+AG_CERT_SER_MAX))

/* vseq_finalized_fn is called once per finalized block, in chain order.
   block->parent is the previously delivered block.  block, its payload
   and proof are only valid during the call. */

typedef void
(* vseq_finalized_fn)( void *               ctx,
                       vseq_block_t const * block,
                       uchar const          hash[ 32 ],
                       uchar const *        proof,
                       ulong                proof_sz );

/* Persistence callbacks for restart safety, see vseq_node_cfg_t.  Both
   must make their argument durable (e.g. write and fsync) before
   returning: the vote or block is sent right after. */

typedef void
(* vseq_persist_vote_fn)( void *        ctx,
                          ulong         slot,
                          uchar const * vote,      /* ag_vote_ser bytes */
                          ulong         vote_sz,
                          uchar const * block,     /* for a notar vote: the block's wire bytes, else NULL */
                          ulong         block_sz );

typedef void
(* vseq_persist_block_fn)( void * ctx,
                           ulong  slot );

struct vseq_node_cfg {
  vseq_sched_t const *    sched;        /* validator sets, outlives the node; epoch_slots>=slot_max */
  ulong                   own_peer;
  fd_bls_sec_t            bls_sec;
  uchar                   id_sec[ 32 ]; /* ed25519 private key */
  long                    ns_per_slot;
  ushort                  network_id;   /* votor's shred_version, nonzero */
  ulong                   slot_max;     /* live slots tracked by votor, >=32 */
  ulong                   payload_max;  /* max block payload bytes */
  ulong                   txq_max;      /* max pending tx bytes */
  ulong                   retain_slots; /* finalized blocks kept for repair */
  ulong                   seed;

  /* Where consensus starts.  root_slot 0 is genesis.  Otherwise root is
     the last finalized block in the ledger and root_proof its certs,
     which must pass vseq_proof_verify. */

  ulong                   root_slot;
  ag_block_hash_t         root_hash;
  uchar const *           root_proof;
  ulong                   root_proof_sz;

  /* Restart safety (the vote history).

     Every vote is passed to persist_vote before it is sent, a notar
     vote with the block it is for: once a block may be finalized, its
     voters must be able to produce it, even if every node restarts.
     On restart, pass them back as prior_blocks and prior_votes, framed
     as (uint sz, bytes); ones at or below the root are ignored, and
     ones the pool cannot hold (slot_max-8 or more slots above the
     root) fail creation: the node must not forget what it signed.  The
     blocks go back into the block store.  The votes go
     into the pool as ours and are sent again, so certs can still form
     from them, and the pool then rejects any new vote of ours that
     would conflict with them (ag_slot_state_check_slashable_offence);
     such votes are withheld.  So a whole cluster can restart at once
     without double voting or deadlocking.

     Blocks are not kept: before building a block for a slot above all
     earlier ones the node calls persist_block, and after a restart with
     block_floor set to the highest such slot it builds nothing up to
     the end of that slot's window. */

  uchar const *           prior_votes;
  ulong                   prior_votes_sz;
  uchar const *           prior_blocks;
  ulong                   prior_blocks_sz;
  ulong                   block_floor;
  vseq_persist_vote_fn    persist_vote;
  vseq_persist_block_fn   persist_block;

  vseq_send_fn            send;
  vseq_finalized_fn       finalized;
  void *                  cb_ctx;
};
typedef struct vseq_node_cfg vseq_node_cfg_t;

struct vseq_node_metrics {
  ulong blocks_built;
  ulong blocks_finalized;
  ulong fast_final_certs;
  ulong final_certs;
  ulong skip_certs;
  ulong repair_reqs_sent;
  ulong standstills;
  ulong bans;
  ulong votes_restored;  /* prior votes loaded into the pool and resent */
  ulong votes_withheld;  /* own votes not sent: they conflict with a prior vote */
  ulong blocks_withheld; /* blocks not built: slot at or below the block floor's window */
};
typedef struct vseq_node_metrics vseq_node_metrics_t;

typedef struct vseq_node vseq_node_t;

FD_PROTOTYPES_BEGIN

/* vseq_node_create allocates a node starting at cfg's root: genesis,
   slot 0 with an all-zero block hash, or a finalized block from the
   ledger.  Returns NULL on failure (logs details), e.g. if root_proof
   does not finalize the root block. */

vseq_node_t *
vseq_node_create( vseq_node_cfg_t const * cfg,
                  long                    now );

void
vseq_node_destroy( vseq_node_t * node );

/* vseq_node_recv handles one message from peer from.  Call
   vseq_node_service afterwards. */

void
vseq_node_recv( vseq_node_t * node,
                long          now,
                ulong         from,
                uchar const * buf,
                ulong         sz );

/* vseq_node_service runs everything due at now: consensus events,
   timeouts, block production, repair and finalized delivery.  Returns
   the time it next needs to run, even if no message arrives. */

long
vseq_node_service( vseq_node_t * node,
                   long          now );

/* vseq_node_submit_tx queues a tx for the next block this node leads.
   Returns 0 on success, -1 if the queue is full or tx is too big. */

int
vseq_node_submit_tx( vseq_node_t * node,
                     uchar const * tx,
                     ulong         sz );

ulong                       vseq_node_delivered_slot( vseq_node_t const * node );
ulong                       vseq_node_quiet_until   ( vseq_node_t const * node ); /* builds no blocks at or below */
vseq_node_metrics_t const * vseq_node_metrics       ( vseq_node_t const * node );

/* vseq_payload_next iterates the txs in a block payload, which is a
   sequence of (uint sz, uchar tx[sz]).  Pass *off=0 to start.  Returns
   a pointer to the next tx and its size in *sz, or NULL at the end or
   on a malformed payload. */

uchar const *
vseq_payload_next( uchar const * payload,
                   ulong         payload_sz,
                   ulong *       off,
                   ulong *       sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_node_h */
