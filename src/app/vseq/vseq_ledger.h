#ifndef HEADER_fd_src_app_vseq_vseq_ledger_h
#define HEADER_fd_src_app_vseq_vseq_ledger_h

/* vseq_ledger stores finalized blocks, in chain order, as append-only
   segment files in a directory:

     0000000007.seg   a 64 byte header, then records
     0000000007.idx   the index of a sealed segment

   Record format (little endian), also served as is by /blocks:

     uint  rec_sz              bytes after this field
     ulong slot
     ulong parent_slot
     uchar parent_hash[ 32 ]
     uchar hash[ 32 ]
     uchar sig[ 64 ]           leader's signature over hash
     uint  payload_sz
     uchar payload[ payload_sz ]
     uint  proof_sz
     uchar proof[ proof_sz ]   certs, see VSEQ_PROOF_MAX in vseq_node.h

   Segment header: uchar magic[8] "VSQSEG01", ulong seq, ulong first_idx
   (ledger-wide index of its first record), ulong base_slot, uchar
   base_hash[32].  The base is the block the first record builds on, so
   every segment says where it fits even after older ones are gone.

   Records go to the newest ("active") segment.  Once it reaches the
   size limit, the next record with its own certs seals it: the segment
   is fsynced, its index is written to a temporary file, fsynced and
   renamed, and the directory is fsynced.  So every sealed segment ends
   with a block a client can verify, and a /blocks span rarely needs to
   cross segments.

   Opening loads sealed segments' indexes (rebuilding a missing or bad
   one by scanning the segment), checks that each segment's base is the
   previous segment's last block, and fully rescans only the active
   segment, cutting a torn tail.  A missing segment in the middle is an
   error.

   Pruning removes whole sealed segments, oldest first, never the
   active one: the .seg goes first, then the .idx.  A crash in between
   leaves an .idx with no .seg below the oldest segment, which opening
   removes.

   Records are not fsynced as they are appended, to keep syncs out of
   consensus: a node that loses its newest records refetches them from
   peers, or finalizes them again from its vote history.  Before the
   vote history forgets anything, vseq_ledger_sync makes the ledger
   durable (see vseqd.c). */

#include "vseq_block.h"

/* VSEQ_LEDGER_REC_SZ is the size of a record, including rec_sz. */

#define VSEQ_LEDGER_REC_SZ( payload_sz, proof_sz ) ( 156UL+(payload_sz)+(proof_sz) )

struct vseq_ledger_rec {
  vseq_block_t    block;    /* payload points into the ledger's read buffer */
  ag_block_hash_t hash;
  uchar const *   proof;    /* also in the read buffer */
  ulong           proof_sz;
};
typedef struct vseq_ledger_rec vseq_ledger_rec_t;

struct vseq_ledger_stats {
  ulong segments;
  ulong bytes;
  ulong sealed;   /* segments sealed by this process */
  ulong pruned;   /* segments pruned by this process */
};
typedef struct vseq_ledger_stats vseq_ledger_stats_t;

typedef struct vseq_ledger vseq_ledger_t;

FD_PROTOTYPES_BEGIN

/* vseq_ledger_open opens or creates the ledger in directory dir.
   seg_bytes is the size at which a segment is sealed (0 for 256 MiB).
   Returns NULL on failure (logs details). */

vseq_ledger_t *
vseq_ledger_open( char const * dir,
                  ulong        payload_max,
                  ulong        proof_max,
                  ulong        seg_bytes );

/* vseq_ledger_follow opens a read-only view of a ledger that another
   process writes, e.g. to serve /blocks.  It never changes the files.
   Call vseq_ledger_refresh to see new records and segments and to drop
   pruned ones.  Returns NULL if dir has no ledger yet. */

vseq_ledger_t *
vseq_ledger_follow( char const * dir,
                    ulong        payload_max,
                    ulong        proof_max );

/* vseq_ledger_refresh catches a followed ledger up with its writer.  A
   record still being written is skipped until it is complete.
   Returns 0, or -1 if the ledger was replaced or damaged: close and
   follow it again. */

int
vseq_ledger_refresh( vseq_ledger_t * ledger );

void
vseq_ledger_close( vseq_ledger_t * ledger );

/* vseq_ledger_sync makes every appended record durable (sealed
   segments already are). */

void
vseq_ledger_sync( vseq_ledger_t * ledger );

void
vseq_ledger_append( vseq_ledger_t *      ledger,
                    vseq_block_t const * block,
                    uchar const          hash[ 32 ],
                    uchar const *        proof,
                    ulong                proof_sz );

/* Records have ledger-wide indexes that do not change when older ones
   are pruned: those kept are [first_idx,cnt). */

ulong vseq_ledger_cnt      ( vseq_ledger_t const * ledger );
ulong vseq_ledger_first_idx( vseq_ledger_t const * ledger );

/* vseq_ledger_base is the block the oldest kept record builds on:
   genesis (slot 0, zero hash) unless history was pruned or the ledger
   started from a peer's history. */

ag_block_id_t
vseq_ledger_base( vseq_ledger_t const * ledger );

/* vseq_ledger_set_base starts an empty ledger after base instead of
   genesis, e.g. to catch up from peers that pruned older history.
   Returns 0 on success, -1 if the ledger is not empty. */

int
vseq_ledger_set_base( vseq_ledger_t *       ledger,
                      ag_block_id_t const * base );

/* vseq_ledger_first_after returns the index of the oldest kept record
   with a slot above slot, or vseq_ledger_cnt if there is none.  Check
   slot against vseq_ledger_base first: below it, history was pruned. */

ulong
vseq_ledger_first_after( vseq_ledger_t const * ledger,
                         ulong                 slot );

/* vseq_ledger_rec_parse parses one record (e.g. from /blocks or a
   peer).  out borrows buf.  Returns 0 if the sizes are consistent; it
   does not check the hash or the certs. */

int
vseq_ledger_rec_parse( uchar const *       buf,
                       ulong               sz,
                       vseq_ledger_rec_t * out );

/* vseq_ledger_read reads record idx.  out is valid until the next
   read.  Returns 0 on success. */

int
vseq_ledger_read( vseq_ledger_t *     ledger,
                  ulong               idx,
                  vseq_ledger_rec_t * out );

/* vseq_ledger_read_span copies records starting at index first, as
   they are on disk, into out.  It takes at least cnt_min records or
   sz_min bytes, then continues to the next record with its own certs,
   so the span normally ends with a record a client can verify.  It
   stays within one segment and never exceeds out_max: if no record with
   certs fits, it returns the records that do, and the reader must fetch
   on from the last one before trusting any of them (a segment always
   ends with certs, so a later span will).  Returns the byte size and
   sets *out_cnt (0 only if first is past the end or the first record
   alone exceeds out_max). */

ulong
vseq_ledger_read_span( vseq_ledger_t * ledger,
                       ulong           first,
                       ulong           cnt_min,
                       ulong           sz_min,
                       uchar *         out,
                       ulong           out_max,
                       ulong *         out_cnt );

/* vseq_ledger_prune removes sealed segments whose records are all
   below slot, oldest first, keeping the active segment.  Returns the
   number removed. */

ulong
vseq_ledger_prune( vseq_ledger_t * ledger,
                   ulong           slot );

vseq_ledger_stats_t
vseq_ledger_stats( vseq_ledger_t const * ledger );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_ledger_h */
