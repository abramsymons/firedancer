#ifndef HEADER_fd_src_app_vseq_vseq_history_h
#define HEADER_fd_src_app_vseq_vseq_history_h

/* vseq_history is a node's vote history file: everything it signed
   that a restart must remember (see vseq_node_cfg_t, restart safety).

     VOTE   a vote it sent (ag_vote_ser bytes)
     BLOCK  the block a notar vote was for (vseq_block wire bytes)
     FLOOR  the highest slot it built a block for

   Each record is written and fdatasync'ed before the vote or block is
   sent.  Record format (little endian):

     uint  body_sz
     ulong check      fd_hash of the body, to drop a torn tail
     uchar type       VOTE, BLOCK or FLOOR
     ulong slot
     uchar data[ body_sz-9 ]

   Records at or below the finalized root are not needed again; the
   file is compacted to the ones above it on open and on request. */

#include "../../util/fd_util.h"

typedef struct vseq_history vseq_history_t;

FD_PROTOTYPES_BEGIN

/* vseq_history_open opens path, creating it if missing, drops a torn
   tail, and compacts it to records above root (see compact).  data_max bounds a
   record's data.  *existed is set to whether the file had records. */

vseq_history_t *
vseq_history_open( char const * path,
                   ulong        root,
                   ulong        data_max,
                   int *        existed );

void
vseq_history_close( vseq_history_t * h );

/* What was in the file above root at the last compaction, framed as
   (uint sz, bytes), for vseq_node_cfg_t prior_votes and prior_blocks. */

uchar const * vseq_history_prior_votes ( vseq_history_t const * h, ulong * sz );
uchar const * vseq_history_prior_blocks( vseq_history_t const * h, ulong * sz );
ulong         vseq_history_block_floor ( vseq_history_t const * h );
ulong         vseq_history_size        ( vseq_history_t const * h ); /* bytes on disk */

/* Durable on return. */

void
vseq_history_add_vote( vseq_history_t * h,
                       ulong            slot,
                       uchar const *    vote,
                       ulong            vote_sz,
                       uchar const *    block,    /* NULL unless a notar vote */
                       ulong            block_sz );

void
vseq_history_add_block_floor( vseq_history_t * h,
                              ulong            slot );

/* vseq_history_compact rewrites the file with only the records above
   root and the block floor, atomically, and makes those records the
   prior votes and blocks. */

void
vseq_history_compact( vseq_history_t * h,
                      ulong            root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_history_h */
