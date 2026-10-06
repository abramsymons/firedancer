#ifndef HEADER_fd_src_app_vseq_vseq_block_h
#define HEADER_fd_src_app_vseq_vseq_block_h

/* A vseq block is an opaque payload that consensus orders.  Nodes do
   not execute it.  The leader of the block's slot signs the block hash
   with its ed25519 identity key.

   Wire format (little endian):

     ulong slot
     ulong parent_slot
     uchar parent_hash[ 32 ]
     uchar sig[ 64 ]          leader's ed25519 signature over hash
     uint  payload_sz
     uchar payload[ payload_sz ]

   hash = SHA-256( "vseq-block-v1" | slot | parent_slot | parent_hash | payload )

   hash is the block hash votor votes on, so a cert over (slot, hash)
   also commits to the payload and, through parent_hash, to every
   ancestor. */

#include "../../choreo/votor/ag_votor_base.h"
#include "../../ballet/sha512/fd_sha512.h"

#define VSEQ_BLOCK_HDR_SZ (8UL+8UL+32UL+64UL+4UL)

#define VSEQ_BLOCK_SUCCESS   ( 0)
#define VSEQ_BLOCK_ERR_SZ    (-1) /* truncated or trailing bytes */
#define VSEQ_BLOCK_ERR_INVAL (-2) /* parent_slot>=slot */
#define VSEQ_BLOCK_ERR_SIG   (-3) /* bad leader signature */

struct vseq_block {
  ulong         slot;
  ag_block_id_t parent;
  uchar         sig[ 64 ];
  uchar const * payload;    /* points into the parsed buffer */
  ulong         payload_sz;
};
typedef struct vseq_block vseq_block_t;

FD_PROTOTYPES_BEGIN

void
vseq_block_hash( ulong                 slot,
                 ag_block_id_t const * parent,
                 uchar const *         payload,
                 ulong                 payload_sz,
                 ag_block_hash_t       out );

/* vseq_block_build writes a signed block into buf, which must hold
   VSEQ_BLOCK_HDR_SZ+payload_sz bytes, and its hash into out_hash.
   Returns the number of bytes written. */

ulong
vseq_block_build( uchar *               buf,
                  ulong                 slot,
                  ag_block_id_t const * parent,
                  uchar const *         payload,
                  ulong                 payload_sz,
                  uchar const           id_pub[ 32 ],
                  uchar const           id_sec[ 32 ],
                  fd_sha512_t *         sha,
                  ag_block_hash_t       out_hash );

/* vseq_block_parse parses buf without checking the signature.  out
   borrows buf. */

int
vseq_block_parse( vseq_block_t * out,
                  uchar const *  buf,
                  ulong          sz );

/* vseq_block_verify computes the hash of a parsed block into out_hash
   and checks the signature against leader_pub. */

int
vseq_block_verify( vseq_block_t const * block,
                   uchar const          leader_pub[ 32 ],
                   fd_sha512_t *        sha,
                   ag_block_hash_t      out_hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_block_h */
