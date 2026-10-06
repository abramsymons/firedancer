#ifndef HEADER_fd_src_app_vseq_vseq_proof_h
#define HEADER_fd_src_app_vseq_vseq_proof_h

/* vseq_proof checks finality proofs (see VSEQ_PROOF_MAX in
   vseq_node.h).  Used by nodes catching up from peers and by the client
   library, so both accept exactly the same proofs. */

#include "../../choreo/votor/ag_cert.h"

#define VSEQ_PROOF_OK             (0)
#define VSEQ_PROOF_ERR_FORMAT     (1) /* malformed cert */
#define VSEQ_PROOF_ERR_MISMATCH   (2) /* cert for another slot, block or network */
#define VSEQ_PROOF_ERR_SIG        (3) /* bad signature or not enough stake */
#define VSEQ_PROOF_ERR_INCOMPLETE (4) /* certs valid but do not finalize the block */

FD_PROTOTYPES_BEGIN

/* vseq_proof_verify checks that proof finalizes block (slot, hash): a
   FastFinal cert on (slot, hash), or a Final cert on slot plus a Notar
   cert on (slot, hash), each signed by enough stake of epoch.  scratch
   is clobbered (an ag_cert_t is too big for some stacks). */

int
vseq_proof_verify( ag_epoch_info_t const * epoch,
                   ushort                  network_id,
                   ulong                   slot,
                   uchar const *           hash,
                   uchar const *           proof,
                   ulong                   proof_sz,
                   ag_cert_t *             scratch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_proof_h */
