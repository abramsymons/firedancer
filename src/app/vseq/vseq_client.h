#ifndef HEADER_fd_src_app_vseq_vseq_client_h
#define HEADER_fd_src_app_vseq_vseq_client_h

/* vseq_client is the C core of the client SDKs, built as
   libvseq_client.so.  It uses the same code as the nodes, so a client
   computes the same leader schedule and accepts exactly the certs a
   node would.

   The API is plain C types for easy FFI (Python ctypes etc).

   validators is cnt records of VSEQ_CLIENT_VALIDATOR_SZ bytes, the
   [[validator]] entries in cluster config order (vseq_sched.h):

     ulong stake         little endian
     uchar identity[32]  ed25519 public key
     uchar bls[48]       compressed BLS12-381 public key
     ulong from_epoch
     ulong until_epoch   ULONG_MAX for no end

   Indexes returned by vseq_client_leader refer to this order. */

#include "../../util/fd_util_base.h"

#define VSEQ_CLIENT_VALIDATOR_SZ (8UL+32UL+48UL+8UL+8UL)

/* vseq_client_verify returns a VSEQ_PROOF_{OK,ERR_*} code (vseq_proof.h):
   0 ok, 1 malformed cert, 2 cert for another slot/block/network,
   3 bad signature or not enough stake, 4 certs do not finalize. */

typedef struct vseq_client vseq_client_t;

FD_PROTOTYPES_BEGIN

/* vseq_client_new returns NULL if the entries do not form a valid
   schedule (see vseq_sched_new) or network_id is not in [1,65535]. */

vseq_client_t *
vseq_client_new( uchar const * validators,
                 ulong         cnt,
                 uint          network_id,
                 ulong         epoch_slots );

void
vseq_client_delete( vseq_client_t * client );

/* vseq_client_leader returns the config entry index of slot's leader. */

ulong
vseq_client_leader( vseq_client_t const * client,
                    ulong                 slot );

/* vseq_client_verify checks that certs finalize block (slot, hash),
   signed by the validator set of slot's epoch.
   certs is a sequence of (uint sz little endian, ag_cert_ser bytes).
   Accepted: a FastFinal cert on (slot, hash), or a Final cert on slot
   together with a Notar cert on (slot, hash). */

int
vseq_client_verify( vseq_client_t * client,
                    ulong           slot,
                    uchar const *   hash,
                    uchar const *   certs,
                    ulong           certs_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_client_h */
