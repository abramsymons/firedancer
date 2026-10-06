#include "vseq_proof.h"
#include "../../choreo/votor/ag_cert_serde.h"

int
vseq_proof_verify( ag_epoch_info_t const * epoch,
                   ushort                  network_id,
                   ulong                   slot,
                   uchar const *           hash,
                   uchar const *           proof,
                   ulong                   proof_sz,
                   ag_cert_t *             cert ) {
  int   fast = 0, final = 0, notar = 0;
  ulong off  = 0UL;
  while( off<proof_sz ) {
    if( FD_UNLIKELY( off+sizeof(uint)>proof_sz ) ) return VSEQ_PROOF_ERR_FORMAT;
    ulong sz = FD_LOAD( uint, proof+off );
    off += sizeof(uint);
    if( FD_UNLIKELY( off+sz>proof_sz ) ) return VSEQ_PROOF_ERR_FORMAT;

    ulong bit_cnt;
    if( FD_UNLIKELY( ag_cert_de( cert, &bit_cnt, proof+off, sz ) ) ) return VSEQ_PROOF_ERR_FORMAT;
    off += sz;
    if( FD_UNLIKELY( bit_cnt>epoch->validator_cnt               ) ) return VSEQ_PROOF_ERR_FORMAT;
    if( FD_UNLIKELY( ag_cert_shred_version( cert )!=network_id ) ) return VSEQ_PROOF_ERR_MISMATCH;
    if( FD_UNLIKELY( ag_cert_slot( cert )!=slot                 ) ) return VSEQ_PROOF_ERR_MISMATCH;

    switch( cert->kind ) {
    case AG_CERT_KIND_FAST_FINAL:
    case AG_CERT_KIND_NOTAR:
      if( FD_UNLIKELY( memcmp( ag_cert_block_hash( cert ), hash, sizeof(ag_block_hash_t) ) ) ) return VSEQ_PROOF_ERR_MISMATCH;
      break;
    case AG_CERT_KIND_FINAL:
      break;
    default:
      return VSEQ_PROOF_ERR_FORMAT;
    }
    if( FD_UNLIKELY( !ag_cert_verify( cert, epoch ) ) ) return VSEQ_PROOF_ERR_SIG;

    fast  |= cert->kind==AG_CERT_KIND_FAST_FINAL;
    final |= cert->kind==AG_CERT_KIND_FINAL;
    notar |= cert->kind==AG_CERT_KIND_NOTAR;
  }
  return ( fast || ( final && notar ) ) ? VSEQ_PROOF_OK : VSEQ_PROOF_ERR_INCOMPLETE;
}
