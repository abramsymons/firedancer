#include "vseq_block.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/ed25519/fd_ed25519.h"

static char const hash_domain[] = "vseq-block-v1";

void
vseq_block_hash( ulong                 slot,
                 ag_block_id_t const * parent,
                 uchar const *         payload,
                 ulong                 payload_sz,
                 ag_block_hash_t       out ) {
  uchar hdr[ 8UL+8UL+32UL ];
  FD_STORE( ulong, hdr,     slot         );
  FD_STORE( ulong, hdr+8UL, parent->slot );
  memcpy( hdr+16UL, parent->hash, sizeof(ag_block_hash_t) );

  fd_sha256_t sha[1];
  fd_sha256_join( fd_sha256_new( sha ) );
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, hash_domain, sizeof(hash_domain)-1UL );
  fd_sha256_append( sha, hdr,         sizeof(hdr)             );
  fd_sha256_append( sha, payload,     payload_sz              );
  fd_sha256_fini  ( sha, out );
}

ulong
vseq_block_build( uchar *               buf,
                  ulong                 slot,
                  ag_block_id_t const * parent,
                  uchar const *         payload,
                  ulong                 payload_sz,
                  uchar const           id_pub[ 32 ],
                  uchar const           id_sec[ 32 ],
                  fd_sha512_t *         sha,
                  ag_block_hash_t       out_hash ) {
  FD_TEST( payload_sz<=UINT_MAX );
  vseq_block_hash( slot, parent, payload, payload_sz, out_hash );

  FD_STORE( ulong, buf,      slot         );
  FD_STORE( ulong, buf+ 8UL, parent->slot );
  memcpy( buf+16UL, parent->hash, sizeof(ag_block_hash_t) );
  fd_ed25519_sign( buf+48UL, out_hash, sizeof(ag_block_hash_t), id_pub, id_sec, sha );
  FD_STORE( uint, buf+112UL, (uint)payload_sz );
  if( FD_LIKELY( payload_sz ) ) memcpy( buf+VSEQ_BLOCK_HDR_SZ, payload, payload_sz );
  return VSEQ_BLOCK_HDR_SZ+payload_sz;
}

int
vseq_block_parse( vseq_block_t * out,
                  uchar const *  buf,
                  ulong          sz ) {
  if( FD_UNLIKELY( sz<VSEQ_BLOCK_HDR_SZ ) ) return VSEQ_BLOCK_ERR_SZ;
  out->slot        = FD_LOAD( ulong, buf      );
  out->parent.slot = FD_LOAD( ulong, buf+ 8UL );
  memcpy( out->parent.hash, buf+16UL, sizeof(ag_block_hash_t) );
  memcpy( out->sig,         buf+48UL, 64UL                    );
  out->payload_sz  = FD_LOAD( uint,  buf+112UL );
  out->payload     = buf+VSEQ_BLOCK_HDR_SZ;
  if( FD_UNLIKELY( sz!=VSEQ_BLOCK_HDR_SZ+out->payload_sz ) ) return VSEQ_BLOCK_ERR_SZ;
  if( FD_UNLIKELY( out->parent.slot>=out->slot            ) ) return VSEQ_BLOCK_ERR_INVAL;
  return VSEQ_BLOCK_SUCCESS;
}

int
vseq_block_verify( vseq_block_t const * block,
                   uchar const          leader_pub[ 32 ],
                   fd_sha512_t *        sha,
                   ag_block_hash_t      out_hash ) {
  vseq_block_hash( block->slot, &block->parent, block->payload, block->payload_sz, out_hash );
  if( FD_UNLIKELY( FD_ED25519_SUCCESS!=fd_ed25519_verify( out_hash, sizeof(ag_block_hash_t), block->sig, leader_pub, sha ) ) ) return VSEQ_BLOCK_ERR_SIG;
  return VSEQ_BLOCK_SUCCESS;
}
