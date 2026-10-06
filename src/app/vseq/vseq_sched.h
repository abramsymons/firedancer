#ifndef HEADER_fd_src_app_vseq_vseq_sched_h
#define HEADER_fd_src_app_vseq_vseq_sched_h

/* vseq_sched is the validator schedule: which validators make up the
   set in each epoch.  It comes from the network config, where every
   validator entry may carry from_epoch and until_epoch:

     the set of epoch E = entries with from_epoch <= E < until_epoch

   The config is part of the release: nodes and clients must all use
   the same one.  To change the set, publish a config that adds or ends
   entries at a future epoch before that epoch starts.

   An epoch is epoch_slots slots.  The schedule keeps one ranked set
   per change (vseq_set_t), so slot s belongs to the last set starting
   at or before s.  Within a set, validators are ranked the way
   Firedancer does (stake descending, then BLS key), and the leader of
   a window is rank window%cnt (ag_epoch_info_leader).

   Validators also get a peer index that does not change over time:
   every distinct identity in the config, sorted by key.  Nodes address
   each other by peer index (vseq_mesh, vseq_node), and a rank only
   means something within one set.

   Each set has a hash, which nodes compare when they connect, so nodes
   with different configs for an epoch never work together. */

#include "../../choreo/votor/ag_epoch_info.h"

#define VSEQ_SCHED_SET_MAX (256UL)

struct vseq_validator {
  ulong        stake;
  ag_id_key_t  id_key;  /* ed25519 public key, signs blocks */
  ag_bls_key_t bls_key; /* compressed BLS12-381 G1 key, signs votes */
};
typedef struct vseq_validator vseq_validator_t;

/* One validator entry of the config */

struct vseq_member {
  vseq_validator_t v;
  ulong            from_epoch;
  ulong            until_epoch; /* ULONG_MAX: no end */
};
typedef struct vseq_member vseq_member_t;

struct vseq_set {
  ulong             first_epoch;
  ulong             start_slot;
  ag_epoch_info_t * epoch;          /* ranked validators */
  ulong *           peer_of_rank;   /* [ epoch->validator_cnt ] */
  ulong *           member_of_rank; /* [ epoch->validator_cnt ] config entry index */
  ulong *           rank_of_peer;   /* [ peer_cnt ], ULONG_MAX if not in the set */
  uchar             hash[ 32 ];
};
typedef struct vseq_set vseq_set_t;

struct vseq_sched {
  ulong         epoch_slots;
  ulong         set_cnt;
  vseq_set_t    sets[ VSEQ_SCHED_SET_MAX ];
  ulong         peer_cnt;
  ag_id_key_t * peer_id;     /* [ peer_cnt ], sorted */
  ulong *       member_peer; /* [ member_cnt ] */
};
typedef struct vseq_sched vseq_sched_t;

FD_PROTOTYPES_BEGIN

/* vseq_sched_new builds the schedule of cnt config entries.  It fails
   (logs why, returns NULL) unless epoch_slots is a positive multiple of
   AG_SLOTS_PER_WINDOW, every epoch from 0 on has validators, and in
   every set each validator has stake, a valid BLS key and keys no
   other validator of the set uses. */

vseq_sched_t *
vseq_sched_new( vseq_member_t const * members,
                ulong                 cnt,
                ulong                 epoch_slots,
                ushort                network_id );

void
vseq_sched_delete( vseq_sched_t * sched );

/* vseq_sched_set returns the set slot belongs to. */

vseq_set_t const *
vseq_sched_set( vseq_sched_t const * sched,
                ulong                slot );

/* vseq_sched_next returns the set after set, or NULL if it is the last. */

static inline vseq_set_t const *
vseq_sched_next( vseq_sched_t const * sched,
                 vseq_set_t const *   set ) {
  return set+1UL<sched->sets+sched->set_cnt ? set+1UL : NULL;
}

/* vseq_sched_leader returns the peer index of slot's leader. */

static inline ulong
vseq_sched_leader( vseq_sched_t const * sched,
                   ulong                slot ) {
  vseq_set_t const * set = vseq_sched_set( sched, slot );
  return set->peer_of_rank[ ag_epoch_info_leader( set->epoch, slot )->id ];
}

/* vseq_sched_peer returns the peer index of identity id_key, or
   ULONG_MAX if it is not in the config. */

ulong
vseq_sched_peer( vseq_sched_t const * sched,
                 uchar const          id_key[ 32 ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_sched_h */
