#include "vseq_sched.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <stdlib.h>

#define SORT_NAME        sort_rank
#define SORT_KEY_T       vseq_member_t const *
#define SORT_BEFORE(a,b) ( (a)->v.stake> (b)->v.stake ||                                    \
                         ( (a)->v.stake==(b)->v.stake &&                                    \
                           memcmp( (a)->v.bls_key, (b)->v.bls_key, sizeof(ag_bls_key_t) )<0 ) )
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME        sort_ulong
#define SORT_KEY_T       ulong
#include "../../util/tmpl/fd_sort.c"

static int
cmp_key( void const * a,
         void const * b ) {
  return memcmp( a, b, sizeof(ag_id_key_t) );
}

ulong
vseq_sched_peer( vseq_sched_t const * sched,
                 uchar const          id_key[ 32 ] ) {
  ag_id_key_t const * k = bsearch( id_key, sched->peer_id, sched->peer_cnt, sizeof(ag_id_key_t), cmp_key );
  return k ? (ulong)( (uchar const *)k-(uchar const *)sched->peer_id )/sizeof(ag_id_key_t) : ULONG_MAX;
}

vseq_set_t const *
vseq_sched_set( vseq_sched_t const * sched,
                ulong                slot ) {
  ulong lo = 0UL, hi = sched->set_cnt; /* sets[0] starts at slot 0 */
  while( hi-lo>1UL ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( sched->sets[ mid ].start_slot<=slot ) lo = mid;
    else                                      hi = mid;
  }
  return &sched->sets[ lo ];
}

/* set_build ranks the members active in epoch e into set.  Returns 0,
   or -1 if they cannot form a set (logs why). */

static int
set_build( vseq_sched_t *        sched,
           vseq_set_t *          set,
           vseq_member_t const * members,
           ulong                 cnt,
           ulong                 e,
           ushort                network_id ) {
  vseq_member_t const * order[ AG_VAT_MAX ];
  ulong                 n = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    vseq_member_t const * m = &members[i];
    if( m->from_epoch>e || e>=m->until_epoch ) continue;
    if( FD_UNLIKELY( n==AG_VAT_MAX ) ) { FD_LOG_WARNING(( "epoch %lu has more than %lu validators", e, AG_VAT_MAX )); return -1; }
    order[ n++ ] = m;
  }
  if( FD_UNLIKELY( !n ) ) { FD_LOG_WARNING(( "epoch %lu has no validators", e )); return -1; }

  ag_epoch_info_t * epoch = aligned_alloc( 64UL, fd_ulong_align_up( sizeof(ag_epoch_info_t), 64UL ) );
  FD_TEST( epoch );
  set->epoch = epoch;
  for( ulong i=0UL; i<n; i++ ) {
    vseq_validator_t const * v = &order[i]->v;
    ulong                    k = (ulong)( order[i]-members );
    if( FD_UNLIKELY( !v->stake ) ) { FD_LOG_WARNING(( "validator entry %lu has no stake", k )); return -1; }
    if( FD_UNLIKELY( fd_bls_pub_de( &epoch->pubkeys[0], v->bls_key, sizeof(ag_bls_key_t) ) ) ) { FD_LOG_WARNING(( "validator entry %lu has a bad BLS key", k )); return -1; }
    for( ulong j=0UL; j<i; j++ ) {
      if( FD_UNLIKELY( !memcmp( v->id_key,  order[j]->v.id_key,  sizeof(ag_id_key_t)  ) ||
                       !memcmp( v->bls_key, order[j]->v.bls_key, sizeof(ag_bls_key_t) ) ) ) {
        FD_LOG_WARNING(( "validator entries %lu and %lu share a key in epoch %lu", (ulong)( order[j]-members ), k, e ));
        return -1;
      }
    }
  }
  sort_rank_inplace( order, n );

  set->first_epoch    = e;
  set->start_slot     = e*sched->epoch_slots;
  set->peer_of_rank   = malloc( n*sizeof(ulong) );
  set->member_of_rank = malloc( n*sizeof(ulong) );
  set->rank_of_peer   = malloc( sched->peer_cnt*sizeof(ulong) );
  uchar * h           = malloc( 8UL + n*(8UL+32UL+48UL) );
  FD_TEST( set->peer_of_rank && set->member_of_rank && set->rank_of_peer && h );
  for( ulong p=0UL; p<sched->peer_cnt; p++ ) set->rank_of_peer[p] = ULONG_MAX;

  /* The hash covers what consensus uses: network, ranks, stakes, keys */
  FD_STORE( ulong, h, (ulong)network_id );
  epoch->validator_cnt = n;
  epoch->total_stake   = 0UL;
  for( ulong r=0UL; r<n; r++ ) {
    vseq_validator_t const * v    = &order[r]->v;
    ag_validator_info_t *    info = &epoch->validators[r];
    *info = (ag_validator_info_t){ .id = r, .stake = v->stake };
    memcpy( info->id_key,  v->id_key,  sizeof(ag_id_key_t)  );
    memcpy( info->bls_key, v->bls_key, sizeof(ag_bls_key_t) );
    FD_TEST( !fd_bls_pub_de( &epoch->pubkeys[r], v->bls_key, sizeof(ag_bls_key_t) ) );
    epoch->total_stake += v->stake;

    ulong m = (ulong)( order[r]-members );
    set->member_of_rank[r] = m;
    set->peer_of_rank  [r] = sched->member_peer[m];
    set->rank_of_peer[ sched->member_peer[m] ] = r;
    uchar * p = h + 8UL + r*(8UL+32UL+48UL);
    FD_STORE( ulong, p, v->stake );
    memcpy( p+ 8UL, v->id_key,  32UL );
    memcpy( p+40UL, v->bls_key, 48UL );
  }
  fd_sha256_hash( h, 8UL + n*(8UL+32UL+48UL), set->hash );
  free( h );
  return 0;
}

static void
set_free( vseq_set_t * set ) {
  free( set->epoch );
  free( set->peer_of_rank );
  free( set->member_of_rank );
  free( set->rank_of_peer );
  memset( set, 0, sizeof(vseq_set_t) );
}

vseq_sched_t *
vseq_sched_new( vseq_member_t const * members,
                ulong                 cnt,
                ulong                 epoch_slots,
                ushort                network_id ) {
  if( FD_UNLIKELY( !epoch_slots || epoch_slots%AG_SLOTS_PER_WINDOW ) ) { FD_LOG_WARNING(( "epoch_slots must be a positive multiple of %lu", AG_SLOTS_PER_WINDOW )); return NULL; }
  if( FD_UNLIKELY( !cnt ) ) { FD_LOG_WARNING(( "no validators" )); return NULL; }

  vseq_sched_t * sched = calloc( 1UL, sizeof(vseq_sched_t) );
  FD_TEST( sched );
  sched->epoch_slots = epoch_slots;

  /* Peers: every distinct identity, sorted */
  sched->peer_id     = malloc( cnt*sizeof(ag_id_key_t) );
  sched->member_peer = malloc( cnt*sizeof(ulong) );
  ulong * epochs     = malloc( 2UL*cnt*sizeof(ulong)+sizeof(ulong) );
  FD_TEST( sched->peer_id && sched->member_peer && epochs );
  for( ulong i=0UL; i<cnt; i++ ) memcpy( sched->peer_id[i], members[i].v.id_key, sizeof(ag_id_key_t) );
  qsort( sched->peer_id, cnt, sizeof(ag_id_key_t), cmp_key );
  for( ulong i=0UL; i<cnt; i++ ) {
    if( i && !memcmp( sched->peer_id[i], sched->peer_id[ sched->peer_cnt-1UL ], sizeof(ag_id_key_t) ) ) continue;
    memmove( sched->peer_id[ sched->peer_cnt++ ], sched->peer_id[i], sizeof(ag_id_key_t) );
  }
  for( ulong i=0UL; i<cnt; i++ ) sched->member_peer[i] = vseq_sched_peer( sched, members[i].v.id_key );

  /* A set starts at epoch 0 and wherever an entry starts or ends */
  ulong epoch_cnt = 0UL;
  epochs[ epoch_cnt++ ] = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    vseq_member_t const * m = &members[i];
    if( FD_UNLIKELY( m->from_epoch>=m->until_epoch ) ) { FD_LOG_WARNING(( "validator entry %lu: from_epoch must be below until_epoch", i )); goto fail; }
    if( FD_UNLIKELY( m->from_epoch>ULONG_MAX/epoch_slots || ( m->until_epoch!=ULONG_MAX && m->until_epoch>ULONG_MAX/epoch_slots ) ) ) { FD_LOG_WARNING(( "validator entry %lu: epoch too large", i )); goto fail; }
    epochs[ epoch_cnt++ ] = m->from_epoch;
    if( m->until_epoch!=ULONG_MAX ) epochs[ epoch_cnt++ ] = m->until_epoch;
  }
  sort_ulong_inplace( epochs, epoch_cnt );

  for( ulong i=0UL; i<epoch_cnt; i++ ) {
    if( i && epochs[i]==epochs[i-1UL] ) continue;
    if( FD_UNLIKELY( sched->set_cnt==VSEQ_SCHED_SET_MAX ) ) { FD_LOG_WARNING(( "more than %lu validator set changes", VSEQ_SCHED_SET_MAX )); goto fail; }
    vseq_set_t * set = &sched->sets[ sched->set_cnt ];
    if( FD_UNLIKELY( set_build( sched, set, members, cnt, epochs[i], network_id ) ) ) { set_free( set ); goto fail; }
    if( sched->set_cnt && !memcmp( set->hash, sched->sets[ sched->set_cnt-1UL ].hash, 32UL ) ) { set_free( set ); continue; } /* no change */
    sched->set_cnt++;
  }
  free( epochs );
  return sched;

fail:
  free( epochs );
  vseq_sched_delete( sched );
  return NULL;
}

void
vseq_sched_delete( vseq_sched_t * sched ) {
  if( FD_UNLIKELY( !sched ) ) return;
  for( ulong i=0UL; i<sched->set_cnt; i++ ) set_free( &sched->sets[i] );
  free( sched->peer_id );
  free( sched->member_peer );
  free( sched );
}
