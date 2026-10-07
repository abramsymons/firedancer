#define _GNU_SOURCE
#include "vseq_ledger.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define REC_HDR_SZ        (8UL+8UL+32UL+32UL+64UL+4UL) /* through payload_sz */
#define REC_FIXED         (REC_HDR_SZ+4UL)            /* plus proof_sz */
#define SEG_HDR_SZ        (64UL)                      /* magic, seq, first_idx, base_slot, base_hash */
#define IDX_HDR_SZ        (72UL)                      /* magic, seq, cnt, size, last_slot, last_hash */
#define IDX_ENT_SZ        (16UL)                      /* slot, offset | PROVED */
#define SEG_BYTES_DEFAULT (256UL<<20)
#define PROVED            (1UL<<63)
#define CHECK_SEED        (0x76737169647863UL)

static char const seg_magic[8] = { 'V','S','Q','S','E','G','0','1' };
static char const idx_magic[8] = { 'V','S','Q','I','D','X','0','1' };

struct seg {
  ulong         seq;
  int           fd;
  ulong         first_idx;
  ulong         cnt;
  ulong         cap;
  ulong *       slot;
  ulong *       off;       /* file offset, | PROVED if the record has certs */
  ulong         size;      /* file size */
  ag_block_id_t base;      /* parent of the first record */
  ag_block_id_t last;      /* last record, or base if empty */
  int           sealed;
};
typedef struct seg seg_t;

struct vseq_ledger {
  char    dir[ 4096 ];
  seg_t * segs;            /* oldest first; the last is active unless sealed */
  ulong   seg_cnt;
  ulong   seg_cap;
  ulong   seg_bytes;
  uchar * buf;
  ulong   buf_max;
  ulong   sealed_cnt;
  ulong   pruned_cnt;
  int     follow;          /* read-only view of a ledger another process writes */
};

/* Helpers ************************************************************/

static void
seg_path( vseq_ledger_t const * l,
          ulong                 seq,
          char const *          ext,
          char                  out[ static 4200 ] ) {
  fd_cstr_printf( out, 4200UL, NULL, "%s/%010lu.%s", l->dir, seq, ext );
}

static void
sync_dir( vseq_ledger_t const * l ) {
  int fd = open( l->dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  if( FD_UNLIKELY( fd<0 || fsync( fd ) ) ) FD_LOG_ERR(( "fsync(%s) failed (%i-%s)", l->dir, errno, fd_io_strerror( errno ) ));
  close( fd );
}

static void
write_at( int           fd,
          uchar const * buf,
          ulong         sz,
          ulong         off,
          char const *  what ) {
  for( ulong done=0UL; done<sz; ) {
    long n = pwrite( fd, buf+done, sz-done, (long)(off+done) );
    if( FD_UNLIKELY( n<0 ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "write to %s failed (%i-%s)", what, errno, fd_io_strerror( errno ) ));
    }
    done += (ulong)n;
  }
}

static void
seg_push( seg_t * s,
          ulong   slot,
          ulong   off ) {
  if( FD_UNLIKELY( s->cnt==s->cap ) ) {
    s->cap  = fd_ulong_max( 2UL*s->cap, 1024UL );
    s->slot = realloc( s->slot, s->cap*sizeof(ulong) );
    s->off  = realloc( s->off,  s->cap*sizeof(ulong) );
    FD_TEST( s->slot && s->off );
  }
  s->slot[ s->cnt ] = slot;
  s->off [ s->cnt ] = off;
  s->cnt++;
}

static void
seg_free( seg_t * s ) {
  if( s->fd>=0 ) close( s->fd );
  free( s->slot );
  free( s->off  );
}

static ulong
rec_off( seg_t const * s,
         ulong         i ) {
  return s->off[i] & ~PROVED;
}

static ulong
rec_end( seg_t const * s,
         ulong         i ) {
  return i+1UL<s->cnt ? rec_off( s, i+1UL ) : s->size;
}

int
vseq_ledger_rec_parse( uchar const *       p,
                       ulong               sz,
                       vseq_ledger_rec_t * out ) {
  if( FD_UNLIKELY( sz<sizeof(uint)+REC_FIXED || FD_LOAD( uint, p )!=sz-sizeof(uint) ) ) return -1;
  out->block.slot        = FD_LOAD( ulong, p+ 4UL );
  out->block.parent.slot = FD_LOAD( ulong, p+12UL );
  memcpy( out->block.parent.hash, p+ 20UL, 32UL );
  memcpy( out->hash,              p+ 52UL, 32UL );
  memcpy( out->block.sig,         p+ 84UL, 64UL );
  out->block.payload_sz  = FD_LOAD( uint, p+148UL );
  out->block.payload     = p+152UL;
  if( FD_UNLIKELY( 156UL+out->block.payload_sz>sz ) ) return -1;
  out->proof_sz          = FD_LOAD( uint, p+152UL+out->block.payload_sz );
  out->proof             = p+156UL+out->block.payload_sz;
  if( FD_UNLIKELY( 156UL+out->block.payload_sz+out->proof_sz!=sz ) ) return -1;
  return 0;
}

/* Segment header ******************************************************/

static void
hdr_write( vseq_ledger_t const * l,
           seg_t const *         s ) {
  uchar h[ SEG_HDR_SZ ] = {0};
  memcpy( h, seg_magic, 8UL );
  FD_STORE( ulong, h+ 8UL, s->seq       );
  FD_STORE( ulong, h+16UL, s->first_idx );
  FD_STORE( ulong, h+24UL, s->base.slot );
  memcpy( h+32UL, s->base.hash, 32UL );
  write_at( s->fd, h, SEG_HDR_SZ, 0UL, l->dir );
  if( FD_UNLIKELY( fsync( s->fd ) ) ) FD_LOG_ERR(( "fsync failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static int
hdr_read( seg_t * s ) {
  uchar h[ SEG_HDR_SZ ];
  if( s->size<SEG_HDR_SZ || pread( s->fd, h, SEG_HDR_SZ, 0L )!=(long)SEG_HDR_SZ ) return -1;
  if( memcmp( h, seg_magic, 8UL ) || FD_LOAD( ulong, h+8UL )!=s->seq ) return -1;
  s->first_idx = FD_LOAD( ulong, h+16UL );
  s->base      = ag_block_id( FD_LOAD( ulong, h+24UL ), h+32UL );
  s->last      = s->base;
  return 0;
}

/* seg_new creates segment seq, empty, after base. */

static seg_t *
seg_new( vseq_ledger_t *       l,
         ulong                 seq,
         ulong                 first_idx,
         ag_block_id_t const * base ) {
  if( FD_UNLIKELY( l->seg_cnt==l->seg_cap ) ) {
    l->seg_cap = fd_ulong_max( 2UL*l->seg_cap, 16UL );
    l->segs    = realloc( l->segs, l->seg_cap*sizeof(seg_t) );
    FD_TEST( l->segs );
  }
  seg_t * s = &l->segs[ l->seg_cnt++ ];
  memset( s, 0, sizeof(seg_t) );
  char path[ 4200 ];
  seg_path( l, seq, "seg", path );
  s->fd = open( path, O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( s->fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  s->seq       = seq;
  s->first_idx = first_idx;
  s->base      = *base;
  s->last      = *base;
  s->size      = SEG_HDR_SZ;
  hdr_write( l, s );
  sync_dir( l );
  return s;
}

/* seg_read_recs reads and checks the records from s->size up to file
   offset end: each one's size, its hash against its contents and its
   chain from s->last.  It adds them to s's index and moves s->size
   past them.  Returns NULL if it got to end, else why it stopped. */

static char const *
seg_read_recs( vseq_ledger_t * l,
               seg_t *         s,
               ulong           end ) {
  while( s->size<end ) {
    ulong off = s->size;
    uint  rec_sz;
    if( off+sizeof(uint)>end || pread( s->fd, &rec_sz, sizeof(uint), (long)off )!=(long)sizeof(uint) ) return "torn record";
    ulong sz = sizeof(uint)+(ulong)rec_sz;
    if( rec_sz<REC_FIXED || sz>l->buf_max ) return "bad record size";
    if( off+sz>end                        ) return "torn record";
    if( pread( s->fd, l->buf, sz, (long)off )!=(long)sz ) return "read failed";

    vseq_ledger_rec_t rec;
    ag_block_hash_t   hash;
    if( vseq_ledger_rec_parse( l->buf, sz, &rec ) ) return "bad record";
    vseq_block_hash( rec.block.slot, &rec.block.parent, rec.block.payload, rec.block.payload_sz, hash );
    if( memcmp( hash, rec.hash, sizeof(ag_block_hash_t) ) ) return "hash does not match contents";
    if( !ag_block_id_eq( &rec.block.parent, &s->last )    ) return "does not extend the previous record";

    seg_push( s, rec.block.slot, off | ( rec.proof_sz ? PROVED : 0UL ) );
    s->last  = ag_block_id( rec.block.slot, rec.hash );
    s->size += sz;
  }
  return NULL;
}

/* seg_scan rebuilds s's index from its whole file.  A bad tail is cut
   off if truncate, else it fails the scan. */

static int
seg_scan( vseq_ledger_t * l,
          seg_t *         s,
          int             truncate ) {
  ulong file_sz = s->size;
  s->cnt  = 0UL;
  s->last = s->base;
  s->size = SEG_HDR_SZ;
  char const * bad = seg_read_recs( l, s, file_sz );
  ulong        off = s->size;
  if( FD_LIKELY( !bad ) ) return 0;

  char path[ 4200 ];
  seg_path( l, s->seq, "seg", path );
  if( !truncate ) {
    FD_LOG_WARNING(( "%s: %s at offset %lu", path, bad, off ));
    return -1;
  }
  FD_LOG_WARNING(( "%s: %s at offset %lu after %lu good records; cutting off %lu bytes", path, bad, off, s->cnt, file_sz-off ));
  if( FD_UNLIKELY( ftruncate( s->fd, (long)off ) ) ) FD_LOG_ERR(( "ftruncate(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return 0;
}

/* Segment index *******************************************************/

static void
idx_write( vseq_ledger_t * l,
           seg_t const *   s ) {
  ulong   sz  = IDX_HDR_SZ + s->cnt*IDX_ENT_SZ + sizeof(ulong);
  uchar * buf = malloc( sz );
  FD_TEST( buf );
  memcpy( buf, idx_magic, 8UL );
  FD_STORE( ulong, buf+ 8UL, s->seq       );
  FD_STORE( ulong, buf+16UL, s->cnt       );
  FD_STORE( ulong, buf+24UL, s->size      );
  FD_STORE( ulong, buf+32UL, s->last.slot );
  memcpy( buf+40UL, s->last.hash, 32UL );
  for( ulong i=0UL; i<s->cnt; i++ ) {
    FD_STORE( ulong, buf+IDX_HDR_SZ+i*IDX_ENT_SZ,     s->slot[i] );
    FD_STORE( ulong, buf+IDX_HDR_SZ+i*IDX_ENT_SZ+8UL, s->off [i] );
  }
  FD_STORE( ulong, buf+sz-sizeof(ulong), fd_hash( CHECK_SEED, buf, sz-sizeof(ulong) ) );

  char path[ 4200 ], tmp[ 4200 ];
  seg_path( l, s->seq, "idx",     path );
  seg_path( l, s->seq, "idx.tmp", tmp  );
  int fd = open( tmp, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  write_at( fd, buf, sz, 0UL, tmp );
  if( FD_UNLIKELY( fsync( fd ) ) ) FD_LOG_ERR(( "fsync(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  close( fd );
  if( FD_UNLIKELY( rename( tmp, path ) ) ) FD_LOG_ERR(( "rename(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  sync_dir( l );
  free( buf );
}

static int
idx_load( vseq_ledger_t const * l,
          seg_t *               s ) {
  char path[ 4200 ];
  seg_path( l, s->seq, "idx", path );
  int fd = open( path, O_RDONLY|O_CLOEXEC );
  if( fd<0 ) return -1;
  struct stat st;
  int     ok  = 0;
  uchar * buf = NULL;
  if( !fstat( fd, &st ) && (ulong)st.st_size>=IDX_HDR_SZ+sizeof(ulong) ) {
    ulong sz = (ulong)st.st_size;
    buf = malloc( sz );
    FD_TEST( buf );
    ok = pread( fd, buf, sz, 0L )==(long)sz
      && !memcmp( buf, idx_magic, 8UL )
      && FD_LOAD( ulong, buf+8UL )==s->seq
      && FD_LOAD( ulong, buf+sz-sizeof(ulong) )==fd_hash( CHECK_SEED, buf, sz-sizeof(ulong) )
      && sz==IDX_HDR_SZ+FD_LOAD( ulong, buf+16UL )*IDX_ENT_SZ+sizeof(ulong)
      && FD_LOAD( ulong, buf+24UL )==s->size;
    if( ok ) {
      ulong cnt = FD_LOAD( ulong, buf+16UL );
      s->cnt = 0UL;
      for( ulong i=0UL; i<cnt; i++ ) {
        ulong off = FD_LOAD( ulong, buf+IDX_HDR_SZ+i*IDX_ENT_SZ+8UL );
        if( (off & ~PROVED)<SEG_HDR_SZ || (off & ~PROVED)>=s->size ) { ok = 0; break; }
        seg_push( s, FD_LOAD( ulong, buf+IDX_HDR_SZ+i*IDX_ENT_SZ ), off );
      }
      s->last = cnt ? ag_block_id( FD_LOAD( ulong, buf+32UL ), buf+40UL ) : s->base;
    }
  }
  free( buf );
  close( fd );
  if( !ok ) s->cnt = 0UL;
  return ok ? 0 : -1;
}

/* Open ***************************************************************/

static int
cmp_ulong( void const * a,
           void const * b ) {
  ulong x = *(ulong const *)a, y = *(ulong const *)b;
  return (x>y) - (x<y);
}

/* list_dir collects the sequence numbers of .seg and .idx files and
   removes leftover temporary files. */

static void
list_dir( vseq_ledger_t * l,
          ulong **        segs, ulong * seg_cnt,
          ulong **        idxs, ulong * idx_cnt ) {
  DIR * d = opendir( l->dir );
  if( FD_UNLIKELY( !d ) ) FD_LOG_ERR(( "opendir(%s) failed (%i-%s)", l->dir, errno, fd_io_strerror( errno ) ));
  ulong seg_max = 0UL, idx_max = 0UL;
  *seg_cnt = *idx_cnt = 0UL;
  *segs = *idxs = NULL;
  for( struct dirent * e; (e = readdir( d )); ) {
    char * end;
    ulong  seq = strtoul( e->d_name, &end, 10 );
    if( end!=e->d_name+10 ) continue;
    if( !strcmp( end, ".idx.tmp" ) && !l->follow ) {
      char path[ 4200 ];
      fd_cstr_printf( path, sizeof(path), NULL, "%s/%s", l->dir, e->d_name );
      unlink( path );
      continue;
    }
    ulong ** arr = !strcmp( end, ".seg" ) ? segs : !strcmp( end, ".idx" ) ? idxs : NULL;
    if( !arr ) continue;
    ulong * cnt = arr==segs ? seg_cnt : idx_cnt;
    ulong * max = arr==segs ? &seg_max : &idx_max;
    if( *cnt==*max ) { *max = 2UL**max+16UL; *arr = realloc( *arr, *max*sizeof(ulong) ); FD_TEST( *arr ); }
    (*arr)[ (*cnt)++ ] = seq;
  }
  closedir( d );
  if( *seg_cnt ) qsort( *segs, *seg_cnt, sizeof(ulong), cmp_ulong );
}

static vseq_ledger_t *
ledger_open( char const * dir,
             ulong        payload_max,
             ulong        proof_max,
             ulong        seg_bytes,
             int          follow ) {
  struct stat st;
  if( !stat( dir, &st ) && !S_ISDIR( st.st_mode ) ) {
    FD_LOG_WARNING(( "%s is a file: ledgers are now directories of segments; move the old file away and restart", dir ));
    return NULL;
  }
  if( follow && stat( dir, &st ) ) return NULL; /* not created yet */
  if( FD_UNLIKELY( !follow && mkdir( dir, 0755 ) && errno!=EEXIST ) ) { FD_LOG_WARNING(( "mkdir(%s) failed (%i-%s)", dir, errno, fd_io_strerror( errno ) )); return NULL; }
  if( FD_UNLIKELY( strlen( dir )>=4000UL ) ) { FD_LOG_WARNING(( "ledger path too long" )); return NULL; }

  vseq_ledger_t * l = calloc( 1UL, sizeof(vseq_ledger_t) );
  FD_TEST( l );
  strcpy( l->dir, dir );
  l->follow    = follow;
  l->seg_bytes = seg_bytes ? seg_bytes : SEG_BYTES_DEFAULT;
  l->buf_max   = sizeof(uint)+REC_FIXED+payload_max+proof_max;
  l->buf       = malloc( l->buf_max );
  FD_TEST( l->buf );

  ulong * segs; ulong seg_cnt;
  ulong * idxs; ulong idx_cnt;
  list_dir( l, &segs, &seg_cnt, &idxs, &idx_cnt );

  /* Indexes without a segment: below the oldest segment they are left
     by an interrupted prune; anywhere else a segment is missing. */
  for( ulong i=0UL; i<idx_cnt && !follow; i++ ) {
    int has_seg = 0;
    for( ulong j=0UL; j<seg_cnt; j++ ) has_seg |= segs[j]==idxs[i];
    if( has_seg ) continue;
    char path[ 4200 ];
    seg_path( l, idxs[i], "idx", path );
    if( FD_UNLIKELY( seg_cnt && idxs[i]>segs[0] ) ) FD_LOG_ERR(( "ledger %s: segment %lu is missing (its index %s exists)", dir, idxs[i], path ));
    FD_LOG_NOTICE(( "removing %s, left by an interrupted prune", path ));
    unlink( path );
  }
  for( ulong i=1UL; i<seg_cnt; i++ ) {
    if( FD_UNLIKELY( segs[i]!=segs[i-1UL]+1UL ) ) FD_LOG_ERR(( "ledger %s: segments %lu to %lu are missing", dir, segs[i-1UL]+1UL, segs[i]-1UL ));
  }

  ag_block_id_t genesis = ag_block_id( 0UL, ag_block_hash_null );
  if( !seg_cnt && !follow ) seg_new( l, 0UL, 0UL, &genesis );
  if( !seg_cnt &&  follow ) {
    free( segs ); free( idxs ); vseq_ledger_close( l );
    return NULL;
  }

  for( ulong i=0UL; i<seg_cnt; i++ ) {
    int     last = i+1UL==seg_cnt;
    if( FD_UNLIKELY( l->seg_cnt==l->seg_cap ) ) {
      l->seg_cap = fd_ulong_max( 2UL*l->seg_cap, 16UL );
      l->segs    = realloc( l->segs, l->seg_cap*sizeof(seg_t) );
      FD_TEST( l->segs );
    }
    seg_t * prev = l->seg_cnt ? &l->segs[ l->seg_cnt-1UL ] : NULL;
    seg_t * s = &l->segs[ l->seg_cnt++ ];
    memset( s, 0, sizeof(seg_t) );
    s->seq = segs[i];
    char path[ 4200 ];
    seg_path( l, s->seq, "seg", path );
    s->fd = open( path, follow ? O_RDONLY|O_CLOEXEC : O_RDWR|O_CLOEXEC );
    if( follow && s->fd<0 && errno==ENOENT && l->seg_cnt==1UL ) { l->seg_cnt--; continue; } /* just pruned */
    if( FD_UNLIKELY( s->fd<0 || fstat( s->fd, &st ) ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    s->size = (ulong)st.st_size;

    if( FD_UNLIKELY( hdr_read( s ) ) && follow && last && s->size<=SEG_HDR_SZ ) {
      seg_free( s ); l->seg_cnt--; /* being created: vseq_ledger_refresh picks it up */
      break;
    }
    if( FD_UNLIKELY( hdr_read( s ) ) ) {
      /* Only a newly created active segment can have a torn header */
      if( !last || s->size>SEG_HDR_SZ ) FD_LOG_ERR(( "%s: bad segment header", path ));
      FD_LOG_WARNING(( "%s: rewriting a torn header", path ));
      s->first_idx = prev ? prev->first_idx+prev->cnt : 0UL;
      s->base      = prev ? prev->last : genesis;
      s->last      = s->base;
      s->size      = SEG_HDR_SZ;
      if( FD_UNLIKELY( ftruncate( s->fd, (long)SEG_HDR_SZ ) ) ) FD_LOG_ERR(( "ftruncate(%s) failed", path ));
      hdr_write( l, s );
    }
    if( prev && FD_UNLIKELY( !ag_block_id_eq( &s->base, &prev->last ) || s->first_idx!=prev->first_idx+prev->cnt ) ) {
      FD_LOG_ERR(( "%s does not continue segment %lu (base slot %lu, expected %lu)", path, prev->seq, s->base.slot, prev->last.slot ));
    }

    if( !idx_load( l, s ) ) {
      s->sealed = 1;
    } else if( !last ) {
      FD_LOG_WARNING(( "%s: index missing or bad, rebuilding", path ));
      if( FD_UNLIKELY( seg_scan( l, s, 0 ) ) ) FD_LOG_ERR(( "%s is damaged; replace it from a peer or an archive", path ));
      if( !follow ) idx_write( l, s );
      s->sealed = 1;
    } else if( follow ) {
      ulong file_sz = s->size;
      s->size = SEG_HDR_SZ;
      seg_read_recs( l, s, file_sz ); /* stops at a record still being written */
    } else {
      char idx[ 4200 ];
      seg_path( l, s->seq, "idx", idx );
      unlink( idx ); /* a stale index of the active segment */
      seg_scan( l, s, 1 );
    }
  }
  free( segs );
  free( idxs );
  if( FD_UNLIKELY( !l->seg_cnt ) ) { vseq_ledger_close( l ); return NULL; }

  seg_t * active = &l->segs[ l->seg_cnt-1UL ];
  if( active->sealed && !follow ) {
    ag_block_id_t base = active->last;
    seg_new( l, active->seq+1UL, active->first_idx+active->cnt, &base );
  }
  return l;
}

void
vseq_ledger_sync( vseq_ledger_t * l ) {
  seg_t * s = &l->segs[ l->seg_cnt-1UL ];
  if( FD_UNLIKELY( fdatasync( s->fd ) ) ) FD_LOG_ERR(( "fdatasync of %s segment %lu failed (%i-%s)", l->dir, s->seq, errno, fd_io_strerror( errno ) ));
}

vseq_ledger_t *
vseq_ledger_open( char const * dir,
                  ulong        payload_max,
                  ulong        proof_max,
                  ulong        seg_bytes ) {
  return ledger_open( dir, payload_max, proof_max, seg_bytes, 0 );
}

vseq_ledger_t *
vseq_ledger_follow( char const * dir,
                    ulong        payload_max,
                    ulong        proof_max ) {
  return ledger_open( dir, payload_max, proof_max, 0UL, 1 );
}

static int
refresh( vseq_ledger_t * l ) {
  struct stat st;

  /* Drop segments the writer pruned (unlinked files keep nlink 0).  It
     never prunes the newest one: if that is gone, the ledger was
     replaced. */
  while( l->seg_cnt && !fstat( l->segs[0].fd, &st ) && !st.st_nlink ) {
    if( l->seg_cnt==1UL ) return -1;
    seg_free( &l->segs[0] );
    memmove( l->segs, l->segs+1UL, (l->seg_cnt-1UL)*sizeof(seg_t) );
    l->seg_cnt--;
  }

  for(;;) {
    seg_t * s = &l->segs[ l->seg_cnt-1UL ];
    if( !s->cnt && hdr_read( s ) ) return 0;   /* base set after we opened it (vseq_ledger_set_base) */
    if( FD_UNLIKELY( fstat( s->fd, &st ) ) ) return -1;
    char const * bad = seg_read_recs( l, s, (ulong)st.st_size );
    if( bad && strcmp( bad, "torn record" ) ) {
      FD_LOG_WARNING(( "%s segment %lu: %s at offset %lu", l->dir, s->seq, bad, s->size ));
      return -1;
    }

    /* The writer creates the next segment only after sealing this one,
       so once it exists this one is complete. */
    char path[ 4200 ];
    seg_path( l, s->seq+1UL, "seg", path );
    int fd = open( path, O_RDONLY|O_CLOEXEC );
    if( fd<0 ) return 0;
    seg_t n = { .seq = s->seq+1UL, .fd = fd };
    if( fstat( fd, &st ) || ( n.size = (ulong)st.st_size, hdr_read( &n ) ) ) { close( fd ); return 0; } /* header not written yet */
    if( FD_UNLIKELY( fstat( s->fd, &st ) || seg_read_recs( l, s, (ulong)st.st_size ) ||
                     !ag_block_id_eq( &n.base, &s->last ) || n.first_idx!=s->first_idx+s->cnt ) ) {
      close( fd );
      FD_LOG_WARNING(( "%s segment %lu does not continue segment %lu", l->dir, n.seq, s->seq ));
      return -1;
    }
    s->sealed = 1;
    if( FD_UNLIKELY( l->seg_cnt==l->seg_cap ) ) {
      l->seg_cap = fd_ulong_max( 2UL*l->seg_cap, 16UL );
      l->segs    = realloc( l->segs, l->seg_cap*sizeof(seg_t) );
      FD_TEST( l->segs );
    }
    n.size = SEG_HDR_SZ;
    l->segs[ l->seg_cnt++ ] = n;
  }
}

int
vseq_ledger_refresh( vseq_ledger_t * l ) {
  FD_TEST( l->follow );
  return refresh( l );
}

void
vseq_ledger_close( vseq_ledger_t * l ) {
  if( FD_UNLIKELY( !l ) ) return;
  for( ulong i=0UL; i<l->seg_cnt; i++ ) seg_free( &l->segs[i] );
  free( l->segs );
  free( l->buf );
  free( l );
}

/* Append and seal *****************************************************/

static void
seal( vseq_ledger_t * l ) {
  seg_t * s = &l->segs[ l->seg_cnt-1UL ];
  if( FD_UNLIKELY( fsync( s->fd ) ) ) FD_LOG_ERR(( "fsync failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  idx_write( l, s );
  s->sealed = 1;
  l->sealed_cnt++;
  ag_block_id_t base = s->last;
  seg_new( l, s->seq+1UL, s->first_idx+s->cnt, &base );
}

void
vseq_ledger_append( vseq_ledger_t *      l,
                    vseq_block_t const * block,
                    uchar const          hash[ 32 ],
                    uchar const *        proof,
                    ulong                proof_sz ) {
  FD_TEST( !l->follow );
  seg_t * s      = &l->segs[ l->seg_cnt-1UL ];
  ulong   rec_sz = REC_FIXED+block->payload_sz+proof_sz;
  uchar * p      = l->buf;
  FD_TEST( sizeof(uint)+rec_sz<=l->buf_max );
  FD_TEST( ag_block_id_eq( &block->parent, &s->last ) );
  FD_STORE( uint,  p,       (uint)rec_sz         );
  FD_STORE( ulong, p+  4UL, block->slot          );
  FD_STORE( ulong, p+ 12UL, block->parent.slot   );
  memcpy(          p+ 20UL, block->parent.hash, 32UL );
  memcpy(          p+ 52UL, hash,               32UL );
  memcpy(          p+ 84UL, block->sig,         64UL );
  FD_STORE( uint,  p+148UL, (uint)block->payload_sz );
  memcpy(          p+152UL, block->payload, block->payload_sz );
  FD_STORE( uint,  p+152UL+block->payload_sz, (uint)proof_sz );
  if( proof_sz ) memcpy( p+156UL+block->payload_sz, proof, proof_sz );

  ulong sz = sizeof(uint)+rec_sz;
  write_at( s->fd, p, sz, s->size, l->dir );
  seg_push( s, block->slot, s->size | ( proof_sz ? PROVED : 0UL ) );
  s->size += sz;
  s->last  = ag_block_id( block->slot, hash );

  if( proof_sz && s->size>=l->seg_bytes ) seal( l );
}

/* Queries ************************************************************/

ulong
vseq_ledger_cnt( vseq_ledger_t const * l ) {
  seg_t const * s = &l->segs[ l->seg_cnt-1UL ];
  return s->first_idx+s->cnt;
}

ulong
vseq_ledger_first_idx( vseq_ledger_t const * l ) {
  return l->segs[0].first_idx;
}

ag_block_id_t
vseq_ledger_base( vseq_ledger_t const * l ) {
  return l->segs[0].base;
}

int
vseq_ledger_set_base( vseq_ledger_t *       l,
                      ag_block_id_t const * base ) {
  seg_t * s = &l->segs[0];
  if( FD_UNLIKELY( l->follow || l->seg_cnt!=1UL || s->cnt ) ) return -1;
  s->base = *base;
  s->last = *base;
  hdr_write( l, s );
  return 0;
}

/* seg_of returns the segment holding ledger-wide index idx. */

static seg_t *
seg_of( vseq_ledger_t const * l,
        ulong                 idx ) {
  ulong lo = 0UL, hi = l->seg_cnt;
  while( hi-lo>1UL ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( l->segs[ mid ].first_idx<=idx ) lo = mid;
    else                                 hi = mid;
  }
  seg_t * s = &l->segs[ lo ];
  return idx>=s->first_idx && idx<s->first_idx+s->cnt ? s : NULL;
}

ulong
vseq_ledger_first_after( vseq_ledger_t const * l,
                         ulong                 slot ) {
  for( ulong i=0UL; i<l->seg_cnt; i++ ) {
    seg_t const * s = &l->segs[i];
    if( !s->cnt || s->last.slot<=slot ) continue;
    ulong lo = 0UL, hi = s->cnt;
    while( lo<hi ) {
      ulong mid = lo+(hi-lo)/2UL;
      if( s->slot[ mid ]<=slot ) lo = mid+1UL;
      else                       hi = mid;
    }
    return s->first_idx+lo;
  }
  return vseq_ledger_cnt( l );
}

int
vseq_ledger_read( vseq_ledger_t *     l,
                  ulong               idx,
                  vseq_ledger_rec_t * out ) {
  seg_t * s = seg_of( l, idx );
  if( FD_UNLIKELY( !s ) ) return -1;
  ulong i   = idx-s->first_idx;
  ulong off = rec_off( s, i );
  ulong sz  = rec_end( s, i )-off;
  if( FD_UNLIKELY( sz>l->buf_max ) ) return -1;
  if( FD_UNLIKELY( pread( s->fd, l->buf, sz, (long)off )!=(long)sz ) ) return -1;
  return vseq_ledger_rec_parse( l->buf, sz, out );
}

ulong
vseq_ledger_read_span( vseq_ledger_t * l,
                       ulong           first,
                       ulong           cnt_min,
                       ulong           sz_min,
                       uchar *         out,
                       ulong           out_max,
                       ulong *         out_cnt ) {
  *out_cnt = 0UL;
  seg_t * s = seg_of( l, first );
  if( FD_UNLIKELY( !s ) ) return 0UL;

  /* Take records while under both minimums, then until one with certs.
     Never exceed out_max: fall back to the last record with certs. */
  ulong i0    = first-s->first_idx;
  ulong start = rec_off( s, i0 );
  ulong cnt = 0UL, proved_end = start, proved_cnt = 0UL, fit_end = start;
  for( ulong i=i0; i<s->cnt; i++ ) {
    ulong end = rec_end( s, i );
    if( end-start>out_max ) break;
    cnt++;
    fit_end = end;
    if( s->off[i] & PROVED ) {
      proved_end = end;
      proved_cnt = cnt;
      if( cnt>=cnt_min || end-start>=sz_min ) break;
    }
  }
  if( !proved_cnt ) { proved_end = fit_end; proved_cnt = cnt; } /* no certs within out_max: the reader fetches on */
  if( !proved_cnt ) return 0UL;

  ulong sz = proved_end-start;
  if( FD_UNLIKELY( pread( s->fd, out, sz, (long)start )!=(long)sz ) ) FD_LOG_ERR(( "ledger read failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  *out_cnt = proved_cnt;
  return sz;
}

/* Prune **************************************************************/

ulong
vseq_ledger_prune( vseq_ledger_t * l,
                   ulong           slot ) {
  ulong removed = 0UL;
  while( !l->follow && l->seg_cnt>1UL && l->segs[0].sealed && l->segs[0].cnt && l->segs[0].last.slot<slot ) {
    seg_t * s = &l->segs[0];
    char seg[ 4200 ], idx[ 4200 ];
    seg_path( l, s->seq, "seg", seg );
    seg_path( l, s->seq, "idx", idx );
    if( FD_UNLIKELY( unlink( seg ) ) ) FD_LOG_ERR(( "unlink(%s) failed (%i-%s)", seg, errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( unlink( idx ) && errno!=ENOENT ) ) FD_LOG_ERR(( "unlink(%s) failed (%i-%s)", idx, errno, fd_io_strerror( errno ) ));
    seg_free( s );
    memmove( l->segs, l->segs+1UL, (l->seg_cnt-1UL)*sizeof(seg_t) );
    l->seg_cnt--;
    removed++;
  }
  if( removed ) {
    sync_dir( l );
    l->pruned_cnt += removed;
  }
  return removed;
}

vseq_ledger_stats_t
vseq_ledger_stats( vseq_ledger_t const * l ) {
  vseq_ledger_stats_t st = { .segments = l->seg_cnt, .sealed = l->sealed_cnt, .pruned = l->pruned_cnt };
  for( ulong i=0UL; i<l->seg_cnt; i++ ) st.bytes += l->segs[i].size;
  return st;
}
