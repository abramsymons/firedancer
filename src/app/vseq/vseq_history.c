#define _GNU_SOURCE
#include "vseq_history.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define TYPE_VOTE  (1)
#define TYPE_BLOCK (2)
#define TYPE_FLOOR (3)

#define HDR_SZ     (4UL+8UL)    /* body_sz, check */
#define BODY_MIN   (1UL+8UL)    /* type, slot */
#define CHECK_SEED (0x7673657168697374UL)

struct vseq_history {
  char    path[ 4096 ];
  int     fd;
  ulong   size;
  ulong   block_floor;
  ulong   data_max;
  uchar * rec;           /* one record */
  uchar * votes;  ulong votes_sz;  ulong votes_max;
  uchar * blocks; ulong blocks_sz; ulong blocks_max;
};

static void
frame_append( uchar **      buf,
              ulong *       sz,
              ulong *       max,
              uchar const * data,
              ulong         data_sz ) {
  if( *sz+sizeof(uint)+data_sz>*max ) {
    *max = 2UL**max + sizeof(uint)+data_sz;
    *buf = realloc( *buf, *max );
    FD_TEST( *buf );
  }
  FD_STORE( uint, *buf+*sz, (uint)data_sz );
  memcpy( *buf+*sz+sizeof(uint), data, data_sz );
  *sz += sizeof(uint)+data_sz;
}

static void
write_all( int           fd,
           uchar const * buf,
           ulong         sz,
           char const *  path ) {
  for( ulong done=0UL; done<sz; ) {
    long n = write( fd, buf+done, sz-done );
    if( FD_UNLIKELY( n<0 ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "write to %s failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    }
    done += (ulong)n;
  }
}

/* rec_build writes a record into h->rec and returns its size. */

static ulong
rec_build( vseq_history_t * h,
           uint             type,
           ulong            slot,
           uchar const *    data,
           ulong            data_sz ) {
  FD_TEST( data_sz<=h->data_max );
  uchar * body = h->rec+HDR_SZ;
  body[0] = (uchar)type;
  FD_STORE( ulong, body+1UL, slot );
  if( data_sz ) memcpy( body+BODY_MIN, data, data_sz );
  ulong body_sz = BODY_MIN+data_sz;
  FD_STORE( uint,  h->rec,     (uint)body_sz );
  FD_STORE( ulong, h->rec+4UL, fd_hash( CHECK_SEED, body, body_sz ) );
  return HDR_SZ+body_sz;
}

static void
sync_dir( char const * path ) {
  char dir[ 4096 ];
  fd_cstr_printf( dir, sizeof(dir), NULL, "%s", path );
  int fd = open( dirname( dir ), O_RDONLY|O_DIRECTORY|O_CLOEXEC );
  if( fd>=0 ) { fsync( fd ); close( fd ); }
}

/* rewrite streams the file into path.tmp keeping records above root
   (collecting them as prior votes and blocks), then renames
   it over the file.  Stops at the first torn or bad record.  The block
   floor goes first, where no torn tail of later appends can reach it. */

static void
rewrite( vseq_history_t * h,
         ulong            root ) {
  h->votes_sz  = 0UL;
  h->blocks_sz = 0UL;
  char tmp[ 4200 ];
  fd_cstr_printf( tmp, sizeof(tmp), NULL, "%s.tmp", h->path );
  int out = open( tmp, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0600 );
  if( FD_UNLIKELY( out<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));

  ulong floor_sz = rec_build( h, TYPE_FLOOR, 0UL, NULL, 0UL ); /* placeholder, rewritten below */
  write_all( out, h->rec, floor_sz, tmp );

  ulong off = 0UL, kept = 0UL, dropped = 0UL, floor = h->block_floor;
  while( off+HDR_SZ<=h->size ) {
    if( pread( h->fd, h->rec, HDR_SZ, (long)off )!=(long)HDR_SZ ) break;
    ulong body_sz = FD_LOAD( uint, h->rec );
    if( body_sz<BODY_MIN || body_sz>BODY_MIN+h->data_max || off+HDR_SZ+body_sz>h->size ) break;
    uchar * body = h->rec+HDR_SZ;
    if( pread( h->fd, body, body_sz, (long)(off+HDR_SZ) )!=(long)body_sz ) break;
    if( FD_LOAD( ulong, h->rec+4UL )!=fd_hash( CHECK_SEED, body, body_sz ) ) break;
    off += HDR_SZ+body_sz;

    uint  type = body[0];
    ulong slot = FD_LOAD( ulong, body+1UL );
    if( type==TYPE_FLOOR ) { floor = fd_ulong_max( floor, slot ); continue; }
    if( slot<=root ) { dropped++; continue; }
    write_all( out, h->rec, HDR_SZ+body_sz, tmp );
    kept++;
    if( type==TYPE_VOTE  ) frame_append( &h->votes,  &h->votes_sz,  &h->votes_max,  body+BODY_MIN, body_sz-BODY_MIN );
    if( type==TYPE_BLOCK ) frame_append( &h->blocks, &h->blocks_sz, &h->blocks_max, body+BODY_MIN, body_sz-BODY_MIN );
  }
  if( FD_UNLIKELY( off<h->size ) ) FD_LOG_WARNING(( "%s: dropping %lu bytes of torn or bad records at offset %lu", h->path, h->size-off, off ));

  h->block_floor = floor;
  FD_TEST( rec_build( h, TYPE_FLOOR, floor, NULL, 0UL )==floor_sz );
  if( FD_UNLIKELY( pwrite( out, h->rec, floor_sz, 0L )!=(long)floor_sz ) ) FD_LOG_ERR(( "write to %s failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fsync( out ) ) ) FD_LOG_ERR(( "fsync(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  struct stat st;
  FD_TEST( !fstat( out, &st ) );
  close( out );
  if( FD_UNLIKELY( rename( tmp, h->path ) ) ) FD_LOG_ERR(( "rename(%s) failed (%i-%s)", tmp, errno, fd_io_strerror( errno ) ));
  sync_dir( h->path );

  close( h->fd );
  h->fd = open( h->path, O_RDWR|O_APPEND|O_CLOEXEC );
  if( FD_UNLIKELY( h->fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", h->path, errno, fd_io_strerror( errno ) ));
  h->size = (ulong)st.st_size;
  FD_LOG_INFO(( "%s: compacted to %lu records above slot %lu (%lu dropped), block floor %lu", h->path, kept, root, dropped, floor ));
}

vseq_history_t *
vseq_history_open( char const * path,
                   ulong        root,
                   ulong        data_max,
                   int *        existed ) {
  vseq_history_t * h = calloc( 1UL, sizeof(vseq_history_t) );
  FD_TEST( h );
  if( FD_UNLIKELY( strlen( path )>=sizeof(h->path)-8UL ) ) { free( h ); return NULL; }
  strcpy( h->path, path );
  h->data_max = data_max;
  h->rec      = malloc( HDR_SZ+BODY_MIN+data_max );
  FD_TEST( h->rec );

  h->fd = open( path, O_RDWR|O_CREAT|O_APPEND|O_CLOEXEC, 0600 );
  if( FD_UNLIKELY( h->fd<0 ) ) {
    FD_LOG_WARNING(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    vseq_history_close( h );
    return NULL;
  }
  struct stat st;
  FD_TEST( !fstat( h->fd, &st ) );
  h->size  = (ulong)st.st_size;
  *existed = h->size>0UL;
  rewrite( h, root );
  return h;
}

void
vseq_history_close( vseq_history_t * h ) {
  if( FD_UNLIKELY( !h ) ) return;
  if( h->fd>=0 ) close( h->fd );
  free( h->blocks );
  free( h->votes );
  free( h->rec );
  free( h );
}

uchar const * vseq_history_prior_votes ( vseq_history_t const * h, ulong * sz ) { *sz = h->votes_sz;  return h->votes;  }
uchar const * vseq_history_prior_blocks( vseq_history_t const * h, ulong * sz ) { *sz = h->blocks_sz; return h->blocks; }
ulong         vseq_history_block_floor ( vseq_history_t const * h ) { return h->block_floor; }
ulong         vseq_history_size        ( vseq_history_t const * h ) { return h->size;        }

static void
append_durable( vseq_history_t * h,
                ulong            sz ) {
  write_all( h->fd, h->rec, sz, h->path );
  h->size += sz;
}

void
vseq_history_add_vote( vseq_history_t * h,
                       ulong            slot,
                       uchar const *    vote,
                       ulong            vote_sz,
                       uchar const *    block,
                       ulong            block_sz ) {
  if( block ) append_durable( h, rec_build( h, TYPE_BLOCK, slot, block, block_sz ) );
  append_durable( h, rec_build( h, TYPE_VOTE, slot, vote, vote_sz ) );
  if( FD_UNLIKELY( fdatasync( h->fd ) ) ) FD_LOG_ERR(( "fdatasync(%s) failed (%i-%s)", h->path, errno, fd_io_strerror( errno ) ));
}

void
vseq_history_add_block_floor( vseq_history_t * h,
                              ulong            slot ) {
  h->block_floor = fd_ulong_max( h->block_floor, slot );
  append_durable( h, rec_build( h, TYPE_FLOOR, slot, NULL, 0UL ) );
  if( FD_UNLIKELY( fdatasync( h->fd ) ) ) FD_LOG_ERR(( "fdatasync(%s) failed (%i-%s)", h->path, errno, fd_io_strerror( errno ) ));
}

void
vseq_history_compact( vseq_history_t * h,
                      ulong            root ) {
  rewrite( h, root );
}
