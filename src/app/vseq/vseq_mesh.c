#define _GNU_SOURCE
#include "vseq_mesh.h"
#include "../../waltz/tlsrec/fd_tlsrec_sock.h"
#include "../../waltz/tls/fd_tls.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_x25519.h"
#include "../../ballet/x509/fd_x509_mock.h"
#include "../../ballet/chacha/fd_chacha_rng.h"
#include "../../util/net/fd_ip4.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define PENDING_MAX      (64UL)
#define EVENT_MAX        (64)
#define HANDSHAKE_NS     (5L*1000L*1000L*1000L)
#define BACKOFF_MIN_NS   (200L*1000L*1000L)
#define BACKOFF_MAX_NS   (5L*1000L*1000L*1000L)

#define CONN_FREE       (0)
#define CONN_CONNECTING (1)
#define CONN_HANDSHAKE  (2)
#define CONN_READY      (3)

typedef struct conn conn_t;

struct conn {
  fd_tlsrec_conn_t tls;
  fd_tlsrec_sock_t sock;
  int              fd;
  int              state;
  int              is_server;
  uint             ev;        /* epoll events currently armed */
  ulong            rank;      /* ULONG_MAX until a server conn is identified */
  long             start_ts;
  uchar *          out;       /* frames awaiting encryption: [out_off,out_sz) */
  ulong            out_off;
  ulong            out_sz;
  uchar *          in;        /* partial frames */
  ulong            in_sz;
  conn_t *         next_dead;
};

struct __attribute__((aligned(FD_SHA512_ALIGN))) vseq_mesh {
  fd_sha512_t         sha[1];
  fd_chacha_rng_t     chacha[1];
  fd_tls_t            tls;
  uchar               id_sec[ 32 ];
  uchar               id_pub[ 32 ];

  vseq_mesh_peer_t *  peers;
  ulong               peer_cnt;
  ulong               own;
  ulong               frame_max;
  ulong               out_max;
  ulong               in_cap;
  vseq_mesh_recv_fn   recv;
  void *              recv_ctx;

  int                 ep;
  int                 lfd;
  long                now;

  conn_t **           by_rank;   /* the conn to each peer, if any */
  ulong *             conn_gen;  /* by peer: bumped each time a connection to it becomes ready */
  uchar *             active;    /* peers we keep connections with */
  long *              next_dial; /* ranks above own only */
  long *              backoff;
  conn_t *            pending[ PENDING_MAX ]; /* accepted, not yet identified */
  ulong               pending_cnt;
  conn_t *            dead;      /* closed this service pass, freed at its end */

  vseq_mesh_metrics_t metrics;
};

static void
mesh_sign( void *      ctx,
           uchar       sig[ static FD_ED25519_SIG_SZ ],
           uchar const payload[ static FD_TLS_CV_SIGN_SZ ] ) {
  vseq_mesh_t * mesh = ctx;
  fd_ed25519_sign( sig, payload, FD_TLS_CV_SIGN_SZ, mesh->id_pub, mesh->id_sec, mesh->sha );
}

static void
conn_events( vseq_mesh_t * mesh,
             conn_t *      c ) {
  uint ev = EPOLLIN;
  if( c->state==CONN_CONNECTING || fd_tlsrec_sock_tx_pending( &c->sock ) ) ev |= EPOLLOUT;
  if( ev==c->ev ) return;
  struct epoll_event e = { .events = ev, .data = { .ptr = c } };
  if( FD_UNLIKELY( epoll_ctl( mesh->ep, EPOLL_CTL_MOD, c->fd, &e ) ) ) FD_LOG_ERR(( "epoll_ctl failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  c->ev = ev;
}

static conn_t *
conn_new( vseq_mesh_t * mesh,
          int           fd,
          int           is_server,
          ulong         rank,
          int           state ) {
  conn_t * c = aligned_alloc( alignof(conn_t), fd_ulong_align_up( sizeof(conn_t), alignof(conn_t) ) );
  FD_TEST( c );
  FD_TEST( fd_tlsrec_conn_init( &c->tls, &mesh->tls, is_server ) );
  fd_tlsrec_sock_init( &c->sock );
  c->fd        = fd;
  c->state     = state;
  c->is_server = is_server;
  c->rank      = rank;
  c->start_ts  = mesh->now;
  c->out       = malloc( mesh->out_max );
  c->out_off   = 0UL;
  c->out_sz    = 0UL;
  c->in        = malloc( mesh->in_cap );
  c->in_sz     = 0UL;
  c->next_dead = NULL;
  FD_TEST( c->out && c->in );

  if( !is_server ) {
    /* Only accept the server key we expect for this rank */
    memcpy( c->tls.hs.cli.server_pubkey, mesh->peers[ rank ].id_pub, 32UL );
    c->tls.hs.cli.server_pubkey_len = 32UL;
    c->tls.hs.cli.server_pubkey_pin = 1;
  }

  c->ev = EPOLLIN | ( state==CONN_CONNECTING ? (uint)EPOLLOUT : 0U );
  struct epoll_event e = { .events = c->ev, .data = { .ptr = c } };
  if( FD_UNLIKELY( epoll_ctl( mesh->ep, EPOLL_CTL_ADD, fd, &e ) ) ) FD_LOG_ERR(( "epoll_ctl failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return c;
}

static void
conn_close( vseq_mesh_t * mesh,
            conn_t *      c,
            char const *  why ) {
  if( FD_UNLIKELY( c->state==CONN_FREE ) ) return;

  if( c->state==CONN_READY ) {
    mesh->metrics.disconnects++;
    FD_LOG_NOTICE(( "disconnected from peer %lu (%s)", c->rank, why ));
  } else if( c->state==CONN_HANDSHAKE ) {
    FD_LOG_INFO(( "handshake with peer %lu failed (%s)", c->rank, why ));
  }

  epoll_ctl( mesh->ep, EPOLL_CTL_DEL, c->fd, NULL );
  close( c->fd );
  c->fd    = -1;
  c->state = CONN_FREE;

  for( ulong i=0UL; i<mesh->pending_cnt; i++ ) {
    if( mesh->pending[i]==c ) { mesh->pending[i] = mesh->pending[ --mesh->pending_cnt ]; break; }
  }
  if( c->rank!=ULONG_MAX && mesh->by_rank[ c->rank ]==c ) {
    mesh->by_rank[ c->rank ] = NULL;
    if( c->rank>mesh->own ) {
      mesh->next_dial[ c->rank ] = mesh->now + mesh->backoff[ c->rank ];
      mesh->backoff  [ c->rank ] = fd_long_min( 2L*mesh->backoff[ c->rank ], BACKOFF_MAX_NS );
    }
  }

  c->next_dead = mesh->dead;
  mesh->dead   = c;
}

static void
conn_pump_out( vseq_mesh_t * mesh,
               conn_t *      c ) {
  if( FD_UNLIKELY( c->state!=CONN_READY && c->state!=CONN_HANDSHAKE ) ) return;
  if( fd_tlsrec_sock_tx_pending( &c->sock ) ) {
    int rc = fd_tlsrec_sock_flush( &c->sock, c->fd );
    if( FD_UNLIKELY( rc<0 || rc>1 ) ) { conn_close( mesh, c, "send failed" ); return; }
  }
  while( c->state==CONN_READY && !fd_tlsrec_sock_tx_pending( &c->sock ) && c->out_off<c->out_sz ) {
    ulong consumed = 0UL;
    int   rc       = fd_tlsrec_sock_tx( &c->sock, &c->tls, c->fd, c->out+c->out_off, c->out_sz-c->out_off, &consumed );
    if( FD_UNLIKELY( rc ) ) { conn_close( mesh, c, fd_tlsrec_sock_strerror( rc ) ); return; }
    if( FD_UNLIKELY( !consumed ) ) break;
    c->out_off += consumed;
  }
  if( c->out_off==c->out_sz ) c->out_off = c->out_sz = 0UL;
  conn_events( mesh, c );
}

static void
conn_ready( vseq_mesh_t * mesh,
            conn_t *      c ) {
  if( c->is_server ) {
    /* Identify the client by its certificate key.  Only lower ranks
       dial us. */
    uchar const * key  = c->tls.hs.srv.client_pubkey;
    ulong         rank = ULONG_MAX;
    for( ulong r=0UL; r<mesh->own; r++ ) if( !memcmp( mesh->peers[r].id_pub, key, 32UL ) ) { rank = r; break; }
    if( FD_UNLIKELY( rank==ULONG_MAX   ) ) { conn_close( mesh, c, "unknown client key" ); return; }
    if( FD_UNLIKELY( !mesh->active[rank] ) ) { conn_close( mesh, c, "not a current validator" ); return; }

    for( ulong i=0UL; i<mesh->pending_cnt; i++ ) {
      if( mesh->pending[i]==c ) { mesh->pending[i] = mesh->pending[ --mesh->pending_cnt ]; break; }
    }
    if( mesh->by_rank[ rank ] ) conn_close( mesh, mesh->by_rank[ rank ], "replaced by new connection" );
    c->rank                = rank;
    mesh->by_rank[ rank ]  = c;
  } else {
    mesh->backoff[ c->rank ] = BACKOFF_MIN_NS;
  }
  c->state = CONN_READY;
  mesh->conn_gen[ c->rank ]++;
  FD_LOG_NOTICE(( "connected to peer %lu", c->rank ));
}

static void
conn_pump_in( vseq_mesh_t * mesh,
              conn_t *      c ) {
  for(;;) {
    ulong rx_sz = 0UL;
    int   rc    = fd_tlsrec_sock_rx( &c->sock, &c->tls, c->fd, &rx_sz );
    if( FD_UNLIKELY( rc ) ) { conn_close( mesh, c, fd_tlsrec_sock_strerror( rc ) ); return; }

    if( c->state==CONN_HANDSHAKE && fd_tlsrec_conn_is_ready( &c->tls ) ) {
      conn_ready( mesh, c );
      if( FD_UNLIKELY( c->state!=CONN_READY ) ) return;
    }

    while( fd_tlsrec_sock_rx_avail( &c->sock ) ) {
      if( FD_UNLIKELY( c->in_sz==mesh->in_cap ) ) { conn_close( mesh, c, "frame too large" ); return; }
      c->in_sz += fd_tlsrec_sock_rx_pop( &c->sock, c->in+c->in_sz, mesh->in_cap-c->in_sz );

      ulong off = 0UL;
      while( c->in_sz-off>=sizeof(uint) ) {
        ulong sz = FD_LOAD( uint, c->in+off );
        if( FD_UNLIKELY( !sz || sz>mesh->frame_max ) ) { conn_close( mesh, c, "bad frame size" ); return; }
        if( c->in_sz-off-sizeof(uint)<sz ) break;
        mesh->recv( mesh->recv_ctx, c->rank, c->in+off+sizeof(uint), sz );
        if( FD_UNLIKELY( c->state!=CONN_READY ) ) return; /* closed by a send in the callback */
        off += sizeof(uint)+sz;
      }
      memmove( c->in, c->in+off, c->in_sz-off );
      c->in_sz -= off;
    }
    if( !rx_sz ) break;
  }
  conn_pump_out( mesh, c );
}

static void
conn_connected( vseq_mesh_t * mesh,
                conn_t *      c ) {
  int       err = 0;
  socklen_t len = sizeof(err);
  if( FD_UNLIKELY( getsockopt( c->fd, SOL_SOCKET, SO_ERROR, &err, &len ) || err ) ) {
    conn_close( mesh, c, "connect failed" );
    return;
  }
  c->state    = CONN_HANDSHAKE;
  c->start_ts = mesh->now;
  conn_pump_in( mesh, c ); /* steps the TLS client, which sends ClientHello */
}

static void
dial( vseq_mesh_t * mesh,
      ulong         rank ) {
  vseq_mesh_peer_t const * p = &mesh->peers[ rank ];
  int fd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int one = 1;
  setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one) );

  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( p->port ), .sin_addr = { .s_addr = p->ip4 } };
  if( FD_UNLIKELY( connect( fd, fd_type_pun( &addr ), sizeof(addr) ) && errno!=EINPROGRESS ) ) {
    close( fd );
    mesh->next_dial[ rank ] = mesh->now + mesh->backoff[ rank ];
    mesh->backoff  [ rank ] = fd_long_min( 2L*mesh->backoff[ rank ], BACKOFF_MAX_NS );
    return;
  }
  mesh->by_rank[ rank ] = conn_new( mesh, fd, 0, rank, CONN_CONNECTING );
}

static void
accept_all( vseq_mesh_t * mesh ) {
  for(;;) {
    int fd = accept4( mesh->lfd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC );
    if( fd<0 ) {
      if( FD_UNLIKELY( errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR ) ) FD_LOG_WARNING(( "accept failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      return;
    }
    if( FD_UNLIKELY( mesh->pending_cnt==PENDING_MAX ) ) { close( fd ); continue; }
    int one = 1;
    setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one) );
    mesh->pending[ mesh->pending_cnt++ ] = conn_new( mesh, fd, 1, ULONG_MAX, CONN_HANDSHAKE );
  }
}

vseq_mesh_t *
vseq_mesh_create( vseq_mesh_peer_t const * peers,
                  ulong                    peer_cnt,
                  ulong                    own_peer,
                  uchar const              id_sec[ 32 ],
                  ulong                    frame_max,
                  ulong                    out_max,
                  vseq_mesh_recv_fn        recv,
                  void *                   recv_ctx,
                  long                     now ) {
  if( FD_UNLIKELY( own_peer>=peer_cnt || !frame_max || out_max<frame_max+sizeof(uint) ) ) { FD_LOG_WARNING(( "bad mesh params" )); return NULL; }

  vseq_mesh_t * mesh = aligned_alloc( alignof(vseq_mesh_t), fd_ulong_align_up( sizeof(vseq_mesh_t), alignof(vseq_mesh_t) ) );
  FD_TEST( mesh );
  memset( mesh, 0, sizeof(vseq_mesh_t) );
  FD_TEST( fd_sha512_join( fd_sha512_new( mesh->sha ) ) );
  memcpy( mesh->id_sec, id_sec, 32UL );
  fd_ed25519_public_from_private( mesh->id_pub, id_sec, mesh->sha );

  mesh->peer_cnt  = peer_cnt;
  mesh->own       = own_peer;
  mesh->frame_max = frame_max;
  mesh->out_max   = out_max;
  mesh->in_cap    = sizeof(uint)+frame_max;
  mesh->recv      = recv;
  mesh->recv_ctx  = recv_ctx;
  mesh->now       = now;
  mesh->peers     = malloc( peer_cnt*sizeof(vseq_mesh_peer_t) );
  mesh->by_rank   = calloc( peer_cnt, sizeof(conn_t *) );
  mesh->next_dial = calloc( peer_cnt, sizeof(long) );
  mesh->backoff   = calloc( peer_cnt, sizeof(long) );
  mesh->conn_gen  = calloc( peer_cnt, sizeof(ulong) );
  mesh->active    = malloc( peer_cnt );
  FD_TEST( mesh->peers && mesh->by_rank && mesh->next_dial && mesh->backoff && mesh->conn_gen && mesh->active );
  memset( mesh->active, 1, peer_cnt );
  memcpy( mesh->peers, peers, peer_cnt*sizeof(vseq_mesh_peer_t) );
  for( ulong r=0UL; r<peer_cnt; r++ ) { mesh->next_dial[r] = now; mesh->backoff[r] = BACKOFF_MIN_NS; }

  if( FD_UNLIKELY( memcmp( mesh->id_pub, peers[ own_peer ].id_pub, 32UL ) ) ) {
    FD_LOG_WARNING(( "identity key does not match peer %lu", own_peer ));
    vseq_mesh_destroy( mesh );
    return NULL;
  }

  /* TLS: fresh X25519 key and RNG key per process, Ed25519 identity
     certificate, client certificates required. */

  uchar key[ 32 ];
  FD_TEST( fd_rng_secure( key, sizeof(key) ) );
  mesh->tls.rng = fd_chacha_rng_init( fd_chacha_rng_join( fd_chacha_rng_new( mesh->chacha, FD_CHACHA_RNG_MODE_SHIFT ) ), key, FD_CHACHA_RNG_ALGO_CHACHA20 );
  FD_TEST( mesh->tls.rng );
  FD_TEST( fd_rng_secure( mesh->tls.kex_private_key, 32UL ) );
  fd_x25519_public( mesh->tls.kex_public_key, mesh->tls.kex_private_key );
  mesh->tls.sign = (fd_tls_sign_t){ .ctx = mesh, .sign_fn = mesh_sign };
  memcpy( mesh->tls.cert_public_key, mesh->id_pub, 32UL );
  fd_x509_mock_cert( mesh->tls.cert_x509, mesh->tls.cert_public_key );
  mesh->tls.cert_x509_sz    = FD_X509_MOCK_CERT_SZ;
  mesh->tls.req_client_cert = 1;

  mesh->ep = epoll_create1( EPOLL_CLOEXEC );
  if( FD_UNLIKELY( mesh->ep<0 ) ) FD_LOG_ERR(( "epoll_create1 failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  mesh->lfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0 );
  if( FD_UNLIKELY( mesh->lfd<0 ) ) FD_LOG_ERR(( "socket failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  int one = 1;
  setsockopt( mesh->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one) );
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = fd_ushort_bswap( peers[ own_peer ].port ), .sin_addr = { .s_addr = 0U } };
  if( FD_UNLIKELY( bind( mesh->lfd, fd_type_pun( &addr ), sizeof(addr) ) ) ) {
    FD_LOG_WARNING(( "bind to port %hu failed (%i-%s)", peers[ own_peer ].port, errno, fd_io_strerror( errno ) ));
    vseq_mesh_destroy( mesh );
    return NULL;
  }
  if( FD_UNLIKELY( listen( mesh->lfd, 128 ) ) ) FD_LOG_ERR(( "listen failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  struct epoll_event e = { .events = EPOLLIN, .data = { .ptr = NULL } };
  if( FD_UNLIKELY( epoll_ctl( mesh->ep, EPOLL_CTL_ADD, mesh->lfd, &e ) ) ) FD_LOG_ERR(( "epoll_ctl failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return mesh;
}

static void
free_dead( vseq_mesh_t * mesh ) {
  while( mesh->dead ) {
    conn_t * c = mesh->dead;
    mesh->dead = c->next_dead;
    free( c->out );
    free( c->in );
    fd_memzero_explicit( &c->tls, sizeof(c->tls) );
    free( c );
  }
}

void
vseq_mesh_destroy( vseq_mesh_t * mesh ) {
  if( FD_UNLIKELY( !mesh ) ) return;
  if( mesh->by_rank ) for( ulong r=0UL; r<mesh->peer_cnt; r++ ) if( mesh->by_rank[r] ) conn_close( mesh, mesh->by_rank[r], "shutdown" );
  while( mesh->pending_cnt ) conn_close( mesh, mesh->pending[0], "shutdown" );
  free_dead( mesh );
  if( mesh->lfd>0 ) close( mesh->lfd );
  if( mesh->ep >0 ) close( mesh->ep  );
  free( mesh->backoff );
  free( mesh->conn_gen );
  free( mesh->next_dial );
  free( mesh->by_rank );
  free( mesh->active );
  free( mesh->peers );
  fd_memzero_explicit( mesh->id_sec, 32UL );
  free( mesh );
}

int
vseq_mesh_fd( vseq_mesh_t const * mesh ) {
  return mesh->ep;
}

long
vseq_mesh_service( vseq_mesh_t * mesh,
                   long          now ) {
  mesh->now = now;

  for( ulong r=mesh->own+1UL; r<mesh->peer_cnt; r++ ) {
    if( mesh->active[r] && !mesh->by_rank[r] && now>=mesh->next_dial[r] ) dial( mesh, r );
  }

  for( ulong r=0UL; r<mesh->peer_cnt; r++ ) {
    conn_t * c = mesh->by_rank[r];
    if( c && c->state!=CONN_READY && now-c->start_ts>HANDSHAKE_NS ) conn_close( mesh, c, "handshake timeout" );
  }
  for( ulong i=0UL; i<mesh->pending_cnt; ) {
    conn_t * c = mesh->pending[i];
    if( now-c->start_ts>HANDSHAKE_NS ) conn_close( mesh, c, "handshake timeout" ); /* removes pending[i] */
    else                               i++;
  }

  struct epoll_event ev[ EVENT_MAX ];
  for(;;) {
    int n = epoll_wait( mesh->ep, ev, EVENT_MAX, 0 );
    if( FD_UNLIKELY( n<0 ) ) {
      if( errno==EINTR ) continue;
      FD_LOG_ERR(( "epoll_wait failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    for( int i=0; i<n; i++ ) {
      conn_t * c = ev[i].data.ptr;
      if( !c ) { accept_all( mesh ); continue; }
      if( c->state==CONN_FREE ) continue;
      if( c->state==CONN_CONNECTING ) { conn_connected( mesh, c ); continue; }
      if( ev[i].events & (EPOLLIN|EPOLLHUP|EPOLLERR) ) conn_pump_in ( mesh, c );
      if( ev[i].events & EPOLLOUT                    ) conn_pump_out( mesh, c );
    }
    free_dead( mesh );
    if( n<EVENT_MAX ) break;
  }

  long next = LONG_MAX;
  for( ulong r=mesh->own+1UL; r<mesh->peer_cnt; r++ ) if( mesh->active[r] && !mesh->by_rank[r] ) next = fd_long_min( next, mesh->next_dial[r] );
  return next;
}

void
vseq_mesh_send( vseq_mesh_t * mesh,
                ulong         dst_peer,
                uchar const * msg,
                ulong         sz ) {
  for( ulong r=0UL; r<mesh->peer_cnt; r++ ) {
    if( r==mesh->own || ( dst_peer!=VSEQ_MESH_DST_ALL && r!=dst_peer ) ) continue;
    conn_t * c = mesh->by_rank[r];
    if( FD_UNLIKELY( !c || c->state!=CONN_READY ) ) { mesh->metrics.frames_dropped++; continue; }
    if( FD_UNLIKELY( c->out_sz+sizeof(uint)+sz>mesh->out_max ) ) {
      memmove( c->out, c->out+c->out_off, c->out_sz-c->out_off );
      c->out_sz -= c->out_off;
      c->out_off = 0UL;
      if( c->out_sz+sizeof(uint)+sz>mesh->out_max ) { mesh->metrics.frames_dropped++; continue; }
    }
    FD_STORE( uint, c->out+c->out_sz, (uint)sz );
    memcpy( c->out+c->out_sz+sizeof(uint), msg, sz );
    c->out_sz += sizeof(uint)+sz;
    conn_pump_out( mesh, c ); /* may close c; it is freed at the end of the next service */
  }
}

ulong
vseq_mesh_connected_cnt( vseq_mesh_t const * mesh ) {
  ulong cnt = 0UL;
  for( ulong r=0UL; r<mesh->peer_cnt; r++ ) cnt += mesh->by_rank[r] && mesh->by_rank[r]->state==CONN_READY;
  return cnt;
}

void
vseq_mesh_set_active( vseq_mesh_t * mesh,
                      ulong         peer,
                      int           active ) {
  if( FD_UNLIKELY( peer>=mesh->peer_cnt || peer==mesh->own || mesh->active[ peer ]==!!active ) ) return;
  mesh->active[ peer ] = (uchar)!!active;
  if( active ) { mesh->next_dial[ peer ] = mesh->now; mesh->backoff[ peer ] = BACKOFF_MIN_NS; }
  else if( mesh->by_rank[ peer ] ) conn_close( mesh, mesh->by_rank[ peer ], "no longer a validator" );
}

void
vseq_mesh_close( vseq_mesh_t * mesh,
                 ulong         peer,
                 char const *  why ) {
  if( FD_LIKELY( peer<mesh->peer_cnt && mesh->by_rank[ peer ] ) ) conn_close( mesh, mesh->by_rank[ peer ], why );
}

int
vseq_mesh_peer_connected( vseq_mesh_t const * mesh,
                          ulong               rank ) {
  return rank<mesh->peer_cnt && mesh->by_rank[ rank ] && mesh->by_rank[ rank ]->state==CONN_READY;
}

ulong
vseq_mesh_peer_conn_gen( vseq_mesh_t const * mesh,
                         ulong               rank ) {
  return rank<mesh->peer_cnt ? mesh->conn_gen[ rank ] : 0UL;
}

vseq_mesh_metrics_t const *
vseq_mesh_metrics( vseq_mesh_t const * mesh ) {
  return &mesh->metrics;
}
