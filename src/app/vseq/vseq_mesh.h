#ifndef HEADER_fd_src_app_vseq_vseq_mesh_h
#define HEADER_fd_src_app_vseq_vseq_mesh_h

/* vseq_mesh keeps one TLS 1.3 over TCP connection to every other
   active node and moves framed messages over them.  Nodes are known by
   peer index (vseq_sched.h); all start active.

   Both sides authenticate with their ed25519 identity keys (mutual TLS
   with raw Ed25519 certificates, as Firedancer's QUIC does).  The lower
   peer index dials the higher and pins its expected key.  The listener
   requires a client certificate and maps the client's key to a peer.
   Messages from a connection are therefore attributed to the
   authenticated peer, which votor relies on.

   Frames are (uint sz, uchar msg[sz]).  Sends never block: each peer
   has a bounded output buffer, and a message that does not fit is
   dropped (consensus repairs or rebroadcasts what matters).

   The mesh owns an epoll set.  Poll vseq_mesh_fd for readability, then
   call vseq_mesh_service. */

#include "../../util/fd_util_base.h"

#define VSEQ_MESH_DST_ALL (ULONG_MAX)

typedef void
(* vseq_mesh_recv_fn)( void *        ctx,
                       ulong         from_peer,
                       uchar const * msg,
                       ulong         sz );

struct vseq_mesh_peer {
  uint   ip4;        /* network byte order */
  ushort port;       /* host byte order */
  uchar  id_pub[ 32 ];
};
typedef struct vseq_mesh_peer vseq_mesh_peer_t;

struct vseq_mesh_metrics {
  ulong disconnects;
  ulong frames_dropped; /* output buffer full or peer not connected */
};
typedef struct vseq_mesh_metrics vseq_mesh_metrics_t;

typedef struct vseq_mesh vseq_mesh_t;

FD_PROTOTYPES_BEGIN

/* vseq_mesh_create listens on peers[own_peer] and starts dialing.
   peers is indexed by peer and copied.  frame_max bounds incoming
   messages, out_max bounds each peer's output buffer.  Returns NULL on
   failure (logs details). */

vseq_mesh_t *
vseq_mesh_create( vseq_mesh_peer_t const * peers,
                  ulong                    peer_cnt,
                  ulong                    own_peer,
                  uchar const              id_sec[ 32 ],
                  ulong                    frame_max,
                  ulong                    out_max,
                  vseq_mesh_recv_fn        recv,
                  void *                   recv_ctx,
                  long                     now );

void
vseq_mesh_destroy( vseq_mesh_t * mesh );

int
vseq_mesh_fd( vseq_mesh_t const * mesh );

/* vseq_mesh_service accepts, connects, reads, delivers frames and
   flushes.  Returns the next time it needs to run (for reconnects). */

long
vseq_mesh_service( vseq_mesh_t * mesh,
                   long          now );

void
vseq_mesh_send( vseq_mesh_t * mesh,
                ulong         dst_peer,
                uchar const * msg,
                ulong         sz );

/* vseq_mesh_set_active starts or stops keeping a connection with peer
   (e.g. as validators join and leave).  vseq_mesh_close drops peer's
   connection now; an active peer is dialed again after a backoff. */

void vseq_mesh_set_active( vseq_mesh_t * mesh, ulong peer, int active );
void vseq_mesh_close     ( vseq_mesh_t * mesh, ulong peer, char const * why );

ulong                       vseq_mesh_connected_cnt( vseq_mesh_t const * mesh );
int                         vseq_mesh_peer_connected( vseq_mesh_t const * mesh, ulong peer );
vseq_mesh_metrics_t const * vseq_mesh_metrics      ( vseq_mesh_t const * mesh );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_vseq_vseq_mesh_h */
