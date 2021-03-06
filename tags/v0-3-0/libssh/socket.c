/*
 * socket.c - socket functions for the library
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008      by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include "libssh/priv.h"

#if !defined(HAVE_SELECT) && !defined(HAVE_POLL)
#error Your system must have either select() or poll()
#endif

#if !defined(HAVE_POLL) && !defined(_WIN32)
#warning your system does not have poll. Select has known limitations
#define SELECT_LIMIT_CHECK
#endif

#ifdef HAVE_POLL
#define USE_POLL
#include <poll.h>
#else
#define USE_SELECT
#endif

/** \defgroup ssh_socket SSH Sockets
 * \addtogroup ssh_socket
 * @{
 */

struct socket {
  socket_t fd;
  int last_errno;
  int data_to_read; /* reading now on socket will
                       not block */
  int data_to_write;
  int data_except;
  BUFFER *out_buffer;
  BUFFER *in_buffer;
  SSH_SESSION *session;
};

/*
 * \internal
 * \brief inits the socket system (windows specific)
 */
int ssh_socket_init(void) {
#ifdef _WIN32
  struct WSAData wsaData;

  /* Initiates use of the Winsock DLL by a process. */
  if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
    return -1;
  }
#endif
  return 0;
}
/*
 * \internal
 * \brief creates a new Socket object
 */
struct socket *ssh_socket_new(SSH_SESSION *session) {
  struct socket *s;

  s = malloc(sizeof(struct socket));
  if (s == NULL) {
    return NULL;
  }
  s->fd = -1;
  s->last_errno = -1;
  s->session = session;
  s->in_buffer = buffer_new();
  if (s->in_buffer == NULL) {
    SAFE_FREE(s);
    return NULL;
  }
  s->out_buffer=buffer_new();
  if (s->out_buffer == NULL) {
    buffer_free(s->in_buffer);
    SAFE_FREE(s);
    return NULL;
  }
  s->data_to_read = 0;
  s->data_to_write = 0;
  s->data_except = 0;

  return s;
}

/* \internal
 * \brief Deletes a socket object
 */
void ssh_socket_free(struct socket *s){
  if (s == NULL) {
    return;
  }
  ssh_socket_close(s);
  buffer_free(s->in_buffer);
  buffer_free(s->out_buffer);
  SAFE_FREE(s);
}

#ifndef _WIN32
int ssh_socket_unix(struct socket *s, const char *path) {
  struct sockaddr_un sunaddr;

  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", path);

  s->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s->fd < 0) {
    return -1;
  }

  if (fcntl(s->fd, F_SETFD, 1) == -1) {
    close(s->fd);
    s->fd = -1;
    return -1;
  }

  if (connect(s->fd, (struct sockaddr *) &sunaddr,
        sizeof(sunaddr)) < 0) {
    close(s->fd);
    s->fd = -1;
    return -1;
  }

  return 0;
}
#endif

/* \internal
 * \brief closes a socket
 */
void ssh_socket_close(struct socket *s){
  if (ssh_socket_is_open(s)) {
#ifdef _WIN32
    closesocket(s->fd);
    s->last_errno = WSAGetLastError();
#else
    close(s->fd);
    s->last_errno = errno;
#endif
    s->fd=-1;
  }
}

/* \internal
 * \brief sets the file descriptor of the socket
 */
void ssh_socket_set_fd(struct socket *s, socket_t fd) {
  s->fd = fd;
}

/* \internal
 * \brief returns the file descriptor of the socket
 */
socket_t ssh_socket_get_fd(struct socket *s) {
  return s->fd;
}

/* \internal
 * \brief returns nonzero if the socket is open
 */
int ssh_socket_is_open(struct socket *s) {
  return s->fd != -1;
}

/* \internal
 * \brief read len bytes from socket into buffer
 */
static int ssh_socket_unbuffered_read(struct socket *s, void *buffer, u32 len) {
  int rc = -1;

  if (s->data_except) {
    return -1;
  }

  rc = recv(s->fd,buffer, len, 0);
#ifdef _WIN32
  s->last_errno = WSAGetLastError();
#else
  s->last_errno = errno;
#endif
  s->data_to_read = 0;

  if (rc < 0) {
    s->data_except = 1;
  }

  return rc;
}

/* \internal
 * \brief writes len bytes from buffer to socket
 */
static int ssh_socket_unbuffered_write(struct socket *s, const void *buffer,
    u32 len) {
  int w = -1;

  if (s->data_except) {
    return -1;
  }

  w = send(s->fd,buffer, len, 0);
#ifdef _WIN32
  s->last_errno = WSAGetLastError();
#else
  s->last_errno = errno;
#endif
  s->data_to_write = 0;

  if (w < 0) {
    s->data_except = 1;
  }

  return w;
}

/* \internal
 * \brief returns nonzero if the current socket is in the fd_set
 */
int ssh_socket_fd_isset(struct socket *s, fd_set *set) {
  if(s->fd == -1) {
    return 0;
  }
  return FD_ISSET(s->fd,set);
}

/* \internal
 * \brief sets the current fd in a fd_set and updates the fd_max
 */

void ssh_socket_fd_set(struct socket *s, fd_set *set, int *fd_max) {
  if (s->fd == -1)
    return;
  FD_SET(s->fd,set);
  if (s->fd >= *fd_max) {
    *fd_max = s->fd + 1;
  }
}

/** \internal
 * \brief reads blocking until len bytes have been read
 */
int ssh_socket_completeread(struct socket *s, void *buffer, u32 len) {
  int r = -1;
  u32 total = 0;
  u32 toread = len;
  if(! ssh_socket_is_open(s)) {
    return SSH_ERROR;
  }

  while((r = ssh_socket_unbuffered_read(s, buffer + total, toread))) {
    if (r < 0) {
      return SSH_ERROR;
    }
    total += r;
    toread -= r;
    if (total == len) {
      return len;
    }
    if (r == 0) {
      return 0;
    }
  }

  /* connection closed */
  return total;
}

/** \internal
 * \brief Blocking write of len bytes
 */
int ssh_socket_completewrite(struct socket *s, const void *buffer, u32 len) {
  SSH_SESSION *session = s->session;
  int written = -1;

  enter_function();

  if(! ssh_socket_is_open(s)) {
    leave_function();
    return SSH_ERROR;
  }

  while (len >0) {
    written = ssh_socket_unbuffered_write(s, buffer, len);
    if (written == 0 || written == -1) {
      leave_function();
      return SSH_ERROR;
    }
    len -= written;
    buffer += written;
  }

  leave_function();
  return SSH_OK;
}

/** \internal
 * \brief buffered read of data (complete)
 * \returns SSH_OK or SSH_ERROR.
 * \returns SSH_AGAIN in nonblocking mode
 */
int ssh_socket_read(struct socket *s, void *buffer, int len){
  SSH_SESSION *session = s->session;
  int rc = SSH_ERROR;

  enter_function();

  rc = ssh_socket_wait_for_data(s, s->session, len);
  if (rc != SSH_OK) {
    leave_function();
    return rc;
  }

  memcpy(buffer, buffer_get_rest(s->in_buffer), len);
  buffer_pass_bytes(s->in_buffer, len);

  leave_function();
  return SSH_OK;
}

#define WRITE_BUFFERING_THRESHOLD 65536
/** \internal
 * \brief buffered write of data
 * \returns SSH_OK, or SSH_ERROR
 * \warning has no effect on socket before a flush
 */
int ssh_socket_write(struct socket *s, const void *buffer, int len) {
  SSH_SESSION *session = s->session;
  int rc = SSH_ERROR;

  enter_function();

  if (buffer_add_data(s->out_buffer, buffer, len) < 0) {
    return SSH_ERROR;
  }

  if (buffer_get_rest_len(s->out_buffer) > WRITE_BUFFERING_THRESHOLD) {
    rc = ssh_socket_nonblocking_flush(s);
  } else {
    rc = len;
  }

  leave_function();
  return rc;
}


/** \internal
 * \brief wait for data on socket
 * \param s socket
 * \param session the ssh session
 * \param len number of bytes to be read
 * \returns SSH_OK bytes are available on socket
 * \returns SSH_AGAIN need to call later for data
 * \returns SSH_ERROR error happened
 */
int ssh_socket_wait_for_data(struct socket *s, SSH_SESSION *session, u32 len) {
  char buffer[4096] = {0};
  char *buf = NULL;
  int except;
  int can_write;
  int to_read;
  int r;

  enter_function();

  to_read = len - buffer_get_rest_len(s->in_buffer);

  if (to_read <= 0) {
    leave_function();
    return SSH_OK;
  }

  if (session->blocking) {
    buf = malloc(to_read);
    if (buf == NULL) {
      leave_function();
      return SSH_ERROR;
    }

    r = ssh_socket_completeread(session->socket,buf,to_read);
    if (r == SSH_ERROR || r == 0) {
      ssh_set_error(session, SSH_FATAL,
          (r == 0) ? "Connection closed by remote host" :
          "Error reading socket");
      ssh_socket_close(session->socket);
      session->alive = 0;
      SAFE_FREE(buf);

      leave_function();
      return SSH_ERROR;
    }

    if (buffer_add_data(s->in_buffer,buf,to_read) < 0) {
      SAFE_FREE(buf);
      leave_function();
      return SSH_ERROR;
    }

    SAFE_FREE(buf);

    leave_function();
    return SSH_OK;
  }

  /* nonblocking read */
  do {
    /* internally sets data_to_read */
    r = ssh_socket_poll(s, &can_write, &except);
    if (r < 0 || !s->data_to_read) {
      leave_function();
      return SSH_AGAIN;
    }

    /* read as much as we can */
    if (ssh_socket_is_open(session->socket)) {
      r = ssh_socket_unbuffered_read(session->socket, buffer, sizeof(buffer));
    } else {
      r =- 1;
    }

    if (r <= 0) {
      ssh_set_error(session, SSH_FATAL,
          (r == 0) ? "Connection closed by remote host" :
          "Error reading socket");
      ssh_socket_close(session->socket);
      session->alive = 0;

      leave_function();
      return SSH_ERROR;
    }

    if (buffer_add_data(s->in_buffer,buffer, (u32) r) < 0) {
      leave_function();
      return SSH_ERROR;
    }
  } while(buffer_get_rest_len(s->in_buffer) < len);

  leave_function();
  return SSH_OK;
}

#ifdef USE_SELECT
/* ssh_socket_poll, select() version */

/* \internal
 * \brief polls the socket for data
 * \param session ssh session
 * \param writeable value pointed to set to 1 if it is possible to write
 * \param except value pointed to set to 1 if there is an exception
 * \return 1 if it is possible to read, 0 otherwise, -1 on error
 */
int ssh_socket_poll(struct socket *s, int *writeable, int *except) {
  SSH_SESSION *session = s->session;
  struct timeval sometime;
  fd_set rdes; // read set
  fd_set wdes; // writing set
  fd_set edes; // exception set
  int fdmax =- 1;

  enter_function();

  FD_ZERO(&rdes);
  FD_ZERO(&wdes);
  FD_ZERO(&edes);

  if (!ssh_socket_is_open(s)) {
    *except = 1;
    *writeable = 0;
    return 0;
  }
#ifdef SELECT_LIMIT_CHECK
  // some systems don't handle the fds > FD_SETSIZE
  if(s->fd > FD_SETSIZE){
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "File descriptor out of range for select: %d", s->fd);

    leave_function();
    return -1;
  }
#endif
  if (!s->data_to_read) {
    ssh_socket_fd_set(s, &rdes, &fdmax);
  }
  if (!s->data_to_write) {
    ssh_socket_fd_set(s, &wdes, &fdmax);
  }
  ssh_socket_fd_set(s, &edes, &fdmax);

  /* Set to return immediately (no blocking) */
  sometime.tv_sec = 0;
  sometime.tv_usec = 0;

  /* Make the call, and listen for errors */
  if (select(fdmax, &rdes, &wdes, &edes, &sometime) < 0) {
    ssh_set_error(session, SSH_FATAL, "select(): %s", strerror(errno));
    leave_function();
    return -1;
  }

  if (!s->data_to_read) {
    s->data_to_read = ssh_socket_fd_isset(s, &rdes);
  }
  if (!s->data_to_write) {
    s->data_to_write = ssh_socket_fd_isset(s, &wdes);
  }
  if (!s->data_except) {
    s->data_except = ssh_socket_fd_isset(s, &edes);
  }
  *except = s->data_except;
  *writeable = s->data_to_write;

  leave_function();
  return (s->data_to_read || (buffer_get_rest_len(s->in_buffer) > 0));
}
#endif

#ifdef USE_POLL
/* ssh_socket_poll, poll() version */
int ssh_socket_poll(struct socket *s, int *writeable, int *except) {
  SSH_SESSION *session = s->session;
  struct pollfd fd[1];
  int rc = -1;

  enter_function();

  if (!ssh_socket_is_open(s)) {
    *except = 1;
    *writeable = 0;
    return 0;
  }

  fd->fd = s->fd;
  fd->events = 0;

  if (!s->data_to_read) {
    fd->events |= POLLIN;
  }
  if (!s->data_to_write) {
    fd->events |= POLLOUT;
  }

  /* Make the call, and listen for errors */
  rc = poll(fd, 1, 0);
  if (rc < 0) {
    ssh_set_error(session, SSH_FATAL, "poll(): %s", strerror(errno));
    leave_function();
    return -1;
  }

  if (!s->data_to_read) {
    s->data_to_read = fd->revents & POLLIN;
  }
  if (!s->data_to_write) {
    s->data_to_write = fd->revents & POLLOUT;
  }
  if (!s->data_except) {
    s->data_except = fd->revents & POLLERR;
  }

  *except = s->data_except;
  *writeable = s->data_to_write;

  leave_function();
  return (s->data_to_read || (buffer_get_rest_len(s->in_buffer) > 0));
}
#endif

/** \internal
 * \brief nonblocking flush of the output buffer
 */
int ssh_socket_nonblocking_flush(struct socket *s) {
  SSH_SESSION *session = s->session;
  int except;
  int can_write;
  int w;

  enter_function();

  /* internally sets data_to_write */
  if (ssh_socket_poll(s, &can_write, &except) < 0) {
    leave_function();
    return SSH_ERROR;
  }

  if (!ssh_socket_is_open(s)) {
    session->alive = 0;
    /* FIXME use ssh_socket_get_errno */
    ssh_set_error(session, SSH_FATAL,
        "Writing packet: error on socket (or connection closed): %s",
        strerror(errno));

    leave_function();
    return SSH_ERROR;
  }

  while(s->data_to_write && buffer_get_rest_len(s->out_buffer) > 0) {
    if (ssh_socket_is_open(s)) {
      w = ssh_socket_unbuffered_write(s, buffer_get_rest(s->out_buffer),
          buffer_get_rest_len(s->out_buffer));
    } else {
      /* write failed */
      w =- 1;
    }

    if (w < 0) {
      session->alive = 0;
      ssh_socket_close(s);
      /* FIXME use ssh_socket_get_errno() */
      ssh_set_error(session, SSH_FATAL,
          "Writing packet: error on socket (or connection closed): %s",
          strerror(errno));

      leave_function();
      return SSH_ERROR;
    }

    buffer_pass_bytes(s->out_buffer, w);
    /* refresh the socket status */
    if (ssh_socket_poll(session->socket, &can_write, &except) < 0) {
      leave_function();
      return SSH_ERROR;
    }
  }

  /* Is there some data pending? */
  if (buffer_get_rest_len(s->out_buffer) > 0) {
    leave_function();
    return SSH_AGAIN;
  }

  /* all data written */
  leave_function();
  return SSH_OK;
}


/** \internal
 * \brief locking flush of the output packet buffer
 */
int ssh_socket_blocking_flush(struct socket *s) {
  SSH_SESSION *session = s->session;

  enter_function();

  if (!ssh_socket_is_open(s)) {
    session->alive = 0;

    leave_function();
    return SSH_ERROR;
  }

  if (s->data_except) {
    leave_function();
    return SSH_ERROR;
  }

  if (buffer_get_rest_len(s->out_buffer) == 0) {
    leave_function();
    return SSH_OK;
  }

  if (ssh_socket_completewrite(s, buffer_get_rest(s->out_buffer),
        buffer_get_rest_len(s->out_buffer)) != SSH_OK) {
    session->alive = 0;
    ssh_socket_close(s);
    /* FIXME use the proper errno */
    ssh_set_error(session, SSH_FATAL,
        "Writing packet: error on socket (or connection closed): %s",
        strerror(errno));

    leave_function();
    return SSH_ERROR;
  }

  if (buffer_reinit(s->out_buffer) < 0) {
    leave_function();
    return SSH_ERROR;
  }

  leave_function();
  return SSH_OK; // no data pending
}

void ssh_socket_set_towrite(struct socket *s) {
  s->data_to_write = 1;
}

void ssh_socket_set_toread(struct socket *s) {
  s->data_to_read = 1;
}

void ssh_socket_set_except(struct socket *s) {
  s->data_except = 1;
}

int ssh_socket_data_available(struct socket *s) {
  return s->data_to_read;
}

int ssh_socket_data_writable(struct socket *s) {
  return s->data_to_write;
}

int ssh_socket_get_status(struct socket *s) {
  int r = 0;

  if (s->data_to_read) {
    r |= SSH_READ_PENDING;
  }

  if (s->data_except) {
    r |= SSH_CLOSED_ERROR;
  }

  return r;
}

/** @}
 */
/* vim: set ts=2 sw=2 et cindent: */
