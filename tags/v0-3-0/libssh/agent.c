/*
 * agent.c - ssh agent functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
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

/* This file is based on authfd.c from OpenSSH */

/*
 * How does the ssh-agent work?
 *
 * a) client sends a request to get a list of all keys
 *    the agent returns the cound and all public keys
 * b) iterate over them to check if the server likes one
 * c) the client sends a sign request to the agent
 *    type, pubkey as blob, data to sign, flags
 *    the agent returns the signed data
 */

#ifndef _WIN32

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <poll.h>
#include <unistd.h>

#include "libssh/agent.h"
#include "libssh/priv.h"

/* macro to check for "agent failure" message */
#define agent_failed(x) \
  (((x) == SSH_AGENT_FAILURE) || ((x) == SSH_COM_AGENT2_FAILURE) || \
   ((x) == SSH2_AGENT_FAILURE))

static u32 agent_get_u32(const void *vp) {
  const u8 *p = (const u8 *)vp;
  u32 v;

  v  = (u32)p[0] << 24;
  v |= (u32)p[1] << 16;
  v |= (u32)p[2] << 8;
  v |= (u32)p[3];

  return v;
}

static void agent_put_u32(void *vp, u32 v) {
  u8 *p = (u8 *)vp;

  p[0] = (u8)(v >> 24) & 0xff;
  p[1] = (u8)(v >> 16) & 0xff;
  p[2] = (u8)(v >> 8) & 0xff;
  p[3] = (u8)v & 0xff;
}

static size_t atomicio(struct socket *s, void *buf, size_t n, int do_read) {
  char *b = buf;
  size_t pos = 0;
  ssize_t res;
  struct pollfd pfd;
  int fd = ssh_socket_get_fd(s);

  pfd.fd = fd;
  pfd.events = do_read ? POLLIN : POLLOUT;

  while (n > pos) {
    if (do_read) {
      res = read(fd, b + pos, n - pos);
    } else {
      res = write(fd, b + pos, n - pos);
    }
    switch (res) {
      case -1:
        if (errno == EINTR) {
          continue;
        }
#ifdef EWOULDBLOCK
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
#else
        if (errno == EAGAIN) {
#endif
          (void) poll(&pfd, 1, -1);
          continue;
        }
        return 0;
    case 0:
      errno = EPIPE;
      return pos;
    default:
      pos += (size_t) res;
    }
  }

  return pos;
}

AGENT *agent_new(struct ssh_session *session) {
  AGENT *agent = NULL;

  agent = malloc(sizeof(AGENT));
  if (agent == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(agent);

  agent->count = 0;
  agent->sock = ssh_socket_new(session);
  if (agent->sock == NULL) {
    SAFE_FREE(agent);
    return NULL;
  }

  return agent;
}

void agent_close(struct agent_struct *agent) {
  if (agent == NULL) {
    return;
  }

  if (getenv("SSH_AUTH_SOCK")) {
    ssh_socket_close(agent->sock);
  }
}

void agent_free(AGENT *agent) {
  if (agent) {
    if (agent->ident) {
      buffer_free(agent->ident);
    }
    if (agent->sock) {
      agent_close(agent);
      ssh_socket_free(agent->sock);
    }
    SAFE_FREE(agent);
  }
}

static int agent_connect(SSH_SESSION *session) {
  const char *auth_sock = NULL;

  if (session == NULL || session->agent == NULL) {
    return -1;
  }

  auth_sock = getenv("SSH_AUTH_SOCK");

  if (auth_sock && *auth_sock) {
    if (ssh_socket_unix(session->agent->sock, auth_sock) < 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

#if 0
static int agent_decode_reply(struct ssh_session *session, int type) {
  switch (type) {
    case SSH_AGENT_FAILURE:
    case SSH2_AGENT_FAILURE:
    case SSH_COM_AGENT2_FAILURE:
      ssh_log(session, SSH_LOG_RARE, "SSH_AGENT_FAILURE");
      return 0;
    case SSH_AGENT_SUCCESS:
      return 1;
    default:
      ssh_set_error(session, SSH_FATAL,
          "Bad response from authentication agent: %d", type);
      break;
  }

  return -1;
}
#endif

static int agent_talk(struct ssh_session *session,
    struct buffer_struct *request, struct buffer_struct *reply) {
  u32 len = 0;
  u8 payload[1024] = {0};

  len = buffer_get_len(request);
  ssh_log(session, SSH_LOG_PACKET, "agent_talk - len of request: %u", len);
  agent_put_u32(payload, len);

  /* send length and then the request packet */
  if (atomicio(session->agent->sock, payload, 4, 0) == 4) {
    buffer_get_data(request, payload, len);
    ssh_log(session, SSH_LOG_PACKET,
        "agent_talk - sending request, payload[0] = %u", payload[0]);
    if (atomicio(session->agent->sock, payload, len, 0)
        != len) {
      ssh_log(session, SSH_LOG_PACKET, "atomicio sending request failed: %s",
          strerror(errno));
      return -1;
    }
  } else {
    ssh_log(session, SSH_LOG_PACKET,
        "atomicio sending request length failed: %s",
        strerror(errno));
    return -1;
  }

  /* wait for response, read the length of the response packet */
  if (atomicio(session->agent->sock, payload, 4, 1) != 4) {
    ssh_log(session, SSH_LOG_PACKET, "atomicio read response length failed: %s",
        strerror(errno));
    return -1;
  }

  len = agent_get_u32(payload);
  if (len > 256 * 1024) {
    ssh_set_error(session, SSH_FATAL,
        "Authentication response too long: %u", len);
    return -1;
  }
  ssh_log(session, SSH_LOG_PACKET, "agent_talk - response length: %u", len);

  while (len > 0) {
    size_t n = len;
    if (n > sizeof(payload)) {
      n = sizeof(payload);
    }
    if (atomicio(session->agent->sock, payload, n, 1) != n) {
      ssh_log(session, SSH_LOG_RARE,
          "Error reading response from authentication socket.");
      return -1;
    }
    if (buffer_add_data(reply, payload, n) < 0) {
      ssh_log(session, SSH_LOG_FUNCTIONS,
          "Not enough space");
      return -1;
    }
    len -= n;
  }

  return 0;
}

int agent_get_ident_count(struct ssh_session *session) {
  BUFFER *request = NULL;
  BUFFER *reply = NULL;
  unsigned int type = 0;
  unsigned int c1 = 0, c2 = 0;
  u8 buf[4] = {0};

  switch (session->version) {
    case 1:
      c1 = SSH_AGENTC_REQUEST_RSA_IDENTITIES;
      c2 = SSH_AGENT_RSA_IDENTITIES_ANSWER;
      break;
    case 2:
      c1 = SSH2_AGENTC_REQUEST_IDENTITIES;
      c2 = SSH2_AGENT_IDENTITIES_ANSWER;
      break;
    default:
      return 0;
  }

  /* send message to the agent requesting the list of identities */
  request = buffer_new();
  if (buffer_add_u8(request, c1) < 0) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    return -1;
  }

  reply = buffer_new();
  if (reply == NULL) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    return -1;
  }

  if (agent_talk(session, request, reply) < 0) {
    buffer_free(request);
    return 0;
  }
  buffer_free(request);

  /* get message type and verify the answer */
  buffer_get_u8(reply, (u8 *) &type);
  ssh_log(session, SSH_LOG_PACKET,
      "agent_ident_count - answer type: %d, expected answer: %d",
      type, c2);
  if (agent_failed(type)) {
    return 0;
  } else if (type != c2) {
    ssh_set_error(session, SSH_FATAL,
        "Bad authentication reply message type: %d", type);
    return -1;
  }

  buffer_get_u32(reply, (u32 *) buf);
  session->agent->count = agent_get_u32(buf);
  ssh_log(session, SSH_LOG_PACKET, "agent_ident_count - count: %d",
      session->agent->count);
  if (session->agent->count > 1024) {
    ssh_set_error(session, SSH_FATAL,
        "Too many identities in authentication reply: %d",
        session->agent->count);
    buffer_free(reply);
    return -1;
  }

  if (session->agent->ident) {
    buffer_free(session->agent->ident);
  }
  session->agent->ident = reply;

  return session->agent->count;
}

/* caller has to free commment */
struct public_key_struct *agent_get_first_ident(struct ssh_session *session,
    char **comment) {
  if (agent_get_ident_count(session) > 0) {
    return agent_get_next_ident(session, comment);
  }

  return NULL;
}

/* caller has to free commment */
struct public_key_struct *agent_get_next_ident(struct ssh_session *session,
    char **comment) {
  struct public_key_struct *pubkey = NULL;
  struct string_struct *blob = NULL;
  struct string_struct *tmp = NULL;

  if (session->agent->count == 0) {
    return NULL;
  }

  switch(session->version) {
    case 1:
      return NULL;
    case 2:
      /* get the blob */
      blob = buffer_get_ssh_string(session->agent->ident);
      if (blob == NULL) {
        return NULL;
      }

      /* get the comment */
      tmp = buffer_get_ssh_string(session->agent->ident);
      if (tmp == NULL) {
        string_free(blob);

        return NULL;
      }

      if (comment) {
        *comment = string_to_char(tmp);
      } else {
        string_free(blob);
        string_free(tmp);

        return NULL;
      }
      string_free(tmp);

      /* get key from blob */
      pubkey = publickey_from_string(session, blob);
      string_free(blob);
      break;
    default:
      return NULL;
  }

  return pubkey;
}

STRING *agent_sign_data(struct ssh_session *session,
    struct buffer_struct *data,
    struct public_key_struct *pubkey) {
  struct string_struct *blob = NULL;
  struct string_struct *sig = NULL;
  struct buffer_struct *request = NULL;
  struct buffer_struct *reply = NULL;
  int type = SSH2_AGENT_FAILURE;
  int flags = 0;
  u32 dlen = 0;

  /* create blob from the pubkey */
  blob = publickey_to_string(pubkey);

  request = buffer_new();
  if (request == NULL) {
    goto error;
  }

  /* create request */
  if (buffer_add_u8(request, SSH2_AGENTC_SIGN_REQUEST) < 0) {
    goto error;
  }

  /* adds len + blob */
  if (buffer_add_ssh_string(request, blob) < 0) {
    goto error;
  }

  /* Add data */
  dlen = buffer_get_len(data);
  if (buffer_add_u32(request, htonl(dlen)) < 0) {
    goto error;
  }
  if (buffer_add_data(request, buffer_get(data), dlen) < 0) {
    goto error;
  }

  if (buffer_add_u32(request, htonl(flags)) < 0) {
    goto error;
  }

  string_free(blob);

  reply = buffer_new();
  if (reply == NULL) {
    goto error;
  }

  /* send the request */
  if (agent_talk(session, request, reply) < 0) {
    buffer_free(request);
    return NULL;
  }
  buffer_free(request);

  /* check if reply is valid */
  if (buffer_get_u8(reply, (u8 *) &type) < 0) {
    goto error;
  }
  if (agent_failed(type)) {
    ssh_log(session, SSH_LOG_RARE, "Agent reports failure in signing the key");
    buffer_free(reply);
    return NULL;
  } else if (type != SSH2_AGENT_SIGN_RESPONSE) {
    ssh_set_error(session, SSH_FATAL, "Bad authentication response: %d", type);
    buffer_free(reply);
    return NULL;
  }

  sig = buffer_get_ssh_string(reply);

  buffer_free(reply);

  return sig;
error:
  ssh_set_error(session, SSH_FATAL, "Not enough memory");
  string_free(blob);
  buffer_free(request);
  buffer_free(reply);

  return NULL;
}

int agent_is_running(SSH_SESSION *session) {
  if (session == NULL || session->agent == NULL) {
    return 0;
  }

  if (ssh_socket_is_open(session->agent->sock)) {
    return 1;
  } else {
    if (agent_connect(session) < 0) {
      return 0;
    } else {
      return 1;
    }
  }

  return 0;
}

#endif /* _WIN32 */

/* vim: set ts=2 sw=2 et cindent: */
