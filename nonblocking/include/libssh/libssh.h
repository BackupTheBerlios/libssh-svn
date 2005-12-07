/*
Copyright 2003,04 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

#ifndef _LIBSSH_H
#define _LIBSSH_H
#include <unistd.h>
#include <sys/select.h> /* for fd_set * */
#include <inttypes.h>

#define LIBSSH_VERSION "libssh-0.2-dev"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct channel_struct CHANNEL;
typedef struct ssh_session SSH_SESSION;
typedef struct ssh_kbdint SSH_KBDINT;



/* the offsets of methods */
#define SSH_KEX 0
#define SSH_HOSTKEYS 1
#define SSH_CRYPT_C_S 2
#define SSH_CRYPT_S_C 3
#define SSH_MAC_C_S 4
#define SSH_MAC_S_C 5
#define SSH_COMP_C_S 6
#define SSH_COMP_S_C 7
#define SSH_LANG_C_S 8
#define SSH_LANG_S_C 9

#define SSH_CRYPT 2
#define SSH_MAC 3
#define SSH_COMP 4
#define SSH_LANG 5

#define SSH_AUTH_SUCCESS 0
#define SSH_AUTH_DENIED 1
#define SSH_AUTH_PARTIAL 2
#define SSH_AUTH_INFO 3
#define SSH_AUTH_ERROR -1

/* status flags */

#define SSH_CLOSED (1<<0)
#define SSH_READ_PENDING (1<<1)
#define SSH_CLOSED_ERROR (1<<2)

#define SSH_SERVER_ERROR -1
#define SSH_SERVER_NOT_KNOWN 0
#define SSH_SERVER_KNOWN_OK 1
#define SSH_SERVER_KNOWN_CHANGED 2
#define SSH_SERVER_FOUND_OTHER 3

#ifndef MD5_DIGEST_LEN
    #define MD5_DIGEST_LEN 16
#endif
/* errors */

#define SSH_NO_ERROR 0
#define SSH_REQUEST_DENIED 1
#define SSH_FATAL 2
#define SSH_EINTR 3

/* error return codes */
typedef enum
{
	SSH_ERROR=-1, 	/* error of some kind */
	SSH_OK=0,     /* No error */
	SSH_AGAIN=1,  /* the nonblocking call must be repeated */
}ssh_retval;


 /* There is a verbosity level */
 /* 3 : packet level */
 /* 2 : protocol level */
 /* 1 : functions level */
 /* 0 : important messages only */
 /* -1 : no messages */




/* deprecated */
void ssh_crypto_init();

/* useful for debug */
void ssh_print_hexa(char *descr,unsigned char *what, int len);
int ssh_get_random(void *where,int len,int strong);


/* in connect.c */


int ssh_is_server_known(SSH_SESSION *session);
int ssh_write_knownhost(SSH_SESSION *session);






#ifdef __cplusplus
} ;
#endif
#endif /* _LIBSSH_H */
