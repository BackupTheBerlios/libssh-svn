#ifndef HAVE_LIBSSH_SESSION_H
#define HAVE_LIBSSH_SESSION_H

#include "options.h"
#include "buffer.h"
#include "kex.h"
#include "string.h"
#include "crypt.h"
#include "channel.h"
#include "packet.h"
#include "errors.h"
#include "keys.h"

struct ssh_session {
    struct error_struct error;
    int fd;
    SSH_OPTIONS *options;
    char *serverbanner;
    char *clientbanner;
    int protoversion;
    int server;
    int client;
    u32 send_seq;
    u32 recv_seq;
/* status flags */

	ssh_state_t 	state;

	STRING 	*autopubkey_pubkey;
	int		autopubkey_counter;	/* needed for ssh_userauth_autopubkey */
	int 	autopubkey_type;
	char 	*autopubkey_privkeyfile;

    int closed;
    int closed_by_except;
    
    int connected; 
    /* !=0 when the user got a session handle */
    int alive;
    /* two previous are deprecated */
    int auth_service_asked;
    
/* socket status */
    int data_to_read; /* reading now on socket will 
                         not block */
    int data_to_write;
    int data_except;
    int blocking; // functions should block
    
    STRING *banner; /* that's the issue banner from 
                       the server */
    char *remotebanner; /* that's the SSH- banner from
                           remote host. */
    char *discon_msg; /* disconnect message from 
                         the remote host */
    BUFFER *in_buffer;
    PACKET in_packet;
    BUFFER *out_buffer;
    
    BUFFER *out_socket_buffer;
    BUFFER *in_socket_buffer;
    
    /* the states are used by the nonblocking stuff to remember */
    /* where it was before being interrupted */
    int packet_state;
    int dh_handshake_state;
    STRING *dh_server_signature; //information used by dh_handshake.
    
    KEX server_kex;
    KEX client_kex;
    BUFFER *in_hashbuf;
    BUFFER *out_hashbuf;
    CRYPTO *current_crypto;
    CRYPTO *next_crypto;  /* next_crypto is going to be used after a SSH2_MSG_NEWKEYS */

    int channel_bytes_toread; /* left number of bytes 
                                 in the channel buffers
                                 */
    CHANNEL *channels; /* linked list of channels */
    int maxchannel;
    int exec_channel_opened; /* version 1 only. more 
                                info in channels1.c */

/* keyb interactive data */
    struct ssh_kbdint *kbdint;
    int version; /* 1 or 2 */
    /* server host keys */
    PRIVATE_KEY *rsa_key;
    PRIVATE_KEY *dsa_key;
    /* auths accepted by server */
    int auth_methods; 
    int hostkeys; /* contains type of host key wanted by client, in server impl */
    struct ssh_message *ssh_message; /* ssh message */
};


/* session.c */
SSH_SESSION *ssh_new();
void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options);
int ssh_get_fd(SSH_SESSION *session);
void ssh_silent_disconnect(SSH_SESSION *session);
int ssh_get_version(SSH_SESSION *session);
void ssh_set_fd_toread(SSH_SESSION *session);
void ssh_set_fd_towrite(SSH_SESSION *session);
void ssh_set_fd_except(SSH_SESSION *session);
/* session.c */

void ssh_cleanup(SSH_SESSION *session);


void make_sessionid(SSH_SESSION *session);
/* add data for the final cookie */
void hashbufin_add_cookie(SSH_SESSION *session,unsigned char *cookie);
void hashbufout_add_cookie(SSH_SESSION *session);
void generate_session_keys(SSH_SESSION *session);
/* returns 1 if server signature ok, 0 otherwise. The NEXT crypto is checked, not the current one */
int signature_verify(SSH_SESSION *session,STRING *signature);






#endif
