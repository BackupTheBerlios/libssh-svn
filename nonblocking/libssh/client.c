/* client.c file */
/*
Copyright 2003-2005 Aris Adamantiadis

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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/session.h"
#include "libssh/connect.h"
#include "libssh/dh.h"

#include "libssh/wrapper.h"

extern int connections;

#define set_status(opt,status) do {\
        if (opt->connect_status_function) \
            opt->connect_status_function(opt->connect_status_arg, status); \
    } while (0)
/* simply gets a banner from a socket */

char *ssh_get_banner(SSH_SESSION *session){
    char buffer[128];
    int i = 0;
    while (i < 127) {
        if(read(session->fd, &buffer[i], 1)<=0){
            ssh_set_error(session,SSH_FATAL,"Remote host closed connection");
            return NULL;
        }
        if (buffer[i] == '\r')
            buffer[i] = 0;
        if (buffer[i] == '\n') {
            buffer[i] = 0;
            return strdup(buffer);
        }
    i++;
    }
    ssh_set_error(session,SSH_FATAL,"Too large banner");
    return NULL;
}

int ssh_analyze_banner(SSH_SESSION *session, int *ssh1, int *ssh2)
{
    char *banner=session->serverbanner;
    if(strncmp(banner,"SSH-",4)!=0){
        ssh_set_error(session,SSH_FATAL,"Protocol mismatch: %s",banner);
        return -1;
    }
    /* a typical banner is :
     * SSH-1.5-blah
     * SSH-1.99-blah
     * SSH-2.0-blah
     */
    switch(banner[4]){
        case '1':
            *ssh1=1;
            if(banner[6]=='9')
                *ssh2=1;
            else
                *ssh2=0;
            break;
        case '2':
            *ssh1=0;
            *ssh2=1;
            break;
        default:
            ssh_set_error(session,SSH_FATAL,"Protocol mismatch: %s",banner);
            return -1;
    }
    return 0;
}

/* ssh_send_banner sends a SSH banner to the server */
/* TODO select a banner compatible with server version */
/* switch SSH1/1.5/2 */
/* and quit when the server is SSH1 only */

int ssh_send_banner(SSH_SESSION *session,int server)
{
	char *banner;
	char buffer[128];
	banner=session->version==1?CLIENTBANNER1:CLIENTBANNER2;
	if ( session->options->banner )
		banner=session->options->banner;
	if ( server )
		session->serverbanner=strdup(banner);
	else
		session->clientbanner=strdup(banner);
	snprintf(buffer,128,"%s\r\n",banner);
	write(session->fd,buffer,strlen(buffer));
	return 0;
}

#define DH_STATE_INIT 0
#define DH_STATE_INIT_TO_SEND 1
#define DH_STATE_INIT_SENT 2
#define DH_STATE_NEWKEYS_TO_SEND 3
#define DH_STATE_NEWKEYS_SENT 4
#define DH_STATE_FINISHED 5
static int dh_handshake(SSH_SESSION *session)
{
	logPF();

    STRING *e,*f,*pubkey,*signature;
    int ret;
    switch(session->dh_handshake_state){
        case DH_STATE_INIT:
            packet_clear_out(session);
            buffer_add_u8(session->out_buffer,SSH2_MSG_KEXDH_INIT);
            dh_generate_x(session);
            dh_generate_e(session);
            e=dh_get_e(session);
            buffer_add_ssh_string(session->out_buffer,e);
            ret=packet_send(session);
            free(e);
            session->dh_handshake_state=DH_STATE_INIT_TO_SEND;
            if(ret==SSH_ERROR)
                return ret;
        case DH_STATE_INIT_TO_SEND:
            ret=packet_flush(session);	// FIXME BLOCKING
            if(ret!=SSH_OK)
                return ret; // SSH_ERROR or SSH_AGAIN
            session->dh_handshake_state=DH_STATE_INIT_SENT;
        case DH_STATE_INIT_SENT:
            ret=packet_wait(session,SSH2_MSG_KEXDH_REPLY);// FIXME BLOCKING
            if(ret != SSH_OK)
                return ret;
            pubkey=buffer_get_ssh_string(session->in_buffer);
            if(!pubkey){
                ssh_set_error(session,SSH_FATAL,"No public key in packet");
                return SSH_ERROR;
            }
            dh_import_pubkey(session,pubkey);
            f=buffer_get_ssh_string(session->in_buffer);
            if(!f){
                ssh_set_error(session,SSH_FATAL,"No F number in packet");
                return SSH_ERROR;
            }
            dh_import_f(session,f);
            free(f);
            if(!(signature=buffer_get_ssh_string(session->in_buffer))){
                ssh_set_error(session,SSH_FATAL,"No signature in packet");
                return SSH_ERROR;
            }
            session->dh_server_signature=signature;
            dh_build_k(session);
            // send the MSG_NEWKEYS
            packet_clear_out(session);
            buffer_add_u8(session->out_buffer,SSH2_MSG_NEWKEYS);
            packet_send(session);
            session->dh_handshake_state=DH_STATE_NEWKEYS_TO_SEND;
        case DH_STATE_NEWKEYS_TO_SEND:
            ret=packet_flush(session);// FIXME BLOCKING
            if(ret != SSH_OK)
                return ret;
            ssh_say(2,"SSH_MSG_NEWKEYS sent\n");
            session->dh_handshake_state=DH_STATE_NEWKEYS_SENT;
        case DH_STATE_NEWKEYS_SENT:
            ret=packet_wait(session,SSH2_MSG_NEWKEYS);// FIXME BLOCKING
            if(ret != SSH_OK)
                return ret;
            ssh_say(2,"Got SSH_MSG_NEWKEYS\n");
            make_sessionid(session);
            /* set the cryptographic functions for the next crypto */
            /* (it is needed for generate_session_keys for key lenghts) */
            if(crypt_set_algorithms(session))
                return SSH_ERROR;
            generate_session_keys(session);
            /* verify the host's signature. XXX do it sooner */
            signature=session->dh_server_signature;
            session->dh_server_signature=NULL;
            if(signature_verify(session,signature)){
                free(signature);
                return SSH_ERROR;
            }
            free(signature);	/* forget it for now ... */
            /* once we got SSH2_MSG_NEWKEYS we can switch next_crypto and current_crypto */
            if(session->current_crypto)
                crypto_free(session->current_crypto);
                /* XXX later, include a function to change keys */
            session->current_crypto=session->next_crypto;
            session->next_crypto=crypto_new();
            session->dh_handshake_state=DH_STATE_FINISHED;
            return SSH_OK;
        default:
            ssh_set_error(session,SSH_FATAL,"Invalid state in dh_handshake():%d",session->dh_handshake_state);
            return SSH_ERROR;
    }
    /* not reached */
    return SSH_ERROR;
}

int ssh_service_request(SSH_SESSION *session,char *service)
{
	logPF();

    STRING *service_s;
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH2_MSG_SERVICE_REQUEST);
    service_s=string_from_char(service);
    buffer_add_ssh_string(session->out_buffer,service_s);
    free(service_s);
    packet_send(session);
    ssh_say(3,"Sent SSH_MSG_SERVICE_REQUEST (service %s)\n",service);
    while(packet_wait(session,SSH2_MSG_SERVICE_ACCEPT) != SSH_OK);// FIXME BLOCKING BAD HACK
/*
	{
        ssh_set_error(session,SSH_FATAL,"did not receive SERVICE_ACCEPT");
        return -1;
    }
*/	
    ssh_say(3,"Received SSH_MSG_SERVICE_ACCEPT (service %s)\n",service);
    return 0;
}



ssh_retval ssh_connect_nonblocking(SSH_SESSION *session)
{
	ssh_retval retval = SSH_ERROR;

	switch (session->state)
	{
	case SSH_STATE_NONE:
		{
            session->fd ==socket(AF_INET, SOCK_STREAM, 0);
			if ( session->fd <= 0 )
			{
				ssh_set_error(session,SSH_FATAL,"socket : %s",strerror(errno));
				return SSH_ERROR;
			}

			struct sockaddr_in addrBind;
			addrBind.sin_family = AF_INET;

			addrBind.sin_addr.s_addr 	= session->options->localhost;
			addrBind.sin_port 			= htons(session->options->localport);

			if ( bind(session->fd, (struct sockaddr *) &addrBind, sizeof(addrBind)) < 0 )
			{
				ssh_set_error(session,SSH_FATAL,"Binding local address %s:%i : %s",
							  inet_ntoa(*(struct in_addr *)&session->options->localhost),
							  session->options->localport,
							  strerror(errno));
				close(session->fd);
				return SSH_ERROR;
			}

			

			struct sockaddr_in addrConnect;
			addrConnect.sin_family 		= AF_INET;
			addrConnect.sin_addr.s_addr	= session->options->remotehost;
			addrConnect.sin_port		= htons(session->options->remoteport);
			

			fcntl(session->fd, F_SETFL, O_NONBLOCK);

			int ret = connect(session->fd,(struct sockaddr*)&addrConnect,sizeof(struct sockaddr_in));

			if ( ret  == 0 )
			{
				retval = SSH_OK;
				break;
			}else
			{
				switch (errno)
				{	/* we can  handle things like connection refused etc here */
				case EINPROGRESS:
					retval = SSH_AGAIN;
					break;

				case EISCONN:
					retval = SSH_OK;
					break;

				default:
					retval = SSH_ERROR;
				}
			}

		}
		break;

	case SSH_STATE_CONNECTING:
		{
			int32_t iError = 0;
			int32_t iSize = sizeof(iError);
			if ( getsockopt(session->fd, SOL_SOCKET, SO_ERROR, &iError,(socklen_t *) &iSize) != 0 )
			{
				retval = SSH_ERROR;
			} else
			{
				switch ( iError )
				{
				case 0:	// der socket is soweit okay
				case EISCONN:
					retval = SSH_OK;
					break;

				case EINPROGRESS: // der socket versuchts
					retval = SSH_AGAIN;
					break;

				default:
					retval = SSH_ERROR;
				}
			}
		}
		break;

	default:
		ssh_say(1,"%s:%i unwanted state %i\n",__PRETTY_FUNCTION__,__LINE__,session->state);
	}

	return retval;
}





/**
 * receive the remotes ssh banner nonblocking, 
 * store it in the incoming buffer
 * 
 * @param session the session
 * 
 * @return SSH_OK if the banner is complete
 *         SSH_AGAIN if the banner is incomplete
 *         SSH_ERROR if an (socket) error showed up
 */
ssh_retval ssh_banner_get_nonblocking(SSH_SESSION *session)
{
	ssh_retval retval = SSH_AGAIN;

	if ( socket_read(session,256) == SSH_ERROR )
		return SSH_ERROR;

	int len = buffer_get_rest_len(session->in_socket_buffer);
	char *c = (char *)buffer_get(session->in_socket_buffer);

	if (*(c + len) == '\n' && *(c + len -1) == '\r' )
	{
		ssh_say(1,"found banner\n%s\n",c);
		retval = SSH_OK;
	}
	return retval;
	
}



ssh_retval ssh_banner_get(SSH_SESSION *session)
{
	if (session->options->blocking == 1)
	{

	}else
	{
		return ssh_banner_get_nonblocking(session);
	}
}



ssh_retval ssh_again(SSH_SESSION *session)
{
	ssh_retval retval;

	switch (session->state)
	{

	case SSH_STATE_NONE:
	case SSH_STATE_CONNECTING:
		retval = ssh_connect(session);
		if (retval == SSH_OK)
		{
        	session->state = SSH_STATE_CONNECTED;
		}
		break;

	case SSH_STATE_CONNECTED:
		/* here we call the connect callback */
		session->state = SSH_STATE_BANNER_RECEIVE;
		break;

	case SSH_STATE_BANNER_RECEIVE:
		if (ssh_banner_get(session) == SSH_OK )
		{
			//
		}
		break;

	case SSH_STATE_BANNER_SEND:
		break;
	}
}



/**
 * check if the SSH_SESSION has things to send
 * 
 * @param session the session
 * 
 * @return returns 1 if the session has things to send, else 0
 */
int ssh_want_send(SSH_SESSION *session) 
{
	if (buffer_get_rest_len(session->out_socket_buffer) > 0 )
	{
		return 1;
	}else
	{
		return 0;
	}
}





int ssh_connect(SSH_SESSION *session)
{
	if(session->options->blocking)
	{
		
	}else
	{
		return ssh_connect_nonblocking(session);
	}
}

char *ssh_get_issue_banner(SSH_SESSION *session){
    if(!session->banner)
        return NULL;
    return string_to_char(session->banner);
}

void ssh_disconnect(SSH_SESSION *session){
    STRING *str;
    if(session->fd!= -1) {
        packet_clear_out(session);
        buffer_add_u8(session->out_buffer,SSH2_MSG_DISCONNECT);
        buffer_add_u32(session->out_buffer,htonl(SSH2_DISCONNECT_BY_APPLICATION));
        str=string_from_char("Bye Bye");
        buffer_add_ssh_string(session->out_buffer,str);
        free(str);
        packet_send(session);
        close(session->fd);
        session->fd=-1;
    }
    session->alive=0;
    ssh_cleanup(session);
    if (!--connections)
#ifdef HAVE_LIBGCRYPT
      gcry_control(GCRYCTL_TERM_SECMEM);
#elif defined HAVE_LIBCRYPTO
      EVP_cleanup();
#endif
}

const char *ssh_copyright(){
    return LIBSSH_VERSION " (c) 2003-2005 Aris Adamantiadis (aris@0xbadc0de.be)"
    " Distributed under the LGPL, please refer to COPYING file for informations"
    " about your rights" ;
}
