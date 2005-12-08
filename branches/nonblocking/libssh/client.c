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

#define _GNU_SOURCE

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

#include "libssh/client.h"

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/session.h"
#include "libssh/connect.h"
#include "libssh/dh.h"

#include "libssh/wrapper.h"

#include "libssh/socket.h"

extern int connections;

#define set_status(opt,status) do {\
        if (opt->connect_status_function) \
            opt->connect_status_function(opt->connect_status_arg, status); \
    } while (0)



ssh_retval ssh_banner_analyze(SSH_SESSION *session, int *ssh1, int *ssh2)
{
	logPF();

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



int dh_handshake(SSH_SESSION *session)
{
	logPF();
	ssh_say(1,"\tstate %i\n",session->state);

    STRING *e,*f,*pubkey,*signature=NULL;
    ssh_retval ret;
    switch(session->state)
	{
        case SSH_STATE_DH_INIT_SEND:
            packet_clear_out(session);
            buffer_add_u8(session->out_buffer,SSH2_MSG_KEXDH_INIT);
            dh_generate_x(session);
            dh_generate_e(session);
            e=dh_get_e(session);
            buffer_add_ssh_string(session->out_buffer,e);
            ret=packet_send(session);

            return ret;
			break;

        case SSH_STATE_DH_INIT_SENDING:
            ret=packet_flush(session);	// FIXME BLOCKING
            return ret; // SSH_ERROR or SSH_AGAIN

//			session->dh_handshake_state=SSH_STATE_DH_INIT_SENT;

        case SSH_STATE_DH_INIT_READ:
            ret=packet_wait(session,SSH2_MSG_KEXDH_REPLY);// FIXME BLOCKING
            if(ret != SSH_OK)
                return ret;

			pubkey=buffer_get_ssh_string(session->in_buffer);
            if(!pubkey)
			{
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
			return SSH_OK;

		case SSH_STATE_DH_NEWKEYS_SEND:
            
            // send the MSG_NEWKEYS
            packet_clear_out(session);
            buffer_add_u8(session->out_buffer,SSH2_MSG_NEWKEYS);
            return packet_send(session);
//            session->dh_handshake_state=SSH_STATE_DH_NEWKEYS_TO_SEND;
			

	case SSH_STATE_DH_NEWKEYS_SENDING:
		ssh_say(1,"\tcase PRE SSH_STATE_DH_NEWKEYS_SENDING:\n");
            ret = packet_flush(session);
			ssh_say(1,"\tcase POST SSH_STATE_DH_NEWKEYS_SENDING:\n");
			if (ret == SSH_OK )
			{
				ssh_say(2,"SSH_MSG_NEWKEYS sent\n");
			}
			
			return ret;
			
			break;

	case SSH_STATE_DH_NEWKEYS_READ:
		ssh_say(1,"\tcase SSH_STATE_DH_NEWKEYS_READ:\n");
            ret=packet_wait(session,SSH2_MSG_NEWKEYS);// FIXME BLOCKING
            if(ret != SSH_OK)
                return ret;
            ssh_say(2,"Got SSH_MSG_NEWKEYS\n");
            make_sessionid(session);
            /* set the cryptographic functions for the next crypto */
            /* (it is needed for generate_session_keys for key lenghts) */
            if(crypt_set_algorithms(session))
			{
				printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
				return SSH_ERROR;
			}

            generate_session_keys(session);
            /* verify the host's signature. XXX do it sooner */
            signature=session->dh_server_signature;
            session->dh_server_signature=NULL;
            if(signature_verify(session,signature))
			{
				ssh_say(1,"\t signature is broken\n");
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
//            session->dh_handshake_state=SSH_STATE_DH_FINISHED;
            return SSH_OK;
        default:
            ssh_set_error(session,SSH_FATAL,"Invalid state in dh_handshake():%d",session->state);
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
	logPF();
	ssh_retval retval = SSH_ERROR;

	switch (session->state)
	{
	case SSH_STATE_NONE:
		{
            session->fd = socket(AF_INET, SOCK_STREAM, 0);
			if ( session->fd <= 0 )
			{
				ssh_set_error(session,SSH_FATAL,"socket : %s",strerror(errno));
				return SSH_ERROR;
			}

			struct sockaddr_in addrBind;
			addrBind.sin_family = AF_INET;

			addrBind.sin_addr.s_addr 	= session->options->localhost;
			addrBind.sin_port 			= 0;//htons(session->options->localport);

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
	ssh_say(1,"\t ssh_connect_nonblocking returns %i\n",retval);
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
	logPF();

	ssh_retval retval = SSH_AGAIN;

	retval = socket_read(session,2560);

	ssh_say(1,"sh_banner_get_nonblocking socket_read %i\n",retval);

	if (retval == SSH_ERROR || session->in_socket_buffer == NULL)
	{
		return retval;
	}

	retval = SSH_AGAIN; 

	int len = buffer_get_rest_len(session->in_socket_buffer);
	char *c = (char *)buffer_get(session->in_socket_buffer);

	ssh_say(1,"\t banner size %i\n\"%.*s\"\n\n",len,len,c);


	int i;
	for (i=0;i<len;i++)
	{
		if ((c[i] == '\n' || c[i] == '\r') && i > 2)
		{
			ssh_say(1,"found banner\n%s\n",c);
			session->serverbanner = strndup(c,i);
			buffer_reinit(session->in_socket_buffer);
			retval = SSH_OK;
		}
	}
	return retval;
	
}


ssh_retval ssh_banner_get(SSH_SESSION *session)
{
	if (session->options->blocking == 1)
	{
		return SSH_ERROR;
	}else
	{
		return ssh_banner_get_nonblocking(session);
	}
}



ssh_retval ssh_banner_send_nonblocking(SSH_SESSION *session)
{
	ssh_retval retval;

	switch ( session->state )
	{
	case SSH_STATE_BANNER_SEND:
		{
			
			char *banner;
			banner=session->version==1?CLIENTBANNER1:CLIENTBANNER2;
			char buffer[128];
			banner=session->version==1?CLIENTBANNER1:CLIENTBANNER2;
			if ( session->options->banner )
				banner=session->options->banner;

			session->clientbanner=strdup(banner);
			snprintf(buffer,128,"%s\r\n",banner);
    

			if(session->out_socket_buffer == NULL)
				session->out_socket_buffer = buffer_new();
			buffer_add_data(session->out_socket_buffer,buffer,strlen(buffer));
			retval = packet_flush(session);
		}
	case SSH_STATE_BANNER_SENDING:
		retval = packet_flush(session);
		break;

	default:
		retval = SSH_ERROR;
	}


	return retval;
}

ssh_retval ssh_banner_send(SSH_SESSION *session)
{
	logPF();
	if (session->options->blocking == 1)
	{
		return SSH_ERROR;
	}else
	{
		return ssh_banner_send_nonblocking(session);
	}
}

ssh_retval ssh_again(SSH_SESSION *session)
{
	logPF();
	ssh_say(1,"\twe are in state %i\n",session->state);

	ssh_retval retval = SSH_AGAIN;
	ssh_retval fnret;
	switch (session->state)
	{

	case SSH_STATE_NONE:
	case SSH_STATE_CONNECTING:
		{
			retval = ssh_connect(session);
			switch ( retval )
			{
			case SSH_OK:
				session->state = SSH_STATE_CONNECTED;
				break;

			case SSH_AGAIN:
			case SSH_ERROR:
				return retval;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);
			}
		}

	case SSH_STATE_CONNECTED:
		/* here we call the connect callback */
		session->state = SSH_STATE_BANNER_RECEIVE;
		session->alive = 1;


	case SSH_STATE_BANNER_RECEIVE:
		{
			fnret = ssh_banner_get(session);
				switch ( fnret )
				{
				case SSH_OK:
					session->state = SSH_STATE_BANNER_SEND;
					int ssh1, ssh2;
					if ( ssh_banner_analyze(session,&ssh1,&ssh2) == SSH_ERROR )
					{
						retval = SSH_ERROR;
					} else
					{
						session->version = 2;
					}
					break;
				case SSH_ERROR:
				case SSH_AGAIN:
					return fnret;
					break;

				default:
					ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

				}
		}

				
//		break;

	case SSH_STATE_BANNER_SEND:
	case SSH_STATE_BANNER_SENDING:
		{
			fnret = ssh_banner_send(session);
			switch ( fnret )
			{
			case SSH_OK:
				session->state = SSH_STATE_KEX_GET;
				break;
			case SSH_AGAIN:
				return SSH_AGAIN;
			case SSH_ERROR:
				return SSH_ERROR;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}
		

	case SSH_STATE_KEX_GET:
		{
			fnret = ssh_get_kex(session,0);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				ssh_say(1,"\t ssh_get_kex finished\n");
				session->state = SSH_STATE_KEX_SEND;
				ssh_list_kex(&session->server_kex);
				set_kex(session);
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}
		
	case SSH_STATE_KEX_SEND:
	case SSH_STATE_KEX_SENDING:
		{
			fnret = ssh_send_kex(session,0);
			switch ( fnret )
			{
			case SSH_ERROR:
				return SSH_ERROR;
				break;

			case SSH_AGAIN:
				return SSH_AGAIN;
				break;

			case SSH_OK:
				session->state = SSH_STATE_DH_INIT_SEND;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}

	case SSH_STATE_DH_INIT_SENDING:
	case SSH_STATE_DH_INIT_SEND:
		{
			ssh_say(1,"case SSH_STATE_DH_INIT_SEND:\n");
			fnret = dh_handshake(session);
			switch (fnret)
			{
			case SSH_OK:
				session->state = SSH_STATE_DH_INIT_READ;
				break;

			case SSH_AGAIN:
				session->state = SSH_STATE_DH_INIT_SENDING;
				break;

			case SSH_ERROR:
				return SSH_ERROR;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}


		}
	
	case SSH_STATE_DH_INIT_READ:
		{
			ssh_say(1,"case SSH_STATE_DH_INIT_READ:\n");
			fnret = dh_handshake(session);
			switch (fnret)
			{
			case SSH_AGAIN:
				return SSH_AGAIN;
				break;

			case SSH_ERROR:
				return SSH_ERROR;
				break;

			case SSH_OK:
				session->state = SSH_STATE_DH_NEWKEYS_SEND;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}

	case SSH_STATE_DH_NEWKEYS_SENDING:
	case SSH_STATE_DH_NEWKEYS_SEND:
		{
			ssh_say(1,"\t case SSH_STATE_DH_NEWKEYS_SEND: %i\n", session->state);
			fnret = dh_handshake(session);
			switch (fnret)
			{
			case SSH_OK:
				ssh_say(1,"\tSSH_STATE_DH_NEWKEYS_SEND -> SSH_OK %i\n",session->state);
				session->state = SSH_STATE_DH_NEWKEYS_READ;
//				return SSH_AGAIN;
				break;

			case SSH_AGAIN:
				ssh_say(1,"\tSSH_STATE_DH_NEWKEYS_SEND -> SSH_AGAIN %i\n",session->state);
				session->state = SSH_STATE_DH_NEWKEYS_SENDING;
				return SSH_AGAIN;
				break;

			case SSH_ERROR:
				ssh_say(1,"\tSSH_STATE_DH_NEWKEYS_SEND -> SSH_ERROR %i\n",session->state);
				return SSH_ERROR;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}



	case SSH_STATE_DH_NEWKEYS_READ:
		{
			ssh_say(1,"\t case SSH_STATE_DH_NEWKEYS_READ: %i\n",session->state);
			fnret = dh_handshake(session);
			switch (fnret)
			{
			case SSH_OK:
				session->state = SSH_STATE_DH_FINISHED;
				break;

			case SSH_AGAIN:
				return SSH_AGAIN;
				break;

			case SSH_ERROR:
				return SSH_ERROR;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}

	case SSH_STATE_DH_FINISHED:
		ssh_say(1,"\t case SSH_STATE_DH_FINISHED:\n");
		return SSH_OK;
		break;




/* request the userauth service */
	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_SENDING:
	{
		ssh_say(1,"\tcase SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_SEND?:\n");
    	fnret = ssh_userauth_autopubkey_nonblocking(session);
		switch (fnret)
		{
		case SSH_ERROR:
		case SSH_AGAIN:
			return fnret;
			break;

		case SSH_OK:
			session->state = SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_READ;
			break;

		default:
			ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

		}
	}
		

	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_READ:
		{
			ssh_say(1,"\tcase SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_ASK_SERVICE_READ:\n");
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				ssh_say(1,"\t\tfnret = %i \n",fnret);
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_SEND;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}

/* send the userauth none request */
	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_SENDING:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}

	case SSH_STATE_AUTH_AUTOPUBKEY_USERAUTH_NONE_READ:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_AUTH_DENIED:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_SEND;
				break;

            case SSH_AUTH_SUCCESS:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_FINISHED;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);
				return SSH_ERROR;

			}
		}




/* request the user service to offer a pubkey */
	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_SENDING:
/*		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);
				return SSH_ERROR;

			}
		}
*/
	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_READ:
/*		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_SEND;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);
				return SSH_ERROR;

			}
		}
*/
		session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_SEND;


/* get a pubkey and offer it */
	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_SENDING:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);


			}
		}

	case SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_READ:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			ssh_say(1,"\tcase SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_READ: %i\n",fnret);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_AUTH_DENIED:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_SEND;
				break;

			case SSH_AUTH_SUCCESS:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_SEND;
//				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);


			}
		}
		



/* request the user service to send the accepted pubkey */
	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_ASK_SERVICE_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_ASK_SERVICE_SENDING:
/*		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_OFFER_PUBKEY_ASK_SERVICE_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}
*/
	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_ASK_SERVICE_READ:
/*		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_ASK_SERVICE_SEND;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",retval,session->state,__FILE__,__LINE__);

			}
		}
*/
		
		session->state = SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_SEND;


/* send the accepted pubkey to login */
	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_SEND:
	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_SENDING:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_READ;
				break;

			default:
				ssh_say(1,"\tssh_again unexpected return value %i in state %i  %s:%i \n",fnret,session->state,__FILE__,__LINE__);



			}
		}

	case SSH_STATE_AUTH_AUTOPUBKEY_PUBKEY_READ:
		{
			fnret = ssh_userauth_autopubkey_nonblocking(session);
			switch (fnret)
			{
			case SSH_ERROR:
			case SSH_AGAIN:
				return fnret;
				break;

			case SSH_OK:
				session->state = SSH_STATE_AUTH_AUTOPUBKEY_FINISHED;
				break;
			}
		}

	case SSH_STATE_AUTH_AUTOPUBKEY_FINISHED:
		{
			printf("AUTOPUBKEY FINISHED \n");
		}
		retval = SSH_OK;
		break;




	}
	return retval;
}



/**
 * check if the SSH_SESSION has things to send
 * 
 * @param session the session
 * 
 * @return returns 1 if the session has things to send, else 0
 */
int ssh_want_write(SSH_SESSION *session) 
{
	logPF();
	ssh_say(1,"\tstate is %i\n",session->state);

	if (session->out_socket_buffer && buffer_get_rest_len(session->out_socket_buffer) > 0 )
	{
		ssh_say(1,"\twe want to write\n");
		return 1;
	}else
	{
		ssh_say(1,"\twe dont need to write\n");
		return 0;
	}
}





ssh_retval ssh_connect(SSH_SESSION *session)
{
	logPF();
	
	session->client=1;

	ssh_retval fnret;

	ssh_crypto_init();
	if(session->options->blocking == 1 )
	{
		ssh_say(1,"Blocking connect ...\n");
		return SSH_ERROR;
	}else
	{
		fnret =  ssh_connect_nonblocking(session);
		switch (fnret)
		{
		case SSH_OK:
			session->state = SSH_STATE_CONNECTED;
            break;

		case SSH_AGAIN:
			session->state = SSH_STATE_CONNECTING;
			break;

		case SSH_ERROR:
			session->state = SSH_STATE_NONE;
			break;
		}

	}
	return fnret;
}

char *ssh_get_issue_banner(SSH_SESSION *session){
    if(!session->banner)
        return NULL;
    return string_to_char(session->banner);
}

void ssh_disconnect(SSH_SESSION *session){
    STRING *str;
    if(session->fd!= -1) 
	{
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
