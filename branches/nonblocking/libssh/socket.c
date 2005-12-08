#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/ssh1.h"
#include <netdb.h>
#include <errno.h>
#include "libssh/crypto.h"
#include "libssh/errors.h"
#include "libssh/packet.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/socket.h"
#include "libssh/connect.h"


/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */

ssh_retval socket_read(SSH_SESSION *session,int len)
{
	logPF();
    int except, can_read=0;
    int to_read;
    int r;
//    char *buf;
    char buffer[4096];

	ssh_retval ret = SSH_OK;

	if(!session->in_socket_buffer)
        session->in_socket_buffer=buffer_new();

    to_read=len - buffer_get_rest_len(session->in_socket_buffer);

	ssh_say(1,"\tshall read %i, %i in in_socket_buffer, %i to go\n",len,buffer_get_rest_len(session->in_socket_buffer),to_read);

	if ( to_read <= 0 )
	{
		
    	return SSH_OK;
	}
	else
	{
//		do
		{
			ssh_fd_poll(session,NULL,&can_read,&except); /* internally sets data_to_read */
			if ( can_read == 0)
			{
            	return SSH_AGAIN;
			}
			session->data_to_read=0;
			/* read as much as we can */
			r=read(session->fd,buffer,sizeof(buffer));
			if ( r<0 )
			{
				switch ( errno )
				{
				case EAGAIN:
					ret = SSH_AGAIN;
					break;

				default:
					ssh_say(1,"Error reading socket");
					ssh_set_error(session,SSH_FATAL,"Error reading socket");
					close(session->fd);
					session->fd=-1;
					session->data_except=1;
					ret = SSH_ERROR;
				}
			}else
			if (r==0)
			{
				ssh_set_error(session,SSH_FATAL,"Connection closed by remote host");
				close(session->fd);
				session->fd=-1;
				session->data_except=1;
				ret = SSH_ERROR;
			}else
			{
				buffer_add_data(session->in_socket_buffer,buffer,r);
				if (buffer_get_rest_len(session->in_socket_buffer) < len )
				{
					ret=SSH_AGAIN;
				}
			}
			ssh_say(1,"post buffer %i : %i\n", to_read, len - buffer_get_rest_len(session->in_socket_buffer));
		} //while ( buffer_get_rest_len(session->in_socket_buffer)<len );
	}
	ssh_say(1,"\tsocket_read retval %i\n",ret);
	return ret;
}


/* this function places the outgoing packet buffer into an outgoing socket buffer */
ssh_retval socket_write(SSH_SESSION *session)
{
	if ( !session->out_socket_buffer )
	{
		session->out_socket_buffer=buffer_new();
	}
	buffer_add_data(session->out_socket_buffer,
					buffer_get(session->out_buffer),
					buffer_get_len(session->out_buffer));
	return packet_flush(session);
}


