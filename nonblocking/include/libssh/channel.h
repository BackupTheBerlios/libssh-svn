#ifndef HAVE_LIBSSH_CHANNEL_H
#define HAVE_LIBSSH_CHANNEL_H

#include "session.h"
#include "buffer.h"


/* in channels.c */

struct channel_struct {
    struct channel_struct *prev;
    struct channel_struct *next;
    SSH_SESSION *session; /* SSH_SESSION pointer */
    u32 local_channel;
    u32 local_window;
    int local_eof;
    u32 local_maxpacket;

    u32 remote_channel;
    u32 remote_window;
    int remote_eof; /* end of file received */
    u32 remote_maxpacket;
    int open; /* shows if the channel is still opened */
    int delayed_close;
    BUFFER *stdout_buffer;
    BUFFER *stderr_buffer;
    void *userarg;
    int version;
    int blocking;
};

CHANNEL *channel_new(SSH_SESSION *session);
int channel_open_forward(CHANNEL *channel,char *remotehost, int remoteport, char *sourcehost, int localport);
int channel_open_session(CHANNEL *channel);
void channel_free(CHANNEL *channel);
int channel_request_pty(CHANNEL *channel);
int channel_request_pty_size(CHANNEL *channel, char *term,int cols, int rows);
int channel_change_pty_size(CHANNEL *channel,int cols,int rows);
int channel_request_shell(CHANNEL *channel);
int channel_request_subsystem(CHANNEL *channel, char *system);
int channel_request_env(CHANNEL *channel,char *name, char *value);
int channel_request_exec(CHANNEL *channel, char *cmd);
int channel_request_sftp(CHANNEL *channel);
int channel_write(CHANNEL *channel,void *data,int len);
int channel_send_eof(CHANNEL *channel);
int channel_read(CHANNEL *channel, BUFFER *buffer,int bytes,int is_stderr);
int channel_poll(CHANNEL *channel, int is_stderr);
int channel_close(CHANNEL *channel);
int channel_read_nonblocking(CHANNEL *channel, char *dest, int len, int is_stderr);
int channel_is_open(CHANNEL *channel);
int channel_is_closed(CHANNEL *channel);
int channel_select(CHANNEL **readchans, CHANNEL **writechans, CHANNEL **exceptchans, struct 
        timeval * timeout);


/* channel.c */
void channel_handle(SSH_SESSION *session, int type);
CHANNEL *channel_new(SSH_SESSION *session);
void channel_default_bufferize(CHANNEL *channel, void *data, int len, int is_stderr);
u32 ssh_channel_new_id(SSH_SESSION *session);
CHANNEL *ssh_channel_from_local(SSH_SESSION *session,u32 num);

#endif
