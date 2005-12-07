#ifndef HAVE_LIBSSH_MESSAGES_H
#define HAVE_LIBSSH_MESSAGES_H

struct ssh_message {
    SSH_SESSION *session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
};

typedef struct ssh_message SSH_MESSAGE;


SSH_MESSAGE *ssh_message_get(SSH_SESSION *session);
int ssh_message_type(SSH_MESSAGE *msg);
int ssh_message_subtype(SSH_MESSAGE *msg);
int ssh_message_reply_default(SSH_MESSAGE *msg);
void ssh_message_free(SSH_MESSAGE *msg);

char *ssh_message_auth_user(SSH_MESSAGE *msg);
char *ssh_message_auth_password(SSH_MESSAGE *msg);
int ssh_message_auth_reply_success(SSH_MESSAGE *msg,int partial);
void ssh_message_auth_set_methods(SSH_MESSAGE *msg, int methods);

CHANNEL *ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg);

CHANNEL *ssh_message_channel_request_channel(SSH_MESSAGE *msg);
// returns the TERM env variable
char *ssh_message_channel_request_pty_term(SSH_MESSAGE *msg);
char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg);
int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg);


#endif
