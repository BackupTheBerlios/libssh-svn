#ifndef HAVE_LIBSSH_CLIENT_H
#define HAVE_LIBSSH_CLIENT_H

#include "libssh/session.h"

/* client.c */
ssh_retval 	ssh_connect(SSH_SESSION *session);
void 		ssh_disconnect(SSH_SESSION *session);
int 		ssh_service_request(SSH_SESSION *session,char *service);
char 		*ssh_get_issue_banner(SSH_SESSION *session);
/* get copyright informations */
const char *ssh_copyright();
ssh_retval ssh_again(SSH_SESSION *session);
int ssh_want_write(SSH_SESSION *session);

#endif 
