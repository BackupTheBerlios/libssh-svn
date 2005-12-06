/* client.c */
int ssh_connect(SSH_SESSION *session);
void ssh_disconnect(SSH_SESSION *session);
int ssh_service_request(SSH_SESSION *session,char *service);
char *ssh_get_issue_banner(SSH_SESSION *session);
/* get copyright informations */
const char *ssh_copyright();

