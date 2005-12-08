/* in auth.c */
/* these functions returns AUTH_ERROR is some serious error has happened,
  AUTH_SUCCESS if success,
  AUTH_PARTIAL if partial success,
  AUTH_DENIED if refused */
int ssh_userauth_none(SSH_SESSION *session,char *username);
int ssh_userauth_password(SSH_SESSION *session,char *username,char *password);
int ssh_userauth_offer_pubkey(SSH_SESSION *session, char *username,int type, STRING *publickey);
int ssh_userauth_pubkey(SSH_SESSION *session, char *username, STRING *publickey, PRIVATE_KEY *privatekey);


ssh_retval ssh_userauth_autopubkey(SSH_SESSION *session);
ssh_retval ssh_userauth_autopubkey_nonblocking(SSH_SESSION *session);

int ssh_userauth_kbdint(SSH_SESSION *session, char *user, char *submethods);
int ssh_userauth_kbdint_getnprompts(SSH_SESSION *session);
char *ssh_userauth_kbdint_getname(SSH_SESSION *session);
char *ssh_userauth_kbdint_getinstruction(SSH_SESSION *session);
char *ssh_userauth_kbdint_getprompt(SSH_SESSION *session, int i, char *echo);
void ssh_userauth_kbdint_setanswer(SSH_SESSION *session, unsigned int i, char *answer);





