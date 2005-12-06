/* auth1.c */
int ssh_userauth1_none(SSH_SESSION *session, char *username);
int ssh_userauth1_offer_pubkey(SSH_SESSION *session, char *username,int type, STRING *pubkey);
int ssh_userauth1_password(SSH_SESSION *session, char *username, char *password);
