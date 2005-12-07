#ifndef HAVE_LIBSSH_KEX_H
#define HAVE_LIBSSH_KEX_H

/* in kex.c */
#include "libssh.h"
#include "string.h"
#include "keys.h"



extern char *ssh_kex_nums[];

typedef struct kex_struct {
	unsigned char cookie[16];
	char **methods;
} KEX;

ssh_retval ssh_send_kex(SSH_SESSION *session,int server_kex);

ssh_retval ssh_get_kex(SSH_SESSION *session, int server);
ssh_retval ssh_get_kex1(SSH_SESSION *session);
ssh_retval ssh_get_kex2(SSH_SESSION *session, int server);

void ssh_list_kex(KEX *kex);
int set_kex(SSH_SESSION *session);

int verify_existing_algo(int algo,char *name);
char **space_tokenize(char *chain);

char *ssh_find_matching(char *in_d, char *what_d);

STRING *make_rsa1_string(STRING *e, STRING *n);
void build_session_id1(SSH_SESSION *session, STRING *servern, STRING *hostn);

STRING *encrypt_session_key(SSH_SESSION *session, PUBLIC_KEY *svrkey,PUBLIC_KEY *hostkey,int slen, int hlen );

#endif
