/* in kex.c */
extern char *ssh_kex_nums[];
void ssh_send_kex(SSH_SESSION *session,int server_kex);
void ssh_list_kex(KEX *kex);
int set_kex(SSH_SESSION *session);
int ssh_get_kex(SSH_SESSION *session, int server_kex);
int verify_existing_algo(int algo,char *name);
char **space_tokenize(char *chain);
int ssh_get_kex1(SSH_SESSION *session);
char *ssh_find_matching(char *in_d, char *what_d);

