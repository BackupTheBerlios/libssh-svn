#ifndef HAVE_OPTIONS_H
#define HAVE_OPTIONS_H

#include "priv.h"

/* options.c */

/* in options.c */



typedef struct ssh_options_struct
{
	char 	*banner; /* explicit banner to send */
	char 	*username;
	u32  	remotehost;
	u16 	remoteport;
	u32 	localhost;
	u16 	localport;

	int		blocking;
	char 	*identity;
	char 	*ssh_dir;
	char 	*known_hosts_file;
	int 	fd;	/* specificaly wanted file descriptor, don't connect host */

	int 	dont_verify_hostkey; /* Don't spare time, don't check host key ! unneeded to say it's dangerous and not safe */
	int 	use_nonexisting_algo; /* if user sets a not supported algorithm for kex, don't complain */
	char 	*wanted_methods[10]; /* the kex methods can be choosed. better use the kex fonctions to do that */
	void 	*wanted_cookie; /* wants a specific cookie to be sent ? if null, generate a new one */
	void 	*passphrase_function; /* this functions will be called if a keyphrase is needed. look keyfiles.c for more info */
	void 	(*connect_status_function)(void *arg, float status); /* status callback function */
	void 	*connect_status_arg; /* arbitrary argument */
	long 	timeout; /* seconds */
	long 	timeout_usec;
	int 	ssh2allowed;
	int 	ssh1allowed;
	char 	*dsakey;
	char 	*rsakey; /* host key for server implementation */
} SSH_OPTIONS;

//typedef struct ssh_options_struct SSH_OPTIONS;

SSH_OPTIONS *ssh_options_new();
SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt);
int ssh_options_set_wanted_algos(SSH_OPTIONS *opt,int algo, char *list);
void ssh_options_set_username(SSH_OPTIONS *opt,char *username);
void ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port);
int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv);

void ssh_options_set_remotehost(SSH_OPTIONS *opt, u32 host);

void ssh_options_set_fd(SSH_OPTIONS *opt, int fd);

void ssh_options_set_bind(SSH_OPTIONS *opt, u32 localhost ,int port);

void ssh_options_set_identity(SSH_OPTIONS *opt, char *identity);
void ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)(void *arg, float status), void *arg);
void ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds, long usec);
void ssh_options_set_ssh_dir(SSH_OPTIONS *opt, char *dir);
void ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, char *dir);
void ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow);
void ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow);
void ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, char *dsakey);
void ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, char *rsakey);


void ssh_options_free(SSH_OPTIONS *opt);
/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(SSH_OPTIONS *opt);
int ssh_options_default_ssh_dir(SSH_OPTIONS *opt);
int ssh_options_default_known_hosts_file(SSH_OPTIONS *opt);


#endif
