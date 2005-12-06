#ifndef HAVE_LIBSSH_DH_H
#define HAVE_LIBSSH_DH_H

/* in dh.c */
/* DH key generation */
void dh_generate_e(SSH_SESSION *session);
void ssh_print_bignum(char *which,bignum num);
void dh_generate_x(SSH_SESSION *session);
void dh_generate_y(SSH_SESSION *session);
void dh_generate_f(SSH_SESSION *session);

STRING *dh_get_e(SSH_SESSION *session);
STRING *dh_get_f(SSH_SESSION *session);
void dh_import_f(SSH_SESSION *session,STRING *f_string);
void dh_import_e(SSH_SESSION *session, STRING *e_string);
void dh_import_pubkey(SSH_SESSION *session,STRING *pubkey_string);
void dh_build_k(SSH_SESSION *session);

bignum make_string_bn(STRING *string);
STRING *make_bignum_string(bignum num);

#endif
