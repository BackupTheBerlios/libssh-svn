#ifndef HAVE_KEYS_H
#define HAVE_KEYS_H

#include "string.h"
#include "buffer.h"
#include "priv.h"


typedef struct private_key_struct {
    int type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_priv;
    gcry_sexp_t rsa_priv;
#elif defined HAVE_LIBCRYPTO
    DSA *dsa_priv;
    RSA *rsa_priv;
#endif
} PRIVATE_KEY;

typedef struct public_key_struct {
    int type;
    char *type_c; /* Don't free it ! it is static */
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_pub;
    gcry_sexp_t rsa_pub;
#elif HAVE_LIBCRYPTO
    DSA *dsa_pub;
    RSA *rsa_pub;
#endif
} PUBLIC_KEY;

typedef struct signature_struct {
    int type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_sign;
    gcry_sexp_t rsa_sign;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *dsa_sign;
    STRING *rsa_sign;
#endif
} SIGNATURE;



/* in keys.c */

char *ssh_type_to_char(int type);
PUBLIC_KEY *publickey_make_dss(BUFFER *buffer);
PUBLIC_KEY *publickey_make_rsa(BUFFER *buffer,char *type);
PUBLIC_KEY *publickey_from_string(STRING *pubkey_s);
SIGNATURE *signature_from_string(STRING *signature,PUBLIC_KEY *pubkey,int needed_type);
void signature_free(SIGNATURE *sign);
STRING *ssh_do_sign(SSH_SESSION *session,BUFFER *sigbuf, 
        PRIVATE_KEY *privatekey);
STRING *ssh_sign_session_id(SSH_SESSION *session, PRIVATE_KEY *privatekey);
STRING *ssh_encrypt_rsa1(SSH_SESSION *session, STRING *data, PUBLIC_KEY *key);


void publickey_free(PUBLIC_KEY *key);

/* this one can be called by the client to see the hash of the public key before accepting it */
int ssh_get_pubkey_hash(SSH_SESSION *session,unsigned char hash[MD5_DIGEST_LEN]);
STRING *ssh_get_pubkey(SSH_SESSION *session);



#endif
