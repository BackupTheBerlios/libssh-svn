#ifndef HAVE_LIBSSH_CRYPT_H
#define HAVE_LIBSSH_CRYPT_H

#include "string.h"
#include "buffer.h"

typedef struct ssh_crypto_struct {
    bignum e,f,x,k,y;
    unsigned char session_id[SHA_DIGEST_LEN];
    
    unsigned char encryptIV[SHA_DIGEST_LEN*2];
    unsigned char decryptIV[SHA_DIGEST_LEN*2];

    unsigned char decryptkey[SHA_DIGEST_LEN*2];
    unsigned char encryptkey[SHA_DIGEST_LEN*2];

    unsigned char encryptMAC[SHA_DIGEST_LEN];
    unsigned char decryptMAC[SHA_DIGEST_LEN];
    unsigned char hmacbuf[EVP_MAX_MD_SIZE];
    struct crypto_struct *in_cipher, *out_cipher; /* the cipher structures/objects */
    STRING *server_pubkey;
    char *server_pubkey_type;
    int do_compress_out; /* idem */
    int do_compress_in; /* don't set them, set the option instead */
    void *compress_out_ctx; /* don't touch it */
    void *compress_in_ctx; /* really, don't */
} CRYPTO;

/* in crypt.c */
u32 packet_decrypt_len(SSH_SESSION *session,char *crypted);
int packet_decrypt(SSH_SESSION *session, void *packet,unsigned int len);
unsigned char *packet_encrypt(SSH_SESSION *session,void *packet,unsigned int len);
 /* it returns the hmac buffer if exists*/
int packet_hmac_verify(SSH_SESSION *session,BUFFER *buffer,unsigned char *mac);

#endif
