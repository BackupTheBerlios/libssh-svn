/*
Copyright 2003,04 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

/* priv.h file */
/* This include file contains everything you shouldn't deal with in user programs. */
/* Consider that anything in this file might change without notice; libssh.h file will keep */
/* backward compatibility on binary & source */

#ifndef _LIBSSH_PRIV_H
#define _LIBSSH_PRIV_H
#include "config.h"
#include "libssh/libssh.h"

/* Debugging constants */

/* Define this if you want to debug crypto systems */
/* it's usefull when you are debugging the lib */
/*#define DEBUG_CRYPTO */

/* some constants */
#define MAX_PACKET_LEN 262144

#define CLIENTBANNER1 "SSH-1.5-" LIBSSH_VERSION
#define CLIENTBANNER2 "SSH-2.0-" LIBSSH_VERSION
#define KBDINT_MAX_PROMPT 256 /* more than openssh's :) */
/* some types for public keys */
#define TYPE_DSS 1
#define TYPE_RSA 2
#define TYPE_RSA1 3

/* profiling constants. Don't touch them unless you know what you do */
#ifdef HAVE_LIBCRYPTO
#define OPENSSL_BIGNUMS
#endif

#define logPF() ssh_say(1,"function: %s:%i\n",__PRETTY_FUNCTION__,__LINE__)

/* integer values */
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
typedef uint8_t u8;

#ifdef __cplusplus
extern "C" {
#endif


/* wrapper things */
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
typedef gcry_md_hd_t SHACTX;
typedef gcry_md_hd_t MD5CTX;
typedef gcry_md_hd_t HMACCTX;
#ifdef MD5_DIGEST_LEN
    #undef MD5_DIGEST_LEN
#endif
#define SHA_DIGEST_LEN 20
#define MD5_DIGEST_LEN 16
#define EVP_MAX_MD_SIZE 36

typedef gcry_mpi_t bignum;

#define bignum_new() gcry_mpi_new(0)
#define bignum_free(num) gcry_mpi_release(num)
#define bignum_set_word(bn,n) gcry_mpi_set_ui(bn,n)
#define bignum_bin2bn(bn,datalen,data) gcry_mpi_scan(data,GCRYMPI_FMT_USG,bn,datalen,NULL)
#define bignum_bn2dec(num) my_gcry_bn2dec(num)
#define bignum_dec2bn(num, data) my_gcry_dec2bn(data, num)
#define bignum_bn2hex(num,data) gcry_mpi_aprint(GCRYMPI_FMT_HEX,data,NULL,num)
#define bignum_hex2bn(num,datalen,data) gcry_mpi_scan(num,GCRYMPI_FMT_HEX,data,datalen,NULL)
#define bignum_rand(num,bits) gcry_mpi_randomize(num,bits,GCRY_STRONG_RANDOM),gcry_mpi_set_bit(num,bits-1),gcry_mpi_set_bit(num,0)
#define bignum_mod_exp(dest,generator,exp,modulo) gcry_mpi_powm(dest,generator,exp,modulo)
#define bignum_num_bits(num) gcry_mpi_get_nbits(num)
#define bignum_num_bytes(num) ((gcry_mpi_get_nbits(num)+7)/8)
#define bignum_is_bit_set(num,bit) gcry_mpi_test_bit(num,bit)
#define bignum_bn2bin(num,datalen,data) gcry_mpi_print(GCRYMPI_FMT_USG,data,datalen,NULL,num)
#define bignum_cmp(num1,num2) gcry_mpi_cmp(num1,num2)

#elif defined HAVE_LIBCRYPTO
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
typedef SHA_CTX* SHACTX;
typedef MD5_CTX*  MD5CTX;
typedef HMAC_CTX* HMACCTX;
#ifdef MD5_DIGEST_LEN
    #undef MD5_DIGEST_LEN
#endif
#define SHA_DIGEST_LEN SHA_DIGEST_LENGTH
#define MD5_DIGEST_LEN MD5_DIGEST_LENGTH

#endif /* OPENSSL_CRYPTO */
#ifdef OPENSSL_BIGNUMS
#include <openssl/bn.h>
typedef BIGNUM*  bignum;
typedef BN_CTX* bignum_CTX;

#define bignum_new() BN_new()
#define bignum_free(num) BN_clear_free(num)
#define bignum_set_word(bn,n) BN_set_word(bn,n)
#define bignum_bin2bn(bn,datalen,data) BN_bin2bn(bn,datalen,data)
#define bignum_bn2dec(num) BN_bn2dec(num)
#define bignum_dec2bn(bn,data) BN_dec2bn(data,bn)
#define bignum_bn2hex(num) BN_bn2hex(num)
#define bignum_rand(rnd, bits, top, bottom) BN_rand(rnd,bits,top,bottom)
#define bignum_ctx_new() BN_CTX_new()
#define bignum_ctx_free(num) BN_CTX_free(num)
#define bignum_mod_exp(dest,generator,exp,modulo,ctx) BN_mod_exp(dest,generator,exp,modulo,ctx)
#define bignum_num_bytes(num) BN_num_bytes(num)
#define bignum_num_bits(num) BN_num_bits(num)
#define bignum_is_bit_set(num,bit) BN_is_bit_set(num,bit)
#define bignum_bn2bin(num,ptr) BN_bn2bin(num,ptr)
#define bignum_cmp(num1,num2) BN_cmp(num1,num2)

#endif /* OPENSSL_BIGNUMS */

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* wrapper.c */
MD5CTX md5_init(void);
void md5_update(MD5CTX c, const void *data, unsigned long len);
void md5_final(unsigned char *md,MD5CTX c);
SHACTX sha1_init(void);
void sha1_update(SHACTX c, const void *data, unsigned long len);
void sha1_final(unsigned char *md,SHACTX c);
void sha1(unsigned char *digest,int len,unsigned char *hash);
#define HMAC_SHA1 1
#define HMAC_MD5 2
HMACCTX hmac_init(const void *key,int len,int type);
void hmac_update(HMACCTX c, const void *data, unsigned long len);
void hmac_final(HMACCTX ctx,unsigned char *hashmacbuf,unsigned int *len);




















typedef enum
{
	SSH_STATE_NONE,					/* not connected */
	SSH_STATE_CONNECTING,			/* connecting the socket */
	SSH_STATE_CONNECTED,			/* connected */
	SSH_STATE_BANNER_RECEIVE, 		/* getting the remotes banner */
	SSH_STATE_BANNER_SEND,			/* send our banner */			
	SSH_STATE_BANNER_SENDING,		/* still send our banner */			
	SSH_STATE_KEX_GET,				/* get the remote kex */
	SSH_STATE_KEX_SEND,				/* get the remote kex */
	SSH_STATE_KEX_SENDING,			/* get the remote kex */
	SSH_STATE_DH_INIT_SEND,
	SSH_STATE_DH_INIT_SENDING,
	SSH_STATE_DH_INIT_READ,
	SSH_STATE_DH_NEWKEYS_SEND,
	SSH_STATE_DH_NEWKEYS_SENDING,
	SSH_STATE_DH_NEWKEYS_READ,
	SSH_STATE_DH_FINISHED




} ssh_state_t;



struct ssh_kbdint {
    u32 nprompts;
    char *name;
    char *instruction;
    char **prompts;
    unsigned char *echo; /* bool array */
    char **answers;
};













/* in misc.c */
/* gets the user home dir. */
char *ssh_get_user_home_dir();
int ssh_file_readaccess_ok(char *file);

/* macro for byte ordering */
u64 ntohll(u64);
#define htonll(x) ntohll(x)


/* session.c */

int ssh_handle_packets(SSH_SESSION *session);

#ifdef HAVE_LIBGCRYPT
/* gcrypt_missing.c */
int my_gcry_dec2bn(bignum *bn, const char *data);
char *my_gcry_bn2dec(bignum bn);
#endif /* !HAVE_LIBGCRYPT */

#ifdef __cplusplus
} ;
#endif

#endif /* _LIBSSH_PRIV_H */
