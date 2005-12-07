/* in keyfiles.c */

PRIVATE_KEY  *_privatekey_from_file(void *session,char *filename,int type);
/* in keyfiles.c */

PRIVATE_KEY *privatekey_from_file(SSH_SESSION *session,char *filename,int type,char *passphrase);
STRING *publickey_to_string(PUBLIC_KEY *key);
PUBLIC_KEY *publickey_from_privatekey(PRIVATE_KEY *prv);
void private_key_free(PRIVATE_KEY *prv);
STRING *publickey_from_file(SSH_SESSION *session, char *filename,int *_type);
STRING *publickey_from_next_file(SSH_SESSION *session,char **pub_keys_path,char **keys_path,
                            char **privkeyfile,int *type,int *count);

