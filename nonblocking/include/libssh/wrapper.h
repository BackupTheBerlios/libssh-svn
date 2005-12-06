/* wrapper.c */
int crypt_set_algorithms(SSH_SESSION *);
int crypt_set_algorithms_server(SSH_SESSION *session);
CRYPTO *crypto_new();
void crypto_free(CRYPTO *crypto);

