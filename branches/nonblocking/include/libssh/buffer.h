#ifndef HAVE_LIBSSH_BUFFER_H
#define HAVE_LIBSSH_BUFFER_H


#include "string.h"

typedef struct buffer_struct {
    char *data;
    int used;
    int allocated;
    int pos;
} BUFFER;

/* buffer.c */
void buffer_add_ssh_string(BUFFER *buffer,STRING *string);
void buffer_add_u8(BUFFER *buffer, u8 data);
void buffer_add_u32(BUFFER *buffer, u32 data);
void buffer_add_u64(BUFFER *buffer,u64 data);
void buffer_add_data(BUFFER *buffer, void *data, int len);
void buffer_add_data_begin(BUFFER *buffer,void *data,int len);
void buffer_add_buffer(BUFFER *buffer, BUFFER *source);
void buffer_reinit(BUFFER *buffer);

/* buffer_get_rest returns a pointer to the current position into the buffer */
void *buffer_get_rest(BUFFER *buffer);
/* buffer_get_rest_len returns the number of bytes which can be read */
int buffer_get_rest_len(BUFFER *buffer);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
int buffer_get_u8(BUFFER *buffer,u8 *data);
int buffer_get_u32(BUFFER *buffer,u32 *data);
int buffer_get_u64(BUFFER *buffer, u64 *data);

int buffer_get_data(BUFFER *buffer,void *data,int requestedlen);
/* buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
STRING *buffer_get_ssh_string(BUFFER *buffer);
/* gets a string out of a SSH-1 mpint */
STRING *buffer_get_mpint(BUFFER *buffer);
/* buffer_pass_bytes acts as if len bytes have been read (used for padding) */
int buffer_pass_bytes_end(BUFFER *buffer,int len);
int buffer_pass_bytes(BUFFER *buffer, int len);

/* buffer.c */

BUFFER *buffer_new();
void buffer_free(BUFFER *buffer);
/* buffer_get returns a pointer to the begining of the buffer. no position is taken into account */
void *buffer_get(BUFFER *buffer);
/* same here */
int buffer_get_len(BUFFER *buffer);


#endif
