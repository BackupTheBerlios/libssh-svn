#ifndef HAVE_LIBSSH_STRING_H
#define HAVE_LIBSSH_STRING_H

#include "priv.h"

/* string.h */

/* strings and buffers */
/* must be 32 bits number + immediatly our data */
typedef struct string_struct {
	u32 size;
	unsigned char string[MAX_PACKET_LEN];
} __attribute__ ((packed)) STRING;


/* You can use these functions, they won't change */
/* makestring returns a newly allocated string from a char * ptr */
STRING *string_from_char(char *what);
/* it returns the string len in host byte orders. str->size is big endian warning ! */
int string_len(STRING *str);
STRING *string_new(unsigned int size);
/* string_fill copies the data in the string. it does NOT check for boundary so allocate enough place with string_new */
void string_fill(STRING *str,void *data,int len);
/* returns a newly allocated char array with the str string and a final nul caracter */
char *string_to_char(STRING *str);
STRING *string_copy(STRING *str);
/* burns the data inside a string */
void string_burn(STRING *str);
void *string_data(STRING *str);

#endif
