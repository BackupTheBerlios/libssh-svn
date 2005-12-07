#ifndef HAVE_ERRORS_H
#define HAVE_ERRORS_H


/* errors.c */


#define ERROR_BUFFERLEN 1024

struct error_struct {
/* error handling */
    int error_code;
    char error_buffer[ERROR_BUFFERLEN];
};

void ssh_set_error(void *error,int code,char *descr,...);
char *ssh_get_error(void *error); 
int ssh_get_error_code(void *error);
void ssh_say(int priority,char *format,...);
void ssh_set_verbosity(int num);


#endif
