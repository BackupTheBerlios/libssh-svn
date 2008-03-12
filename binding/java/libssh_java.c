#include "be_badcode_libssh_SSHSession.h"
#include <stdio.h>

JNIEXPORT void JNICALL Java_be_badcode_libssh_SSHSession_hello
  (JNIEnv *env, jobject this){
    printf("Hello, world !\n");
}

