all: libssh_java.so test/Test.class

CFLAGS=-I/usr/lib/jvm/java-6-sun-1.6.0.03/include/ -I/usr/lib/jvm/java-6-sun-1.6.0.03/include/linux/ -fpic

libssh_java.so: libssh_java.o
	gcc -o libssh_java.so -shared libssh_java.o

libssh_java.o: libssh_java.c be_badcode_libssh_SSHSession.h
	gcc -c -o libssh_java.o libssh_java.c $(CFLAGS)

be_badcode_libssh_SSHSession.h: be/badcode/libssh/SSHSession.class
	javah -jni be.badcode.libssh.SSHSession
be/badcode/libssh/SSHSession.class: be/badcode/libssh/SSHSession.java
	javac be/badcode/libssh/SSHSession.java
test/Test.class: test/Test.java
	javac -cp . test/Test.java
clean:
	rm -f libssh_java.o libssh_java.so be_badcode_libssh_SSHSession.h test/*.class be/badcode/libssh/*.class
