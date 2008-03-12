all: libssh_java.so be/badcode/libssh/tests/Test.class

CFLAGS=-I/usr/lib/jvm/java-6-sun-1.6.0.03/include/ -I/usr/lib/jvm/java-6-sun-1.6.0.03/include/linux/ -fpic

libssh_java.so: libssh_java.o
	gcc -o libssh_java.so -shared libssh_java.o

libssh_java.o: libssh_java.c be_badcode_libssh_Session.h
	gcc -c -o libssh_java.o libssh_java.c $(CFLAGS)

be_badcode_libssh_Session.h: be/badcode/libssh/Session.class
	javah -jni be.badcode.libssh.Session
be/badcode/libssh/Session.class: be/badcode/libssh/Session.java
	javac be/badcode/libssh/Session.java
be/badcode/libssh/tests/Test.class: be/badcode/libssh/tests/Test.java
	javac -cp be/badcode/libssh/tests/Test.java
clean:
	rm -f libssh_java.o libssh_java.so be_badcode_libssh*.h test/*.class be/badcode/libssh/*.class
