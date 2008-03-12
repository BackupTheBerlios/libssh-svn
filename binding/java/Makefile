all: libssh_java.so be/badcode/libssh/tests/Test.class

CFLAGS=-I/usr/lib/jvm/java-6-sun-1.6.0.03/include/ -I/usr/lib/jvm/java-6-sun-1.6.0.03/include/linux/ -fpic

libssh_java.so: libssh_java.o
	gcc -o libssh_java.so -shared libssh_java.o

libssh_java.o: libssh_java.c be_badcode_libssh_Session.h be_badcode_libssh_Options.h be_badcode_libssh_Channel.h
	gcc -c -o libssh_java.o libssh_java.c $(CFLAGS)

be_badcode_libssh_Session.h: be/badcode/libssh/Session.class
	javah -jni be.badcode.libssh.Session
be_badcode_libssh_Options.h: be/badcode/libssh/Options.class
	javah -jni be.badcode.libssh.Options
be_badcode_libssh_Channel.h: be/badcode/libssh/Channel.class
	javah -jni be.badcode.libssh.Channel
be/badcode/libssh/Session.class: be/badcode/libssh/Session.java
	javac be/badcode/libssh/Session.java
be/badcode/libssh/Options.class: be/badcode/libssh/Options.java
	javac be/badcode/libssh/Options.java
be/badcode/libssh/Channel.class: be/badcode/libssh/Channel.java
	javac be/badcode/libssh/Channel.java

be/badcode/libssh/tests/Test.class: be/badcode/libssh/tests/Test.java
	javac -cp be/badcode/libssh/tests/Test.java
clean:
	rm -f libssh_java.o libssh_java.so be_badcode_libssh*.h test/*.class be/badcode/libssh/*.class
