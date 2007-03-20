#! /usr/bin/env python

import sys
import getpass
import termios
import fcntl
import array
import select
import pylibssh

def auth_kdbint(session):
	err = session.userauth_kbdint("", "")
	print err
	while(err ==pylibssh.SSH_AUTH_INFO) :	
		name = session.userauth_kbdint_getname()
		instruction = session.userauth_kbdint_getname()
		n = session.userauth_kbdint_getnprompts()	
		print n
		for i in range(0, n) :
			(prompt, echo) = session.userauth_kbdint_getprompt(i)
			if(echo) :
				pass
			else :
				ptr = getpass.getpass(prompt)
				session.userauth_kbdint_setanswer(i, ptr)
			
		err = ssh.userauth_kbdint("", "")
		print err

	return err	
			
if __name__ == "__main__":
	print "------ DEBUT SAMPLE SSH ------"

	#options = libssh.OPTIONS(["-l", "shy", "localhost"])
	options = pylibssh.OPTIONS("shy", "localhost", 22)
	options.username = "shy"
	options.port = 22
	options.host = "localhost"
	#options.timeout = [1, 1]
	#options.timeout[0] = 3
	#print options.timeout

	#options.getopt(["-l", "shy", "localhost"])
	
	ssh = pylibssh.SESSION(options)

	try :
		ssh.connect()
	except OSError :
		print ssh.get_error()	
		sys.exit(-1)
	
	state = ssh.is_server_known()
	if(state == pylibssh.SSH_SERVER_KNOWN_OK) :
		print "SSH_SERVER_KNOWN_OK"
	elif(state == pylibssh.SSH_SERVER_KNOWN_CHANGED) :
		print "SSH_SERVER_KNOWN_CHANGED"
	elif(state == pylibssh.SSH_SERVER_FOUND_OTHER) :
		print "SSH_SERVER_FOUND_OTHER"


	auth = ssh.userauth_autopubkey()
	if(auth == pylibssh.SSH_AUTH_ERROR) :
		print "SSH_AUTH_ERROR"
		sys.exit(-1)

	print ssh.issue_banner

	print ssh.version

	if(auth != pylibssh.SSH_AUTH_SUCCESS) :
		print "AUTH_KDBINT"
		auth = auth_kdbint(ssh)
		if(auth == pylibssh.SSH_AUTH_ERROR) :
			print ssh.get_error()
			sys.exit(-1)
			
	if(auth !=pylibssh.SSH_AUTH_SUCCESS) :
		print "AUTH_PASSWORD"
		if(ssh.userauth_password("fuck") != pylibssh.SSH_AUTH_SUCCESS) :
			print ssh.get_error()
			sys.exit(-1)
			
	channel = pylibssh.CHANNEL(ssh)
	
	interactive = sys.stdin.isatty()
	terminal_local = None
	if(interactive) :
		terminal_local = termios.tcgetattr(0)

	channel.open_session()
	
	if(interactive) :
		channel.request_pty()
		win = array.array('h', [0, 1, 2, 3])
		fcntl.ioctl(1, termios.TIOCGWINSZ, win, 4)
		print win
		channel.change_pty_size(win[0], win[1])
		
	if(channel.request_shell()):
		print ssh.get_error();
		sys.exit(-1)
	
	if(interactive) :
		#####
		#cfmakeraw
		#####
		termios.tcsetattr(0, termios.TCSANOW, terminal_local)

	while 1 :
		maxfd = ssh.fd + 1
		(rr, wr, er) = select.select([ssh.fd], [], [], 30)
		if ssh.fd in rr :
			print "la"
		if ssh.fd :
			print "here"
			channel.send_eof()
		
			
		#for fd in rr :
		#	print fd
		
		
	#if(channel.request_exec("echo bla > /tmp/truc")) : 
	#	print ssh.get_error()
	
	channel.free()
	#del channel

#if(auth != libssh.SSH_AUTH_SUCCESS) :
#	password = getpass.getpass('Password : ')
#	if(ssh.userauth_password("", password) != libssh.SSH_AUTH_SUCCESS) :
#		print ssh.get_error()


	#print ssh.is_server_known()

	print "------ END SAMPLE SSH ------"
