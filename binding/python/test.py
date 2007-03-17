#! /usr/bin/env python

import sys
import getpass
import termios
import libssh

def auth_kdbint(session):
	err = session.userauth_kbdint("", "")
	print err
	while(err == libssh.SSH_AUTH_INFO) :	
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
	print "------ DEBUT TEST ------"

	#options = libssh.OPTIONS(["-l", "shy", "localhost"])
	options = libssh.OPTIONS("shy")
	options.username = "shy"
	options.port = 22
	options.host = "localhost"
	#options.timeout = [1, 1]
	#options.timeout[0] = 3
	#print options.timeout

	options.getopt(["-l", "shy", "localhost"])
	
	ssh = libssh.SESSION(options)

	try :
		ssh.connect()
	except OSError :
		print ssh.get_error()	
		sys.exit(-1)
	
	state = ssh.is_server_known()
	if(state == libssh.SSH_SERVER_KNOWN_OK) :
		print "SSH_SERVER_KNOWN_OK"
	elif(state == libssh.SSH_SERVER_KNOWN_CHANGED) :
		print "SSH_SERVER_KNOWN_CHANGED"
	elif(state == libssh.SSH_SERVER_FOUND_OTHER) :
		print "SSH_SERVER_FOUND_OTHER"


	auth = ssh.userauth_autopubkey()
	if(auth == libssh.SSH_AUTH_ERROR) :
		print "SSH_AUTH_ERROR"
		sys.exit(-1)

	print ssh.issue_banner

	print ssh.version

	if(auth != libssh.SSH_AUTH_SUCCESS) :
		auth = auth_kdbint(ssh)
		if(auth == libssh.SSH_AUTH_ERROR) :
			ssh.get_error()
							
	channel = libssh.CHANNEL(ssh)
	interactive = sys.stdin.isatty()
	if(interactive) :
		fd = termios.tcgetattr(0)

	channel.open_session()
	
	if(channel.request_exec("echo bla > /tmp/truc")) : 
		print ssh.get_error()
	
	channel.free()
	#del channel

#if(auth != libssh.SSH_AUTH_SUCCESS) :
#	password = getpass.getpass('Password : ')
#	if(ssh.userauth_password("", password) != libssh.SSH_AUTH_SUCCESS) :
#		print ssh.get_error()


	#print ssh.is_server_known()

	print "------ END TEST ------"
