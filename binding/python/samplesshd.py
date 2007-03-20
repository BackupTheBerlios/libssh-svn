#! /usr/bin/env python

import sys
import getpass
import termios
import fcntl
import array
import select
import pylibssh
	
if __name__ == "__main__":
	print "------ DEBUT SAMPLE SSHD ------"
	options = pylibssh.OPTIONS("", "", 22)
	options.dsa_server_key = "/etc/ssh/ssh_host_dsa_key"
	options.rsa_server_key = "/etc/ssh/ssh_host_rsa_key"

	bind = pylibssh.BIND()
	bind.set_options(options)
	
	if(bind.listen() < 0):
		print bind.get_error()
		sys.exit(-1)
		
	session = bind.accept()
	print type(session)
	print type(bind)
	#if(truc == None) :
	#print bind.get_error()
	#	sys.exit(-1)
	
	print "Socket Connecte : %d" % session.fd
	if(session.accept()) :
		print session.get_error()
		sys.exit(-1)
	
	auth = 0
	
	while (not auth) :
		print "la"
		message = session.message_get()
		if(message == None) :
			break
			
		print type(message)
		ttype = message.type()
		if(ttype == pylibssh.SSH_AUTH_REQUEST) :
			print "AUTH_REQUEST"
			subtype = message.subtype()
			if(subtype == pylibssh.SSH_AUTH_PASSWORD) :
				print "AUTH_PASSWORD"
				print "User %s wants to auth with pass %s" % (message.auth_user(), message.auth_password())
			elif(subtype == pylibssh.SSH_AUTH_NONE):
				print "DEFAULT 2"
				message.auth_set_methods(pylibssh.SSH_AUTH_PASSWORD)
				message.reply_default()
			else:
				print "DEFAULT 2"
				message.auth_set_methods(pylibssh.SSH_AUTH_PASSWORD)
				message.reply_default()

		else :
				print "DEFAULT 1 %d" % ttype
				message.reply_default()
	
		del message
	
	print "------ END SAMPLESSHD ------"
