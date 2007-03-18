from distutils.core import setup, Extension

extension = Extension('pylibssh', sources = ['src/libssh.c'], libraries=['ssh'])

setup(	name = 'pylibssh',
	version = '0.2',
	description = 'libssh python wrapper',
	ext_modules = [extension])		
