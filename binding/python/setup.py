from distutils.core import setup, Extension

extension = Extension('libssh', sources = ['src/libssh.c'], libraries=['ssh'])

setup(	name = 'zeppoo',
	version = '0.2',
	description = 'libssh python wrapper',
	ext_modules = [extension])		
