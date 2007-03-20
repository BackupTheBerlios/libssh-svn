#include <Python.h>
#include "structmember.h"

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libssh/server.h>

typedef struct {
	PyObject_HEAD
	PyObject *buf;
	BUFFER *buffer;
} BUFFER_OBJECT;

typedef struct {
	PyObject_HEAD
	PyObject *banner;
	PyObject *dsa_server_key;
	PyObject *fd;
	PyObject *host;
	PyObject *identity;
	PyObject *known_hosts_file;
	PyObject *port;
	PyObject *rsa_server_key;
	PyObject *ssh_dir;
	//PyObject *timeout;
	PyObject *username;
	SSH_OPTIONS *options;
} OPTIONS_OBJECT;

typedef struct {
	PyObject_HEAD
	PyObject *disconnect_message;
	PyObject *fd;
	PyObject *issue_banner;
	PyObject *status;
	PyObject *version;
	SSH_SESSION *session;
} SESSION_OBJECT;

typedef struct {
	PyObject_HEAD
	SESSION_OBJECT *session;
	CHANNEL *channel;
} CHANNEL_OBJECT;

typedef struct {
	PyObject_HEAD
	SSH_MESSAGE *message;
} MESSAGE_OBJECT;

typedef struct {
	PyObject_HEAD
	SSH_BIND *bind;
} BIND_OBJECT;



static void BUFFER_dealloc(BUFFER_OBJECT *self)
{
	printf("JE ME BARRE DE BUFFER  !!\n");

	if(self->buffer != NULL)
		buffer_free(self->buffer);
	
	self->buffer = NULL;

        self->ob_type->tp_free((PyObject *)self);
}

static PyObject *BUFFER_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	BUFFER_OBJECT *self;

	printf("CREATION DE BUFFER !!!\n");

	self = (BUFFER_OBJECT *)type->tp_alloc(type, 0);

	if(self != NULL){
		self->buffer = buffer_new();
	
		self->buf = PyString_FromString("");
		if(self->buf == NULL){
			Py_DECREF(self);
			return NULL;
		}
	}

	return (PyObject *)self;
}

static int BUFFER_init(BUFFER_OBJECT *self, PyObject *args, PyObject *kwds)
{
	return 0;
}

static PyObject *
BUFFER_OBJECT_get_buf(BUFFER_OBJECT *self, void *closure)
{
	self->buf = PyString_FromStringAndSize(buffer_get(self->buffer), buffer_get_len(self->buffer));
	
	Py_INCREF(self->buf);
	return self->buf;
}

static PyMethodDef BUFFER_OBJECT_methods[] = {
	{ NULL }
};

static PyMemberDef BUFFER_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef BUFFER_OBJECT_getseters[] = {
	{ "buf", (getter)BUFFER_OBJECT_get_buf, NULL, "buf", NULL },
	{ NULL }  /* Sentinel */
};

static PyTypeObject BUFFER_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.BUFFER",		/* tp_name */
	sizeof(BUFFER_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)BUFFER_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"BUFFER_OBJECT",		/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	BUFFER_OBJECT_methods,		/* tp_methods */
	0,
	//BUFFER_OBJECT_members,	/* tp_members */
	BUFFER_OBJECT_getseters,	/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)BUFFER_init,		/* tp_init */
	0,				/* tp_alloc */
	BUFFER_new,			/* tp_new */
};


static void OPTIONS_OBJECT_dealloc(OPTIONS_OBJECT *self)
{
	printf("JE ME BARRE DE OPTIONS !!\n");

	Py_XDECREF(self->banner);
	Py_XDECREF(self->dsa_server_key);
	Py_XDECREF(self->fd);
	Py_XDECREF(self->host);
	Py_XDECREF(self->identity);
	Py_XDECREF(self->known_hosts_file);
	Py_XDECREF(self->port);
	Py_XDECREF(self->rsa_server_key);
	Py_XDECREF(self->ssh_dir);
	//Py_XDECREF(self->timeout);
	Py_XDECREF(self->username);
	
	self->options = NULL;

        self->ob_type->tp_free((PyObject *)self);
}

static PyObject *OPTIONS_OBJECT_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	OPTIONS_OBJECT *self;

	printf("CREATION DE OPTIONS !!!\n");

	self = (OPTIONS_OBJECT *)type->tp_alloc(type, 0);

	if(self != NULL){
		self->banner = PyString_FromString("");
		if(self->banner == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->dsa_server_key = PyString_FromString("");
		if(self->dsa_server_key == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->fd = PyInt_FromLong(0);
		if(self->fd == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->host = PyString_FromString("");
		if(self->host == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->identity = PyString_FromString("");
		if(self->identity == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->known_hosts_file = PyString_FromString("");
		if(self->known_hosts_file == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->port = PyInt_FromLong(22);
		if(self->port == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->rsa_server_key = PyString_FromString("");
		if(self->rsa_server_key == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->ssh_dir = PyString_FromString("");
		if(self->ssh_dir == NULL){
			Py_DECREF(self);
			return NULL;
		}

		/*self->timeout = PyList_New(0);
		if(self->timeout == NULL){
			Py_DECREF(self);
			return NULL;
		}*/

		self->username = PyString_FromString("");
		if(self->username == NULL){
			Py_DECREF(self);
			return NULL;
		}


		self->options = ssh_options_new();
	}

	return (PyObject *)self;
}

static int OPTIONS_OBJECT_init(OPTIONS_OBJECT *self, PyObject *args, PyObject *kwds)
{
	PyObject *username, *hostname, *tmp;
	char *user, *host;
	int port = 0;
	
	static char *kwlist[] = { "username", "hostname", "port", NULL };

	if(self->options == NULL)
		return -1;
	
	if(!PyArg_ParseTupleAndKeywords(args, kwds, "SSi", kwlist, &username, &hostname, &port))
		return -1; 

	if(username){
		tmp = self->username;
		Py_INCREF(username);
		self->username = username;
		Py_DECREF(tmp);
		
		user = PyString_AsString(self->username);

		ssh_options_set_username(self->options, user);
	}

	if(hostname){
		tmp = self->host;
		Py_INCREF(hostname);
		self->host = hostname;
		Py_DECREF(self->host);
		
		host = PyString_AsString(self->host);
		ssh_options_set_host(self->options, host);
	}
	
	if(port){
		self->port = PyInt_FromLong(port);
		Py_INCREF(self->port);
		
		ssh_options_set_port(self->options, port);
	}
	
	/*int argc, i;
	char **argvlist = NULL;
	PyObject *argv;
	PyObject *(*getitem)(PyObject *, int);

	argc = i = 0;
	static char *kwlist[] = { "argv", NULL };

	if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &argv))
		return -1;

	if(PyList_Check(argv)){
		argc = PyList_Size(argv);
		getitem = PyList_GetItem;
	}

	argvlist = PyMem_NEW(char *, argc+1);
	
	if(argvlist == NULL){
		PyErr_NoMemory();
		return -1;
	}

	for(i = 0; i < argc; i++){
		if(!PyArg_Parse((*getitem)(argv, i), "s", &argvlist[i]))
			return -1;
	}

	argvlist[argc] = NULL;
	
	for(i = 0; i < argc; i++)
		printf("ARGV[%d] = %s\n", i, argvlist[i]);

	if(ssh_options_getopt(self->options, &argc, argvlist)){
		PyMem_Del(argvlist);
		return -1;
	}

	PyMem_Del(argvlist);
	*/

	return 0;
}

//void 	ssh_options_set_banner (SSH_OPTIONS *opt, char *banner)
// 	set the server banner sent to clients

static PyObject *
OPTIONS_OBJECT_get_banner(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->banner);
	return self->banner;
}

static int 
OPTIONS_OBJECT_set_banner(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *banner;
	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the banner");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The banner attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->banner);
	Py_INCREF(value);
	self->banner = value;    

	banner = PyString_AsString(self->banner);
	
//	ssh_options_set_banner(self->options, banner);

	return 0;
}

//void 	ssh_options_set_bind (SSH_OPTIONS *opt, char *bindaddr, int port)
// 	set the local address and port binding

static PyObject *OPTIONS_OBJECT_set_bind(OPTIONS_OBJECT *self, PyObject *args){
	char *bindaddr = NULL;
	int port;
	
	if(self->options == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "si", &bindaddr, &port))
		return NULL;

	printf("BINDADDR %s %d\n", bindaddr, port);

	ssh_options_set_bind(self->options, bindaddr, port);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//void 	ssh_options_set_dsa_server_key (SSH_OPTIONS *opt, char *dsakey)

static PyObject *
OPTIONS_OBJECT_get_dsa_server_key(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->dsa_server_key);
	return self->dsa_server_key;
}

static int 
OPTIONS_OBJECT_set_dsa_server_key(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *dsa_server_key;
	
	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the dsa_server_key");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The dsa_server_key attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->dsa_server_key);
	Py_INCREF(value);
	self->dsa_server_key = value;    

	dsa_server_key = PyString_AsString(self->dsa_server_key);
	
	ssh_options_set_dsa_server_key(self->options, dsa_server_key);

	return 0;
}

//void 	ssh_options_set_fd (SSH_OPTIONS *opt, int fd)
//	set a file descriptor for connection

static PyObject *
OPTIONS_OBJECT_get_fd(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->fd);
	return self->fd;
}

static int 
OPTIONS_OBJECT_set_fd(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	int fd;

	if(self->options == NULL)
		return -1;
		
	if(value == NULL){
		PyErr_SetString(PyExc_TypeError, "Cannot delete the fd");
		return -1;
	}

	if(!PyInt_Check(value)){
		PyErr_SetString(PyExc_TypeError, "The fd attribute value must be an int");
		return -1;
	}

		
	Py_DECREF(self->fd);
	Py_INCREF(value);
		
	self->fd = value;
	
	fd = PyInt_AsLong(self->fd);
	ssh_options_set_fd(self->options, fd);

	return 0;
}

//void 	ssh_options_set_host (SSH_OPTIONS *opt, const char *hostname)
// 	set destination hostname

static PyObject *
OPTIONS_OBJECT_get_host(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->host);
	return self->host;
}

static int 
OPTIONS_OBJECT_set_host(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *host;
	
	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the host");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The host attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->host);
	Py_INCREF(value);
	self->host = value;    

	host = PyString_AsString(self->host);
	
	ssh_options_set_host(self->options, host);

	return 0;
}

//void 	ssh_options_set_identity (SSH_OPTIONS *opt, char *identity)
// 	set the identity file name

static PyObject *
OPTIONS_OBJECT_get_identity(OPTIONS_OBJECT *self, void *closure){
	Py_INCREF(self->identity);
	return self->identity;
}

static int 
OPTIONS_OBJECT_set_identity(OPTIONS_OBJECT *self, PyObject *value, void *closure){
	char *identity;

	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the identity");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The identity attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->identity);
	Py_INCREF(value);
	self->identity = value;    

	identity = PyString_AsString(self->identity);
	
	ssh_options_set_identity(self->options, identity);

	return 0;
}

//void 	ssh_options_set_known_hosts_file (SSH_OPTIONS *opt, char *dir)
// 	set the known hosts file name

static PyObject *
OPTIONS_OBJECT_get_known_hosts_file(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->known_hosts_file);
	return self->known_hosts_file;
}

static int 
OPTIONS_OBJECT_set_known_hosts_file(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *known_hosts_file;

	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the known_hosts_file");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The known_hosts_file attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->known_hosts_file);
	Py_INCREF(value);
	self->known_hosts_file = value;    

	known_hosts_file = PyString_AsString(self->known_hosts_file);
	
	ssh_options_set_known_hosts_file(self->options, known_hosts_file);

	return 0;
}

//void 	ssh_options_set_port (SSH_OPTIONS *opt, unsigned int port)
// 	set port to connect or to bind for a connection

static PyObject *
OPTIONS_OBJECT_get_port(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->port);
	return self->port;
}

static int 
OPTIONS_OBJECT_set_port(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	int port;

	if(self->options == NULL)
		return -1;
	
	if(value == NULL){
		PyErr_SetString(PyExc_TypeError, "Cannot delete the port");
		return -1;
	}

	if(!PyInt_Check(value)){
		PyErr_SetString(PyExc_TypeError, "The port attribute value must be an int");
		return -1;
	}

	
	Py_DECREF(self->port);
	Py_INCREF(value);
		
	self->port = value;
	
	port = PyInt_AsLong(self->port);
	
	ssh_options_set_port(self->options, port);

	return 0;
}

//void 	ssh_options_set_rsa_server_key (SSH_OPTIONS *opt, char *rsakey)

static PyObject *
OPTIONS_OBJECT_get_rsa_server_key(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->rsa_server_key);
	return self->rsa_server_key;
}

static int 
OPTIONS_OBJECT_set_rsa_server_key(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *rsa_server_key;

	if(self->options == NULL)
		return -1;
	
	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the rsa_server_key");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The rsa_server_key attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->rsa_server_key);
	Py_INCREF(value);
	self->rsa_server_key = value;    

	rsa_server_key = PyString_AsString(self->rsa_server_key);
	
	ssh_options_set_rsa_server_key(self->options, rsa_server_key);

	return 0;
}

//void 	ssh_options_set_ssh_dir (SSH_OPTIONS *opt, char *dir)
// 	set the ssh directory

static PyObject *
OPTIONS_OBJECT_get_ssh_dir(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->ssh_dir);
	return self->ssh_dir;
}

static int 
OPTIONS_OBJECT_set_ssh_dir(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *ssh_dir;

	if(self->options == NULL)
		return -1;

	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the ssh_dir");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The ssh_dir attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->ssh_dir);
	Py_INCREF(value);
	self->ssh_dir = value;    

	ssh_dir = PyString_AsString(self->ssh_dir);
	
	ssh_options_set_ssh_dir(self->options, ssh_dir);

	return 0;
}

//void 	ssh_options_set_status_callback (SSH_OPTIONS *opt, void(*callback)(void *arg, float status), void *arg)
// 	set a callback to show connection status in realtime

//void 	ssh_options_set_timeout (SSH_OPTIONS *opt, long seconds, long usec)
// 	set a timeout for the connection

/*
static PyObject *
OPTIONS_OBJECT_get_timeout(OPTIONS_OBJECT *self, void *closure){
	Py_INCREF(self->timeout);
	return self->timeout;
}

static int
OPTIONS_OBJECT_set_timeout(OPTIONS_OBJECT *self, PyObject *value, void *closure){
	PyObject *tmp;
	long seconds, usec;
	int len, i;	

	seconds = usec = 0;
	
	printf("HERE !!\n");
	if(value == NULL){
		PyErr_SetString(PyExc_TypeError, "Cannot delete the timeout");
		return -1;
	}
	
	if(!PyList_Check(value)){
		PyErr_SetString(PyExc_TypeError, "The timeout attribute value must be a list");
		return -1;
	}

        Py_DECREF(self->timeout);
        Py_INCREF(value);
	self->timeout = value;

	len = PyList_Size(self->timeout);
	for(i=0; i < len; i++){
		tmp = PyList_GetItem(self->timeout, i);
	}

	ssh_options_set_timeout(self->options, seconds, usec);

	return 0;
}*/

static PyObject *
OPTIONS_OBJECT_set_timeout(OPTIONS_OBJECT *self, PyObject *args)
{
	long seconds, timeout;
	
	if(self->options == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "ll", &seconds, &timeout))
		return NULL;

	printf("SECONDS %d TIMEOUT %d\n", seconds, timeout);

	ssh_options_set_timeout(self->options, seconds, timeout);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//void 	ssh_options_set_username (SSH_OPTIONS *opt, char *username)
// 	set username for authentication

static PyObject *
OPTIONS_OBJECT_get_username(OPTIONS_OBJECT *self, void *closure)
{
	Py_INCREF(self->username);
	return self->username;
}

static int 
OPTIONS_OBJECT_set_username(OPTIONS_OBJECT *self, PyObject *value, void *closure)
{
	char *username;

	if(self->options == NULL)
		return -1;

	if(value == NULL) {
		PyErr_SetString(PyExc_TypeError, "Cannot delete the username");
		return -1;
	}
	    
	if(!PyString_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "The username attribute value must be a string");
		return -1;
	}
	          
	Py_DECREF(self->username);
	Py_INCREF(value);
	self->username = value;    

	username = PyString_AsString(self->username);
	
	ssh_options_set_username(self->options, username);

	return 0;
}

//int 	ssh_options_set_wanted_algos (SSH_OPTIONS *opt, int algo, char *list)
// 	set the algorithms to be used for cryptography and compression 



static PyObject *OPTIONS_OBJECT_getopt(OPTIONS_OBJECT *self, PyObject *args)
{
	int argc, i;
	char **argvlist = NULL;
	PyObject *argv;
	PyObject *(*getitem)(PyObject *, int);

	argc = i = 0;

	if(self->options == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "O", &argv))
		return NULL;

	if(PyList_Check(argv)){
		argc = PyList_Size(argv);
		getitem = PyList_GetItem;
	}

	argvlist = PyMem_NEW(char *, argc+1);
	
	if(argvlist == NULL){
		PyErr_NoMemory();
		return NULL;
	}

	for(i = 0; i < argc; i++){
		if(!PyArg_Parse((*getitem)(argv, i), "s", &argvlist[i]))
			return NULL;
	}

	argvlist[argc] = NULL;
	
	for(i = 0; i < argc; i++)
		printf("ARGV[%d] = %s\n", i, argvlist[i]);

	if(ssh_options_getopt(self->options, &argc, argvlist)){
		PyMem_Del(argvlist);
		return NULL;
	}

	PyMem_Del(argvlist);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef OPTIONS_OBJECT_methods[] = {
//	{ "getopt", (PyCFunction)OPTIONS_OBJECT_getopt, METH_VARARGS, "blabla" },
	{ "set_bind", (PyCFunction)OPTIONS_OBJECT_set_bind, METH_VARARGS, "blabla" },
	{ "set_timeout", (PyCFunction)OPTIONS_OBJECT_set_timeout, METH_VARARGS, "blabla" },
	{ NULL }
};

static PyMemberDef OPTIONS_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef OPTIONS_OBJECT_getseters[] = {
	{ "banner", (getter)OPTIONS_OBJECT_get_banner, (setter)OPTIONS_OBJECT_set_banner, "banner", NULL },
	{ "dsa_server_key", (getter)OPTIONS_OBJECT_get_dsa_server_key, (setter)OPTIONS_OBJECT_set_dsa_server_key, "dsa_server_key", NULL },
	{ "fd", (getter)OPTIONS_OBJECT_get_fd, (setter)OPTIONS_OBJECT_set_fd, "fd", NULL },
	{ "host", (getter)OPTIONS_OBJECT_get_host, (setter)OPTIONS_OBJECT_set_host, "host", NULL },
	{ "identity", (getter)OPTIONS_OBJECT_get_identity, (setter)OPTIONS_OBJECT_set_identity, "identity", NULL },
	{ "known_hosts_file", (getter)OPTIONS_OBJECT_get_known_hosts_file, (setter)OPTIONS_OBJECT_set_known_hosts_file, "known_hosts_file", NULL },
	{ "port", (getter)OPTIONS_OBJECT_get_port, (setter)OPTIONS_OBJECT_set_port, "port", NULL },
	{ "rsa_server_key", (getter)OPTIONS_OBJECT_get_rsa_server_key, (setter)OPTIONS_OBJECT_set_rsa_server_key, "rsa_server_key", NULL },
	{ "ssh_dir", (getter)OPTIONS_OBJECT_get_ssh_dir, (setter)OPTIONS_OBJECT_set_ssh_dir, "ssh_dir", NULL },
	{ "username", (getter)OPTIONS_OBJECT_get_username, (setter)OPTIONS_OBJECT_set_username, "username", NULL },
	{ NULL }  /* Sentinel */
};

static PyTypeObject OPTIONS_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.OPTIONS",		/* tp_name */
	sizeof(OPTIONS_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)OPTIONS_OBJECT_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"OPTIONS_OBJECT",		/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	OPTIONS_OBJECT_methods,		/* tp_methods */
	0,
	//OPTIONS_OBJECT_members,	/* tp_members */
	OPTIONS_OBJECT_getseters,	/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)OPTIONS_OBJECT_init,		/* tp_init */
	0,				/* tp_alloc */
	OPTIONS_OBJECT_new,			/* tp_new */
};



static void 
CHANNEL_OBJECT_dealloc(CHANNEL_OBJECT *self)
{
	printf("JE ME BARRE DE CHANNEL !!\n");
	
	if(self->channel != NULL && channel_is_closed(self->channel)){
		channel_free(self->channel);
	}
		
	self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
CHANNEL_OBJECT_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	CHANNEL_OBJECT *self;

	printf("CREATION DE CHANNEL !!!\n");

	self = (CHANNEL_OBJECT *)type->tp_alloc(type, 0);

	self->channel = NULL;

        return (PyObject *)self;
}

static int 
CHANNEL_OBJECT_init(CHANNEL_OBJECT *self, PyObject *args, PyObject *kwds)
{
	PyObject *obj;
	static char *kwlist[] = { "session", NULL };

	if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &obj))
		return -1;

	self->session = (SESSION_OBJECT *)obj;
	
	self->channel = channel_new(self->session->session);
	
	return 0;
}


//int 	channel_change_pty_size (CHANNEL *channel, int cols, int rows)
// 	change the size of the terminal associated to a channel

static PyObject *
CHANNEL_OBJECT_change_pty_size(CHANNEL_OBJECT *self, PyObject *args)
{
	int cols, rows, state;
	
	if(self->channel == NULL)
		return NULL;	
	
	if(!PyArg_ParseTuple(args, "ii", &cols, &rows))
		return NULL;
	
	state = channel_change_pty_size(self->channel, cols, rows);
	
	return Py_BuildValue("i", state);
}

//int 	channel_close (CHANNEL *channel)
// 	close a channel

static PyObject *
CHANNEL_OBJECT_close(CHANNEL_OBJECT *self)
{
	int state;
	
	if(self->channel == NULL)
		return NULL;	
	
	state = channel_close(self->channel);
	
	return Py_BuildValue("i", state);
}

//void 	channel_free (CHANNEL *channel)
// 	close and free a channel

static PyObject *
CHANNEL_OBJECT_free(CHANNEL_OBJECT *self){
	
	if(self->channel == NULL)
		return NULL;
	
	channel_free(self->channel);

	self->channel = NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

//SSH_SESSION * 	channel_get_session (CHANNEL *channel)
// 	recover the session in which belong a channel

static PyObject *
CHANNEL_OBJECT_get_session(CHANNEL_OBJECT *self)
{
	Py_INCREF(self->session);
	return (PyObject *)self->session;
}

//int 	channel_is_closed (CHANNEL *channel)
// 	returns if the channel is closed or not

static PyObject *
CHANNEL_OBJECT_is_closed(CHANNEL_OBJECT *self)
{
	int state;
	
	if(self->channel == NULL)
		return NULL;
	
	state = channel_is_closed(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_is_eof (CHANNEL *channel)
//	returns if the remote has sent an EOF

static PyObject *
CHANNEL_OBJECT_is_eof(CHANNEL_OBJECT *self)
{
	int state;
	
	if(self->channel == NULL)
		return NULL;
	
	state = channel_is_eof(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_is_open (CHANNEL *channel)
// 	returns if the channel is open or not

static PyObject *
CHANNEL_OBJECT_is_open(CHANNEL_OBJECT *self)
{
	int state;
	
	if(self->channel == NULL)
		return NULL;
	
	state = channel_is_open(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_open_forward (CHANNEL *channel, char *remotehost, int remoteport, char *sourcehost, int localport)
// 	open a TCP/IP forwarding channel.

static PyObject *
CHANNEL_OBJECT_open_forward(CHANNEL_OBJECT *self, PyObject *args)
{
	char *remotehost, *sourcehost;
	int remoteport, localport, state;

	if(self->channel == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "sisi", &remotehost, &remoteport, &sourcehost, &localport))
		return NULL;		
		
	state = channel_open_forward(self->channel, remotehost, remoteport, sourcehost, localport);

	return Py_BuildValue("i", state);
}

//int 	channel_open_session (CHANNEL *channel)
// 	open a session channel (suited for a shell. Not tcp)


static PyObject *
CHANNEL_OBJECT_open_session(CHANNEL_OBJECT *self)
{
	int state;

	if(self->channel == NULL)
		return NULL;
	
	state = channel_open_session(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_poll (CHANNEL *channel, int is_stderr)
// 	polls the channel for data to read

static PyObject *
CHANNEL_OBJECT_poll(CHANNEL_OBJECT *self, PyObject *args)
{
	int state, is_stderr;

	if(self->channel == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "i", &is_stderr))
		return NULL;		
		
	state = channel_poll(self->channel, is_stderr);

	return Py_BuildValue("i", state);
}

//int 	channel_read (CHANNEL *channel, BUFFER *buffer, int bytes, int is_stderr)
 //	reads data from a channel


static PyObject *
CHANNEL_OBJECT_read(CHANNEL_OBJECT *self, PyObject *args)
{
	PyObject *obj;
	BUFFER_OBJECT *buffer;
	int state, bytes, is_stderr;

	if(self->channel == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "Oii", &obj, &bytes, &is_stderr))
		return NULL;		
		
	buffer = (BUFFER_OBJECT *)obj;
	
	state = channel_read(self->channel, buffer->buffer, bytes, is_stderr);

	return Py_BuildValue("i", state);
}


//int 	channel_read_nonblocking (CHANNEL *channel, char *dest, int len, int is_stderr)
// 	nonblocking read

/*
static PyObject *
CHANNEL_OBJECT_read_nonblocking(CHANNEL_OBJECT *self, PyObject *args)
{
	int state, is_stderr;

	if(self->channel == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "i", &is_stderr))
		return NULL;		
		
	state = channel_poll(self->channel, is_stderr);

	return Py_BuildValue("i", state);
}*/

//int 	channel_request_env (CHANNEL *channel, char *name, char *value)
// 	set the environement variables

//int 	channel_request_exec (CHANNEL *channel, char *cmd)
// 	run a shell command without an interactive shell

static PyObject *
CHANNEL_OBJECT_request_exec(CHANNEL_OBJECT *self, PyObject *args)
{
	int state;
	char *cmd;

	if(self->channel == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "s", &cmd))
		return NULL;
	
	printf("CMD %s\n", cmd);
	
	state = channel_request_exec(self->channel, cmd);
	
	return Py_BuildValue("i", state);
}

//int 	channel_request_pty (CHANNEL *channel)
// 	requests a pty

static PyObject *
CHANNEL_OBJECT_request_pty(CHANNEL_OBJECT *self)
{
	int state;

	if(self->channel == NULL)
		return NULL;
	
	state = channel_request_pty(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_request_pty_size (CHANNEL *channel, char *terminal, int col, int row)
// 	requests a pty with a specific type and size

//int 	channel_request_shell (CHANNEL *channel)
// 	requests a shell

static PyObject *
CHANNEL_OBJECT_request_shell(CHANNEL_OBJECT *self)
{
	int state;

	if(self->channel == NULL)
		return NULL;
	
	state = channel_request_shell(self->channel);

	return Py_BuildValue("i", state);
}

//int 	channel_request_subsystem (CHANNEL *channel, char *system)
// 	requests a subsystem (for example sftp)

static PyObject *
CHANNEL_OBJECT_request_subsystem(CHANNEL_OBJECT *self, PyObject *args)
{
	int state;
	char *system;

	if(self->channel == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "s", &system))
		return NULL;
	
	printf("SYSTEM %s\n", system);
	
	state = channel_request_subsystem(self->channel, system);
	
	return Py_BuildValue("i", state);
}


//int 	channel_select (CHANNEL **readchans, CHANNEL **writechans, CHANNEL **exceptchans, struct timeval *timeout)
// 	act as the standard select(2) for channels

//int 	channel_send_eof (CHANNEL *channel)
// 	send an end of file on the channel

static PyObject *
CHANNEL_OBJECT_send_eof(CHANNEL_OBJECT *self)
{
	int state;
	
	if(self->channel == NULL)
		return NULL;
	
	state = channel_send_eof(self->channel);

	return Py_BuildValue("i", state);
}

//void 	channel_set_blocking (CHANNEL *channel, int blocking)
// 	put the channel into nonblocking mode
/*
static PyObject *
CHANNEL_OBJECT_set_blocking(CHANNEL_OBJECT *self, PyObject *value, void *closure){
	int blocking;

	if(self->channel == NULL)
		return -1;
		
	if(value == NULL){
		PyErr_SetString(PyExc_TypeError, "Cannot delete the blocking");
		return -1;
	}

	if(!PyInt_Check(value)){
		PyErr_SetString(PyExc_TypeError, "The blocking attribute value must be an int");
		return -1;
	}

		
	Py_DECREF(self->blocking);
	Py_INCREF(value);
		
	self->blocking = value;
	
	blocking = PyInt_AsLong(self->blocking);
	ssh_options_set_blocking(self->options, blocking);

	return 0;
}*/

//int 	channel_write (CHANNEL *channel, void *data, int len)
// 	blocking write on channel 
	

static PyMethodDef CHANNEL_OBJECT_methods[] = {
	{ "change_pty_size", (PyCFunction)CHANNEL_OBJECT_change_pty_size, METH_VARARGS, "blabla" },
	{ "close", (PyCFunction)CHANNEL_OBJECT_close, METH_NOARGS, "blabla" },
	{ "free", (PyCFunction)CHANNEL_OBJECT_free, METH_NOARGS, "blabla" },
	{ "is_closed", (PyCFunction)CHANNEL_OBJECT_is_closed, METH_NOARGS, "blabla" },
	{ "is_eof", (PyCFunction)CHANNEL_OBJECT_is_eof, METH_NOARGS, "blabla" },
	{ "is_open", (PyCFunction)CHANNEL_OBJECT_is_open, METH_NOARGS, "blabla" },
	{ "open_forward", (PyCFunction)CHANNEL_OBJECT_open_forward, METH_VARARGS, "blabla" },
	{ "open_session", (PyCFunction)CHANNEL_OBJECT_open_session, METH_NOARGS, "blabla" },
	{ "poll", (PyCFunction)CHANNEL_OBJECT_poll, METH_VARARGS, "blabla" },
	{ "read", (PyCFunction)CHANNEL_OBJECT_read, METH_VARARGS, "blabla" },
	{ "request_exec", (PyCFunction)CHANNEL_OBJECT_request_exec, METH_VARARGS, "blabla" },
	{ "request_pty", (PyCFunction)CHANNEL_OBJECT_request_pty, METH_NOARGS, "blabla" },
	{ "request_shell", (PyCFunction)CHANNEL_OBJECT_request_shell, METH_VARARGS, "blabla" },
	{ "request_subsystem", (PyCFunction)CHANNEL_OBJECT_request_subsystem, METH_VARARGS, "blabla" },
	{ "send_eof", (PyCFunction)CHANNEL_OBJECT_send_eof, METH_NOARGS, "blabla" },
	{ NULL }
};

static PyMemberDef CHANNEL_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef CHANNEL_OBJECT_getseters[] = {
	{ "session", (getter)CHANNEL_OBJECT_get_session, NULL, "session", NULL },
	{ NULL }  /* Sentinel */
};

static PyTypeObject CHANNEL_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.CHANNEL",		/* tp_name */
	sizeof(CHANNEL_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)CHANNEL_OBJECT_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"CHANNEL_OBJECT",		/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	CHANNEL_OBJECT_methods,		/* tp_methods */
	0,
	//CHANNEL_OBJECT_members,	/* tp_members */
	CHANNEL_OBJECT_getseters,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)CHANNEL_OBJECT_init,		/* tp_init */
	0,				/* tp_alloc */
	CHANNEL_OBJECT_new,			/* tp_new */
};

static void 
MESSAGE_OBJECT_dealloc(MESSAGE_OBJECT *self)
{
	printf("JE ME BARRE DE MESSAGE  !!\n");

	if(self->message != NULL)
		ssh_message_free(self->message);
	
	self->message = NULL;

        self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
MESSAGE_OBJECT_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	MESSAGE_OBJECT *self;

	printf("CREATION DE MESSAGE !!!\n");

	self = (MESSAGE_OBJECT *)type->tp_alloc(type, 0);

	return (PyObject *)self;
}

static int 
MESSAGE_OBJECT_init(MESSAGE_OBJECT *self, PyObject *args, PyObject *kwds)
{
	return 0;
}

//int ssh_message_type(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_ttype(MESSAGE_OBJECT *self)
{
	int type;
	
	if(self->message == NULL)
		return NULL;
	
	type = ssh_message_type(self->message);

	return Py_BuildValue("i", type);
}

//int ssh_message_subtype(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_subtype(MESSAGE_OBJECT *self)
{
	int subtype;
	
	if(self->message == NULL)
		return NULL;
	
	subtype = ssh_message_subtype(self->message);

	return Py_BuildValue("i", subtype);
}

//int ssh_message_reply_default(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_reply_default(MESSAGE_OBJECT *self)
{
	int state;

	if(self->message == NULL)
		return NULL;
	
	state = ssh_message_reply_default(self->message);
	
	return Py_BuildValue("i", state);
}

//void ssh_message_free(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_free(MESSAGE_OBJECT *self)
{
	if(self->message == NULL)
		return NULL;
	
	ssh_message_free(self->message);

	Py_INCREF(Py_None);
	return Py_None;
}

//char *ssh_message_auth_user(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_auth_user(MESSAGE_OBJECT *self)
{
	char *user;
	
	if(self->message == NULL)
		return NULL;
	
	user = ssh_message_auth_user(self->message);

	return Py_BuildValue("s", user);
}

//char *ssh_message_auth_password(SSH_MESSAGE *msg);

static PyObject *
MESSAGE_OBJECT_auth_password(MESSAGE_OBJECT *self)
{
	char *password;
	
	if(self->message == NULL)
		return NULL;
	
	password = ssh_message_auth_password(self->message);

	return Py_BuildValue("s", password);
}

//int ssh_message_auth_reply_success(SSH_MESSAGE *msg,int partial);

static PyObject *
MESSAGE_OBJECT_auth_reply_success(MESSAGE_OBJECT *self, PyObject *args)
{
	int state, partial;

	if(self->message == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "i", &partial))
		return NULL;
	
	state = ssh_message_auth_reply_success(self->message, partial);
	
	return Py_BuildValue("i", state);
}

//void ssh_message_auth_set_methods(SSH_MESSAGE *msg, int methods);

static PyObject *
MESSAGE_OBJECT_auth_set_methods(MESSAGE_OBJECT *self, PyObject *args)
{
	int methods;
	
	if(self->message == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "i", &methods))
		return NULL;
	
	ssh_message_auth_set_methods(self->message, methods);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//CHANNEL *ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg);
/*
static PyObject *
MESSAGE_OBJECT_request_open_reply_accept(MESSAGE_OBJECT *self)
{
	int state, partial;

	if(self->message == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "i", &partial))
		return NULL;
	
	state = ssh_message_auth_reply_success(self->message, partial);
	
	return Py_BuildValue("i", state);
}*/

//CHANNEL *ssh_message_channel_request_channel(SSH_MESSAGE *msg);
// returns the TERM env variable

//char *ssh_message_channel_request_pty_term(SSH_MESSAGE *msg);

//char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg);

//int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg);


static PyMethodDef MESSAGE_OBJECT_methods[] = {
	{ "type", (PyCFunction)MESSAGE_OBJECT_ttype, METH_NOARGS, "type" },
	{ "subtype", (PyCFunction)MESSAGE_OBJECT_subtype, METH_NOARGS, "subtype" },
	{ "reply_default", (PyCFunction)MESSAGE_OBJECT_reply_default, METH_NOARGS, "reply_default" },
	{ "free", (PyCFunction)MESSAGE_OBJECT_free, METH_NOARGS, "free"},
	{ "auth_user", (PyCFunction)MESSAGE_OBJECT_auth_user, METH_NOARGS, "auth_user" },
	{ "auth_password", (PyCFunction)MESSAGE_OBJECT_auth_password, METH_NOARGS, "auth_password" },
	{ "auth_reply_success", (PyCFunction)MESSAGE_OBJECT_auth_reply_success,METH_VARARGS, "auth_reply_success" },
	{ "auth_set_methods", (PyCFunction)MESSAGE_OBJECT_auth_set_methods, METH_VARARGS, "auth_set_methods" },
	{ NULL }
};

static PyMemberDef MESSAGE_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef MESSAGE_OBJECT_getseters[] = {
	{ NULL }  /* Sentinel */
};

static PyTypeObject MESSAGE_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.MESSAGE",		/* tp_name */
	sizeof(MESSAGE_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)MESSAGE_OBJECT_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"MESSAGE_OBJECT",		/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	MESSAGE_OBJECT_methods,		/* tp_methods */
	0,
	//BUFFER_OBJECT_members,	/* tp_members */
	MESSAGE_OBJECT_getseters,	/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)MESSAGE_OBJECT_init,		/* tp_init */
	0,				/* tp_alloc */
	MESSAGE_OBJECT_new,			/* tp_new */
};

static void 
SESSION_OBJECT_dealloc(SESSION_OBJECT *self)
{
	printf("JE ME BARRE DE SESSION !!\n");
	
	Py_XDECREF(self->disconnect_message);
	Py_XDECREF(self->fd);
	Py_XDECREF(self->issue_banner);
	Py_XDECREF(self->status);
	Py_XDECREF(self->version);
	
	if(self->session != NULL){
		ssh_disconnect(self->session);
		ssh_finalize();
	}

	self->session = NULL;
	self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
SESSION_OBJECT_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	SESSION_OBJECT *self;
	
	printf("CREATION DE SESSION !!!\n");
	
	self = (SESSION_OBJECT *)type->tp_alloc(type, 0);

	if(self != NULL){
		
		self->disconnect_message = PyString_FromString("");
		if(self->disconnect_message == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->fd = PyInt_FromLong(0);
		if(self->fd == NULL){
			Py_DECREF(self);
			return NULL;
		}

		self->issue_banner = PyString_FromString("");
		if(self->issue_banner == NULL){
			Py_DECREF(self);
			return NULL;
		}
		self->status = PyInt_FromLong(0);
		if(self->status == NULL){
			Py_DECREF(self);
			return NULL;
		}
		
		self->version = PyInt_FromLong(0);
		if(self->version == NULL){
			Py_DECREF(self);
			return NULL;
		}
	}

	return (PyObject *)self;
}


static int 
SESSION_OBJECT_init(SESSION_OBJECT *self, PyObject *args, PyObject *kwds)
{
	PyObject *obj;
	OPTIONS_OBJECT *options;
	
	static char *kwlist[] = { "options", NULL };

	printf("JE SUIS DANS INIT SESSION\n");
	if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &obj))
		return -1;

	options = (OPTIONS_OBJECT *)obj;

	self->session = ssh_new();
	
	ssh_set_options(self->session, options->options);
							 
	return 0;
}

//int 	pubkey_get_hash (SSH_SESSION *session, unsigned char hash[MD5_DIGEST_LEN])

//int 	ssh_connect (SSH_SESSION *session)
// 	connect to the ssh server

static PyObject *
SESSION_OBJECT_connect(SESSION_OBJECT *self)
{
	if(self->session != NULL){
		if(ssh_connect(self->session))
			return PyErr_SetFromErrno(PyExc_OSError);
	}
	else
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

//void 	ssh_disconnect (SSH_SESSION *session)
// 	disconnect from a session (client or server)

static PyObject *
SESSION_OBJECT_disconnect(SESSION_OBJECT *self)
{
	if(self->session == NULL)
		return NULL;
	
		
	ssh_disconnect(self->session);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//const char * 	ssh_get_disconnect_message (SSH_SESSION *session)
// 	get the disconnect message from the server

static PyObject *
SESSION_OBJECT_get_disconnect_message(SESSION_OBJECT *self, void *closure)
{
        const char *disconnect_message;

	if(self->session == NULL)
		return NULL;
	
	//disconnect_message = ssh_get_disconnect_message(self->session);
	if(disconnect_message != NULL){
		Py_DECREF(self->disconnect_message);
		self->disconnect_message = PyString_FromString(disconnect_message);
		Py_INCREF(self->disconnect_message);
		return self->disconnect_message;
	}

	Py_INCREF(Py_None);
        return Py_None;
}


//int 	ssh_get_fd (SSH_SESSION *session)
// 	recover the fd of connection


static PyObject *
SESSION_OBJECT_get_fd(SESSION_OBJECT *self, void *closure)
{
	int fd;

	if(self->session == NULL)
		return NULL;

	
	fd = ssh_get_fd(self->session);
	Py_XDECREF(self->fd);
	self->fd = PyInt_FromLong(fd);
	Py_XINCREF(self->fd);
	return self->fd;
}

//char * 	ssh_get_issue_banner (SSH_SESSION *session)
// 	get the issue banner from the server

static PyObject *
SESSION_OBJECT_get_issue_banner(SESSION_OBJECT *self, void *closure)
{
        const char *issue_banner;

	if(self->session == NULL)
		return NULL;
	
	issue_banner = ssh_get_issue_banner(self->session);
	if(issue_banner != NULL){
		Py_DECREF(self->issue_banner);
		self->issue_banner = PyString_FromString(issue_banner);
		Py_INCREF(self->issue_banner);
		return self->issue_banner;
	}

	Py_INCREF(Py_None);
        return Py_None;
}

//int 	ssh_get_pubkey_hash (SSH_SESSION *session, unsigned char hash[MD5_DIGEST_LEN])
// 	get the md5 hash of the server public key

//int 	ssh_get_status (SSH_SESSION *session)
// 	get session status

static PyObject *
SESSION_OBJECT_get_status(SESSION_OBJECT *self, void *closure)
{
	int status;
	
	if(self->session == NULL)
		return NULL;
	
	//status = ssh_get_status(self->session);
	Py_DECREF(self->status);
	self->status = PyInt_FromLong(status);
	Py_INCREF(self->status);
	return self->status;
}

//int 	ssh_get_version (SSH_SESSION *session)
// 	get the protocol version of the session

static PyObject *
SESSION_OBJECT_get_version(SESSION_OBJECT *self, void *closure)
{
	int ver;
	
	if(self->session == NULL)
		return NULL;
	
	ver = ssh_get_version(self->session);
	Py_DECREF(self->version);
	self->version = PyInt_FromLong(ver);
	Py_INCREF(self->version);
	return self->version;
}

//int 	ssh_handle_packets (SSH_SESSION *session)

static PyObject *
SESSION_OBJECT_handle_packets(SESSION_OBJECT *self)
{
	int state;

	if(self->session == NULL)
		return NULL;
	
	//state = ssh_handle_packets(self->session);
	
	return Py_BuildValue("i", state);
}

//int 	ssh_is_server_known (SSH_SESSION *session)
 //	test if the server is known

static PyObject *
SESSION_OBJECT_is_server_known(SESSION_OBJECT *self)
{
	int state;

	if(self->session == NULL)
		return NULL;
	
	state = ssh_is_server_known(self->session);
	
	return Py_BuildValue("i", state);
}

//int 	ssh_select (CHANNEL **channels, CHANNEL **outchannels, int maxfd, fd_set *readfds, struct timeval *timeout)
// 	wrapper for the select syscall

//void 	ssh_set_blocking (SSH_SESSION *session, int blocking)
//	set the session in blocking/nonblocking mode

static PyObject *
SESSION_OBJECT_set_blocking(SESSION_OBJECT *self, PyObject *args)
{
	int blocking;

	if(self->session == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "i", &blocking))
		return NULL;		
		
	//ssh_set_blocking(self->session, blocking);
        
	Py_INCREF(Py_None);
	return Py_None;
}

//void 	ssh_set_fd_except (SSH_SESSION *session)
// 	say the session it has an exception to catch on the file descriptor

//void 	ssh_set_fd_toread (SSH_SESSION *session)
// 	say to the session it has data to read on the file descriptor without blocking

//void 	ssh_set_fd_towrite (SSH_SESSION *session)
// 	say the session it may write to the file descriptor without blocking

//void 	ssh_set_options (SSH_SESSION *session, SSH_OPTIONS *options)
// 	set the options for the current session

static PyObject *
SESSION_OBJECT_set_options(SESSION_OBJECT *self, PyObject *args)
{
	PyObject *obj;
	OPTIONS_OBJECT *options;

	if(self->session == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "O", &obj))
		return NULL;

	options = (OPTIONS_OBJECT *)obj;
	ssh_set_options(self->session, options->options);
	
        Py_INCREF(Py_None);
	return Py_None;
}

//void 	ssh_silent_disconnect (SSH_SESSION *session)
// 	disconnect impolitely from remote host

static PyObject *SESSION_OBJECT_silent_disconnect(SESSION_OBJECT *self)
{	
	if(self->session == NULL)
		return NULL;
	
	ssh_silent_disconnect(self->session);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//int 	ssh_write_knownhost (SSH_SESSION *session)
// 	write the current server as known in the known hosts file 

static PyObject *
SESSION_OBJECT_write_knowhost(SESSION_OBJECT *self)
{
	int state;
	
	if(self->session == NULL)
		return NULL;
	
	state = ssh_write_knownhost(self->session);
	
	return Py_BuildValue("i", state);
}


//int ssh_accept(SSH_SESSION *session);
static PyObject *
SESSION_OBJECT_accept(SESSION_OBJECT *self)
{
	int state;

	if(self->session == NULL)
		return NULL;
	
	state = ssh_accept(self->session);

	return Py_BuildValue("i", state);
}



static PyObject *
SESSION_OBJECT_get_error(SESSION_OBJECT *self)
{
	char *error;

	if(self->session == NULL)
		return NULL;
	
	error = ssh_get_error(self->session);

	return Py_BuildValue("s", error);
}



//int 	ssh_userauth_autopubkey (SSH_SESSION *session)
// 	Tries to automaticaly authenticate with public key and "none".

static PyObject *
SESSION_OBJECT_userauth_autopubkey(SESSION_OBJECT *self)
{
	int auth;

	if(self->session == NULL)
		return NULL;
	
	auth = ssh_userauth_autopubkey(self->session);
	
	return Py_BuildValue("i", auth);
}

//int 	ssh_userauth_kbdint (SSH_SESSION *session, char *user, char *submethods)
// 	Try to authenticate through the "keyboard-interactive" method.

static PyObject *
SESSION_OBJECT_userauth_kbdint(SESSION_OBJECT *self, PyObject *args)
{
	char *user, *submethods;
	int err;
	
	if(self->session == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "ss", &user, &submethods))
		return NULL;

	err = ssh_userauth_kbdint(self->session, NULL, NULL);
	
	return Py_BuildValue("i", err);
}

//char * 	ssh_userauth_kbdint_getinstruction (SSH_SESSION *session)
// 	get the "instruction" of the message block

static PyObject *
SESSION_OBJECT_userauth_kbdint_getinstruction(SESSION_OBJECT *self)
{
	char *instruction;

	if(self->session == NULL)
		return NULL;
	
	instruction = ssh_userauth_kbdint_getinstruction(self->session);

	return Py_BuildValue("s", instruction);
}

//char * 	ssh_userauth_kbdint_getname (SSH_SESSION *session)
// 	get the "name" of the message block

static PyObject *
SESSION_OBJECT_userauth_kbdint_getname(SESSION_OBJECT *self)
{
	char *name;

	if(self->session == NULL)
		return NULL;
	
	name = ssh_userauth_kbdint_getname(self->session);

	return Py_BuildValue("s", name);
}

//int 	ssh_userauth_kbdint_getnprompts (SSH_SESSION *session)
// 	get the number of prompts (questions) the server has given

static PyObject *
SESSION_OBJECT_userauth_kbdint_getnprompts(SESSION_OBJECT *self)
{
	int n;

	if(self->session == NULL)
		return NULL;
	
	n = ssh_userauth_kbdint_getnprompts(self->session);

	return Py_BuildValue("i", n);
}

//char * 	ssh_userauth_kbdint_getprompt (SSH_SESSION *session, int i, char *echo)
// 	get a prompt from a message block

static PyObject *
SESSION_OBJECT_userauth_kbdint_getprompt(SESSION_OBJECT *self, PyObject *args)
{
	int i;
	char echo;
	char *prompt;

	if(self->session == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "i", &i))
		return NULL;
	
	prompt = ssh_userauth_kbdint_getprompt(self->session, i, &echo);

	return Py_BuildValue("si", prompt, echo);
}

//void 	ssh_userauth_kbdint_setanswer (SSH_SESSION *session, unsigned int i, char *answer)
// 	set the answer for a question from a message block.

//int 	ssh_userauth_none (SSH_SESSION *session, char *username)
// 	Try to authenticate through the "none" method.

//int 	ssh_userauth_offer_pubkey (SSH_SESSION *session, char *username, int type, STRING *publickey)
// 	Try to authenticate through public key.

//int 	ssh_userauth_password (SSH_SESSION *session, char *username, char *password)
// 	Try to authenticate by password.

static PyObject *
SESSION_OBJECT_userauth_password(SESSION_OBJECT *self, PyObject *args)
{
	char *username, *password;
	int auth;
	
	if(self->session == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "s",  &password))
		return NULL;

	auth = ssh_userauth_password(self->session, NULL, password);

	return Py_BuildValue("i", auth);
}

//int 	ssh_userauth_pubkey (SSH_SESSION *session, char *username, STRING *publickey, PRIVATE_KEY *privatekey)
// 	Try to authenticate through public key. 
		
	


static PyObject *
SESSION_OBJECT_userauth_kbdint_setanswer(SESSION_OBJECT *self, PyObject *args)
{
	int i;
	char *answer;

	if(self->session == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "is", &i, &answer))
		return NULL;

	ssh_userauth_kbdint_setanswer(self->session, i, answer);

	Py_INCREF(Py_None);
	return Py_None;	
}

static PyObject *
SESSION_OBJECT_message_get(SESSION_OBJECT *self)
{
	PyObject *obj;
	MESSAGE_OBJECT *message;
	
	if(self->session == NULL)
		return NULL;

	obj = MESSAGE_OBJECT_new(&MESSAGE_OBJECT_type, NULL, NULL);

	message = (MESSAGE_OBJECT *)obj;
	message->message = ssh_message_get(self->session);
	if(message->message == NULL){
		printf("VIDE !!\n");
		MESSAGE_OBJECT_dealloc(message);
		Py_INCREF(Py_None);
		return Py_None;
	}
	
	return obj;	
}

static PyMethodDef SESSION_OBJECT_methods[] = {
	{ "connect", (PyCFunction)SESSION_OBJECT_connect, METH_NOARGS, "connect" },
	{ "set_options", (PyCFunction)SESSION_OBJECT_set_options, METH_VARARGS, "blabla" },
	{ "handle_packets", (PyCFunction)SESSION_OBJECT_handle_packets, METH_NOARGS, "blabla" },
	{ "is_server_known", (PyCFunction)SESSION_OBJECT_is_server_known, METH_NOARGS, "blabla" },
	{ "accept", (PyCFunction)SESSION_OBJECT_accept, METH_NOARGS, "blabla" },
	{ "get_error", (PyCFunction)SESSION_OBJECT_get_error, METH_NOARGS, "blabla" },
	
	{ "userauth_autopubkey", (PyCFunction)SESSION_OBJECT_userauth_autopubkey, METH_NOARGS, "blabla" },
	{ "userauth_password", (PyCFunction)SESSION_OBJECT_userauth_password, METH_VARARGS, "blabla" },
	{ "userauth_kbdint", (PyCFunction)SESSION_OBJECT_userauth_kbdint, METH_VARARGS, "blabla" },
	{ "userauth_kbdint_getnprompts", (PyCFunction)SESSION_OBJECT_userauth_kbdint_getnprompts, METH_NOARGS, "blabla" },
	{ "userauth_kbdint_getname", (PyCFunction)SESSION_OBJECT_userauth_kbdint_getname, METH_NOARGS, "blabla" },
	{ "userauth_kbdint_getinstruction", (PyCFunction)SESSION_OBJECT_userauth_kbdint_getinstruction, METH_NOARGS, "blabla" },
	{ "userauth_kbdint_getprompt", (PyCFunction)SESSION_OBJECT_userauth_kbdint_getprompt, METH_VARARGS, "blabla" },
	{ "userauth_kbdint_setanswer", (PyCFunction)SESSION_OBJECT_userauth_kbdint_setanswer, METH_VARARGS, "blabla" },
	
	{ "message_get", (PyCFunction)SESSION_OBJECT_message_get, METH_NOARGS, "blabla"},
	{ NULL }
};

static PyMemberDef SESSION_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef SESSION_OBJECT_getseters[] = {
	{ "disconnect_message", (getter)SESSION_OBJECT_get_disconnect_message, NULL, "disconnect_message", NULL },
	{ "fd", (getter)SESSION_OBJECT_get_fd, NULL, "fd", NULL },
	{ "issue_banner", (getter)SESSION_OBJECT_get_issue_banner, NULL, "issue_banner", NULL },
	{ "status", (getter)SESSION_OBJECT_get_status, NULL, "status", NULL },
	{ "version", (getter)SESSION_OBJECT_get_version, NULL, "version", NULL },
	{ NULL }
};


static PyTypeObject SESSION_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.SESSION",		/* tp_name */
	sizeof(SESSION_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)SESSION_OBJECT_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"SESSION_OBJECT",			/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	SESSION_OBJECT_methods,		/* tp_methods */
	0,
	//SESSION_OBJECT_members,	/* tp_members */
	SESSION_OBJECT_getseters,	/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)SESSION_OBJECT_init,		/* tp_init */
	0,				/* tp_alloc */
	SESSION_OBJECT_new,			/* tp_new */
};


static void BIND_OBJECT_dealloc(BIND_OBJECT *self)
{
	printf("JE ME BARRE DE BIND !!\n");

	if(self->bind != NULL)
		ssh_bind_free(self->bind);
	
	self->bind = NULL;

        self->ob_type->tp_free((PyObject *)self);
}

static PyObject *BIND_OBJECT_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	BIND_OBJECT *self;

	printf("CREATION DE BIND !!!\n");

	self = (BIND_OBJECT *)type->tp_alloc(type, 0);

	if(self != NULL){
		self->bind = ssh_bind_new();
	}

	return (PyObject *)self;
}

static int BIND_OBJECT_init(BIND_OBJECT *self, PyObject *args, PyObject *kwds)
{
	return 0;
}

//void ssh_bind_set_options(SSH_BIND *ssh_bind, SSH_OPTIONS *options);

static PyObject *
BIND_OBJECT_set_options(BIND_OBJECT *self, PyObject *args)
{
	PyObject *obj;
	OPTIONS_OBJECT *options;

	if(self->bind == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "O", &obj))
		return NULL;

	
	options = (OPTIONS_OBJECT *)obj;
	ssh_bind_set_options(self->bind, options->options);
	
	Py_INCREF(Py_None);
	return Py_None;
}

//int ssh_bind_listen(SSH_BIND *ssh_bind);

static PyObject *
BIND_OBJECT_listen(BIND_OBJECT *self)
{
	int state;
	
	if(self->bind == NULL)
		return NULL;
	
	state = ssh_bind_listen(self->bind);
	
	return Py_BuildValue("i", state);
}

//void ssh_bind_set_blocking(SSH_BIND *ssh_bind,int blocking);

static PyObject *
BIND_OBJECT_set_blocking(BIND_OBJECT *self, PyObject *args)
{
	int blocking;

	if(self->bind == NULL)
		return NULL;
	
	if(!PyArg_ParseTuple(args, "i", &blocking))
		return NULL;

	ssh_bind_set_blocking(self->bind, blocking);
	
        Py_INCREF(Py_None);
	return Py_None;
}

//int ssh_bind_get_fd(SSH_BIND *ssh_bind);

static PyObject *
BIND_OBJECT_get_fd(BIND_OBJECT *self)
{
	int fd;
	
	if(self->bind == NULL)
		return NULL;
	
	fd = ssh_bind_get_fd(self->bind);
	
	return Py_BuildValue("i", fd);
}

//int ssh_bind_set_toaccept(SSH_BIND *ssh_bind);

static PyObject *
BIND_OBJECT_set_toaccept(BIND_OBJECT *self)
{
	int state;
	
	if(self->bind == NULL)
		return NULL;

	//state = ssh_bind_set_toaccept(self->bind);
	
	return Py_BuildValue("i", state);
}

//SSH_SESSION *ssh_bind_accept(SSH_BIND *ssh_bind);

static PyObject *
BIND_OBJECT_accept(BIND_OBJECT *self)
{
	PyObject *tmp;
	SESSION_OBJECT *session;
	
	if(self->bind == NULL)
		return NULL;
	
	tmp = SESSION_OBJECT_new(&SESSION_OBJECT_type, NULL, NULL);
	session = (SESSION_OBJECT *)tmp;
	
	session->session = ssh_bind_accept(self->bind);
	return tmp;
}

//void ssh_bind_free(SSH_BIND *ssh_bind);


static PyObject *
BIND_OBJECT_get_error(BIND_OBJECT *self)
{
	char *error;

	if(self->bind == NULL)
		return NULL;
	
	error = ssh_get_error(self->bind);

	return Py_BuildValue("s", error);
}

static PyMethodDef BIND_OBJECT_methods[] = {
	{ "set_options", (PyCFunction)BIND_OBJECT_set_options, METH_VARARGS, "set_options" },
	{ "listen", (PyCFunction)BIND_OBJECT_listen, METH_NOARGS, "listen" },
	{ "set_blocking", (PyCFunction)BIND_OBJECT_set_blocking, METH_VARARGS, "set_blocking" },
	{ "get_fd", (PyCFunction)BIND_OBJECT_get_fd, METH_NOARGS, "get_fd" },
	{ "set_toaccept", (PyCFunction)BIND_OBJECT_set_toaccept, METH_NOARGS, "set_toaccept" },
	{ "accept", (PyCFunction)BIND_OBJECT_accept, METH_NOARGS, "accept" },

	{ "get_error", (PyCFunction)BIND_OBJECT_get_error, METH_NOARGS, "blabla" },
	
	{ NULL }
};

static PyMemberDef BIND_OBJECT_members[] = {
	{ NULL }
};

static PyGetSetDef BIND_OBJECT_getseters[] = {
	{ NULL }  /* Sentinel */
};

static PyTypeObject BIND_OBJECT_type = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"pylibssh.BIND",		/* tp_name */
	sizeof(BIND_OBJECT),		/* tp_basicsize */
	0,				/* tp_itemsize */	
	(destructor)BIND_OBJECT_dealloc, 	/* tp_dealloc */
	0,				/* tp_print*/
        0,				/* tp_getattr */
	0,                      	/* tp_setattr */
	0,              	        /* tp_compare */
	0,      	                /* tp_repr */
	0,	                        /* tp_as_number */
	0,                         	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */	
	"BIND_OBJECT",		/* tp_doc */
        0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	BIND_OBJECT_methods,		/* tp_methods */
	0,
	//BIND_OBJECT_members,	/* tp_members */
	BIND_OBJECT_getseters,	/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)BIND_OBJECT_init,		/* tp_init */
	0,				/* tp_alloc */
	BIND_OBJECT_new,			/* tp_new */
};

static void install_int_const(PyObject *d, char *name, int value){
	PyObject *v = PyInt_FromLong( (long)value );
	if (!v || PyDict_SetItemString(d, name, v) )
		PyErr_Clear();

	Py_XDECREF(v);
}

void initpylibssh(void){
	PyObject *m, *d;

	if(PyType_Ready(&BUFFER_OBJECT_type) < 0)
		return;
	
	if(PyType_Ready(&OPTIONS_OBJECT_type) < 0)
		return;
	
	if(PyType_Ready(&SESSION_OBJECT_type) < 0)
		return;

	if(PyType_Ready(&CHANNEL_OBJECT_type) < 0)
		return;

	if(PyType_Ready(&MESSAGE_OBJECT_type) < 0)
		return;
	
	if(PyType_Ready(&BIND_OBJECT_type) < 0)
		return;
	
	m = Py_InitModule("pylibssh", NULL);
	
	Py_INCREF(&BUFFER_OBJECT_type);
	PyModule_AddObject(m, "BUFFER", (PyObject *)&BUFFER_OBJECT_type);
	
	Py_INCREF(&OPTIONS_OBJECT_type);
	PyModule_AddObject(m, "OPTIONS", (PyObject *)&OPTIONS_OBJECT_type);
	
	Py_INCREF(&SESSION_OBJECT_type);
	PyModule_AddObject(m, "SESSION", (PyObject *)&SESSION_OBJECT_type);

	Py_INCREF(&CHANNEL_OBJECT_type);
	PyModule_AddObject(m, "CHANNEL", (PyObject *)&CHANNEL_OBJECT_type);
	
	Py_INCREF(&MESSAGE_OBJECT_type);
	PyModule_AddObject(m, "MESSAGE", (PyObject *)&MESSAGE_OBJECT_type);
	
	Py_INCREF(&BIND_OBJECT_type);
	PyModule_AddObject(m, "BIND", (PyObject *)&BIND_OBJECT_type);
	
	d = PyModule_GetDict(m);

	/* the offsets of methods */
	install_int_const(d, "SSH_KEX", SSH_KEX);
	install_int_const(d, "SSH_HOSTKEYS", SSH_HOSTKEYS);
	install_int_const(d, "SSH_CRYPT_C_S", SSH_CRYPT_C_S);
	install_int_const(d, "SSH_CRYPT_S_C", SSH_CRYPT_S_C);
	install_int_const(d, "SSH_MAC_C_S", SSH_MAC_C_S);
	install_int_const(d, "SSH_MAC_S_C", SSH_MAC_S_C);
	install_int_const(d, "SSH_COMP_C_S", SSH_COMP_C_S);
	install_int_const(d, "SSH_COMP_S_C", SSH_COMP_S_C);
	install_int_const(d, "SSH_LANG_C_S", SSH_LANG_C_S);
	install_int_const(d, "SSH_LANG_S_C", SSH_LANG_S_C);

	install_int_const(d, "SSH_CRYPT", SSH_CRYPT);
	install_int_const(d, "SSH_MAC", SSH_MAC);
	install_int_const(d, "SSH_COMP", SSH_COMP);
	install_int_const(d, "SSH_LANG", SSH_LANG);

	install_int_const(d, "SSH_AUTH_SUCCESS", SSH_AUTH_SUCCESS);
	install_int_const(d, "SSH_AUTH_DENIED", SSH_AUTH_DENIED);
	install_int_const(d, "SSH_AUTH_PARTIAL", SSH_AUTH_PARTIAL); 
	install_int_const(d, "SSH_AUTH_INFO", SSH_AUTH_INFO);
	install_int_const(d, "SSH_AUTH_ERROR", SSH_AUTH_ERROR);
	install_int_const(d, "SSH_AUTH_ERROR", SSH_AUTH_ERROR);

	install_int_const(d, "SSH_CLOSED", SSH_CLOSED);
	install_int_const(d, "SSH_READ_PENDING", SSH_READ_PENDING);
	install_int_const(d, "SSH_CLOSED_ERROR", SSH_CLOSED_ERROR);

	install_int_const(d, "SSH_SERVER_ERROR", SSH_SERVER_ERROR);
	install_int_const(d, "SSH_SERVER_NOT_KNOWN", SSH_SERVER_NOT_KNOWN);
	install_int_const(d, "SSH_SERVER_KNOWN_OK", SSH_SERVER_KNOWN_OK);
	install_int_const(d, "SSH_SERVER_KNOWN_CHANGED", SSH_SERVER_KNOWN_CHANGED);
	install_int_const(d, "SSH_SERVER_FOUND_OTHER", SSH_SERVER_FOUND_OTHER);

	install_int_const(d, "MD5_DIGEST_LEN", MD5_DIGEST_LEN);

	install_int_const(d, "SSH_NO_ERROR", SSH_NO_ERROR);
	install_int_const(d, "SSH_REQUEST_DENIED", SSH_REQUEST_DENIED);
	install_int_const(d, "SSH_FATAL", SSH_FATAL);
	install_int_const(d, "SSH_EINTR", SSH_EINTR);

	install_int_const(d, "SSH_OK", SSH_OK);
	install_int_const(d, "SSH_ERROR", SSH_ERROR);
	install_int_const(d, "SSH_AGAIN", SSH_AGAIN);


	install_int_const(d, "SSH_AUTH_REQUEST", SSH_AUTH_REQUEST);
	install_int_const(d, "SSH_CHANNEL_REQUEST_OPEN", SSH_CHANNEL_REQUEST_OPEN);
	install_int_const(d, "SSH_CHANNEL_REQUEST", SSH_CHANNEL_REQUEST);
	install_int_const(d, "SSH_AUTH_NONE", SSH_AUTH_NONE);
	install_int_const(d, "SSH_AUTH_PASSWORD", SSH_AUTH_PASSWORD);
	install_int_const(d, "SSH_AUTH_HOSTBASED", SSH_AUTH_HOSTBASED);
	install_int_const(d, "SSH_AUTH_PUBLICKEY", SSH_AUTH_PUBLICKEY);
	install_int_const(d, "SSH_AUTH_KEYBINT", SSH_AUTH_KEYBINT);
	install_int_const(d, "SSH_AUTH_UNKNOWN", SSH_AUTH_UNKNOWN);
	install_int_const(d, "SSH_CHANNEL_SESSION", SSH_CHANNEL_SESSION);
	install_int_const(d, "SSH_CHANNEL_TCPIP", SSH_CHANNEL_TCPIP);
	install_int_const(d, "SSH_CHANNEL_X11", SSH_CHANNEL_X11);
	install_int_const(d, "SSH_CHANNEL_UNKNOWN", SSH_CHANNEL_UNKNOWN);
	install_int_const(d, "SSH_CHANNEL_REQUEST_PTY", SSH_CHANNEL_REQUEST_PTY);
	install_int_const(d, "SSH_CHANNEL_REQUEST_EXEC", SSH_CHANNEL_REQUEST_EXEC);
	install_int_const(d, "SSH_CHANNEL_REQUEST_SHELL", SSH_CHANNEL_REQUEST_SHELL);
	install_int_const(d, "SSH_CHANNEL_REQUEST_ENV", SSH_CHANNEL_REQUEST_ENV);
	install_int_const(d, "SSH_CHANNEL_REQUEST_SUBSYSTEM", SSH_CHANNEL_REQUEST_SUBSYSTEM);
	install_int_const(d, "SSH_CHANNEL_REQUEST_WINDOW_CHANGE", SSH_CHANNEL_REQUEST_WINDOW_CHANGE);
	install_int_const(d, "SSH_CHANNEL_REQUEST_UNKNOWN", SSH_CHANNEL_REQUEST_UNKNOWN);
	
}
