/*
 * options.hpp
 *
 *  Created on: 21 juin 2009
 *      Author: aris
 */

#ifndef OPTIONS_HPP_
#define OPTIONS_HPP_
#include "session.hpp"
namespace ssh {

class Options {
public:
	Options();
	~Options();
	void setWantedAlgos(int algo, std::string list);
	void setUsername(std::string username);
	void setPort(int port);
	void setHost(std::string host);
	int getopt(int *argcptr, int **argv);
	void setFd(socket_t fd);
	void setBind(std::string bindaddr);
	void setSshDir(std::string dir);
	void setKnownHostsFile(std::string filename);
	void setIdentity(std::string idfile);
	void setBanner(std::string banner);
	void setTimeout(long seconds, long usecs);
	void allowSsh1(bool allow);
	void allowSsh2(bool allow);
	void setLogVerbosity(int verbosity);
	void setDsaServerKey(std::string key);
	void setRsaServerKey(std::string key);
};

}

#endif /* OPTIONS_HPP_ */
