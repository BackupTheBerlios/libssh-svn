/*
 * channel.hpp
 *
 *  Created on: 21 juin 2009
 *      Author: aris
 */

#ifndef CHANNEL_HPP_
#define CHANNEL_HPP_
#include <libssh/libssh.h>
#include "session.hpp"
namespace ssh {

class Channel {
public:
	Channel(Session &s);
	bool openForward(std::string remotehost, int remoteport, std::string localhost, int localport);
	bool openSession();
	bool requestPty();
	bool requestPty(std::string term, int cols, int rows);
	bool changePty(int cols, int rows);
	bool requestShell();
	bool requestSubsystem(std::string subsystem);
	bool requestEnv(std::string name, std::string value);
	bool requestExec(std::string command);
	bool requestSftp();

	int write(const void *data, u32 len);
	void sendEof();
	int read(void *dest, u32 len, bool isstderr);
	int poll(bool isstderr);
	bool close();
	void setBlocking(bool blocking);
	int readNonBlocking(void *dest, u32 len, bool isstderr);
	bool isOpen();
	bool isClosed();
	bool isEof();
	Session &getSession();
	int getExitStatus();
};

}

#endif /* CHANNEL_HPP_ */
