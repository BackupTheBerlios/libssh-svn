/*
 * session.hpp
 * wraps the SSH_SESSION data object
 */

#ifndef SESSION_HPP_

#include <libssh/libssh.h>
#include <string>

namespace ssh {
  class Session{
  private:
    SSH_SESSION *session;
  public:
    Session();
    socket_t getFd();
    int getVersion();
    int getStatus();
    std::string getDisconnectMessage();
    void setOptions();
    void socketCanRead();
    void socketCanWrite();
    void socketExcept();
    void setBlocking(bool block);
    void silentDisconnect();
    void connect();
    void disconnect();
    void serviceRequest();
    std::string getIssueBanner();
    int getPubkeyHash(unsigned char **hash);
    void freePubkeyHash(unsigned char **hash);
    STRING *getPubkey();

    int fdPoll(bool &write, bool &except);
    int isServerKnown();
    void writeKnownhost();

    int userauthList();
    int userauthNone();
    int userauthPassword(std::string password);
    int userauthOfferPubkey(int type, STRING *pubkey);
    int userauthPubkey(STRING *pubkey, void *privkey);
    int userauthAgentPubkey(STRING *pubkey);
    int userauthKeyboardInteractive(void *);
};
}

#endif

