
#include <libssh/libssh.h>

namespace ssh {
  class Session{
  private:
    SSH_SESSION *session;
  public:
    Session();
};
}

