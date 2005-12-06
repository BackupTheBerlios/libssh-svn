int ssh_fd_poll(SSH_SESSION *session,int *write, int *except);
int ssh_select(CHANNEL **channels,CHANNEL **outchannels, int maxfd, fd_set *readfds, struct timeval *timeout);

