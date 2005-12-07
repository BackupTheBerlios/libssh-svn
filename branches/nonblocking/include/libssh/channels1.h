/* channels1.c */
int channel_open_session1(CHANNEL *channel);
int channel_request_pty_size1(CHANNEL *channel, char *terminal,int cols, 
        int rows);
int channel_change_pty_size1(CHANNEL *channel, int cols, int rows);
int channel_request_shell1(CHANNEL *channel);
int channel_request_exec1(CHANNEL *channel, char *cmd);
void channel_handle1(SSH_SESSION *session,int type);
int channel_write1(CHANNEL *channel, void *data, int len);

