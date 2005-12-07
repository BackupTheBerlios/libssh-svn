#ifndef HAVE_PACKET_H
#define HAVE_PACKET_H

/* in packet.c */

/* i should remove it one day */
typedef struct packet_struct {
	int valid;
	u32 len;
	u8 type;
} PACKET;


void packet_clear_out(SSH_SESSION *session);
void packet_parse(SSH_SESSION *session);
int packet_send(SSH_SESSION *session);

int packet_read(SSH_SESSION *session);
int packet_translate(SSH_SESSION *session);
int packet_wait(SSH_SESSION *session,int type);
int packet_flush(SSH_SESSION *session);

#endif
