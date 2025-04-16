#ifndef COMM_H
#define COMM_H

void comm_init(const char *hostname, int port);
void comm_cleanup();
int comm_send_initial_hash(const char *hash);
int comm_send_periodic_hash(const char *hash);
void comm_send_ticket_request();

#endif
