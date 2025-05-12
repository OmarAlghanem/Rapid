#ifndef SERVER_COMM_H
#define SERVER_COMM_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8443
#define BUFFER_SIZE 1024
#define SHA256_DIGEST_LENGTH 32
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

/* Server Initialization */
void server_init(void);
void server_cleanup(void);

/* SSL/TLS Functions */
SSL_CTX *create_server_context(void);
void configure_server_context(SSL_CTX *ctx);
int init_server_ssl(void);

/* Connection Handling */
void handle_client(SSL *ssl);

/* Hash Verification */
int verify_client_hash(const char *received_hash, const char *hash_type);

/* Command Processing */
void process_client_command(const char *command);

#endif // SERVER_COMM_H