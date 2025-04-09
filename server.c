#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8443
#define BUFFER_SIZE 1024

char stored_hash[65] = {0};

SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) exit(EXIT_FAILURE);
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "certs/client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", NULL);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT)
    };

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);

    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    printf("[SERVER] Starting with empty stored hash\n");
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        SSL_accept(ssl);

        int client_blocked = 0;
        uint32_t key = 0;  
        char buffer[BUFFER_SIZE];
        
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            if (strncmp(buffer, "HASH:", 5) == 0) {
                printf("\n[SERVER] Received hash: %s\n", buffer + 5);
                
                if (stored_hash[0] == '\0') {
                    strncpy(stored_hash, buffer + 5, 64);
                    stored_hash[64] = '\0';
                    printf("[SERVER] Stored initial hash: %s\n", stored_hash);
                    SSL_write(ssl, "HASH_STORED\n", 12);
                } else {
                    printf("[SERVER] Comparing with stored hash: %s\n", stored_hash);
                    if (strncmp(buffer + 5, stored_hash, 64) != 0) {
                        SSL_write(ssl, "HASH_MISMATCH\n", 14);
                        printf("[SERVER] Hash mismatch! Blocking client.\n");
                        client_blocked = 1;
                    } else {
                        SSL_write(ssl, "HASH_OK\n", 8);
                        printf("[SERVER] Hash matches!\n");
                    }
                }
            }
        }

        uint32_t ticket_counter = 0;
        if (!client_blocked) {
            key = rand();  
            uint32_t counter = rand();  
            char handshake[BUFFER_SIZE];
            snprintf(handshake, sizeof(handshake), "KEY=%u;CNT=%u\n", key, counter);
            SSL_write(ssl, handshake, strlen(handshake));
            ticket_counter = counter;
        }

        while (1) {
            bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes <= 0) break;

            buffer[bytes] = '\0';
            
            if (client_blocked) {
                printf("[SERVER] Ignoring request from blocked client\n");
                continue;
            }

            if (strstr(buffer, "TICKET")) {
                char ticket[32];
                snprintf(ticket, sizeof(ticket), "%u\n", ticket_counter ^ key);
                SSL_write(ssl, ticket, strlen(ticket));
                printf("[SERVER] Sent valid ticket\n");
                ticket_counter++; 
            }
            else if (strncmp(buffer, "HASH:", 5) == 0) {
                printf("\n[SERVER] Received periodic hash: %s\n", buffer + 5);
                if (strncmp(buffer + 5, stored_hash, 64) != 0) {
                    SSL_write(ssl, "HASH_MISMATCH\n", 14);
                    printf("[SERVER] Periodic hash mismatch! Blocking client.\n");
                    client_blocked = 1;
                } else {
                    SSL_write(ssl, "HASH_OK\n", 8);
                    printf("[SERVER] Periodic hash matches!\n");
                }
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
