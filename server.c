// src/server.c
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

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "/home/cal/Downloads/Graduation project/certs/ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

int main() {
    int server_fd = -1, client_fd = -1;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL_CTX *ctx;

    srand(time(NULL)); // Seed for key generation
    init_openssl();
    
    ctx = create_context();
    configure_context(ctx);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while(1) {
        printf("Waiting for connections...\n");
        
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) == -1) {
            perror("Accept failed");
            continue;
        }

        printf("Connection accepted\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            uint32_t key = rand();
            int sequence[] = {1, 2, 3, 4}; 
            int seq_length = sizeof(sequence)/sizeof(sequence[0]);

            char handshake_msg[BUFFER_SIZE];
            snprintf(handshake_msg, sizeof(handshake_msg), "KEY=%u;SEQ=1,2,3,4\n", key);

            SSL_write(ssl, handshake_msg, strlen(handshake_msg));

            int current_seq_index = 0;
            char buffer[BUFFER_SIZE];

            while(1) {
                int bytes = SSL_read(ssl, buffer, sizeof(buffer));
                if (bytes > 0) { //Client is alive
                    buffer[bytes] = '\0';
                    if (strstr(buffer, "TICKET")) {
                        printf("TICKET");

                        if (current_seq_index >= seq_length) current_seq_index = 0;
                        int encrypted = sequence[current_seq_index] ^ key;
                        char ticket[32];
                        snprintf(ticket, sizeof(ticket), "%d\n", encrypted);
                        SSL_write(ssl, ticket, strlen(ticket));
                        current_seq_index++;
                    }
                    else {
                    SSL_write(ssl, "NO\n", 7);
                    printf("no ticket");
                    break; // Client disconnected
                }
                } else {
                    SSL_write(ssl, "NO\n", 7);

                    printf("no ticket");
                    break; // Client disconnected
                }
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}