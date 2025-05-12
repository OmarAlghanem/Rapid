#include "server_robo.h"
#include <sys/types.h>

static SSL_CTX *ctx = NULL;
static int server_socket = INVALID_SOCKET;
static const char *expected_initial_hash = "d8aad79a5790be73caaf7e314cd560f0203dc4ff2fb4d61a3e8f836440d49e7a"; // Replace with your expected hash
static const char *expected_periodic_hash = "12d3a0e9ca700e51d4b87ef9873bc9da68e8a3def757883cefc059ebf53761ea"; // Replace with your expected hash

/* Initialize server */
/* Initialize server */
void server_init() {
    if (init_server_ssl() != 0) {
        fprintf(stderr, "SSL initialization failed\n");
        exit(1);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        perror("Socket creation failed");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_socket);
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Bind failed");
        close(server_socket);
        exit(1);
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        perror("Listen failed");
        close(server_socket);
        exit(1);
    }

    printf("Server listening on port %d...\n", PORT);
}
/* Cleanup resources */
void server_cleanup() {
    if (server_socket != INVALID_SOCKET) {
        close(server_socket);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

/* Create SSL context */
SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

/* Configure SSL context */
void configure_server_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Verify client certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", NULL);
}

/* Initialize SSL */
int init_server_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_server_context();
    configure_server_context(ctx);

    return 0;
}

/* Handle client connection */
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (1) {
        bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            int err = SSL_get_error(ssl, bytes_received);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                printf("Client disconnected\n");
            } else {
                fprintf(stderr, "SSL read error: %d\n", err);
            }
            break;
        }

        buffer[bytes_received] = '\0';
        printf("Received: %s\n", buffer);

        if (strncmp(buffer, "HASH:", 5) == 0) {
            /* Parse hash message */
            char *hash_type = strtok(buffer + 5, ":");
            char *received_hash = strtok(NULL, ":");
            
            if (hash_type && received_hash) {
                if (verify_client_hash(received_hash, hash_type) == 0) {
                    SSL_write(ssl, "HASH_OK\n", 8);
                } else {
                    SSL_write(ssl, "HASH_INVALID\n", 13);
                    break;
                }
            }
        } 
        else if (strncmp(buffer, "TICKET", 6) == 0) {
            SSL_write(ssl, "TICKET_ACK\n", 11);
        }
        else {
            /* Process movement commands */
            process_client_command(buffer);
            SSL_write(ssl, "COMMAND_ACK\n", 12);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

/* Verify client hash */
int verify_client_hash(const char *received_hash, const char *hash_type) {
    const char *expected_hash = NULL;
    
    if (strcmp(hash_type, "INIT") == 0) {
        expected_hash = expected_initial_hash;
    } else if (strcmp(hash_type, "PERIODIC") == 0) {
        expected_hash = expected_periodic_hash;
    } else {
        return -1;
    }

    printf("Verifying %s hash:\nReceived: %s\nExpected: %s\n", 
           hash_type, received_hash, expected_hash);

    return strcmp(received_hash, expected_hash);
}

/* Process client commands */
void process_client_command(const char *command) {
    printf("Processing command: %s\n", command);
    
    if (strcmp(command, "spin ninety") == 0) {
        printf("Client requested: Spin 90 degrees\n");
    } 
    else if (strcmp(command, "spin oneeighty") == 0) {
        printf("Client requested: Spin 180 degrees\n");
    } 
    else if (strcmp(command, "rest") == 0) {
        printf("Client requested: Rest position\n");
    } 
    else {
        printf("Unknown command received: %s\n", command);
    }
}

/* Main server loop */
int main() {
    server_init();

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        handle_client(ssl);
        close(client_socket);
    }

    server_cleanup();
    return 0;
}