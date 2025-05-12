#include "server_robo.h"
#include <sys/types.h>
#include <stdbool.h> // Added for bool

static SSL_CTX *ctx = NULL;
static int server_socket = INVALID_SOCKET;

// Expected hashes from your original server.c
static const char *expected_initial_hash = "85ba4c6cf20ddf22547fae7aa809f3efb09633003e5fc0c6fb5d6c460fe763ab";
// This is used for all sequences as per your request ("PERIODIC HASH")
static const char *expected_sequence_hash = "f6a57a99415f06169a0e3ba5d3df7bd9841ce7aa4644c6960e58e569d1e6f215";


/* Initialize server (minor change: srand) */
void server_init() {
    srand(time(NULL)); // Seed random number generator for KEY/SEQ

    if (init_server_ssl() != 0) {
        fprintf(stderr, "SERVER: SSL initialization failed\n");
        exit(1);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        perror("SERVER: Socket creation failed");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("SERVER: Setsockopt failed");
        close(server_socket);
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("SERVER: Bind failed");
        close(server_socket);
        exit(1);
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        perror("SERVER: Listen failed");
        close(server_socket);
        exit(1);
    }

    printf("SERVER: Server listening on port %d...\n", PORT);
}

/* Cleanup resources (no change from your original) */
void server_cleanup() {
    if (server_socket != INVALID_SOCKET) {
        close(server_socket);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

/* Create SSL context (no change from your original) */
SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *new_ctx = SSL_CTX_new(method); // Renamed to new_ctx
    if (!new_ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return new_ctx;
}

/* Configure SSL context (no change from your original) */
// server.c

// ... (all other code from the previous full server.c I provided) ...

/* Configure SSL context */
void configure_server_context(SSL_CTX *cfg_ctx) { // Renamed param in my version
    SSL_CTX_set_ecdh_auto(cfg_ctx, 1);

    /* Set the key and cert */
    // REVERTING to your original file paths for the server's own certificate and key
    if (SSL_CTX_use_certificate_file(cfg_ctx, "certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        // Keeping my more specific error message here:
        fprintf(stderr, "SERVER: Error loading certificate file (client.crt as server cert).\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(cfg_ctx, "certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        // Keeping my more specific error message here:
        fprintf(stderr, "SERVER: Error loading private key file (client.key as server key).\n");
        exit(EXIT_FAILURE);
    }
    // Verify the private key (this is good practice)
    if (!SSL_CTX_check_private_key(cfg_ctx)) {
        fprintf(stderr, "SERVER: Private key does not match the public certificate (using client.crt as server cert)\n");
        exit(EXIT_FAILURE);
    }


    /* Verify client certificate (this part is for authenticating the connecting client) */
    // This requires the server to have the CA certificate that signed the actual client's certificate.
    // This setup means:
    // 1. Server presents client.crt as its own cert.
    // 2. Client connects, verifies client.crt against ca.crt.
    // 3. Server requests client's cert for authentication.
    // 4. Server verifies the actual connecting client's cert against ca.crt.
    SSL_CTX_set_verify(cfg_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (!SSL_CTX_load_verify_locations(cfg_ctx, "certs/ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SERVER: Error loading CA certificate (ca.crt) for client verification.\n");
        exit(EXIT_FAILURE);
    }
    printf("SERVER: SSL Context configured. Server will use 'certs/client.crt' and 'certs/client.key'. Client certificates will be verified against 'certs/ca.crt'.\n");
}

// ... (the rest of server.c, including handle_client, main, etc., from my previous full response) ...

/* Initialize SSL (no change from your original) */
int init_server_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_server_context();
    configure_server_context(ctx);

    return 0;
}


/* Handle client connection (major changes here) */
void handle_client(SSL *ssl_conn) { // Renamed param
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Client-specific state for handshake and keep-alive
    uint32_t client_key = 0;
    int client_seq[NUM_SEQ_VALUES];
    size_t client_seq_len = NUM_SEQ_VALUES;
    size_t current_client_seq_index = 0;
    bool client_esp32_acked = false;
    bool client_initial_hash_ok = false;
    bool client_fully_handshaked_and_ready = false; // Master flag

    // --- Stage A: Server expects HANDSHAKE_REQ ---
    bytes_received = SSL_read(ssl_conn, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        fprintf(stderr, "SERVER: SSL_read error during initial HANDSHAKE_REQ listen.\n");
        ERR_print_errors_fp(stderr);
        goto client_cleanup;
    }
    buffer[bytes_received] = '\0';
    printf("SERVER: Received from client: %s", buffer); // Client sends with \n

    if (strncmp(buffer, "HANDSHAKE_REQ\n", bytes_received) != 0) {
        fprintf(stderr, "SERVER: Expected HANDSHAKE_REQ, got: %s. Closing connection.\n", buffer);
        goto client_cleanup;
    }
    printf("SERVER: HANDSHAKE_REQ received.\n");

    // --- Stage A response & Stage B setup ---
    const char *proceed_msg = "PROCEED_HANDSHAKE_KEYSEQ\n";
    if (SSL_write(ssl_conn, proceed_msg, strlen(proceed_msg)) <= 0) {
        fprintf(stderr, "SERVER: SSL_write error sending PROCEED_HANDSHAKE_KEYSEQ.\n");
        ERR_print_errors_fp(stderr);
        goto client_cleanup;
    }
    printf("SERVER: Sent PROCEED_HANDSHAKE_KEYSEQ.\n");

    // Generate KEY and SEQ for this client
    client_key = (uint32_t)rand(); // Simple key generation
    printf("SERVER: Generated KEY for client: %u\n", client_key);
    printf("SERVER: Generating SEQ for client: ");
    char seq_str_part[KEY_SEQ_MAX_LEN / 2]; // Part of the message for just numbers
    char *seq_ptr = seq_str_part;
    for (size_t i = 0; i < client_seq_len; ++i) {
        client_seq[i] = rand() % 10000; // Sequence numbers up to 9999
        printf("%d ", client_seq[i]);
        int written = snprintf(seq_ptr, sizeof(seq_str_part) - (seq_ptr - seq_str_part), "%d%s",
                               client_seq[i], (i < client_seq_len - 1) ? "," : "");
        if (written < 0 || (size_t)written >= sizeof(seq_str_part) - (seq_ptr - seq_str_part)) {
            fprintf(stderr, "SERVER: Error formatting SEQ string (overflow).\n");
            goto client_cleanup;
        }
        seq_ptr += written;
    }
    printf("\n");

    char key_seq_msg[KEY_SEQ_MAX_LEN];
    snprintf(key_seq_msg, sizeof(key_seq_msg), "KEY=%u;SEQ=%s\n", client_key, seq_str_part);

    if (SSL_write(ssl_conn, key_seq_msg, strlen(key_seq_msg)) <= 0) {
        fprintf(stderr, "SERVER: SSL_write error sending KEY/SEQ string.\n");
        ERR_print_errors_fp(stderr);
        goto client_cleanup;
    }
    printf("SERVER: Sent KEY/SEQ string: %s", key_seq_msg);

    // --- Stage E: Server expects HS_ACK or HS_NACK from Client ---
    bytes_received = SSL_read(ssl_conn, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        fprintf(stderr, "SERVER: SSL_read error waiting for HS_ACK/HS_NACK.\n");
        ERR_print_errors_fp(stderr);
        goto client_cleanup;
    }
    buffer[bytes_received] = '\0';
    printf("SERVER: Received from client (ESP32 status): %s", buffer);

    if (strncmp(buffer, "HS_ACK\n", bytes_received) == 0) {
        client_esp32_acked = true;
        printf("SERVER: ESP32 handshake ACKed by client.\n");
    } else if (strncmp(buffer, "HS_NACK:", 8) == 0) { // Check for "HS_NACK:" prefix
        client_esp32_acked = false;
        printf("SERVER: ESP32 handshake NACKed by client. Reason: %s", buffer + 8); // Print reason part
        // As per user: "if the hash for the sequence is false ... then the server terminates"
        // Similar principle: if critical handshake part fails, server should terminate.
        fprintf(stderr, "SERVER: ESP32 Handshake failed. Terminating connection.\n");
        // Optionally send a message to client before closing.
        // SSL_write(ssl_conn, "ERROR:ESP32_HANDSHAKE_FAILED\n", strlen("ERROR:ESP32_HANDSHAKE_FAILED\n"));
        goto client_cleanup;
    } else {
        fprintf(stderr, "SERVER: Expected HS_ACK or HS_NACK, got: %s. Terminating.\n", buffer);
        goto client_cleanup;
    }

    // --- Main Loop for HASH and TICKET messages ---
    while (true) {
        bytes_received = SSL_read(ssl_conn, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            int err = SSL_get_error(ssl_conn, bytes_received);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_NONE) { // SSL_ERROR_NONE can sometimes mean orderly shutdown from client
                printf("SERVER: Client disconnected or SSL_read error with code %d.\n", err);
            } else {
                fprintf(stderr, "SERVER: SSL_read error: %d\n", err);
                ERR_print_errors_fp(stderr);
            }
            break; // Exit while loop, will lead to cleanup
        }
        buffer[bytes_received] = '\0';
        printf("SERVER: Received: %s", buffer); // Client messages usually end with \n

        if (strncmp(buffer, "HASH:", 5) == 0) {
            if (!client_esp32_acked) {
                fprintf(stderr, "SERVER: Received HASH message, but ESP32 not ACKed. Ignoring & closing.\n");
                SSL_write(ssl_conn, "ERROR:ESP32_HANDSHAKE_INCOMPLETE\n", strlen("ERROR:ESP32_HANDSHAKE_INCOMPLETE\n"));
                goto client_cleanup;
            }

            char *type_and_hash = buffer + 5; // Points to "TYPE:hash_value\n"
            char *colon_ptr = strchr(type_and_hash, ':');
            if (!colon_ptr) {
                fprintf(stderr, "SERVER: Invalid HASH message format (missing second colon): %s\n", buffer);
                SSL_write(ssl_conn, "ERROR:INVALID_HASH_FORMAT\n", strlen("ERROR:INVALID_HASH_FORMAT\n"));
                goto client_cleanup;
            }
            *colon_ptr = '\0'; // Null-terminate the hash type
            char *hash_type = type_and_hash;
            char *received_hash = colon_ptr + 1;

            // Remove trailing newline from received_hash if present
            size_t len_rec_hash = strlen(received_hash);
            if (len_rec_hash > 0 && received_hash[len_rec_hash - 1] == '\n') {
                received_hash[len_rec_hash - 1] = '\0';
            }
            
            const char *expected_hash_to_use = NULL;
            if (strcmp(hash_type, "INIT") == 0) {
                expected_hash_to_use = expected_initial_hash;
            } else { // For "seq1", "seq2", etc. use the general sequence hash
                expected_hash_to_use = expected_sequence_hash;
                if (!client_initial_hash_ok) {
                     fprintf(stderr, "SERVER: Received sequence HASH, but initial hash not verified yet. Closing.\n");
                     SSL_write(ssl_conn, "ERROR:INIT_HASH_PENDING\n", strlen("ERROR:INIT_HASH_PENDING\n"));
                     goto client_cleanup;
                }
            }

            printf("SERVER: Verifying HASH type '%s'. Received: '%s', Expected: '%s'\n",
                   hash_type, received_hash, expected_hash_to_use);

            if (strcmp(received_hash, expected_hash_to_use) == 0) {
                SSL_write(ssl_conn, "HASH_OK\n", strlen("HASH_OK\n"));
                printf("SERVER: Hash OK for type %s.\n", hash_type);
                if (strcmp(hash_type, "INIT") == 0) {
                    client_initial_hash_ok = true;
                }
                // If it's a sequence hash and it's OK, the client will enter keep-alive.
                // Server is now ready for tickets or next sequence if any.
                client_fully_handshaked_and_ready = client_esp32_acked && client_initial_hash_ok;

            } else {
                // Check for HASH_INVALID_FILE scenario (from your original client/server)
                // For now, simplified: any mismatch is HASH_INVALID.
                // If you need HASH_INVALID_FILE, that logic needs to be here.
                // Your original server did not have HASH_INVALID_FILE logic, client did.
                // Sticking to current server logic.
                SSL_write(ssl_conn, "HASH_INVALID\n", strlen("HASH_INVALID\n"));
                fprintf(stderr, "SERVER: Hash INVALID for type %s. Closing connection.\n", hash_type);
                goto client_cleanup; // Terminate on any invalid hash
            }
        } else if (strncmp(buffer, "TICKET\n", bytes_received) == 0) {
            if (!client_fully_handshaked_and_ready) {
                fprintf(stderr, "SERVER: Received TICKET, but client not fully handshaked/ready. Ignoring & closing.\n");
                SSL_write(ssl_conn, "ERROR:NOT_READY_FOR_TICKETS\n", strlen("ERROR:NOT_READY_FOR_TICKETS\n"));
                goto client_cleanup;
            }

            uint32_t num_to_send = client_seq[current_client_seq_index];
            uint32_t encrypted_num = num_to_send ^ client_key;

            char encrypted_num_str[32]; // Buffer for uint32_t as string
            snprintf(encrypted_num_str, sizeof(encrypted_num_str), "%u\n", encrypted_num);

            printf("SERVER: TICKET received. Sending encrypted number %u (original %u, index %zu) to client.\n",
                   encrypted_num, num_to_send, current_client_seq_index);
            if (SSL_write(ssl_conn, encrypted_num_str, strlen(encrypted_num_str)) <= 0) {
                fprintf(stderr, "SERVER: SSL_write error sending encrypted number for TICKET.\n");
                ERR_print_errors_fp(stderr);
                goto client_cleanup; // If can't send, something is wrong
            }
            current_client_seq_index = (current_client_seq_index + 1) % client_seq_len;
        } else {
            fprintf(stderr, "SERVER: Unknown message type from client: %s. Closing connection.\n", buffer);
            // SSL_write(ssl_conn, "ERROR:UNKNOWN_MESSAGE\n", strlen("ERROR:UNKNOWN_MESSAGE\n"));
            goto client_cleanup;
        }
    } // End of while(true) message loop

client_cleanup:
    printf("SERVER: Cleaning up client connection.\n");
    if (ssl_conn) { // Check if ssl_conn is not NULL
        int ret = SSL_shutdown(ssl_conn);
        if (ret == 0) { // Graceful shutdown needs another SSL_shutdown
            SSL_shutdown(ssl_conn);
        }
        SSL_free(ssl_conn);
    }
    // The client_socket is closed in main after handle_client returns
}


/* Verify client hash (original, but now called differently) */
// This function is kept simple as the decision of which expected hash to use
// is now made in handle_client.
int verify_client_hash(const char *received_hash, const char *expected_hash_param) {
    // Parameters hash_type is not used here directly from client message anymore.
    // The expected_hash_param is passed by handle_client.
    printf("SERVER: Verifying hash. Received: '%s', Expected: '%s'\n",
           received_hash, expected_hash_param);
    return strcmp(received_hash, expected_hash_param);
}

/* Process client commands (original - effectively replaced by new logic in handle_client) */
/*
void process_client_command(const char *command) {
    // This function is no longer directly relevant as commands are HASH or TICKET.
    printf("Processing command: %s\n", command);
}
*/

/* Main server loop (no change from your original) */
int main() {
    server_init(); // Seeds rand()

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        printf("SERVER: Waiting for a new client connection...\n");
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            perror("SERVER: Accept failed");
            continue; // Try to accept next connection
        }

        printf("SERVER: Client connected: %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl_for_client = SSL_new(ctx); // Use a new SSL object for each client
        if (!ssl_for_client) {
            fprintf(stderr, "SERVER: SSL_new() failed.\n");
            close(client_socket);
            continue;
        }
        SSL_set_fd(ssl_for_client, client_socket);

        if (SSL_accept(ssl_for_client) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "SERVER: SSL_accept failed for client %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            SSL_free(ssl_for_client); // Free SSL object
            close(client_socket);    // Close socket
            continue;
        }
        printf("SERVER: SSL handshake successful with client %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        handle_client(ssl_for_client); // ssl_for_client is freed inside handle_client or by its cleanup path

        printf("SERVER: Closing client socket for %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        close(client_socket); // Close client socket after handling
    }

    server_cleanup();
    return 0;
}
