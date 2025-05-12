#include "server_robo.h"
#include <sys/types.h>
#include <pthread.h> // For threading client handling
#include <time.h>    // For random seed
#include <stdint.h>  // For uint32_t
#include <stdbool.h> // For bool type


static SSL_CTX *ctx = NULL;
static int server_socket = INVALID_SOCKET;
static const char *expected_initial_hash = "d8aad79a5790be73caaf7e314cd560f0203dc4ff2fb4d61a3e8f836440d49e7a"; // Replace with your expected hash
static const char *expected_periodic_hash = "12d3a0e9ca700e51d4b87ef9873bc9da68e8a3def757883cefc059ebf53761ea"; // Replace with your expected hash

// --- Watchdog/Handshake Related ---
#define MAX_SEQUENCE_LENGTH 10 // Max numbers in the sequence
#define SEQUENCE_SEND_INTERVAL_MS 500 // How often to check if a new number should be sent (adjust as needed)

// Structure to hold state for each connected client
typedef struct {
    SSL *ssl;
    struct sockaddr_in addr;
    pthread_t thread_id;
    bool handshake_complete;
    uint32_t decryption_key;
    int sequence[MAX_SEQUENCE_LENGTH];
    size_t sequence_length;
    size_t current_sequence_index;
    bool ticket_received; // Flag to indicate if a ticket was received since last sequence number sent
    time_t last_comm_time; // Track last successful communication
} ClientState;


// Function Prototypes for Watchdog/Handshake
uint32_t generate_key();
void generate_sequence(int *seq_array, size_t *length);
int send_to_client(ClientState *client, const char *message);
int send_encrypted_sequence(ClientState *client);
uint32_t encrypt_number(uint32_t number, uint32_t key);
int handle_handshake(ClientState *client);
int handle_ticket(ClientState *client);
void *client_thread_func(void *arg); // Thread function for handling client


/* Initialize server */
void server_init() {
    srand(time(NULL)); // Seed random number generator for keys/sequences

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
    // Cleanup OpenSSL library internals
    EVP_cleanup();
    ERR_free_strings();
}

/* Create SSL context */
SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx_local = SSL_CTX_new(method); // Use local var to avoid shadowing global
    if (!ctx_local) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx_local;
}

/* Configure SSL context */
void configure_server_context(SSL_CTX *ctx_local) { // Use local var name
    SSL_CTX_set_ecdh_auto(ctx_local, 1);

    /* Set the key and cert */
    // Ensure paths are correct relative to where the server executable runs
    if (SSL_CTX_use_certificate_file(ctx_local, "certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading server certificate file. Check path: certs/client.crt\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_local, "certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
         fprintf(stderr, "Error loading server private key file. Check path: certs/client.key\n");
        exit(EXIT_FAILURE);
    }
     // Check if the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx_local)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }


    /* Verify client certificate (Optional but recommended)*/
    // Require client to present a certificate signed by our CA
    SSL_CTX_set_verify(ctx_local, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // NULL is default verify_callback
    if (!SSL_CTX_load_verify_locations(ctx_local, "certs/ca.crt", NULL)) {
         fprintf(stderr, "Error loading CA certificate for client verification. Check path: certs/ca.crt\n");
         // Decide if this is fatal - for now, we'll let it continue but log error
         // exit(EXIT_FAILURE);
    }
     printf("SSL Context configured. Client certificate verification enabled.\n");
}

/* Initialize SSL */
int init_server_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ctx = create_server_context(); // Assign to global ctx
    configure_server_context(ctx);

    return 0; // Success
}

// --- Watchdog/Handshake Helper Functions ---

// Generate a simple pseudo-random 32-bit key
uint32_t generate_key() {
    // Combine rand() calls for potentially better distribution if RAND_MAX is small
    uint32_t key = ((uint32_t)rand() << 16) | (uint32_t)rand();
    return key ? key : 1; // Ensure key is never 0 (as 0 XOR N = N)
}

// Generate a pseudo-random sequence of numbers
void generate_sequence(int *seq_array, size_t *length) {
    *length = (rand() % (MAX_SEQUENCE_LENGTH - 3)) + 3; // Generate 3 to MAX_SEQUENCE_LENGTH numbers
    printf("Generating sequence of length %zu\n", *length);
    for (size_t i = 0; i < *length; i++) {
        seq_array[i] = rand() % 1000; // Numbers between 0 and 999
        printf("  Seq[%zu] = %d\n", i, seq_array[i]);
    }
}

// Simple XOR encryption
uint32_t encrypt_number(uint32_t number, uint32_t key) {
    return number ^ key;
}

// Safely send data to the client via SSL
int send_to_client(ClientState *client, const char *message) {
    if (!client || !client->ssl || !message) return -1;
    printf("Server -> Client (%s:%d): %s\n",
           inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), message);
    int bytes_sent = SSL_write(client->ssl, message, strlen(message));
    if (bytes_sent <= 0) {
        int err = SSL_get_error(client->ssl, bytes_sent);
        fprintf(stderr, "SSL_write error to client %s:%d: %d\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), err);
        ERR_print_errors_fp(stderr);
        return -1; // Indicate error
    }
    client->last_comm_time = time(NULL); // Update last communication time on success
    return 0; // Indicate success
}


// Handle the initial handshake request from the client
int handle_handshake(ClientState *client) {
    printf("Client %s:%d requesting handshake.\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));

    client->decryption_key = generate_key();
    generate_sequence(client->sequence, &client->sequence_length);
    client->current_sequence_index = 0;
    client->ticket_received = false; // Requires ticket before first sequence send

    // Format the handshake message: "KEY=key_val;SEQ=num1,num2,..."
    char handshake_msg[BUFFER_SIZE];
    char seq_str[BUFFER_SIZE / 2] = {0}; // Buffer for the sequence part
    char num_buf[12]; // Buffer for individual numbers

    for (size_t i = 0; i < client->sequence_length; i++) {
        sprintf(num_buf, "%d", client->sequence[i]);
        strcat(seq_str, num_buf);
        if (i < client->sequence_length - 1) {
            strcat(seq_str, ",");
        }
    }

    snprintf(handshake_msg, sizeof(handshake_msg), "KEY=%u;SEQ=%s\n", // Add newline
             client->decryption_key, seq_str);

    if (send_to_client(client, handshake_msg) != 0) {
        fprintf(stderr, "Failed to send handshake to client %s:%d\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        return -1;
    }

     // Wait for ACK (or NACK) from client (ESP32 via Pi)
    char ack_buffer[BUFFER_SIZE];
    int bytes_received = SSL_read(client->ssl, ack_buffer, sizeof(ack_buffer) - 1);
     if (bytes_received <= 0) {
        int err = SSL_get_error(client->ssl, bytes_received);
         fprintf(stderr, "Error receiving handshake ACK from client %s:%d: %d\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), err);
         return -1;
    }
     ack_buffer[bytes_received] = '\0';
     printf("Server <- Client (%s:%d): %s", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), ack_buffer); // Print raw ACK/NACK

     if (strncmp(ack_buffer, "HS_ACK", 6) == 0) { // Client confirms receipt of handshake
         printf("Handshake ACK received from client %s:%d. Handshake complete.\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        client->handshake_complete = true;
        client->last_comm_time = time(NULL);
        return 0; // Handshake successful
     } else {
         printf("Handshake failed or NACK received from client %s:%d.\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
         return -1; // Handshake failed
     }
}

// Handle the "TICKET" message from the client
int handle_ticket(ClientState *client) {
     printf("Ticket received from client %s:%d.\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
    if (!client->handshake_complete) {
        fprintf(stderr, "Error: Ticket received before handshake complete from %s:%d.\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        send_to_client(client, "ERROR:HANDSHAKE_REQUIRED\n");
        return -1; // Error state
    }

    client->ticket_received = true; // Mark ticket as received
    client->last_comm_time = time(NULL); // Update communication time

    // Acknowledge the ticket immediately (optional, but good practice)
    // send_to_client(client, "TICKET_ACK\n"); // Client might not wait for this

    // The main loop will now check ticket_received and send the next sequence number.
    return 0; // Ticket processed successfully
}


// Send the next encrypted sequence number if a ticket has been received
int send_encrypted_sequence(ClientState *client) {
    if (!client->handshake_complete || !client->ticket_received) {
        // Either handshake isn't done, or no ticket received since last send.
        return 0; // Not an error, just nothing to send yet.
    }

    if (client->sequence_length == 0) {
         fprintf(stderr, "Error: Cannot send sequence, length is zero for client %s:%d.\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        return -1;
    }


    uint32_t number_to_send = client->sequence[client->current_sequence_index];
    uint32_t encrypted_num = encrypt_number(number_to_send, client->decryption_key);

    printf("Sending sequence index %zu (Value: %u, Encrypted: %u) to client %s:%d\n",
           client->current_sequence_index, number_to_send, encrypted_num,
           inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));


    char msg_buffer[64];
    snprintf(msg_buffer, sizeof(msg_buffer), "%u\n", encrypted_num); // Send as string, newline terminated

    if (send_to_client(client, msg_buffer) != 0) {
        fprintf(stderr, "Failed to send encrypted sequence to client %s:%d\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        return -1; // Error sending
    }

    // Move to next sequence number and reset ticket flag
    client->current_sequence_index = (client->current_sequence_index + 1) % client->sequence_length;
    client->ticket_received = false; // Require a new ticket for the next number

    return 0; // Success
}


/* Verify client hash */
// Returns 0 on match, non-zero on mismatch or error
int verify_client_hash(const char *received_hash, const char *hash_type) {
    const char *expected_hash = NULL;

    if (strcmp(hash_type, "INIT") == 0) {
        expected_hash = expected_initial_hash;
    } else if (strcmp(hash_type, "PERIODIC") == 0) {
        expected_hash = expected_periodic_hash;
    } else {
         fprintf(stderr, "Unknown hash type received: %s\n", hash_type);
        return -1; // Indicate error
    }

    if (!received_hash) {
         fprintf(stderr, "Received NULL hash for type %s\n", hash_type);
         return -1;
    }

    printf("Verifying %s hash:\n  Received: %s\n  Expected: %s\n",
           hash_type, received_hash, expected_hash);

    int result = strcmp(received_hash, expected_hash);
    if (result == 0) {
         printf("Hash verification successful (%s).\n", hash_type);
    } else {
         fprintf(stderr, "HASH MISMATCH DETECTED (%s)!\n", hash_type);
    }
    return result; // 0 for match, non-zero for mismatch
}

/* Process client commands (like movement) - Keep this simple for now */
void process_client_command(ClientState *client, const char *command) {
    printf("Processing command from %s:%d: %s\n",
           inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), command);

    // Example command processing (add more as needed)
    if (strcmp(command, "spin ninety") == 0) {
        printf("Client %s:%d requested: Spin 90 degrees\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        send_to_client(client, "COMMAND_ACK:spin ninety\n");
    }
    else if (strcmp(command, "spin oneeighty") == 0) {
        printf("Client %s:%d requested: Spin 180 degrees\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
         send_to_client(client, "COMMAND_ACK:spin oneeighty\n");
    }
    else if (strcmp(command, "rest") == 0) {
        printf("Client %s:%d requested: Rest position\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
         send_to_client(client, "COMMAND_ACK:rest\n");
    }
    else {
        printf("Unknown command received from %s:%d: %s\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), command);
         send_to_client(client, "COMMAND_NACK:Unknown\n");
    }
     client->last_comm_time = time(NULL); // Update communication time
}


/* Handle client connection in a separate thread */
void *client_thread_func(void *arg) {
    ClientState *client = (ClientState *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_received;
    bool running = true;

    printf("Thread started for client %s:%d\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));

    // Initial Handshake
    if (handle_handshake(client) != 0) {
        fprintf(stderr, "Handshake failed for client %s:%d. Closing connection.\n",
                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
        running = false; // Exit thread if handshake fails
    }

    // Main communication loop for this client
    while (running) {
        // Check for incoming data (non-blocking read might be better here)
        // For simplicity, using blocking read with timeout could be an option,
        // or select()/poll(). Here we use a simple blocking read.

        bytes_received = SSL_read(client->ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0) {
            int err = SSL_get_error(client->ssl, bytes_received);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                printf("Client %s:%d disconnected (SSL_read error: %d).\n",
                       inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), err);
                 if(err != SSL_ERROR_ZERO_RETURN) ERR_print_errors_fp(stderr); // Print details if not clean shutdown
            } else {
                fprintf(stderr, "SSL read error from %s:%d: %d\n",
                        inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), err);
                ERR_print_errors_fp(stderr);
            }
            running = false; // Exit loop on read error/disconnect
            break;
        }

        buffer[bytes_received] = '\0'; // Null-terminate
        printf("Server <- Client (%s:%d): %s", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), buffer); // Print raw message with newline if present
        client->last_comm_time = time(NULL); // Update comm time

        // --- Message Parsing and Handling ---
        if (strncmp(buffer, "HASH:", 5) == 0) {
            // Parse hash message: HASH:TYPE:HASH_VALUE
            char *type_start = buffer + 5;
            char *hash_start = strchr(type_start, ':');
            if (hash_start) {
                *hash_start = '\0'; // Null-terminate the type
                hash_start++;     // Move to the start of the hash value
                char *newline = strchr(hash_start, '\n'); // Remove trailing newline if present
                if(newline) *newline = '\0';

                char *hash_type = type_start;
                char *received_hash = hash_start;

                int verify_result = verify_client_hash(received_hash, hash_type);

                if (verify_result == 0) {
                    send_to_client(client, "HASH_OK\n");
                    // If INIT hash is OK, proceed. If PERIODIC is OK, continue normally.
                } else {
                    // Hash mismatch
                    send_to_client(client, "HASH_INVALID\n");
                    if (strcmp(hash_type, "PERIODIC") == 0) {
                         fprintf(stderr, "Periodic hash mismatch from %s:%d! Disconnecting client.\n",
                                inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
                        running = false; // Disconnect on periodic hash failure
                    }
                    // Optional: Handle INIT hash failure differently if needed
                    // else { running = false; } // Disconnect on INIT failure too?
                }
            } else {
                fprintf(stderr, "Invalid HASH message format from %s:%d: %s",
                        inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), buffer);
                send_to_client(client, "ERROR:INVALID_HASH_FORMAT\n");
                // running = false; // Optionally disconnect on bad format
            }
        } else if (strncmp(buffer, "TICKET", 6) == 0) {
            if (handle_ticket(client) == 0) {
                 // Ticket handled, now send the sequence number
                 if(send_encrypted_sequence(client) != 0) {
                     fprintf(stderr, "Error sending sequence number after ticket from %s:%d\n",
                            inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
                     // Decide if this is fatal
                     // running = false;
                 }
            } else {
                 fprintf(stderr, "Error handling ticket from %s:%d\n",
                        inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
                 // Decide if this is fatal
                 // running = false;
            }
        }
        // Add handling for other client commands (movement, etc.)
         else if (strncmp(buffer, "COMMAND:", 8) == 0) { // Example prefix for commands
             process_client_command(client, buffer + 8); // Pass command part
         }
        // Example: Handle client explicitly requesting disconnect
         else if (strncmp(buffer, "QUIT", 4) == 0) {
             printf("Client %s:%d requested disconnect.\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
             running = false;
         }
        else {
            fprintf(stderr, "Unknown message type from %s:%d: %s",
                    inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), buffer);
            send_to_client(client, "ERROR:UNKNOWN_COMMAND\n");
        }

        // Optional: Small delay to prevent busy-waiting if using non-blocking IO
        // usleep(10000); // 10ms delay

    } // End of while(running) loop

    // --- Cleanup for this client ---
    printf("Shutting down connection for client %s:%d\n",
           inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));

    if (client->ssl) {
        SSL_shutdown(client->ssl); // Attempt graceful shutdown
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    // Note: The socket descriptor is implicitly closed when SSL_free is called if SSL owns it.
    // If SSL_set_fd was used, we should close the original socket descriptor passed to accept().
    // This is handled in main() after pthread_join.

     printf("Thread finished for client %s:%d\n", inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port));
    free(client); // Free the ClientState structure allocated in main()
    pthread_exit(NULL); // Terminate the thread
}


/* Main server loop */
int main() {
    server_init();

    printf("Server started. Waiting for connections...\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            perror("Accept failed");
            // Consider adding a small delay here if accept fails continuously
            continue;
        }

        printf("Client connection accepted from: %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create SSL structure for the connection
        SSL *ssl_conn = SSL_new(ctx);
        if (!ssl_conn) {
            fprintf(stderr, "SSL_new() failed.\n");
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }
        // Associate the socket with the SSL structure
        SSL_set_fd(ssl_conn, client_socket);

        // Perform SSL handshake
        if (SSL_accept(ssl_conn) <= 0) {
            fprintf(stderr, "SSL_accept failed for client %s:%d\n",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            ERR_print_errors_fp(stderr);
            SSL_free(ssl_conn); // Frees the SSL struct
            close(client_socket); // Close the underlying socket
            continue;
        }

        printf("SSL handshake successful with %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));


        // --- Create Client State and Thread ---
        ClientState *client_state = (ClientState *)malloc(sizeof(ClientState));
        if (!client_state) {
            perror("Failed to allocate memory for client state");
            SSL_shutdown(ssl_conn);
            SSL_free(ssl_conn);
            close(client_socket);
            continue;
        }

        // Initialize client state
        client_state->ssl = ssl_conn;
        client_state->addr = client_addr;
        client_state->handshake_complete = false;
        client_state->decryption_key = 0;
        client_state->sequence_length = 0;
        client_state->current_sequence_index = 0;
        client_state->ticket_received = false;
        client_state->last_comm_time = time(NULL);
        // Note: client_socket descriptor is managed by SSL, closed via SSL_free


        // Create a new thread to handle this client
        if (pthread_create(&client_state->thread_id, NULL, client_thread_func, client_state) != 0) {
            perror("pthread_create failed");
            free(client_state); // Clean up allocated state
             SSL_shutdown(ssl_conn);
             SSL_free(ssl_conn);
             close(client_socket); // Close socket as thread wasn't created
            continue;
        }

        // Detach the thread so resources are automatically released when it exits
        // Or use pthread_join if you need to wait for specific threads.
        pthread_detach(client_state->thread_id);
        printf("Client handler thread created and detached for %s:%d.\n",
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    } // End of main accept loop

    printf("Server shutting down.\n");
    server_cleanup();
    return 0;
}
