#include "server_robo.h"
#include <openssl/sha.h>
#include <openssl/crypto.h> // For CRYPTO_memcmp

// --- Security-Critical Configuration ---
static const char *expected_initial_hash = "959ba68b7b0555667b893179d151b9dd33f780428328af99091132ddcb5b3630";
static const char *allowed_periodic_hash = "d3f4223dcd927e83491831e8a6840c4b6e641d67e14c021358f09b6d70c7b123"; // Your valid sequence hash

// --- Hash Verification ---
int verify_client_hash(const char *received_hash, const char *hash_type) {
    const char *expected = NULL;
    
    if(strcmp(hash_type, "INIT") == 0) {
        expected = expected_initial_hash;
    } 
    else if(strcmp(hash_type, "PERIODIC") == 0) {
        expected = allowed_periodic_hash; // Only one valid periodic hash
    }
    else {
        return -1; // Invalid hash type
    }

    // Constant-time comparison to prevent timing attacks
    return CRYPTO_memcmp(received_hash, expected, strlen(expected));
}

// --- Command Processing ---
void process_client_command(const char *command) {
    printf("Validating command: %s\n", command);
    
    // Add sequence validation if needed (optional secondary check)
    if(strcmp(command, "seq1") != 0) { // Replace "seq1" with your allowed sequence
        printf("ALERT: Received forbidden command: %s\n", command);
    }
}

// --- Modified handle_client Function ---
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    bool initial_validated = false;
    bool periodic_validated = false;

    while(1) {
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
        if(bytes <= 0) break;
        buffer[bytes] = '\0';

        if(strncmp(buffer, "HASH:", 5) == 0) {
            char *type = strtok(buffer+5, ":");
            char *hash = strtok(NULL, ":");
            
            if(!type || !hash) {
                SSL_write(ssl, "HASH_INVALID\n", 13);
                break;
            }

            if(verify_client_hash(hash, type) == 0) {
                if(strcmp(type, "INIT") == 0) {
                    initial_validated = true;
                    SSL_write(ssl, "HASH_OK\n", 8);
                } 
                else if(initial_validated) { // Require valid INIT first
                    periodic_validated = true;
                    SSL_write(ssl, "HASH_OK\n", 8);
                }
            } else {
                SSL_write(ssl, "HASH_INVALID\n", 13);
                printf("Hash validation failed for type: %s\n", type);
                break;
            }
        }
        else if(periodic_validated) { // Only process commands after full validation
            process_client_command(buffer);
            SSL_write(ssl, "COMMAND_ACK\n", 12);
        }
        else {
            SSL_write(ssl, "PROTOCOL_VIOLATION\n", 19);
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}
