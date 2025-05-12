#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#include <wiringPi.h>
#include <softPwm.h>

#include "client_robot.h" // Use your actual header filename here
#include "opcode_utils.h"

// --- SSL components ---
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static int sock = -1;
static int i2c_fd = -1;

// --- State Flags ---
static bool initial_hash_sent = false; // Tracks if the very first hash (after config) was sent

// --- Attack Success Indicator ---
void attack_success_indicator() {
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("!!! Buffer Overflow Successful - Control Hijacked! !!!\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
    fflush(stdout);
}
END_FUNCTION(attack_success_indicator)

// --- Idle Function ---
void idle() {
    // Safe default function pointer target
}
END_FUNCTION(idle)

// --- Vulnerable Struct for Attack ---
struct VulnerableCmd {
    char buf[64];
    void (*func_ptr)(void);
};

/* SSL context configuration */
static void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading client certificate or key. Check paths.\n");
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL)) {
         fprintf(stderr, "Warning: Error loading CA certificate for verification.\n");
    }
}

/* I2C Setup */
static int setup_i2c() {
    int fd = open(I2C_DEVICE, O_RDWR); // From client_robot.h
    if (fd < 0) { perror("Failed to open I2C device"); return -1; }
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) { // From client_robot.h
        perror("Failed to set I2C slave address"); close(fd); return -1;
    }
    printf("I2C device setup complete.\n");
    return fd;
}

/* --- Servo control functions WITH Hash_chain calls inside --- */
#define CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(config_servo)

void config_servo() {
    printf("Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) { fprintf(stderr, "Warning: WiringPi initialization failed.\n"); }
    else { printf("WiringPi setup OK.\n"); }
    pinMode(BASE_SERVO_PIN, OUTPUT); // From client_robot.h
    pinMode(SECOND_SERVO, OUTPUT);
    pinMode(THIRD_SERVO, OUTPUT);
    pinMode(FOURTH_SERVO, OUTPUT);
    pinMode(GRIPPER, OUTPUT);
    if (softPwmCreate(BASE_SERVO_PIN, 0, 200) != 0) { fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE); }
    if (softPwmCreate(SECOND_SERVO, 0, 200) != 0) { fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE); }
    if (softPwmCreate(THIRD_SERVO, 0, 200) != 0) { fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE); }
    if (softPwmCreate(FOURTH_SERVO, 0, 200) != 0) { fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE); }
    if (softPwmCreate(GRIPPER, 0, 200) != 0) { fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE); }
    else { printf("Soft PWM created OK.\n"); }
    delay(1000); // Increased delay for stability
}
END_FUNCTION(config_servo)

#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(spin_ninety)
void spin_ninety() {
    Hash_chain(spin_ninety, SPIN_NINETY_LENGTH);
    printf("Executing spin_ninety() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 15); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(500); // Shorter delay after stop maybe enough
    printf("spin_ninety() finished.\n");
}
END_FUNCTION(spin_ninety)

#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(spin_oneeighty)
void spin_oneeighty() {
    Hash_chain(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH);
    printf("Executing spin_oneeighty() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 25); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(500);
    printf("spin_oneeighty() finished.\n");
}
END_FUNCTION(spin_oneeighty)

#define REST_LENGTH GET_FUNCTION_LENGTH(rest)
void rest() {
    Hash_chain(rest, REST_LENGTH);
    printf("Executing rest() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 5); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(500);
    printf("rest() finished.\n");
}
END_FUNCTION(rest)
// --- New Movement Functions ---
#define PICK_LENGTH GET_FUNCTION_LENGTH(pick)
void pick() {
    Hash_chain(pick, PICK_LENGTH);
    printf("Executing pick() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 13);
    softPwmWrite(SECOND_SERVO, 15);
    softPwmWrite(THIRD_SERVO, 20);
    softPwmWrite(FOURTH_SERVO, 14);
    softPwmWrite(GRIPPER, 10);
    delay(500);
    printf("pick() finished.\n");
}
END_FUNCTION(pick)

#define NEUTRAL_LENGTH GET_FUNCTION_LENGTH(neutral)
void neutral() {
    Hash_chain(neutral, NEUTRAL_LENGTH);
    printf("Executing neutral() [Hash Updated]...\n");
    softPwmWrite(SECOND_SERVO, 20);
    softPwmWrite(BASE_SERVO_PIN, 20);
    softPwmWrite(THIRD_SERVO, 20);
    softPwmWrite(FOURTH_SERVO, 23);
    delay(500);
    printf("neutral() finished.\n");
}
END_FUNCTION(neutral)

#define PLACE_LENGTH GET_FUNCTION_LENGTH(Place)
void Place() {
    Hash_chain(Place, PLACE_LENGTH);
    printf("Executing Place() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 25);
    softPwmWrite(SECOND_SERVO, 15);
    softPwmWrite(THIRD_SERVO, 20);
    softPwmWrite(FOURTH_SERVO, 14);
    delay(500);
    printf("Place() finished.\n");
}
END_FUNCTION(Place)

#define STAND_LENGTH GET_FUNCTION_LENGTH(stand)
void stand() {
    Hash_chain(stand, STAND_LENGTH);
    printf("Executing stand() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 18);
    softPwmWrite(SECOND_SERVO, 22);
    softPwmWrite(THIRD_SERVO, 10);
    delay(500);
    printf("stand() finished.\n");
}
END_FUNCTION(stand)
/* Utility to convert binary hash to hex string */
void hex_to_string(const unsigned char *hash, size_t length, char *output) {
    for (size_t i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[length * 2] = '\0';
}

/* Communication initialization */
void comm_init(const char *hostname, int port) {
    printf("Initializing communication to %s:%d...\n", hostname, port);
    SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    configure_context(ctx);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); SSL_CTX_free(ctx); exit(EXIT_FAILURE); }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(port); // PORT from client_robot.h
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("inet_pton"); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect"); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    printf("Connected to server.\n");
    ssl = SSL_new(ctx); SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    printf("SSL handshake successful.\n");
    i2c_fd = setup_i2c();
    if (i2c_fd < 0) { fprintf(stderr, "I2C setup failed.\n"); /* Cleanup */ exit(EXIT_FAILURE); }
    config_servo();
    Hash_chain_reset();
    Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
    printf("Initial Hash chain state created based on config_servo.\n");
    initial_hash_sent = false;
}

/* Communication cleanup */
void comm_cleanup() {
    printf("Cleaning up communication...\n");
    if (ssl) {
        // Attempt graceful shutdown
        int ret = SSL_shutdown(ssl);
        if (ret == 0) {
             // Shutdown not finished, wait for peer close_notify
             // For simplicity here, we might just proceed, but proper handling
             // might involve retrying SSL_shutdown or just closing the socket.
             printf("SSL_shutdown initiated, waiting for peer...\n");
             // Optionally add a short delay or read attempt here
        } else if (ret < 0) {
             // Error during shutdown
             fprintf(stderr, "Warning: SSL_shutdown failed.\n");
             ERR_print_errors_fp(stderr);
        }
        SSL_free(ssl); ssl = NULL;
    }
    if (sock != -1) { close(sock); sock = -1; }
    if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
    if (i2c_fd != -1) { close(i2c_fd); i2c_fd = -1; }
    printf("Cleanup complete.\n");
}

/* Send current hash state to server */
int comm_send_current_hash(const char *context_message) {
    char *current_hash_hex = get_hash_chain_current();
    if (!current_hash_hex) {
        fprintf(stderr, "Failed to get current hash chain string for %s.\n", context_message);
        return -1;
    }

    char msg[BUFFER_SIZE];
    const char* hash_type_str = initial_hash_sent ? "PERIODIC" : "INIT";
    snprintf(msg, sizeof(msg), "HASH:%s:%s", hash_type_str, current_hash_hex);
    printf("Sending %s hash (%s): %s\n", hash_type_str, context_message, msg);

    int write_result = SSL_write(ssl, msg, strlen(msg));
    free(current_hash_hex);
    if (write_result <= 0) {
        fprintf(stderr, "SSL_write error sending hash (%s).\n", context_message);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    printf("Waiting for server response to %s hash...\n", hash_type_str);
    int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (bytes <= 0) {
        int err = SSL_get_error(ssl, bytes);
        fprintf(stderr, "SSL_read error waiting for HASH_OK (%s): %d.\n", context_message, err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    buffer[bytes] = '\0';
    printf("Server response: %s\n", buffer);

    // Handle HASH_OK response
    if (strncmp(buffer, "HASH_OK", 7) == 0) {
        if (!initial_hash_sent) {
            initial_hash_sent = true;
        }
        printf("Server accepted %s hash (%s).\n", hash_type_str, context_message);
        return 0;
    }
    // Handle HASH_INVALID_FILE response
    else if (strncmp(buffer, "HASH_INVALID_FILE", 17) == 0) {
        printf("Server requested file update due to hash mismatch\n");
        
        // Read file size (network byte order)
        uint32_t net_size;
        int size_bytes_read = 0;
        while (size_bytes_read < sizeof(net_size)) {
            int n = SSL_read(ssl, ((char*)&net_size) + size_bytes_read, 
                           sizeof(net_size) - size_bytes_read);
            if (n <= 0) {
                fprintf(stderr, "Error reading file size\n");
                return -1;
            }
            size_bytes_read += n;
        }
        
        uint32_t file_size = ntohl(net_size);
        printf("Receiving file of size %u bytes\n", file_size);

        // Open file for writing
        const char *file_path = "/home/rapid/update_code.c";
        FILE *fp = fopen(file_path, "wb");
        if (!fp) {
            perror("Failed to create file");
            return -1;
        }

        // Receive file data in chunks
        char file_buffer[1024];
        uint32_t total_received = 0;
        while (total_received < file_size) {
            uint32_t remaining = file_size - total_received;
            size_t chunk_size = (remaining > sizeof(file_buffer)) ? 
                               sizeof(file_buffer) : remaining;
            
            int bytes_received = SSL_read(ssl, file_buffer, chunk_size);
            if (bytes_received <= 0) {
                fprintf(stderr, "Error receiving file data\n");
                fclose(fp);
                remove(file_path);
                return -1;
            }

            size_t written = fwrite(file_buffer, 1, bytes_received, fp);
            if (written != bytes_received) {
                fprintf(stderr, "Error writing to file\n");
                fclose(fp);
                remove(file_path);
                return -1;
            }

            total_received += bytes_received;
            printf("Received %u/%u bytes (%.1f%%)\r", 
                  total_received, file_size, 
                  (total_received * 100.0) / file_size);
            fflush(stdout);
        }

        fclose(fp);
        printf("\nFile successfully saved to %s\n", file_path);
        return -2; // Special return code for file received
    }
    // Handle regular HASH_INVALID response
    else {
        fprintf(stderr, "Server rejected %s hash (%s).\n", hash_type_str, context_message);
        return -1;
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    printf("Client starting...\n");

    if (argc != 2) { fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]); return EXIT_FAILURE; }
    printf("Server IP provided: %s\n", argv[1]);
    const char *env_command_full = getenv("COMMAND");
    if (!env_command_full) { fprintf(stderr, "Error: COMMAND env var not set.\n"); return EXIT_FAILURE; }
    printf("COMMAND received: %s\n", env_command_full);

    // Initialize Communication & Base Hash State
    comm_init(argv[1], PORT); // PORT from client_robot.h

    // --- Send Initial Hash ---
    if (comm_send_current_hash("initial config") != 0) {
        fprintf(stderr, "Initial hash verification failed. Terminating.\n");
        comm_cleanup();
        return EXIT_FAILURE;
    }
    // *** ADDED DELAY ***
    delay(100); // Add a small delay (100ms) after initial hash OK

    // --- Command Execution ---
    bool command_or_sequence_executed_successfully = false;

    // Attack Command Handling (Unchanged)
    if (strcmp(env_command_full, "attack") == 0) {
        printf("Executing command: attack (reading payload from stdin)\n");
        struct VulnerableCmd cmd;
        cmd.func_ptr = idle; memset(cmd.buf, 0, sizeof(cmd.buf));
        printf("Target buffer: %p, Target func_ptr: %p\n", (void*)cmd.buf, (void*)&cmd.func_ptr);
        size_t max_read = sizeof(cmd.buf) + sizeof(cmd.func_ptr);
        ssize_t bytes_read = read(STDIN_FILENO, &cmd, max_read);
        if (bytes_read < 0) { perror("read from stdin failed"); } else { printf("Read %zd bytes.\n", bytes_read); }
        if (cmd.func_ptr) cmd.func_ptr();
        command_or_sequence_executed_successfully = true; // Mark as done (no hash check after attack)

    // Sequence Command Handling
    } else {
        bool known_sequence = false;
        printf("Executing command sequence...\n");
        // Reset hash chain for the sequence
        Hash_chain_reset();
        Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
        printf("Hash chain reset for sequence.\n");

        if (strcmp(env_command_full, "seq1") == 0) { // Seq 1: 90 -> Rest
            printf("Executing Sequence 1\n");
            pick();
            neutral();
            Place();
            stand();
            printf("Sequence 1 finished.\n");
            known_sequence = true;
            if (comm_send_current_hash("sequence 1 final") == 0) {
                command_or_sequence_executed_successfully = true;
            } else { fprintf(stderr, "Sequence 1 hash verification failed.\n"); }
        } else if (strcmp(env_command_full, "seq2") == 0) { // Seq 2: 90 -> 180
             printf("Executing Sequence 2\n");
             spin_ninety(); spin_oneeighty();
             printf("Sequence 2 finished.\n");
             known_sequence = true;
             if (comm_send_current_hash("sequence 2 final") == 0) {
                 command_or_sequence_executed_successfully = true;
             } else { fprintf(stderr, "Sequence 2 hash verification failed.\n"); }
        } else if (strcmp(env_command_full, "seq3") == 0) { // Seq 3: 180 -> Rest
             printf("Executing Sequence 3\n");
             spin_oneeighty(); rest();
             printf("Sequence 3 finished.\n");
             known_sequence = true;
             if (comm_send_current_hash("sequence 3 final") == 0) {
                 command_or_sequence_executed_successfully = true;
             } else { fprintf(stderr, "Sequence 3 hash verification failed.\n"); }
        } else {
            fprintf(stderr, "Unknown COMMAND received: '%s'\n", env_command_full);
        }

        // *** ADDED DELAY ***
        // Add delay only if a known sequence finished and its hash was checked
        if (known_sequence && command_or_sequence_executed_successfully) {
             printf("Adding short delay before cleanup...\n");
             delay(100); // Small delay (100ms)
        } else if (known_sequence && !command_or_sequence_executed_successfully) {
             fprintf(stderr, "Sequence hash failed, cleaning up immediately.\n");
        }
    }

    // --- Cleanup ---
    comm_cleanup();

    printf("Client finished (Overall Success Status: %s).\n", command_or_sequence_executed_successfully ? "OK" : "FAILED/Attack/Unknown");
    // Return success only if attack ran or if sequence ran AND hash was OK
    return command_or_sequence_executed_successfully ? EXIT_SUCCESS : EXIT_FAILURE;
}
