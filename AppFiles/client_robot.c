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
    int fd = open(I2C_DEVICE, O_RDWR);
    if (fd < 0) { perror("Failed to open I2C device"); return -1; }
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        perror("Failed to set I2C slave address"); close(fd); return -1;
    }
    printf("I2C device setup complete.\n");
    return fd;
}

/* --- Servo control functions WITH Hash_chain calls inside --- */

// Define lengths needed for Hash_chain calls
#define CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(config_servo)
#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(spin_ninety)
#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(spin_oneeighty)
#define REST_LENGTH GET_FUNCTION_LENGTH(rest)

void config_servo() {
    // No hash chain here, it's the initial state added in comm_init
    printf("Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) {
        fprintf(stderr, "Warning: WiringPi initialization failed (maybe already setup?).\n");
    } else { printf("WiringPi setup OK.\n"); }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    if (softPwmCreate(BASE_SERVO_PIN, 0, 200) != 0) {
         fprintf(stderr, "Soft PWM creation failed.\n"); exit(EXIT_FAILURE);
    } else { printf("Soft PWM created OK.\n"); }
    delay(1000);
}
END_FUNCTION(config_servo) // Marker still needed for length calculation

void spin_ninety() {
    // Add this function's opcodes to the current hash chain
    Hash_chain(spin_ninety, SPIN_NINETY_LENGTH);
    printf("Executing spin_ninety() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 15);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
    delay(1000);
    printf("spin_ninety() finished.\n");
}
END_FUNCTION(spin_ninety)

void spin_oneeighty() {
    // Add this function's opcodes to the current hash chain
    Hash_chain(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH);
    printf("Executing spin_oneeighty() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 25);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
    delay(1000);
    printf("spin_oneeighty() finished.\n");
}
END_FUNCTION(spin_oneeighty)

void rest() {
    // Add this function's opcodes to the current hash chain
    Hash_chain(rest, REST_LENGTH);
    printf("Executing rest() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 5);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
    delay(1000);
    printf("rest() finished.\n");
}
END_FUNCTION(rest)

/* Utility to convert binary hash to hex string */
void hex_to_string(const unsigned char *hash, size_t length, char *output) {
    for (size_t i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[length * 2] = '\0';
}

/* Communication initialization */
void comm_init(const char *hostname, int port) {
    // ... (socket creation, connection, SSL handshake - same as before) ...
    printf("Initializing communication to %s:%d...\n", hostname, port);
    SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    configure_context(ctx);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); SSL_CTX_free(ctx); exit(EXIT_FAILURE); }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
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

    // Hardware Initialization
    i2c_fd = setup_i2c();
    if (i2c_fd < 0) { fprintf(stderr, "I2C setup failed.\n"); exit(EXIT_FAILURE); } // Simplified cleanup on error
    config_servo();

    // Initialize Hash Chain state with config_servo
    Hash_chain_reset(); // Start fresh
    Hash_chain(config_servo, CONFIG_SERVO_LENGTH); // Add config_servo hash as the base
    printf("Initial Hash chain state created based on config_servo.\n");
    initial_hash_sent = false; // Reset flag
}

/* Communication cleanup */
void comm_cleanup() {
    printf("Cleaning up communication...\n");
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
    if (sock != -1) { close(sock); sock = -1; }
    if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
    if (i2c_fd != -1) { close(i2c_fd); i2c_fd = -1; }
    printf("Cleanup complete.\n");
}

/* Send current hash state to server */
// This function now sends either the INITIAL hash or the PERIODIC hash (after a sequence)
int comm_send_current_hash(const char *context_message) {
    char *current_hash_hex = get_hash_chain_current(); // Get current state
    if (!current_hash_hex) {
        fprintf(stderr, "Failed to get current hash chain string for %s.\n", context_message);
        return -1;
    }

    char msg[BUFFER_SIZE];
    // Determine if it's the initial hash or a periodic one
    const char* hash_type_str = initial_hash_sent ? "PERIODIC" : "INIT";

    snprintf(msg, sizeof(msg), "HASH:%s:%s", hash_type_str, current_hash_hex);
    printf("Sending %s hash (%s): %s\n", hash_type_str, context_message, msg);

    int write_result = SSL_write(ssl, msg, strlen(msg));
    free(current_hash_hex); // Free the hash string

    if (write_result <= 0) { /* Error handling */ return -1; }

    char buffer[BUFFER_SIZE];
    printf("Waiting for server response to %s hash...\n", hash_type_str);
    int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (bytes <= 0) { /* Error handling */ return -1; }
    buffer[bytes] = '\0';
    printf("Server response: %s\n", buffer);

    if (strncmp(buffer, "HASH_OK", 7) == 0) {
        if (!initial_hash_sent) {
            initial_hash_sent = true; // Mark initial hash as successfully sent
        }
        printf("Server accepted %s hash (%s).\n", hash_type_str, context_message);
        return 0; // Success
    } else {
        fprintf(stderr, "Server rejected %s hash (%s).\n", hash_type_str, context_message);
        return -1; // Failure
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    printf("Client starting...\n");

    if (argc != 2) { /* Argument check */ return EXIT_FAILURE; }
    printf("Server IP provided: %s\n", argv[1]);
    const char *env_command_full = getenv("COMMAND");
    if (!env_command_full) { /* Env check */ return EXIT_FAILURE; }
    printf("COMMAND received: %s\n", env_command_full);

    // Initialize Communication & Base Hash State
    comm_init(argv[1], PORT);

    // Send Initial Hash right after init (based on config_servo)
    if (comm_send_current_hash("initial config") != 0) {
        fprintf(stderr, "Initial hash verification failed. Terminating.\n");
        comm_cleanup();
        return EXIT_FAILURE;
    }

    // --- Command Execution ---
    bool command_or_sequence_executed = false;

    // === Attack Command Handling (Unchanged) ===
    if (strcmp(env_command_full, "attack") == 0) {
        printf("Executing command: attack (reading payload from stdin)\n");
        struct VulnerableCmd cmd;
        cmd.func_ptr = idle;
        memset(cmd.buf, 0, sizeof(cmd.buf));
        printf("Target buffer: %p, Target func_ptr: %p\n", (void*)cmd.buf, (void*)&cmd.func_ptr);
        printf("Reading attack payload from stdin...\n");
        size_t max_read = sizeof(cmd.buf) + sizeof(cmd.func_ptr);
        ssize_t bytes_read = read(STDIN_FILENO, &cmd, max_read);
        if (bytes_read < 0) { perror("read from stdin failed"); }
        else { printf("Read %zd bytes.\n", bytes_read); }
        printf("Calling function pointer stored at %p...\n", (void*)&cmd.func_ptr);
        if (cmd.func_ptr) cmd.func_ptr();
        command_or_sequence_executed = true; // Mark as executed

    // === Sequence Command Handling ===
    } else if (strcmp(env_command_full, "seq1") == 0) { // Sequence 1: Spin 90 -> Rest
        printf("Executing Sequence 1: Spin 90 -> Rest\n");
        // Reset hash chain to initial state (config_servo) for this sequence
        Hash_chain_reset();
        Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
        printf("Hash chain reset for sequence 1.\n");
        // Execute sequence
        spin_ninety();
        rest();
        printf("Sequence 1 finished.\n");
        // Send final hash for this sequence
        if (comm_send_current_hash("sequence 1 final") != 0) {
             fprintf(stderr, "Sequence 1 hash verification failed.\n");
             // Decide if to terminate or just log
        }
        command_or_sequence_executed = true;
    } else if (strcmp(env_command_full, "seq2") == 0) { // Sequence 2: Spin 90 -> Spin 180
         printf("Executing Sequence 2: Spin 90 -> Spin 180\n");
         Hash_chain_reset(); Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
         printf("Hash chain reset for sequence 2.\n");
         spin_ninety();
         spin_oneeighty();
         printf("Sequence 2 finished.\n");
         if (comm_send_current_hash("sequence 2 final") != 0) { /* Handle error */ }
         command_or_sequence_executed = true;
    } else if (strcmp(env_command_full, "seq3") == 0) { // Sequence 3: Spin 180 -> Rest
         printf("Executing Sequence 3: Spin 180 -> Rest\n");
         Hash_chain_reset(); Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
         printf("Hash chain reset for sequence 3.\n");
         spin_oneeighty();
         rest();
         printf("Sequence 3 finished.\n");
         if (comm_send_current_hash("sequence 3 final") != 0) { /* Handle error */ }
         command_or_sequence_executed = true;
    } else {
        // --- Handle unknown commands ---
        fprintf(stderr, "Unknown COMMAND received: '%s'\n", env_command_full);
        // No action, no hash sent for unknown commands
    }

    // --- Cleanup ---
    comm_cleanup();

    if (!command_or_sequence_executed) {
        // This might occur if COMMAND was invalid but not "attack"
        fprintf(stderr, "Warning: No valid command or sequence was executed.\n");
    }

    printf("Client finished.\n");
    return EXIT_SUCCESS;
}
