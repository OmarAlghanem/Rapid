#include "client_robot_rapid.h" // Use the RAPID header
#include "opcode_utils.h"     // Include opcode utils for RAPID
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
#include <time.h>   // For clock_gettime
#include <sys/resource.h> // For memory usage

// --- SSL components (Unchanged) ---
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static int sock = -1;
static int i2c_fd = -1;

// --- State Flags (Unchanged) ---
static bool initial_hash_sent = false;

// === NEW: Global Accumulator for Network Wait Time ===
static long long total_network_wait_ns = 0;
// === === === === === === === === === === === === ===

// --- Helper Function for Timing Network Calls ---
// Adds duration between start and end (using MONOTONIC clock) to the accumulator
static inline void accumulate_network_wait_time(const struct timespec *start, const struct timespec *end) {
    total_network_wait_ns += (end->tv_sec - start->tv_sec) * 1000000000LL + (end->tv_nsec - start->tv_nsec);
}

// --- Attack Success Indicator & Idle (Unchanged) ---
void attack_success_indicator() {
    printf("\n![Attack Successful]!\n"); fflush(stdout);
}
END_FUNCTION(attack_success_indicator)
void idle() { }
END_FUNCTION(idle)

// --- Vulnerable Struct (Unchanged) ---
struct VulnerableCmd { char buf[64]; void (*func_ptr)(void); };

// --- SSL config, I2C setup (Unchanged) ---
static void configure_context(SSL_CTX *ctx) { /* ... as before ... */
    if (SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL)) {
        fprintf(stderr, "[RAPID] Warning: Error loading CA certificate.\n");
    }
}
static int setup_i2c() { /* ... as before ... */
    int fd = open(I2C_DEVICE, O_RDWR);
    if (fd < 0) { perror("[RAPID] I2C open failed"); return -1; }
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        perror("[RAPID] I2C ioctl failed"); close(fd); return -1;
    }
    printf("[RAPID] I2C setup complete.\n");
    return fd;
}

/* --- Servo control functions WITH Hash_chain calls (Unchanged) --- */
void config_servo() { /* ... as before ... */
    printf("[RAPID] Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) { fprintf(stderr, "[RAPID] Warning: WiringPi init failed.\n"); }
    else { printf("[RAPID] WiringPi setup OK.\n"); }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    if (softPwmCreate(BASE_SERVO_PIN, 0, 200) != 0) { fprintf(stderr, "[RAPID] PWM creation failed.\n"); exit(EXIT_FAILURE); }
    else { printf("[RAPID] PWM created OK.\n"); }
    delay(1000);
}
END_FUNCTION(config_servo)
void spin_ninety() { /* ... as before, including Hash_chain ... */
    Hash_chain(spin_ninety, SPIN_NINETY_LENGTH);
    printf("[RAPID] Executing spin_ninety() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 15); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000);
    printf("[RAPID] spin_ninety() finished.\n");
}
END_FUNCTION(spin_ninety)
void spin_oneeighty() { /* ... as before, including Hash_chain ... */
    Hash_chain(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH);
    printf("[RAPID] Executing spin_oneeighty() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 25); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000);
    printf("[RAPID] spin_oneeighty() finished.\n");
}
END_FUNCTION(spin_oneeighty)
void rest() { /* ... as before, including Hash_chain ... */
    Hash_chain(rest, REST_LENGTH);
    printf("[RAPID] Executing rest() [Hash Updated]...\n");
    softPwmWrite(BASE_SERVO_PIN, 5); delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000);
    printf("[RAPID] rest() finished.\n");
}
END_FUNCTION(rest)

/* --- Utility hex_to_string (Unchanged) --- */
void hex_to_string(const unsigned char *hash, size_t length, char *output) { /* ... as before ... */
    for (size_t i = 0; i < length; i++) { sprintf(output + (i * 2), "%02x", hash[i]); }
    output[length * 2] = '\0';
}

/* --- Communication functions (MODIFIED to time network waits) --- */
void comm_init(const char *hostname, int port) {
    struct timespec net_start, net_end; // For timing network calls

    printf("[RAPID] Initializing communication to %s:%d...\n", hostname, port);
    SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { /* Error */ exit(EXIT_FAILURE); }
    configure_context(ctx); // Local setup - not timed as network wait
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { /* Error */ exit(EXIT_FAILURE); }
    struct sockaddr_in addr = {0}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) { /* Error */ exit(EXIT_FAILURE); }

    // Time connect() call
    printf("[RAPID] Connecting to server...\n");
    clock_gettime(CLOCK_MONOTONIC, &net_start);
    int connect_status = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    clock_gettime(CLOCK_MONOTONIC, &net_end);
    accumulate_network_wait_time(&net_start, &net_end);
    if (connect_status != 0) { perror("[RAPID] connect"); exit(EXIT_FAILURE); } // Check status *after* timing
    printf("[RAPID] Connected to server.\n");

    // Time SSL_connect() call
    ssl = SSL_new(ctx); SSL_set_fd(ssl, sock);
    printf("[RAPID] Performing SSL handshake...\n");
    clock_gettime(CLOCK_MONOTONIC, &net_start);
    int ssl_connect_status = SSL_connect(ssl);
    clock_gettime(CLOCK_MONOTONIC, &net_end);
    accumulate_network_wait_time(&net_start, &net_end);
    if (ssl_connect_status != 1) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); } // Check status *after* timing
    printf("[RAPID] SSL handshake successful.\n");

    // Hardware Init (Not timed as network wait)
    i2c_fd = setup_i2c(); if (i2c_fd < 0) { /* Error */ exit(EXIT_FAILURE); }
    config_servo();
    Hash_chain_reset(); Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
    printf("[RAPID] Initial Hash chain state created.\n");
    initial_hash_sent = false;
}

// comm_cleanup - No network waits here
void comm_cleanup() { /* ... as before ... */
    printf("[RAPID] Cleaning up communication...\n");
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
    if (sock != -1) { close(sock); sock = -1; }
    if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
    if (i2c_fd != -1) { close(i2c_fd); i2c_fd = -1; }
    printf("[RAPID] Cleanup complete.\n");
}

// comm_send_current_hash - MODIFIED to time SSL_write/SSL_read
int comm_send_current_hash(const char *context_message) {
    struct timespec net_start, net_end; // For timing network calls

    char *current_hash_hex = get_hash_chain_current();
    if (!current_hash_hex) { return -1; }
    char msg[BUFFER_SIZE];
    const char* hash_type_str = initial_hash_sent ? "PERIODIC" : "INIT";
    snprintf(msg, sizeof(msg), "HASH:%s:%s", hash_type_str, current_hash_hex);
    printf("[RAPID] Sending %s hash (%s)...\n", hash_type_str, context_message);

    // Time SSL_write()
    clock_gettime(CLOCK_MONOTONIC, &net_start);
    int write_result = SSL_write(ssl, msg, strlen(msg));
    clock_gettime(CLOCK_MONOTONIC, &net_end);
    accumulate_network_wait_time(&net_start, &net_end);
    free(current_hash_hex); // Free after use, before status check
    if (write_result <= 0) { ERR_print_errors_fp(stderr); return -1; }

    // Time SSL_read()
    char buffer[BUFFER_SIZE];
    printf("[RAPID] Waiting for server response to %s hash...\n", hash_type_str);
    clock_gettime(CLOCK_MONOTONIC, &net_start);
    int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
    clock_gettime(CLOCK_MONOTONIC, &net_end);
    accumulate_network_wait_time(&net_start, &net_end);
    if (bytes <= 0) { ERR_print_errors_fp(stderr); return -1; }
    buffer[bytes] = '\0';

    // Check response
    if (strncmp(buffer, "HASH_OK", 7) == 0) {
        if (!initial_hash_sent) { initial_hash_sent = true; }
        printf("[RAPID] Server accepted %s hash (%s).\n", hash_type_str, context_message);
        return 0; // Success
    } else {
        fprintf(stderr, "[RAPID] Server rejected %s hash (%s).\n", hash_type_str, context_message);
        return -1; // Failure
    }
}

/* --- Main function (MODIFIED for timing) --- */
int main(int argc, char *argv[]) {
    // Overall Wall-Clock Timing
    struct timespec start_time_wall, end_time_wall;
    // Memory Usage (Optional)
    struct rusage usage_start, usage_end;
    // Network wait accumulator is global: total_network_wait_ns

    // === Start Overall Wall Clock & Resource Usage ===
    clock_gettime(CLOCK_MONOTONIC, &start_time_wall); // Use MONOTONIC for wall time
    getrusage(RUSAGE_SELF, &usage_start);
    total_network_wait_ns = 0; // Reset network wait accumulator

    printf("--- Starting RAPID Robot App Benchmark ---\n");

    // --- Argument and Env Var Handling ---
    if (argc != 2) { /* Usage */ return EXIT_FAILURE; }
    printf("[RAPID] Server IP: %s\n", argv[1]);
    const char *env_command_full = getenv("COMMAND");
    if (!env_command_full) { /* Error */ return EXIT_FAILURE; }
    printf("[RAPID] COMMAND: %s\n", env_command_full);

    // --- Core RAPID Application Logic ---
    // Initialize Comm & Hardware (Network waits inside are timed)
    comm_init(argv[1], PORT);

    // Send Initial Hash (Network waits inside are timed)
    if (comm_send_current_hash("initial config") != 0) {
        fprintf(stderr, "[RAPID] Initial hash verification failed.\n");
        comm_cleanup(); return EXIT_FAILURE;
    }

    bool command_or_sequence_executed_successfully = false;

    // Attack Command Handling (Unchanged, no specific network timing added here)
    if (strcmp(env_command_full, "attack") == 0) {
        // Attack logic here...
        printf("[RAPID] Executing command: attack\n");
        struct VulnerableCmd cmd; cmd.func_ptr = idle; memset(cmd.buf, 0, sizeof(cmd.buf));
        size_t max_read = sizeof(cmd.buf) + sizeof(cmd.func_ptr);
        ssize_t bytes_read = read(STDIN_FILENO, &cmd, max_read);
        if (bytes_read < 0) perror("[RAPID] read failed");
        if (cmd.func_ptr) cmd.func_ptr();
        command_or_sequence_executed_successfully = true;
    }
    // Sequence Command Handling
    else {
        bool known_sequence = false;
        printf("[RAPID] Executing command sequence...\n");
        // Reset hash chain (Local compute, part of measured time)
        Hash_chain_reset(); Hash_chain(config_servo, CONFIG_SERVO_LENGTH);

        // Execute sequence (Local compute + internal hash calls)
        if (strcmp(env_command_full, "seq1") == 0) {
            printf("[RAPID] Executing Sequence 1\n"); spin_ninety(); rest(); printf("[RAPID] Seq 1 done.\n");
            known_sequence = true;
            // Send final hash (Network waits inside are timed)
            if (comm_send_current_hash("seq 1 final") == 0) command_or_sequence_executed_successfully = true;
        } else if (strcmp(env_command_full, "seq2") == 0) {
            printf("[RAPID] Executing Sequence 2\n"); spin_ninety(); spin_oneeighty(); printf("[RAPID] Seq 2 done.\n");
            known_sequence = true;
            if (comm_send_current_hash("seq 2 final") == 0) command_or_sequence_executed_successfully = true;
        } else if (strcmp(env_command_full, "seq3") == 0) {
            printf("[RAPID] Executing Sequence 3\n"); spin_oneeighty(); rest(); printf("[RAPID] Seq 3 done.\n");
            known_sequence = true;
            if (comm_send_current_hash("seq 3 final") == 0) command_or_sequence_executed_successfully = true;
        } else { fprintf(stderr, "[RAPID] Unknown COMMAND: '%s'\n", env_command_full); }

        if (known_sequence && !command_or_sequence_executed_successfully) {
            fprintf(stderr, "[RAPID] Sequence hash failed.\n");
        }
    }
    // --- End Core RAPID Application Logic ---

    comm_cleanup(); // Local cleanup operations

    // === Stop Overall Wall Clock & Resource Usage ===
    clock_gettime(CLOCK_MONOTONIC, &end_time_wall); // Use MONOTONIC
    getrusage(RUSAGE_SELF, &usage_end);

    // --- Calculate and Print Results ---
    long long overall_wall_ns = (end_time_wall.tv_sec - start_time_wall.tv_sec) * 1000000000LL + (end_time_wall.tv_nsec - start_time_wall.tv_nsec);
    long long compute_only_ns = overall_wall_ns - total_network_wait_ns; // Subtract measured network waits
    if (compute_only_ns < 0) compute_only_ns = 0; // Prevent negative time

    double overall_wall_s = (double)overall_wall_ns / 1e9;
    double network_wait_s = (double)total_network_wait_ns / 1e9;
    double compute_only_s = (double)compute_only_ns / 1e9;

    long mem_usage_kb = usage_end.ru_maxrss - usage_start.ru_maxrss;

    printf("\n--- RAPID App Benchmark Results ---\n");
    printf("Runtime (Command: %s):\n", env_command_full);
    printf("  Total Wall-Clock Time        : %.6f seconds (%lld ns)\n", overall_wall_s, overall_wall_ns);
    printf("  Accumulated Network Wait Time: %.6f seconds (%lld ns)\n", network_wait_s, total_network_wait_ns);
    printf("  Estimated Compute Time       : %.6f seconds (%lld ns) (Total Wall - Network Wait)\n", compute_only_s, compute_only_ns);

    printf("\nMemory Usage (Resident Set Size Increase - Approx Peak):\n");
    printf("  Max Resident Set Size Change: %ld KB\n", mem_usage_kb);
    printf("\nSpatial Overhead (Static Code/Data):\n");
    printf("  Run 'size client_robot_rapid' after compilation.\n");
    printf("--- End RAPID App Benchmark ---\n");

    return command_or_sequence_executed_successfully ? EXIT_SUCCESS : EXIT_FAILURE;
}
