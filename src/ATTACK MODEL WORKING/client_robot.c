#include <stdio.h>      // Added for printf etc.
#include <stdlib.h>     // Added for exit, getenv etc.
#include <string.h>     // Added for strcmp, strcpy, strtok, memset etc.
#include <unistd.h>     // Needed for read(), STDIN_FILENO, close
#include <errno.h>      // For errno
#include <stdbool.h>    // For bool type

#include <sys/socket.h> // Network includes
#include <arpa/inet.h>  // For inet_pton

#include <openssl/ssl.h> // OpenSSL includes
#include <openssl/err.h>

#include <fcntl.h>        // For I2C open
#include <linux/i2c-dev.h> // For I2C ioctl
#include <sys/ioctl.h>    // For I2C ioctl

#include <wiringPi.h>     // WiringPi includes
#include <softPwm.h>      // For software PWM

#include "client_robo.h" // Use your actual header filename here
#include "opcode_utils.h"

// --- SSL components ---
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static int sock = -1;
static int i2c_fd = -1;

// --- State Flags ---
static bool initial_hash_sent = false;

// --- NEW: Function to indicate successful attack ---
void attack_success_indicator() {
    // Simple visual confirmation
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("!!! Buffer Overflow Successful - Control Hijacked! !!!\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
    fflush(stdout); // Ensure it gets printed immediately
    // You could add more actions here if desired
}
END_FUNCTION(attack_success_indicator) // Add marker if you intend to hash/analyze it

// --- NEW: Idle function for default pointer value ---
void idle() {
    // This function does nothing, acts as a safe default
    // printf("Idle function called (default pointer).\n"); // Optional debug
}
END_FUNCTION(idle) // Add marker if needed

// --- REPLACE struct AttackCmd ---
// Structure inspired by servo_demo.c, vulnerable to overflow + pointer hijack
struct VulnerableCmd {
    char buf[64];             // Vulnerable buffer (target for padding)
    void (*func_ptr)(void);   // Function pointer (target for overwrite)
};


/* SSL context configuration */
static void configure_context(SSL_CTX *ctx) {
    // Ensure the paths to certificates are correct
    if (SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading client certificate or key. Check paths.\n");
        exit(EXIT_FAILURE);
    }
     // Optional: Load CA cert if server requires client cert verification by CA
    if (!SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL)) {
         fprintf(stderr, "Warning: Error loading CA certificate for verification.\n");
         // Depending on setup, this might not be a fatal error
    }
}

/* I2C Setup */
static int setup_i2c() {
    int fd = open(I2C_DEVICE, O_RDWR); // I2C_DEVICE from client_robo.h
    if (fd < 0) {
        perror("Failed to open I2C device");
        return -1;
    }
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) { // ESP32_ADDR from client_robo.h
        perror("Failed to set I2C slave address");
        close(fd);
        return -1;
    }
    printf("I2C device setup complete.\n");
    return fd;
}

/* Servo control functions */
#define CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(config_servo)
void config_servo() {
    printf("Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) {
        fprintf(stderr, "Warning: WiringPi initialization failed (maybe already setup?).\n");
    } else {
         printf("WiringPi setup OK.\n");
    }
    pinMode(BASE_SERVO_PIN, OUTPUT); // BASE_SERVO_PIN from client_robo.h
    if (softPwmCreate(BASE_SERVO_PIN, 0, 200) != 0) {
         fprintf(stderr, "Soft PWM creation failed.\n");
         exit(EXIT_FAILURE);
    } else {
         printf("Soft PWM created OK.\n");
    }
    delay(500);
}
END_FUNCTION(config_servo)

#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(spin_ninety)
void spin_ninety() {
    printf("Executing spin_ninety()...\n");
    softPwmWrite(BASE_SERVO_PIN, 15);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
    printf("spin_ninety() finished.\n");
}
END_FUNCTION(spin_ninety)

#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(spin_oneeighty)
void spin_oneeighty() {
    printf("Executing spin_oneeighty()...\n");
    softPwmWrite(BASE_SERVO_PIN, 25);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
    printf("spin_oneeighty() finished.\n");
}
END_FUNCTION(spin_oneeighty)

#define REST_LENGTH GET_FUNCTION_LENGTH(rest)
void rest() {
    printf("Executing rest()...\n");
    softPwmWrite(BASE_SERVO_PIN, 5);
    delay(1000);
    softPwmWrite(BASE_SERVO_PIN, 0);
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
    printf("Initializing communication to %s:%d...\n", hostname, port);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL Context
    printf("Creating SSL Context...\n");
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    configure_context(ctx);
    printf("SSL Context configured.\n");

    // Create Socket
    printf("Creating socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
     if (sock < 0) { perror("socket creation failed"); SSL_CTX_free(ctx); exit(EXIT_FAILURE); }
    printf("Socket created (fd=%d).\n", sock);

    // Prepare Server Address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    printf("Attempting to resolve hostname '%s' to IP address...\n", hostname);
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton error: Invalid IP address format '%s'?\n", hostname);
        perror("inet_pton"); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
     printf("Successfully converted '%s' to network address.\n", hostname);

    // Connect to Server
    printf("Attempting to connect to %s:%d...\n", hostname, port);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "connect error: Failed to connect to %s:%d.\n", hostname, port);
        perror("connect");
        fprintf(stderr, "Check:\n1. Server IP address ('%s') is correct.\n2. Server is running and listening on port %d.\n3. Network path allows connection.\n", hostname, port);
        close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    printf("Connected to server successfully.\n");

    // SSL Handshake
    printf("Creating SSL structure...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    printf("Performing SSL handshake...\n");
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect error: Handshake failed.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    printf("SSL handshake successful. Cipher: %s\n", SSL_get_cipher(ssl));

    // Hardware Initialization
    printf("Setting up I2C...\n");
    i2c_fd = setup_i2c();
    if (i2c_fd < 0) {
         fprintf(stderr, "I2C setup failed after connection.\n");
        SSL_shutdown(ssl); SSL_free(ssl); close(sock); SSL_CTX_free(ctx); exit(EXIT_FAILURE);
    }
    config_servo();

    // Initialize Hash Chain
    Hash_chain_reset();
    Hash_chain(config_servo, CONFIG_SERVO_LENGTH);
    printf("Hash chain initialized with config_servo.\n");
    initial_hash_sent = false;
}

/* Communication cleanup */
void comm_cleanup() {
    printf("Cleaning up communication...\n");
    if (ssl) {
        // Non-blocking shutdown attempt (optional, can be blocking)
        // SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
    }
    if (sock != -1) {
        close(sock);
        sock = -1;
    }
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    if (i2c_fd != -1) {
        close(i2c_fd);
        i2c_fd = -1;
    }
    // Consider adding OpenSSL cleanup if needed, e.g., at program exit
    // EVP_cleanup(); ERR_free_strings(); CONF_modules_unload(1);
     printf("Cleanup complete.\n");
}

/* Send current hash state to server */
int comm_send_current_hash() {
    char *current_hash_hex = get_hash_chain_current();
    if (!current_hash_hex) {
        fprintf(stderr, "Failed to get current hash chain string.\n");
        return -1;
    }

    char msg[BUFFER_SIZE]; // BUFFER_SIZE from client_robo.h
    const char* hash_type_str = initial_hash_sent ? "PERIODIC" : "INIT";

    snprintf(msg, sizeof(msg), "HASH:%s:%s", hash_type_str, current_hash_hex);
    printf("Sending hash: %s\n", msg);

    int write_result = SSL_write(ssl, msg, strlen(msg));
    free(current_hash_hex);
    if (write_result <= 0) {
        int err = SSL_get_error(ssl, write_result);
        fprintf(stderr, "SSL_write error sending hash: %d\n", err);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    printf("Waiting for server response to hash...\n");
    int bytes = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if (bytes <= 0) {
        int err = SSL_get_error(ssl, bytes);
        fprintf(stderr, "SSL_read error after sending hash: %d\n", err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    buffer[bytes] = '\0';
    printf("Server response to hash: %s\n", buffer);

    if (strncmp(buffer, "HASH_OK", 7) == 0) {
        if (!initial_hash_sent) {
            initial_hash_sent = true;
        }
        printf("Server accepted hash.\n");
        return 0; // Success
    } else {
        fprintf(stderr, "Server rejected %s hash.\n", hash_type_str);
        return -1; // Failure
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    printf("Client starting...\n");

    // Argument Check
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("Server IP provided via command line: %s\n", argv[1]);

    // Get Command from Environment
    const char *env_command_full = getenv("COMMAND");
    if (!env_command_full) {
        fprintf(stderr, "Error: COMMAND environment variable not set.\n");
        return EXIT_FAILURE;
    }
     printf("COMMAND received: %s\n", env_command_full);

    // Initialize Communication
    comm_init(argv[1], PORT); // PORT from client_robo.h

    // Send Initial/Periodic Hash
    if (comm_send_current_hash() != 0) {
        fprintf(stderr, "Hash verification failed. Terminating.\n");
        comm_cleanup();
        return EXIT_FAILURE;
    }

    // Parse and Execute Command
    bool command_executed = false;

    // === Attack Command Handling ===
    if (strcmp(env_command_full, "attack") == 0) {
        printf("Executing command: attack (reading payload from stdin to hijack func_ptr)\n");

        struct VulnerableCmd cmd; // Use the new struct

        // Initialize function pointer to a safe default
        cmd.func_ptr = idle;

        // Clear buffer (optional)
        memset(cmd.buf, 0, sizeof(cmd.buf));

        printf("Target buffer address: %p\n", (void*)cmd.buf);
        printf("Target func_ptr address: %p\n", (void*)&cmd.func_ptr);
        printf("Size of buf: %zu, Size of func_ptr: %zu\n", sizeof(cmd.buf), sizeof(cmd.func_ptr));
        printf("Address of attack_success_indicator: %p\n", (void*)attack_success_indicator);
        printf("Address of idle: %p\n", (void*)idle);
        printf("Reading attack payload from standard input...\n");

        // Read raw bytes from stdin directly into the struct.
        size_t max_read = sizeof(cmd.buf) + sizeof(cmd.func_ptr);
        ssize_t bytes_read = read(STDIN_FILENO, &cmd, max_read);

        if (bytes_read < 0) {
            perror("read from stdin failed");
        } else {
            printf("Read %zd bytes from stdin.\n", bytes_read);
            if (cmd.func_ptr != idle) {
                printf("Function pointer cmd.func_ptr (%p) appears overwritten (default was %p).\n",
                       (void*)cmd.func_ptr, (void*)idle);
            } else {
                 printf("Function pointer cmd.func_ptr (%p) was NOT overwritten.\n", (void*)cmd.func_ptr);
            }
        }

        // Call the function pointer
        printf("Calling function pointer stored at %p...\n", (void*)&cmd.func_ptr);
        if (cmd.func_ptr != NULL) {
             cmd.func_ptr(); // Execute the code at the pointer's address
        } else {
             printf("Function pointer is NULL, not calling.\n");
        }

        command_executed = true; // Mark attack as "executed"
         // Client might crash here or after this point depending on stack state

    } else {
        // --- Standard command parsing logic ---
        char env_command_copy[BUFFER_SIZE]; // BUFFER_SIZE from client_robo.h
        strncpy(env_command_copy, env_command_full, sizeof(env_command_copy) - 1);
        env_command_copy[sizeof(env_command_copy) - 1] = '\0';

        char *command = strtok(env_command_copy, " ");
        char *payload = strtok(NULL, "");

        printf("Parsed standard command: '%s', Payload: '%s'\n", command ? command : "NULL", payload ? payload : "NULL");

        if (command) {
            if (strcmp(command, "spin") == 0 && payload && strcmp(payload, "ninety") == 0) {
                printf("Hashing and executing: spin ninety\n");
                Hash_chain(spin_ninety, SPIN_NINETY_LENGTH);
                spin_ninety();
                command_executed = true;
            } else if (strcmp(command, "spin") == 0 && payload && strcmp(payload, "oneeighty") == 0) {
                 printf("Hashing and executing: spin oneeighty\n");
                Hash_chain(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH);
                spin_oneeighty();
                command_executed = true;
            } else if (strcmp(command, "rest") == 0) {
                 printf("Hashing and executing: rest\n");
                Hash_chain(rest, REST_LENGTH);
                rest();
                command_executed = true;
            }
             else {
                fprintf(stderr, "Unknown or incomplete standard command: '%s' with payload '%s'\n", command, payload ? payload : "N/A");
            }
        } else {
             fprintf(stderr, "Error: Failed to parse standard command from environment variable '%s'\n", env_command_full);
        }
    }

    // Cleanup
    comm_cleanup();

    if (!command_executed && initial_hash_sent) {
         fprintf(stderr, "Warning: Command execution failed or command unknown after hash validation.\n");
    }

    printf("Client finished.\n");
    return EXIT_SUCCESS;
}
