#ifndef CLIENT_ROBO_H // Or COMM_SERVO_H if that's the convention
#define CLIENT_ROBO_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <sys/mman.h> // Included if needed
//#include <time.h> // Included if needed
#include <openssl/evp.h> // Use EVP if opcode_utils uses it
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
//#include <dirent.h> // Included if needed
#include <stdint.h>
//#include <sys/stat.h> // Included if needed
#include <openssl/sha.h> // Keep for SHA256_DIGEST_LENGTH
#include <stddef.h> // For size_t

// --- Defines ---
#define BASE_SERVO_PIN 21
#define PORT 8443
#define BUFFER_SIZE 1024 // Or 4096 if preferred
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

/* --- Communication Functions --- */
void comm_init(const char *hostname, int port);
void comm_cleanup();
// int comm_send_hash(const char *hash, int is_initial); // Old hash sending
int comm_send_current_hash(); // Preferred hash sending

/* --- Robotic Arm Control Functions --- */
void spin_ninety(void);
void spin_oneeighty(void);
void rest(void);
void config_servo(void);

/* --- Attack / Utility Functions --- */
void attack_success_indicator(void); // Function called upon successful hijack
void idle(void);                     // Safe default function pointer target

/* --- Hash Calculation Functions --- */
// (Declarations depend on whether opcode_utils.h is fully static inline
// or if you have separate .c definitions)
// e.g., char *get_hash_chain_current(void); if not static inline

/* --- Utility Functions --- */
void hex_to_string(const unsigned char *hash, size_t length, char *output);
// ... other utility function declarations ...

#endif // CLIENT_ROBO_H
