#ifndef SERVO_CONTROL_H
#define SERVO_CONTROL_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define BASE_SERVO_PIN 21
#define PORT 8443
#define BUFFER_SIZE 1024
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

/* SHA-256 Hashing Functions */
unsigned char *compute_sha256(const unsigned char *data, size_t data_len, unsigned int *hash_len);
int calculate_file_hash(const char *filepath, unsigned char *hash_output);

/* Opcode Extraction Functions */
unsigned char *get_opcode(void *func_ptr, size_t length);
void read_executable_segments(pid_t pid, FILE *output);

/* Robotic Arm Control Functions */
void spin_ninety(void);
void spin_oneeighty(void);
void rest(void);
void config_servo(void);

/* I2C Communication Functions */
int setup_i2c(void);
void send_to_i2c(int i2c_fd, const char *message);

/* SSL/TLS Functions */
SSL_CTX *create_context(void);
void configure_context(SSL_CTX *ctx);

/* Utility Functions */
void print_hash(const unsigned char *hash, size_t length);
void hex_to_string(const unsigned char *hash, size_t length, char *output);

#endif // SERVO_CONTROL_H
