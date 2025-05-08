#ifndef CLIENT_ROBOT_RAPID_H
#define CLIENT_ROBOT_RAPID_H

// Include all headers from your latest working client_robot.h
#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdbool.h> // Ensure bool is included
#include <time.h>    // For timing
#include <sys/resource.h> // For memory usage

// --- Defines (from your latest client_robot.h) ---
#define BASE_SERVO_PIN 21
#define PORT 8443
#define BUFFER_SIZE 1024 // Or 4096 if preferred
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

/* --- Communication Functions --- */
void comm_init(const char *hostname, int port);
void comm_cleanup();
int comm_send_current_hash(const char *context_message);

/* --- Robotic Arm Control Functions --- */
void spin_ninety(void);
void spin_oneeighty(void);
void rest(void);
void config_servo(void);

/* --- Attack / Utility Functions --- */
void attack_success_indicator(void);
void idle(void);

/* --- Utility Functions --- */
void hex_to_string(const unsigned char *hash, size_t length, char *output);

// Define lengths needed for Hash_chain calls (Can also be in .c)
#define CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(config_servo)
#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(spin_ninety)
#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(spin_oneeighty)
#define REST_LENGTH GET_FUNCTION_LENGTH(rest)

#endif // CLIENT_ROBOT_RAPID_H
