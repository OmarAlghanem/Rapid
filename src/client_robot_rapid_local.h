#ifndef CLIENT_ROBOT_BASE_PLUS_HASHING_H
#define CLIENT_ROBOT_BASE_PLUS_HASHING_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/resource.h>
#include <stddef.h>         // For size_t
#include <stdint.h>
#include <openssl/sha.h>    // For SHA256 defines needed by opcode_utils
#include <openssl/evp.h>    // For EVP functions used by opcode_utils

// --- Base Defines ---
#define BASE_SERVO_PIN 21
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32 // Needed by opcode_utils

/* --- Base Robotic Arm Control Functions --- */
void base_config_servo(void);
void base_spin_ninety(void);
void base_spin_oneeighty(void);
void base_rest(void);

/* --- Base I2C Setup --- */
int base_setup_i2c(void);
void base_cleanup_i2c(void);

/* --- Utility Functions (Declare if used by base, like hex_to_string) --- */
// void hex_to_string(const unsigned char *hash, size_t length, char *output);

/* --- Function Length Defines --- */
// Requires opcode_utils.h to be included where GET_FUNCTION_LENGTH is used (in .c)
// Requires END_FUNCTION markers after function definitions in the .c file.
#define CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(base_config_servo)
#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(base_spin_ninety)
#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(base_spin_oneeighty)
#define REST_LENGTH GET_FUNCTION_LENGTH(base_rest)

#endif // CLIENT_ROBOT_BASE_PLUS_HASHING_H
