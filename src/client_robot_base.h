#ifndef CLIENT_ROBOT_BASE_H
#define CLIENT_ROBOT_BASE_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // For delay, close
#include <fcntl.h> // For I2C
#include <linux/i2c-dev.h> // For I2C
#include <sys/ioctl.h> // For I2C
#include <time.h> // For timing
#include <sys/resource.h> // For memory usage

// --- Base Defines ---
#define BASE_SERVO_PIN 21
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08 // Assuming ESP32 communication is part of base app function

/* --- Base Robotic Arm Control Functions --- */
void base_config_servo(void);
void base_spin_ninety(void);
void base_spin_oneeighty(void);
void base_rest(void);

/* --- Base I2C Setup (if needed for core function) --- */
int base_setup_i2c(void);
void base_cleanup_i2c(void);

#endif // CLIENT_ROBOT_BASE_H
