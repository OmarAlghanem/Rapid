#include "client_robot_base_plus_hashing.h" // Use the new header
#include "opcode_utils.h"                 // Include for hashing functions
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <wiringPi.h>
#include <softPwm.h>
#include <time.h>
#include <sys/resource.h>
#include <string.h>                       // Included if needed by base or hashing utils

static int base_i2c_fd = -1;

/* --- Base I2C Setup (Identical to original base) --- */
int base_setup_i2c() {
    printf("[Base] Setting up I2C...\n");
    int fd = open(I2C_DEVICE, O_RDWR);
    if (fd < 0) { perror("[Base] I2C open failed"); return -1; }
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        perror("[Base] I2C ioctl failed"); close(fd); return -1;
    }
    printf("[Base] I2C setup complete.\n");
    base_i2c_fd = fd;
    return fd;
}

/* --- Base I2C Cleanup (Identical to original base) --- */
void base_cleanup_i2c() {
    if (base_i2c_fd != -1) {
        printf("[Base] Closing I2C device...\n");
        close(base_i2c_fd);
        base_i2c_fd = -1;
    }
}

/* --- Base Servo control functions (Identical + Hashing call + Marker) --- */

void base_config_servo() {
    // Identical logic to base_config_servo in client_robot_base.c
    printf("[Base] Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) { fprintf(stderr, "[Base] Warning: WiringPi init failed.\n"); }
    else { printf("[Base] WiringPi setup OK.\n"); }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    if (softPwmCreate(BASE_SERVO_PIN, 0, 200) != 0) { fprintf(stderr, "[Base] PWM creation failed.\n"); exit(EXIT_FAILURE); }
    else { printf("[Base] PWM created OK.\n"); }
    delay(1000);
}
END_FUNCTION(base_config_servo) // ADDED Marker

void base_spin_ninety() {
    Hash_chain(base_spin_ninety, SPIN_NINETY_LENGTH); // ADDED Hashing Call
    // Identical logic to base_spin_ninety in client_robot_base.c
    printf("[Base] Executing spin_ninety()...\n");
    softPwmWrite(BASE_SERVO_PIN, 15); delay(1000); // Use delay from user's base file
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000); // Use delay from user's base file
    printf("[Base] spin_ninety() finished.\n");
}
END_FUNCTION(base_spin_ninety) // ADDED Marker

void base_spin_oneeighty() {
    Hash_chain(base_spin_oneeighty, SPIN_ONEEIGHTY_LENGTH); // ADDED Hashing Call
    // Identical logic to base_spin_oneeighty in client_robot_base.c
    printf("[Base] Executing spin_oneeighty()...\n");
    softPwmWrite(BASE_SERVO_PIN, 25); delay(1000); // Use delay from user's base file
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000); // Use delay from user's base file
    printf("[Base] spin_oneeighty() finished.\n");
}
END_FUNCTION(base_spin_oneeighty) // ADDED Marker

void base_rest() {
    Hash_chain(base_rest, REST_LENGTH); // ADDED Hashing Call
    // Identical logic to base_rest in client_robot_base.c
    printf("[Base] Executing rest()...\n");
    softPwmWrite(BASE_SERVO_PIN, 5); delay(1000); // Use delay from user's base file
    softPwmWrite(BASE_SERVO_PIN, 0); delay(1000); // Use delay from user's base file
    printf("[Base] rest() finished.\n");
}
END_FUNCTION(base_rest) // ADDED Marker

/* --- Utility hex_to_string (Add definition ONLY if needed by opcode_utils/debug) --- */
// void hex_to_string(const unsigned char *hash, size_t length, char *output) { /* ... */ }


/* Main function for Base App + Hashing */
int main(void) {
    // Timing/Resource variables (Identical to original base)
    struct timespec start_time, end_time;
    long long elapsed_ns;
    double elapsed_s;
    struct rusage usage_start, usage_end;

    printf("--- Starting Base+Hashing Robot App Benchmark ---\n"); // Label changed

    // Start Timing/Resource measurement (Identical to original base)
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    getrusage(RUSAGE_SELF, &usage_start);

    // --- Core Logic (Identical to original base + hash init) ---
    if (base_setup_i2c() < 0) return EXIT_FAILURE;
    base_config_servo(); // Configure servo

    // ADDED: Initialize Hash Chain after config
    Hash_chain_reset();
    Hash_chain(base_config_servo, CONFIG_SERVO_LENGTH);
    // NO extra printf here to match base version's print count exactly

    // Run the EXACT SAME fixed sequence as in client_robot_base.c
    printf("[Base] Running benchmark sequence (90 -> Rest)...\n"); // Keep original print
    base_spin_ninety();      // Moves robot AND calls hash internally
    base_rest();             // Moves robot AND calls hash internally
    base_spin_oneeighty();   // Moves robot AND calls hash internally
    base_spin_ninety();      // ...
    base_spin_oneeighty();
    base_rest();
    base_spin_oneeighty();
    base_spin_oneeighty();
    base_spin_ninety();
    base_spin_oneeighty();
    base_rest();
    base_spin_oneeighty();
    printf("[Base] Benchmark sequence finished.\n"); // Keep original print

    base_cleanup_i2c(); // Cleanup hardware
    // --- End Core Logic ---

    // Stop Timing/Resource measurement (Identical to original base)
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    getrusage(RUSAGE_SELF, &usage_end);

    // --- Calculation and Printing (Identical except for title) ---
    elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
    elapsed_s = (double)elapsed_ns / 1e9;
    long mem_usage_kb = usage_end.ru_maxrss - usage_start.ru_maxrss;

    printf("\n--- Base+Hashing App Benchmark Results ---\n"); // Label changed
    printf("Runtime:\n");
    printf("  Elapsed Process CPU Time: %.6f seconds (%lld nanoseconds)\n", elapsed_s, elapsed_ns);
    printf("\nMemory Usage (Resident Set Size Increase - Approx Peak):\n");
    printf("  Max Resident Set Size Change: %ld KB\n", mem_usage_kb);
    printf("\nSpatial Overhead (Static Code/Data):\n");
    printf("  Run 'size client_robot_base_plus_hashing' after compilation.\n");
    printf("--- End Base+Hashing App Benchmark ---\n"); // Label changed

    return EXIT_SUCCESS;
}
