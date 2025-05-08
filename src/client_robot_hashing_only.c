#include "client_robot_hashing_only.h" // Use the new header
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

#define BASE_SERVO_PIN 21    // Physical pin 40
#define SECOND_SERVO 16      // Physical pin 38
#define THIRD_SERVO 20       // Physical pin 36
#define FOURTH_SERVO 26      // Physical pin 37
#define GRIPPER 19           // Physical pin 35

#define BASE_CONFIG_SERVO_LENGTH GET_FUNCTION_LENGTH(base_config_servo)
void base_config_servo() {
    Hash_chain(base_config_servo,BASE_CONFIG_SERVO_LENGTH);
    printf("[Base] Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) { fprintf(stderr, "[Base] Warning: WiringPi init failed.\n"); }
    softPwmCreate(BASE_SERVO_PIN, 0, 200);  // Range: 0-200 (≈50Hz PWM)
    softPwmCreate(SECOND_SERVO, 0, 200);
    softPwmCreate(THIRD_SERVO, 0, 200);
    softPwmCreate(FOURTH_SERVO, 0, 200);
    softPwmCreate(GRIPPER, 0, 200);
    delay(100);  // Allow servo initialization
}
END_FUNCTION(base_config_servo)

void calibrate_servo(int servo_pin, const char* servo_name) {
    printf("Calibrating %s (Pin %d)...\n", servo_name, servo_pin);
    printf("Enter PWM values to test (0-200). Type '-1' to exit.\n");

    int pwm_value;
    while(1) {
        printf("PWM value: ");
        scanf("%d", &pwm_value);
        if(pwm_value < 0) break;

        softPwmWrite(servo_pin, pwm_value);
        delay(2000);  // Observe servo position for 2 seconds
        softPwmWrite(servo_pin, 0);  // Stop sending PWM (optional)
    }
}
//#define PICK_LENGTH GET_FUNCTION_LENGTH(pick)
void pick() {
 //   Hash_chain(pick,PICK_LENGTH);
    printf("Starting PICK movement...\n");
    
    // Base servo position
    softPwmWrite(BASE_SERVO_PIN, 13);
    printf("BASE_SERVO set to 5\n");
    delay(100);
    
    // Second servo position
    softPwmWrite(SECOND_SERVO, 15);
    printf("SECOND_SERVO set to 20\n");
    delay(100);
    
    // Third servo position
    softPwmWrite(THIRD_SERVO, 20);
    printf("THIRD_SERVO set to 20\n");
    delay(100);
    
    // Fourth servo position
    softPwmWrite(FOURTH_SERVO, 14);
    printf("FOURTH_SERVO set to 14\n");
    delay(100);
    
    // Close gripper
    softPwmWrite(GRIPPER, 10);
    printf("GRIPPER closed to 10\n");
    delay(100);
    
    printf("Pick movement completed!\n");
}
//END_FUNCTION(pick)
//#define NEUTRAL_LENGTH GET_FUNCTION_LENGTH(neutral)
void neutral() {
 //   Hash_chain(neutral,NEUTRAL_LENGTH);
    printf("Starting neutral movement...\n");
    
    // Second servo position
    softPwmWrite(SECOND_SERVO, 20);
    printf("SECOND_SERVO set to 20\n");
    delay(100);
    
    softPwmWrite(BASE_SERVO_PIN, 20);
    printf("BASE_SERVO set to 5\n");
    delay(100);
    
    // Third servo position
    softPwmWrite(THIRD_SERVO, 20);
    printf("THIRD_SERVO set to 20\n");
    delay(100);
    
    // Fourth servo position
    softPwmWrite(FOURTH_SERVO, 23);
    printf("FOURTH_SERVO set to 14\n");
    delay(100);
    
    // Close gripper
    softPwmWrite(GRIPPER, 10);
    printf("GRIPPER closed to 10\n");
    delay(100);
    
    printf("Pick movement completed!\n");
}
//END_FUNCTION(neutral)
//#define PLACE_LENGTH GET_FUNCTION_LENGTH(Place)
void Place() {
 //   Hash_chain(Place,PLACE_LENGTH);
    printf("Starting PICK movement...\n");
    
    // Base servo position
    softPwmWrite(BASE_SERVO_PIN, 25);
    printf("BASE_SERVO set to 5\n");
    delay(100);
    
    // Second servo position
    softPwmWrite(SECOND_SERVO, 15);
    printf("SECOND_SERVO set to 20\n");
    delay(100);
    
    // Third servo position
    softPwmWrite(THIRD_SERVO, 20);
    printf("THIRD_SERVO set to 20\n");
    delay(100);
    
    // Fourth servo position
    softPwmWrite(FOURTH_SERVO, 14);
    printf("FOURTH_SERVO set to 14\n");
    delay(100);
    
    // Close gripper
    softPwmWrite(GRIPPER, 10);
    printf("GRIPPER closed to 10\n");
    delay(100);
    
    printf("Pick movement completed!\n");
}
//END_FUNCTION(Place)
//#define STAND_LENGTH GET_FUNCTION_LENGTH(stand)
void stand() {
//    Hash_chain(stand,STAND_LENGTH);
    printf("Starting PICK movement...\n");
    
    // Base servo position
    softPwmWrite(BASE_SERVO_PIN, 18);
    printf("BASE_SERVO set to 5\n");
    delay(100);
    
    // Second servo position
    softPwmWrite(SECOND_SERVO, 22);
    printf("SECOND_SERVO set to 20\n");
    delay(100);
    
    // Third servo position
    softPwmWrite(THIRD_SERVO, 10);
    printf("THIRD_SERVO set to 20\n");
    delay(100);
    
    // Fourth servo position
    softPwmWrite(FOURTH_SERVO, 14);
    printf("FOURTH_SERVO set to 14\n");
    delay(100);
    
    // Close gripper
    softPwmWrite(GRIPPER, 10);
    printf("GRIPPER closed to 10\n");
    delay(100);
    
    printf("Pick movement completed!\n");
}
//END_FUNCTION(stand)
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
    Hash_chain_reset();
    // --- Core Logic (Identical to original base + hash init) ---
    base_config_servo(); // Configure servo
    pick();
    delay(100);
    neutral();
    delay(100);
    Place();
    delay(100);
    stand();
    delay(100);

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
