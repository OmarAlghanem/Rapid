#include "client_robot_base.h"
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

#define BASE_SERVO_PIN 21    // Physical pin 40
#define SECOND_SERVO 16      // Physical pin 38
#define THIRD_SERVO 20       // Physical pin 36
#define FOURTH_SERVO 26      // Physical pin 37
#define GRIPPER 19           // Physical pin 35

void base_config_servo() {
    printf("[Base] Configuring servo...\n");
    if (wiringPiSetupGpio() == -1) { fprintf(stderr, "[Base] Warning: WiringPi init failed.\n"); }

    // Initialize PWM for all servos
    softPwmCreate(BASE_SERVO_PIN, 0, 200);  // Range: 0-200 (≈50Hz PWM)
    softPwmCreate(SECOND_SERVO, 0, 200);
    softPwmCreate(THIRD_SERVO, 0, 200);
    softPwmCreate(FOURTH_SERVO, 0, 200);
    softPwmCreate(GRIPPER, 0, 200);
    delay(100);  // Allow servo initialization
}
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

void pick() {
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

void neutral() {
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

void Place() {
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
void stand() {
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
/* Main function for Base App */
int main(void) {
    struct timespec start_time, end_time;
    long long elapsed_ns;
    double elapsed_s;
    struct rusage usage_start, usage_end;

    printf("--- Starting Base Robot App Benchmark ---\n");

    // Record start time and resource usage
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    getrusage(RUSAGE_SELF, &usage_start);
    base_config_servo();
    pick();
    delay(100);
    neutral();
    delay(100);
    Place();
    delay(100);
    stand();
    delay(100);
    // --- End Core Base Application Logic ---

    // Record end time and resource usage
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    getrusage(RUSAGE_SELF, &usage_end);

    // --- Calculate and Print Timings ---
    elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000LL + (end_time.tv_nsec - start_time.tv_nsec);
    elapsed_s = (double)elapsed_ns / 1000000000.0;
    long mem_usage_kb = usage_end.ru_maxrss - usage_start.ru_maxrss;

    printf("\n--- Base App Benchmark Results ---\n");
    printf("Runtime:\n");
    printf("  Elapsed Process CPU Time: %.6f seconds (%lld nanoseconds)\n", elapsed_s, elapsed_ns);
    printf("\nMemory Usage (Resident Set Size Increase - Approx Peak):\n");
    printf("  Max Resident Set Size Change: %ld KB\n", mem_usage_kb);
    printf("\nSpatial Overhead (Static Code/Data):\n");
    printf("  Run 'size client_robot_base' after compilation.\n");
    printf("--- End Base App Benchmark ---\n");

    return EXIT_SUCCESS;
}
