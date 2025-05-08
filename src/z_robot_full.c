#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// --- GPIO Pins (From Header) ---
#define BASE_SERVO_PIN 21    // Physical pin 40
#define SECOND_SERVO 16      // Physical pin 38
#define THIRD_SERVO 20       // Physical pin 36
#define FOURTH_SERVO 26      // Physical pin 37
#define GRIPPER 19           // Physical pin 35

// --- Movement Functions ---
void config_servo() {
    if(wiringPiSetupGpio() == -1) {
        fprintf(stderr, "WiringPi init failed!\n");
        exit(1);
    }
    
    // Initialize PWM for all servos
    softPwmCreate(BASE_SERVO_PIN, 0, 200);  // Range: 0-200 (≈50Hz PWM)
    softPwmCreate(SECOND_SERVO, 0, 200);
    softPwmCreate(THIRD_SERVO, 0, 200);
    softPwmCreate(FOURTH_SERVO, 0, 200);
    softPwmCreate(GRIPPER, 0, 200);
    delay(3000);  // Allow servo initialization
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
// --- Add this pick movement function ---
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
void attack() {
    printf("Starting PICK movement...\n");
    
    // Base servo position
    softPwmWrite(BASE_SERVO_PIN, 18);
    printf("BASE_SERVO set to 5\n");
    delay(500);
    softPwmWrite(BASE_SERVO_PIN, 25);
    printf("BASE_SERVO set to 5\n");
    delay(500);
    softPwmWrite(BASE_SERVO_PIN, 10);
    printf("BASE_SERVO set to 5\n");
    delay(500);
    // Second servo position
    softPwmWrite(SECOND_SERVO, 22);
    printf("SECOND_SERVO set to 20\n");
    delay(500);
    softPwmWrite(SECOND_SERVO, 15);
    printf("SECOND_SERVO set to 20\n");
    delay(500);
    // Third servo position
    softPwmWrite(THIRD_SERVO, 11);
    printf("THIRD_SERVO set to 20\n");
    delay(500);
    softPwmWrite(THIRD_SERVO, 20);
    printf("THIRD_SERVO set to 20\n");
    delay(500);
    
    // Fourth servo position
    softPwmWrite(FOURTH_SERVO, 14);
    printf("FOURTH_SERVO set to 14\n");
    delay(500);
    softPwmWrite(FOURTH_SERVO, 20);
    printf("FOURTH_SERVO set to 14\n");
    delay(500);
    // Close gripper
    softPwmWrite(GRIPPER, 10);
    printf("GRIPPER closed to 10\n");
    delay(500);
    
    printf("attack!\n");
}
// --- Update main function to test ---
//int main() {
//    config_servo();
    
    // Execute pick movement
//    pick();
    
    // Optional: Add return to rest positions
    // rest();
    // rest1();
    
  //  return 0;
//}
int main() {
    config_servo();
    pick();
    delay(1000);
    neutral();
    delay(1000);
    Place();
    delay(1000);
    stand();
    delay(3000);
}
