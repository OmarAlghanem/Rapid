#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <unistd.h>

#define SERVO_PIN_1 17  // GPIO17 for the first servo
#define SERVO_PIN_2 27  // GPIO27 for the second servo
#define SERVO_PIN_3 22  // GPIO22 for the third servo
#define SERVO_PIN_4 23  // GPIO23 for the fourth servo
#define SERVO_PIN_5 24  // GPIO24 for the fifth servo

void setServoAngle(int angle, int servoPin) {
    // Limit the range for the servo to 120 degrees
    if (angle > 120) angle = 120; // Max angle is 120 degrees

    // Map angle (0° to 120°) to PWM values (5-25)
    int pulse = (angle * 20 / 120) + 5;  // Maps angle (0-120) to pulse range (5-25)

    // Make sure pulse is within the range
    if (pulse < 5) pulse = 5;
    if (pulse > 25) pulse = 25;

    softPwmWrite(servoPin, pulse);
}

int main() {
    if (wiringPiSetupGpio() == -1) {
        printf("Failed to initialize wiringPi\n");
        return 1;
    }

    pinMode(SERVO_PIN_1, OUTPUT);
    pinMode(SERVO_PIN_2, OUTPUT);
    pinMode(SERVO_PIN_3, OUTPUT);
    pinMode(SERVO_PIN_4, OUTPUT);
    pinMode(SERVO_PIN_5, OUTPUT);
    softPwmCreate(SERVO_PIN_1, 5, 25); // Min 5 (0°), Max 25 (120°)
    softPwmCreate(SERVO_PIN_2, 5, 25); // Min 5 (0°), Max 25 (120°)
    softPwmCreate(SERVO_PIN_3, 5, 25); // Min 5 (0°), Max 25 (120°)
    softPwmCreate(SERVO_PIN_4, 5, 25); // Min 5 (0°), Max 25 (120°)
    softPwmCreate(SERVO_PIN_5, 5, 25); // Min 5 (0°), Max 25 (120°)

    // Set initial angles
    setServoAngle(120, SERVO_PIN_2);  // Servo 2 starts at 120 degrees
    setServoAngle(90, SERVO_PIN_5);   // Servo 5 starts at 90 degrees
    setServoAngle(60, SERVO_PIN_4);   // Servo 4 starts at 60 degrees

    char input;
    printf("Press 'q' to move Servo 1 to 0 degrees, 'w' to move Servo 1 to 90 degrees,\n");
    printf("'a' to move Servo 2 to 90 degrees, 's' to move Servo 2 to 120 degrees,\n");
    printf("'z' to move Servo 3 to 0 degrees, 'x' to move Servo 3 to 90 degrees,\n");
    printf("'e' to move Servo 4 to 0 degrees, 'r' to move Servo 4 to 90 degrees,\n");
    printf("'d' to move Servo 5 to 90 degrees, 'f' to move Servo 5 to 120 degrees, or 'c' to exit.\n");

    while (1) {
        input = getchar();  // Get user input from keyboard

        if (input == 'q') {
            printf("Moving Servo 1 to 0 degrees\n");
            setServoAngle(0, SERVO_PIN_1);
        } else if (input == 'w') {
            printf("Moving Servo 1 to 90 degrees\n");
            setServoAngle(90, SERVO_PIN_1);
        } else if (input == 'a') {
            printf("Moving Servo 2 to 90 degrees\n");
            setServoAngle(90, SERVO_PIN_2);
        } else if (input == 's') {
            printf("Moving Servo 2 to 120 degrees\n");
            setServoAngle(120, SERVO_PIN_2);  // Use 120 as max
        } else if (input == 'z') {
            printf("Moving Servo 3 to 0 degrees\n");
            setServoAngle(0, SERVO_PIN_3);
        } else if (input == 'x') {
            printf("Moving Servo 3 to 90 degrees\n");
            setServoAngle(90, SERVO_PIN_3);
        } else if (input == 'e') {
            printf("Moving Servo 4 to 0 degrees\n");
            setServoAngle(0, SERVO_PIN_4);
        } else if (input == 'r') {
            printf("Moving Servo 4 to 60 degrees\n");
            setServoAngle(60, SERVO_PIN_4);
        } else if (input == 'd') {
            printf("Moving Servo 5 to 90 degrees\n");
            setServoAngle(90, SERVO_PIN_5);
        } else if (input == 'f') {
            printf("Moving Servo 5 to 120 degrees\n");
            setServoAngle(120, SERVO_PIN_5);
        } else if (input == 'c') {
            printf("Exiting...\n");
            break;  // Exit the loop if 'c' is pressed
        }

        // Clear the input buffer if necessary (for cases like pressing Enter after the key)
        while (getchar() != '\n'); 
    }

    return 0;
}