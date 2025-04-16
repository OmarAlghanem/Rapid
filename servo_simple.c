#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#define BASE_SERVO_PIN 21
// Retrieves opcode and returns it as a heap-allocated buffer
unsigned char *get_opcode(void *func_ptr, size_t length) {
    // Align address to page boundary
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((long)func_ptr & ~(page_size - 1));

    // Make memory readable
    if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        return NULL;
    }

    // Allocate buffer and copy opcode
    unsigned char *buffer = malloc(length);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }
    memcpy(buffer, func_ptr, length);
    
    return buffer;
}
// Simple printf wrapper function
void spin_ninety() {
    softPwmWrite(BASE_SERVO_PIN, 15);
    printf("Servo at 90 degrees\n");
    delay(1000);
}
void spin_oneeighty() {
    softPwmWrite(BASE_SERVO_PIN, 25);
    printf("Servo at 180 degrees\n");
    delay(1000);
}
void rest(){
    softPwmWrite(BASE_SERVO_PIN, 0);
    printf("Servo at rest\n");
    delay(1000);
}
void config_servo(){
    if (wiringPiSetupGpio() == -1) {
        printf("Failed to initialize WiringPi\n");
    }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    softPwmCreate(BASE_SERVO_PIN, 0, 200);

    printf("Servo control program running\n");
}
int main() {
    struct timespec begin;
    timespec_get(&begin, TIME_UTC);
    
    size_t length = 28;  // Number of bytes to retrieve
    unsigned char *opcode = get_opcode((void *)spin_oneeighty, length);
    
    if (!opcode) {
        fprintf(stderr, "Failed to retrieve opcode\n");
        return 1;
    }

    // Print from main()
    printf("%zu-byte opcode for %p:\n", length, spin_oneeighty);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", opcode[i]);
    }
    printf("\n");

    free(opcode);
    
    config_servo();
    spin_ninety();
    spin_oneeighty();
    rest();
    struct timespec end;
    timespec_get(&end, TIME_UTC);
    double time_spent = (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1000000000.0;
    printf("time: %lf\n", time_spent);
    return 0;
}
