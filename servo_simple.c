#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/evp.h>

#define BASE_SERVO_PIN 21

unsigned char *compute_sha256(const unsigned char *data, size_t data_len, size_t *hash_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char *hash = malloc(EVP_MD_size(md));
    *hash_len = EVP_MD_size(md);

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    EVP_DigestFinal_ex(mdctx, hash, hash_len);
    EVP_MD_CTX_free(mdctx);

    return hash;
}

unsigned char *get_opcode(void *func_ptr, size_t length) {
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((long)func_ptr & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        return NULL;
    }

    unsigned char *buffer = malloc(length);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }
    memcpy(buffer, func_ptr, length);
    return buffer;
}

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

void rest() {
    softPwmWrite(BASE_SERVO_PIN, 0);
    printf("Servo at rest\n");
    delay(1000);
}

void config_servo() {
    if (wiringPiSetupGpio() == -1) {
        printf("Failed to initialize WiringPi\n");
    }
    pinMode(BASE_SERVO_PIN, OUTPUT);
    softPwmCreate(BASE_SERVO_PIN, 0, 200);
    printf("Servo control program running\n");
}

int main() {
    size_t opcode_length = 28;  // Same length for all functions
    unsigned char *current_hash = NULL;
    size_t hash_length = 0;

    // Define functions in execution order
    void (*functions[])(void) = {config_servo, spin_ninety, spin_oneeighty, rest};
    const char *names[] = {"config_servo", "spin_ninety", "spin_oneeighty", "rest"};
    int num_functions = sizeof(functions) / sizeof(functions[0]);

    for (int i = 0; i < num_functions; i++) {
        unsigned char *opcode = get_opcode((void *)functions[i], opcode_length);
        if (!opcode) {
            fprintf(stderr, "Failed to retrieve opcode for %s\n", names[i]);
            return 1;
        }

        printf("%zu-byte opcode for %s (%p):\n", opcode_length, names[i], functions[i]);
        for (size_t j = 0; j < opcode_length; j++) {
            printf("%02x ", opcode[j]);
        }
        printf("\n");

        if (i == 0) {
            // Initial hash
            current_hash = compute_sha256(opcode, opcode_length, &hash_length);
        } else {
            // Combine previous hash with new opcode
            unsigned char *combined = malloc(hash_length + opcode_length);
            memcpy(combined, current_hash, hash_length);
            memcpy(combined + hash_length, opcode, opcode_length);
            free(current_hash);
            
            current_hash = compute_sha256(combined, hash_length + opcode_length, &hash_length);
            free(combined);
        }

        free(opcode);
    }

    printf("\nFinal cumulative hash:\n");
    for (size_t i = 0; i < hash_length; i++) {
        printf("%02x", current_hash[i]);
    }
    printf("\n");

    // Original program execution
    config_servo();
    spin_ninety();
    spin_oneeighty();
    rest();

    free(current_hash);
    return 0;
}
