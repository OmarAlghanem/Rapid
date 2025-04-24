#ifndef COMM_SERVO_H
#define COMM_SERVO_H

#include <wiringPi.h>
#include <softPwm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <stddef.h>

#define BASE_SERVO_PIN 21
#define PORT 8443
#define BUFFER_SIZE 4096
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

/* Combined Communication and Control Functions */
void comm_init(const char *hostname, int port);
void comm_cleanup();
int comm_send_hash(const char *hash, int is_initial);
void comm_send_ticket_request();
int comm_send_command(const char *command);

/* Robotic Arm Control Functions */
void spin_ninety(void);
void spin_oneeighty(void);
void rest(void);
void config_servo(void);

/* OLD Hash Calculation Functions */
unsigned char *compute_sha256(const unsigned char *data, size_t data_len, unsigned int *hash_len);
unsigned char *get_opcode(void *func_ptr, size_t length);
char *calculate_program_hash();

/* Hash Calculation Functions */
/**
 * Place an end-label immediately after any function you want to inspect.
 * Usage: after your function definition write:
 *   END_FUNCTION(func_name);
 */
#define END_FUNCTION(func) \
    asm(                          \
        ".global " #func "_end\n" \
        #func "_end:");

/**
 * PRINT_OPCODES(func):
 *   - computes size = &func_end - (char*)func
 *   - dumps all bytes of the function in hex (for debugging)
 * Usage: PRINT_OPCODES(func_name);
 */
#define PRINT_OPCODES(func) do {                                         \
    extern char func##_end;                                              \
    size_t size = (size_t)((char*)&func##_end - (char*)(func));         \
    printf("Size of %s(): %zu bytes\n", #func, size);                \
    unsigned char *p = (unsigned char*)(func);                           \
    for (size_t i = 0; i < size; ++i)                                    \
        printf("%02x ", p[i]);                                         \
    printf("\n\n");                                                 \
} while (0)

/**
 * get_opcodes:
 *   - func      : pointer to the start of the function
 *   - end_label : address of the linker-generated end label
 *
 * Returns a malloc'd C-string containing space-separated
 * hex bytes of the function's machine code. Caller must free().
 */
static inline char *get_opcodes(void (*func)(), void *end_label) {
    unsigned char *code = (unsigned char*)func;
    size_t size = (char*)end_label - (char*)func;
    size_t buflen = size * 3 + 1; /* two hex chars + space per byte + NUL */
    char *buf = malloc(buflen);
    if (!buf) return NULL;
    char *p = buf;
    for (size_t i = 0; i < size; i++) {
        int n = sprintf(p, "%02x ", code[i]);
        p += n;
    }
    *p = '\0';
    return buf;
}

/**
 * GET_OPCODES(func):
 *   - convenience macro to call get_opcodes on any function
 *     annotated with END_FUNCTION(func)
 *   - uses GCC statement-expression extension to declare extern label
 *   - yields a char* that must be freed
 *
 * Usage:
 *   char *dump = GET_OPCODES(my_function);
 *   // ... use dump ...
 *   free(dump);
 */
#define GET_OPCODES(func)                                                  \
    ({ extern char func##_end;                                            \
       get_opcodes((void*)(func), (void*)&func##_end); })




/* Utility Functions */
void print_hash(const unsigned char *hash, size_t length);
void hex_to_string(const unsigned char *hash, size_t length, char *output);

#endif // COMM_SERVO_H
