#ifndef OPCODE_UTILS_H
#define OPCODE_UTILS_H

#include <stdio.h>
#include <stddef.h>

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
 *   - dumps all bytes of the function in hex
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

#endif /* OPCODE_UTILS_H */
