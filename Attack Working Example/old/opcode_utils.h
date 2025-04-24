#ifndef OPCODE_UTILS_H
#define OPCODE_UTILS_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

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

#endif /* OPCODE_UTILS_H */

