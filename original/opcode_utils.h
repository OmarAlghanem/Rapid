#ifndef OPCODE_UTILS_H
#define OPCODE_UTILS_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <openssl/sha.h>  // for SHA256
#include <openssl/evp.h>  // Added for EVP API

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
 * Convenience macro to call get_opcodes on a function
 * annotated with END_FUNCTION(func). Returns a malloc'd string.
 * Usage:
 *   char *dump = GET_OPCODES(my_function);
 *   // use dump...
 *   free(dump);
 */
#define GET_OPCODES(func)                                                  \
    ({ extern char func##_end;                                            \
       get_opcodes((void*)(func), (void*)&func##_end); })

/**
 * get_function_length:
 *   - func      : pointer to the start of the function
 *   - end_label : address of the linker-generated end label
 *
 * Returns the length of the function in bytes.
 */
static inline size_t get_function_length(void (*func)(), void *end_label) {
    return (size_t)((char*)end_label - (char*)func);
}

/**
 * GET_FUNCTION_LENGTH(func):
 * Convenience macro to get the byte-length of a function
 * annotated with END_FUNCTION(func).
 * Usage:
 *   size_t len = GET_FUNCTION_LENGTH(my_function);
 */
#define GET_FUNCTION_LENGTH(func)                                        \
    ({ extern char func##_end;                                          \
       get_function_length((void*)(func), (void*)&func##_end); })

/**
 * get_opcodes_limited:
 *   - func   : pointer to the start of the function
 *   - length : maximum number of bytes to read
 *
 * Returns a malloc'd C-string containing up to 'length' space-separated
 * hex bytes of the function's machine code. Caller must free().
 */
static inline char *get_opcodes_limited(void (*func)(), size_t length) {
    unsigned char *code = (unsigned char*)func;
    size_t buflen = length * 3 + 1; /* two hex chars + space per byte + NUL */
    char *buf = malloc(buflen);
    if (!buf) return NULL;
    char *p = buf;
    for (size_t i = 0; i < length; i++) {
        int n = sprintf(p, "%02x ", code[i]);
        p += n;
    }
    *p = '\0';
    return buf;
}

/**
 * GET_OPCODES_LIMITED(func, length_expr):
 * Convenience macro to call get_opcodes_limited for a function
 * annotated with END_FUNCTION(func), limiting to a specified byte count.
 * Usage:
 *   char *dump = GET_OPCODES_LIMITED(my_function, len);
 *   // use dump...
 *   free(dump);
 */
#define GET_OPCODES_LIMITED(func, length_expr)                              \
    ({ extern char func##_end;                                            \
       get_opcodes_limited((void*)(func), (length_expr)); })

/**
 * hash_function:
 *   - func   : pointer to the start of the data (e.g., a function)
 *   - length : number of bytes to hash
 *
 * Returns a malloc'd C-string containing the SHA-256 hash
 * in lowercase hex (64 chars + NUL). Caller must free().
 */
static inline char *hash_function(void (*func)(), size_t length) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_Digest((unsigned char*)func, length, digest, NULL, EVP_sha256(), NULL); // Replaced SHA256 with EVP
    size_t hexlen = SHA256_DIGEST_LENGTH * 2 + 1;
    char *hex = malloc(hexlen);
    if (!hex) return NULL;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", digest[i]);
    }
    hex[hexlen - 1] = '\0';
    return hex;
}

/**
 * GET_HASH(func, length_expr):
 * Convenience macro to produce a SHA-256 hash of the first
 * length_expr bytes of func's machine code.
 * Usage:
 *   char *digest = GET_HASH(my_function, MY_FUNC_LEN);
 *   // use digest...
 *   free(digest);
 */
#define GET_HASH(func, length_expr) \
    hash_function((void*)(func), (length_expr))

/**
 * Hash chain state and functions:
 */
static int __hash_chain_initialized = 0;
static unsigned char __hash_chain_state[SHA256_DIGEST_LENGTH];

/**
 * Hash_chain_reset(): resets the internal chain state
 */
static inline void Hash_chain_reset(void) {
    __hash_chain_initialized = 0;
}

/**
 * Hash_chain:
 *   - func   : pointer to the start of the function
 *   - length : number of bytes to include
 *
 * Returns a pointer to the 32-byte binary digest. Chains across calls.
 */
static inline unsigned char *Hash_chain(void (*func)(), size_t length) {
    if (!__hash_chain_initialized) {
        EVP_Digest((unsigned char*)func, length, __hash_chain_state, NULL, EVP_sha256(), NULL); // Replaced SHA256 with EVP
        __hash_chain_initialized = 1;
    } else {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, __hash_chain_state, SHA256_DIGEST_LENGTH);
        EVP_DigestUpdate(ctx, (unsigned char*)func, length);
        EVP_DigestFinal_ex(ctx, __hash_chain_state, NULL);
        EVP_MD_CTX_free(ctx);
    }
    return __hash_chain_state;
}

/**
 * get_hash_chain_string:
 *   - func   : pointer to the start of the function
 *   - length : number of bytes to hash in this link
 *
 * Calls Hash_chain and returns a malloc'd lowercase hex string
 * of the 32-byte digest (64 chars + NUL). Caller must free().
 */
static inline char *get_hash_chain_string(void (*func)(), size_t length) {
    unsigned char *bin = Hash_chain(func, length);
    size_t hexlen = SHA256_DIGEST_LENGTH * 2 + 1;
    char *hex = malloc(hexlen);
    if (!hex) return NULL;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + i*2, "%02x", bin[i]);
    }
    hex[hexlen - 1] = '\0';
    return hex;
}

/**
 * GET_HASH_CHAIN(func, length_expr):
 * Convenience macro to call get_hash_chain_string for a function
 * annotated with END_FUNCTION(func).
 */
#define GET_HASH_CHAIN(func, length_expr) \
    get_hash_chain_string((void*)(func), (length_expr))

/**
 * get_hash_chain_current:
 *   Returns a malloc'd NUL-terminated lowercase hex string (64 chars)
 *   of the current chain state without advancing the chain.
 * Caller must free().
 */
static inline char *get_hash_chain_current(void) {
    size_t hexlen = SHA256_DIGEST_LENGTH * 2 + 1;
    char *hex = malloc(hexlen);
    if (!hex) return NULL;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + i*2, "%02x", __hash_chain_state[i]);
    }
    hex[hexlen - 1] = '\0';
    return hex;
}


/**
 * get_hash_chain_state:
 *   Returns a pointer to the internal 32-byte binary chain state.
 *   Do not modify the returned buffer.
 */
static inline const unsigned char *get_hash_chain_state(void) {
    return __hash_chain_state;
}

#endif /* OPCODE_UTILS_H */
