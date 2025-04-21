// src/test.c
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    
    // Initialize the OpenSSL library
    SSL_library_init();
    
    // Load error strings
    SSL_load_error_strings();
    
    printf("OpenSSL initialization successful!\n");
    
    // Cleanup
    EVP_cleanup();
    
    return 0;
}