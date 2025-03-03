// client.c (Raspberry Pi)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#define PORT 8443
#define BUFFER_SIZE 1024
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08  // I2C address of ESP32

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

int setup_i2c() {
    int i2c_fd = open(I2C_DEVICE, O_RDWR);
    if (i2c_fd < 0) {
        perror("Failed to open I2C bus");
        return -1;
    }

    if (ioctl(i2c_fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        perror("Failed to set I2C slave address");
        return -1;
    }

    return i2c_fd;
}

void send_to_i2c(int i2c_fd, const char *message) {
    if (write(i2c_fd, message, strlen(message)) != strlen(message)) {
        perror("Failed to write to I2C");
    }
}

void read_from_i2c(int i2c_fd, char *buffer, int length) {
    if (read(i2c_fd, buffer, length) != length) {
        perror("Failed to read from I2C");
    }
}

int main() {
    const char *hostname = "192.168.59.41";  // Server IP
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(hostname);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char buffer[BUFFER_SIZE];
        int i2c_fd = setup_i2c();
        if (i2c_fd == -1) exit(EXIT_FAILURE);

        // Receive handshake from server
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            send_to_i2c(i2c_fd, buffer);  // Send handshake to ESP32
        }

        // Send tickets every 5 seconds
        int count = 0;
        while (1) {
            sleep(1);
            if(count<10){
              SSL_write(ssl, "TICKET\n", 7);
            }
            else{
              SSL_write(ssl, "HACKED\n", 7);
            }
            count = count + 1;
            bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                send_to_i2c(i2c_fd, buffer);  // Send ticket to ESP32
            }
        }

        close(i2c_fd);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
