#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include "comm.h"

#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define BUFFER_SIZE 1024

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;
static int sock = -1;
static int i2c_fd = -1;

static void configure_context(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

static int setup_i2c() {
    int fd = open(I2C_DEVICE, O_RDWR);
    if (fd < 0) return -1;
    if (ioctl(fd, I2C_SLAVE, ESP32_ADDR) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void comm_init(const char *hostname, int port) {
    ctx = SSL_CTX_new(TLS_client_method());
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(hostname)
    };
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    i2c_fd = setup_i2c();
}

int comm_send_initial_hash(const char *hash) {
    char msg[BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "HASH:%s", hash);
    SSL_write(ssl, msg, strlen(msg));

    // Handle server response
    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
    buffer[bytes] = '\0';

    bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
    if (bytes > 0 && i2c_fd != -1) {
        write(i2c_fd, buffer, bytes);
    }
    return 0;
}

int comm_send_periodic_hash(const char *hash) {
    char msg[BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "HASH:%s", hash);
    SSL_write(ssl, msg, strlen(msg));
    return 0;
}

void comm_send_ticket_request() {
    SSL_write(ssl, "TICKET\n", 7);
    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, BUFFER_SIZE-1);
    if (bytes > 0 && i2c_fd != -1) {
        write(i2c_fd, buffer, bytes);
    }
}

void comm_cleanup() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(sock);
    SSL_CTX_free(ctx);
    if (i2c_fd != -1) close(i2c_fd);
}
