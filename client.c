#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h> // Added for EVP functions
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <time.h>
#define PORT 8443
#define BUFFER_SIZE 1024
#define I2C_DEVICE "/dev/i2c-1"
#define ESP32_ADDR 0x08
#define SHA256_DIGEST_LENGTH 32

// Opcode extraction functions
void read_executable_segments(pid_t pid, FILE *output) {
    char maps_path[256], mem_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("Failed to open maps file");
        return;
    }

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) {
        perror("Failed to open mem file");
        fclose(maps_file);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), maps_file)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[2] != 'x') continue;

        size_t size = end - start;
        unsigned char *buffer = malloc(size);
        if (!buffer) {
            perror("Failed to allocate buffer");
            continue;
        }

        if (lseek(mem_fd, start, SEEK_SET) == (off_t)-1) {
            perror("Failed to seek");
            free(buffer);
            continue;
        }

        ssize_t bytes_read = read(mem_fd, buffer, size);
        if (bytes_read > 0) {
            fprintf(output, "Opcodes from %lx to %lx (%zd bytes):\n", start, end, bytes_read);
            for (ssize_t i = 0; i < bytes_read; i++) {
                fprintf(output, "%02x ", buffer[i]);
                if ((i + 1) % 16 == 0) fprintf(output, "\n");
            }
            fprintf(output, "\n\n");
        }
        free(buffer);
    }

    fclose(maps_file);
    close(mem_fd);
}

// Hashing functions
int calculate_file_hash(const char *filepath, unsigned char *hash_output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return -1;
        }
    }

    unsigned int len;
    if (EVP_DigestFinal_ex(mdctx, hash_output, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

// I2C functions
int setup_i2c() {
    int i2c_fd = open(I2C_DEVICE, O_RDWR);
    if (i2c_fd < 0) return -1;
    if (ioctl(i2c_fd, I2C_SLAVE, ESP32_ADDR) < 0) return -1;
    return i2c_fd;
}

void send_to_i2c(int i2c_fd, const char *message) {
    write(i2c_fd, message, strlen(message));
}

// SSL functions
SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) exit(EXIT_FAILURE);
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_use_certificate_file(ctx, "../certs/client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "../certs/client.key", SSL_FILETYPE_PEM);
    SSL_CTX_load_verify_locations(ctx, "../certs/ca.crt", NULL);
}

int main() {
    const char *hostname = "192.168.62.41";
    struct sockaddr_in addr;
    SSL_CTX *ctx = create_context();
    configure_context(ctx);
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(hostname);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    // Initial hash generation
    FILE *opcode_file = fopen("extractedOpcodes.txt", "w");
    read_executable_segments(getpid(), opcode_file);
    fclose(opcode_file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    calculate_file_hash("extractedOpcodes.txt", hash);

    char hash_msg[2 * SHA256_DIGEST_LENGTH + 6];
    snprintf(hash_msg, sizeof(hash_msg), "HASH:");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash_msg + 5 + i*2, 3, "%02x", hash[i]);
    }
    SSL_write(ssl, hash_msg, strlen(hash_msg));

    // Main loop
    int i2c_fd = setup_i2c();
    time_t last_check = time(NULL);
    while (1) {
        // Periodic hash check
        if (time(NULL) - last_check >= 120) {
            FILE *opcode_file = fopen("extractedOpcodes.txt", "w");
            read_executable_segments(getpid(), opcode_file);
            fclose(opcode_file);
            
            unsigned char new_hash[SHA256_DIGEST_LENGTH];
            calculate_file_hash("extractedOpcodes.txt", new_hash);
            
            char new_hash_msg[2 * SHA256_DIGEST_LENGTH + 6];
            snprintf(new_hash_msg, sizeof(new_hash_msg), "HASH:");
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                snprintf(new_hash_msg + 5 + i*2, 3, "%02x", new_hash[i]);
            }
            SSL_write(ssl, new_hash_msg, strlen(new_hash_msg));
            last_check = time(NULL);
        }

        // Existing ticket logic
        char buffer[BUFFER_SIZE];
        SSL_write(ssl, "TICKET\n", 7);
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            send_to_i2c(i2c_fd, buffer);
        }
        sleep(1);
    }

    close(i2c_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
