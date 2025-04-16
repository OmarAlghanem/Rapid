#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "comm.h"

#define SHA256_DIGEST_LENGTH 32

void read_executable_segments(pid_t pid, FILE *output) {
    char maps_path[256], mem_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) return;

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) {
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
        if (!buffer) continue;

        if (lseek(mem_fd, start, SEEK_SET) == (off_t)-1) {
            free(buffer);
            continue;
        }

        ssize_t bytes_read = read(mem_fd, buffer, size);
        if (bytes_read > 0) {
            for (ssize_t i = 0; i < bytes_read; i++) {
                fprintf(output, "%02x ", buffer[i]);
            }
        }
        free(buffer);
    }

    fclose(maps_file);
    close(mem_fd);
}

int calculate_file_hash(const char *filepath, unsigned char *hash_output) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return -1;
    }

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    EVP_DigestFinal_ex(mdctx, hash_output, NULL);
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

int main() {
    // Initial hash generation
    FILE *opcode_file = fopen("extractedOpcodes.txt", "w");
    read_executable_segments(getpid(), opcode_file);
    fclose(opcode_file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (calculate_file_hash("extractedOpcodes.txt", hash) != 0) {
        fprintf(stderr, "Initial hash generation failed\n");
        exit(EXIT_FAILURE);
    }

    char hash_str[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash_str + i*2, 3, "%02x", hash[i]);
    }

    // Initialize communications
    comm_init("192.168.62.41", 8443);
    comm_send_initial_hash(hash_str);

    time_t last_check = time(NULL);
    while (1) {
        // Periodic hash check
        if (time(NULL) - last_check >= 120) {
            FILE *opcode_file = fopen("extractedOpcodes.txt", "w");
            read_executable_segments(getpid(), opcode_file);
            fclose(opcode_file);

            unsigned char new_hash[SHA256_DIGEST_LENGTH];
            if (calculate_file_hash("extractedOpcodes.txt", new_hash) == 0) {
                char new_hash_str[2 * SHA256_DIGEST_LENGTH + 1];
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    snprintf(new_hash_str + i*2, 3, "%02x", new_hash[i]);
                }
                comm_send_periodic_hash(new_hash_str);
            }
            last_check = time(NULL);
        }

        comm_send_ticket_request();
        sleep(1);
    }

    comm_cleanup();
    return 0;
}
