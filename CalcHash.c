#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 4096

int calculate_file_hash(const char *filepath, unsigned char *hash_output) {
    FILE *file = NULL;
    SHA256_CTX sha256_ctx;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read = 0;

    file = fopen(filepath, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s: %s\n", filepath, strerror(errno));
        return -1;
    }

    if (!SHA256_Init(&sha256_ctx)) {
        fprintf(stderr, "Error: SHA256_Init failed\n");
        fclose(file);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (!SHA256_Update(&sha256_ctx, buffer, bytes_read)) {
            fprintf(stderr, "Error: SHA256_Update failed\n");
            fclose(file);
            return -1;
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Error: Failed to read file\n");
        fclose(file);
        return -1;
    }

    if (!SHA256_Final(hash_output, &sha256_ctx)) {
        fprintf(stderr, "Error: SHA256_Final failed\n");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

void write_hash_to_file(FILE *output_file, const char *filepath, unsigned char *hash) {
    fprintf(output_file, "%s: ", filepath);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(output_file, "%02x", hash[i]);
    }
    fprintf(output_file, "\n");
}

int process_directory(const char *dirpath, FILE *output_file) {
    DIR *dir;
    struct dirent *entry;
    char filepath[MAX_PATH_LENGTH];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int files_processed = 0;

    dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Error: Cannot open directory %s: %s\n", dirpath, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
        
        struct stat path_stat;
        if (stat(filepath, &path_stat) == 0 && S_ISREG(path_stat.st_mode)) {
            if (calculate_file_hash(filepath, hash) == 0) {
                write_hash_to_file(output_file, filepath, hash);
                files_processed++;
            }
        }
    }

    if (files_processed == 0) {
        fprintf(stderr, "No files found in directory.\n");
    }

    closedir(dir);
    return 0;
}

int is_directory(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISDIR(path_stat.st_mode);
}

int is_regular_file(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISREG(path_stat.st_mode);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_or_directory_path>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    FILE *output_file;

    // Open hash.txt for writing
    output_file = fopen("hash.txt", "w");
    if (!output_file) {
        fprintf(stderr, "Error: Cannot create hash.txt file\n");
        return 1;
    }

    if (is_directory(path)) {
        printf("Processing directory: %s\n", path);
        process_directory(path, output_file);
    } else if (is_regular_file(path)) {
        if (calculate_file_hash(path, hash) == 0) {
            write_hash_to_file(output_file, path, hash);
            printf("Hash written to hash.txt\n");
        }
    } else {
        fprintf(stderr, "Error: %s is neither a regular file nor a directory\n", path);
        fclose(output_file);
        return 1;
    }

    fclose(output_file);
    return 0;
}