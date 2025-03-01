#include <stdio.h>

#include <stdlib.h>

#include <fcntl.h>

#include <unistd.h>

#include <string.h>

#include <stdint.h>



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

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {

            continue;

        }



        if (perms[2] != 'x') {

            continue;

        }



        size_t size = end - start;

        unsigned char *buffer = malloc(size);

        if (!buffer) {

            perror("Failed to allocate buffer");

            continue;

        }



        if (lseek(mem_fd, start, SEEK_SET) == (off_t)-1) {

            perror("Failed to seek in mem file");

            free(buffer);

            continue;

        }



        ssize_t bytes_read = read(mem_fd, buffer, size);

        if (bytes_read == -1) {

            perror("Failed to read from mem file");

            free(buffer);

            continue;

        }



        // Write to file instead of stdout

        fprintf(output, "Opcodes from %lx to %lx (%zd bytes):\n", start, end, bytes_read);

        for (ssize_t i = 0; i < bytes_read; i++) {

            fprintf(output, "%02x ", buffer[i]);

            if ((i + 1) % 16 == 0) fprintf(output, "\n");

        }

        fprintf(output, "\n\n");

        free(buffer);

    }



    fclose(maps_file);

    close(mem_fd);

}



int main(int argc, char *argv[]) {

    if (argc != 2) {

        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);

        return EXIT_FAILURE;

    }



    FILE *output = fopen("extractedOpcodes.txt", "w");

    if (!output) {

        perror("Failed to create output file");

        return EXIT_FAILURE;

    }



    pid_t pid = atoi(argv[1]);

    read_executable_segments(pid, output);

    

    fclose(output);

    return EXIT_SUCCESS;

}

