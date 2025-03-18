#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address>\n", argv[0]);
        return 1;
    }

    pid_t target = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 0);

    // Attach to the target process.
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        return 1;
    }
    waitpid(target, NULL, 0);

    // Read original data.
    long original = ptrace(PTRACE_PEEKDATA, target, (void*)addr, NULL);
    printf("Original data at 0x%lx: 0x%lx\n", addr, original);

    // For simulation, XOR the original data with a fixed value.
    long new_data = original ^ 0xDEADBEEF;
    if (ptrace(PTRACE_POKEDATA, target, (void*)addr, (void*)new_data) == -1) {
        perror("ptrace(PTRACE_POKEDATA)");
        return 1;
    }
    printf("Injected new data 0x%lx at 0x%lx\n", new_data, addr);

    // Detach from the process.
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
