#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // for sleep()

// Command functions
void config_servos()  { printf("config_servos()\n"); }
void spin_oneeighty() { printf("spin_oneeighty()\n"); }
void spin_ninety()    { printf("spin_ninety()\n"); }
void rest()           { printf("rest()\n"); }

// Hidden function not reachable via switch
// Now prints "spinning..." each second
void spin_forever() {
    while (1) {
        printf("spinning...\n");
        fflush(stdout);
        sleep(1);
    }
}

void force_shutdown() {
    printf("Force shutdown...\n");
    exit(0);
}

void idle()           { /* no-op */ }

// Struct: buffer, then function pointer, then choice
struct Cmd {
    char buf[64];
    void (*func_ptr)(void);
    int  choice;
};

int main(void) {
    struct Cmd cmd;
    char *input;

    while (1) {
        // reset fields
        cmd.choice    = 1;      // default case: config_servos()
        cmd.func_ptr = idle;    // default pointer: do nothing

        // prompt and read (unsafe)
        printf("Enter choice (1-5) or overflow payload: ");
        fflush(stdout);
        input = gets(cmd.buf);
        if (input == NULL) {
            printf("EOF detected, exiting\n");
            break;
        }

        // numeric input sets choice 1-5
        if (strlen(cmd.buf) == 1 && cmd.buf[0] >= '1' && cmd.buf[0] <= '5') {
            cmd.choice = cmd.buf[0] - '0';
        }

        // dispatch selected command
        switch (cmd.choice) {
            case 1: config_servos();   break;
            case 2: spin_oneeighty();  break;
            case 3: spin_ninety();     break;
            case 4: rest();            break;
            case 5: printf("Exiting...\n"); exit(0);
            default: fprintf(stderr, "Invalid choice: %d\n", cmd.choice); exit(1);
        }

        // always call the function pointer: overwritten via overflow
        cmd.func_ptr();
    }

    return 0;
}
