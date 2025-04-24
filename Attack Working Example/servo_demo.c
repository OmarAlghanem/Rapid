#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // for sleep()
#include "opcode_utils.h"

// Command functions

#define CONFIG_SERVOS_LENGTH  GET_FUNCTION_LENGTH(config_servos) //Initialize function length
void config_servos()    {
    Hash_chain_reset();
    Hash_chain(config_servos, CONFIG_SERVOS_LENGTH);
    printf("config_servos()\n"); 
    }
END_FUNCTION(config_servos) //Indicator for function length calculation


#define SPIN_ONEEIGHTY_LENGTH GET_FUNCTION_LENGTH(spin_oneeighty)
void spin_oneeighty()   { 
    Hash_chain(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH);
    printf("spin_oneeighty()\n"); 
}
END_FUNCTION(spin_oneeighty)


#define SPIN_NINETY_LENGTH GET_FUNCTION_LENGTH(spin_ninety)
void spin_ninety()  {
    Hash_chain(spin_ninety,SPIN_NINETY_LENGTH);
    printf("spin_ninety()\n"); 
}
END_FUNCTION(spin_ninety)


#define REST_LENGTH GET_FUNCTION_LENGTH(rest)
void rest() {
    Hash_chain(rest,REST_LENGTH);
    printf("rest()\n"); 
}
END_FUNCTION(rest)


// Hidden function not reachable via switch
// Now prints "spinning..." each second
void spin_forever() {
    //PRINT_OPCODES(spin_forever);
    while (1) {
        printf("spinning...\n");
        fflush(stdout);
        sleep(1);
    }
}
END_FUNCTION(spin_forever)


void force_shutdown() {
    //PRINT_OPCODES(force_shutdown);
    printf("Force shutdown...\n");
    exit(0);
}
END_FUNCTION(force_shutdown) 


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
            case 1:
                PRINT_OPCODES(config_servos);
                config_servos();
                printf("config_servos hash: %s\n", hash_function(config_servos, CONFIG_SERVOS_LENGTH));
                printf("Current hash chain: %s\n", get_hash_chain_current());
               break;
            case 2: 
                PRINT_OPCODES(spin_oneeighty);
                spin_oneeighty();
                printf("spin_oneeighty hash: %s\n", hash_function(spin_oneeighty, SPIN_ONEEIGHTY_LENGTH));
                printf("Current hash chain: %s\n", get_hash_chain_current());
                break;
            case 3:
                PRINT_OPCODES(spin_ninety);
                spin_ninety();
                printf("spin_ninety hash: %s\n", hash_function(config_servos, SPIN_NINETY_LENGTH));
                printf("Current hash chain: %s\n", get_hash_chain_current());
                break;
            case 4: 
                PRINT_OPCODES(rest);
                rest();
                printf("rest hash: %s\n", hash_function(rest, REST_LENGTH));
                printf("Current hash chain: %s\n", get_hash_chain_current());
                Hash_chain_reset();
                printf("Current hash chain after reset: %s\n", get_hash_chain_current());
                break;
            case 5: 
                printf("Exiting...\n");
                exit(0);
            default: 
                fprintf(stderr, "Invalid choice: %d\n", cmd.choice);
                exit(1);
        }

        // always call the function pointer: overwritten via overflow
        cmd.func_ptr();
    }

    return 0;
}
