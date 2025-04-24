#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>    // add this for _exit
#include <unistd.h>    // for read()
#include "opcode_utils.h"

extern char *gets(char *);  // <-- add this

/*–– Example functions ––*/
int sum(int a, int b) {
    char buf[32];
    // print the exact address of buf[]
    printf("buf starts at %p\nEnter payload:\n> ", (void*)buf);
    // unsafe overflow read
    read(0, buf, 256);
    return a + b;
}
END_FUNCTION(sum)

int mul(int a, int b) {
    return a * b;
}
END_FUNCTION(mul)


void test() {
    for(int i = 0; i < 5; i++) {
        printf("hello %d\n", i);
    }
}
END_FUNCTION(test)

__attribute__((optimize("O0")))
void exploit() {
    puts("CODE REUSE OCCURED!");
    _Exit(0);           // immediate terminate—no stray ret
}
END_FUNCTION(exploit)

int main(void) {
    /*
    /* automatically prints size + opcodes of sum */
    //PRINT_OPCODES(sum);
    //printf("sum(1,2) = %d\n\n", sum(1,2));
    //printf("\n");
    /* same for mul */
    //PRINT_OPCODES(mul);
    //printf("mul(3,4) = %d\n", mul(3,4));
    //printf("\n");

    //PRINT_OPCODES(test);
    //test();
    
    //PRINT_OPCODES(sum);
    //PRINT_OPCODES(exploit);
    sum(0,0);
    return 0;
}

