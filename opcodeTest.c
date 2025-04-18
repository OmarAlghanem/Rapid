#include <stdio.h>
#include <stdint.h>
#include "opcode_utils.h"

/*–– Example functions ––*/
int sum(int a, int b) {
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


int main(void) {
    /* automatically prints size + opcodes of sum */
    PRINT_OPCODES(sum);
    printf("sum(1,2) = %d\n\n", sum(1,2));
    printf("\n");
    /* same for mul */
    PRINT_OPCODES(mul);
    printf("mul(3,4) = %d\n", mul(3,4));
    printf("\n");

    PRINT_OPCODES(test);
    test();

    return 0;
}
