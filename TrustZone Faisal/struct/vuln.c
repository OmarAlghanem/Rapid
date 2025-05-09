// vuln.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct VulnStruct {
    char buffer[64];
    void (*func_ptr)(char*);
};

void vuln(void) {
    printf("WEOWOWOEWOEWOO\n");
}

void greet(char *name) {
    printf("Hello, %s\n", name);
}

void foo(char *arg) {
    struct VulnStruct local_struct;
    local_struct.func_ptr = greet;           // initialize pointer
    strcpy(local_struct.buffer, arg);        // overflow point
    local_struct.func_ptr(local_struct.buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <payload>\n", argv[0]);
        return 1;
    }
    foo(argv[1]);
    return 0;
}
