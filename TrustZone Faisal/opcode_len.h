#ifndef OPCODE_LEN_H
#define OPCODE_LEN_H

#include <stddef.h>

/*-------------------------------------------------------------
 * END_FUNCTION(func)
 *   Place immediately after a function body to emit a symbol
 *   named  func_end:   The linker then knows the address
 *   just past the last instruction.
 *-----------------------------------------------------------*/
#define END_FUNCTION(func) \
    asm (".global " #func "_end\n" #func "_end:")

/*-------------------------------------------------------------
 * GET_FUNCTION_LENGTH(func)
 *   Computes  &func_end - &func  at run-time and returns
 *   it as a size_t (byte count).
 *-----------------------------------------------------------*/
#define GET_FUNCTION_LENGTH(func)                     \
    ({ extern char func##_end;                        \
       (size_t)((char*)&func##_end - (char*)(func)); })

#endif /* OPCODE_LEN_H */

