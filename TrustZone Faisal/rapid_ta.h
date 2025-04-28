/*-----------------------------------------------------------------------
 *  rapid_ta.h
 *
 *  Shared interface between normal-world client and secure-world TA.
 *---------------------------------------------------------------------*/
 #ifndef RAPID_TA_H
 #define RAPID_TA_H
 
 #include <tee_api_types.h>
 #include <stdint.h>
 
 /* 128-bit UUID — keep fixed once deployed */
 #define RAPID_TA_UUID \
     { 0x71f6ac14, 0x54d3, 0x11ee, \
       { 0x9e, 0x8e, 0x02, 0x42, 0xac, 0x13, 0x00, 0x04 } }
 
 /* Command IDs */
 enum rapid_cmd {
     CMD_HASH_RESET = 0,      /* Start a new hash chain              */
     CMD_HASH_UPDATE,         /* Extend chain with caller-supplied bytes */
     CMD_HASH_GET_STATE       /* Read current 32-byte digest         */
 };
 
 #endif /* RAPID_TA_H */
 