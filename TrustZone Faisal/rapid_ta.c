/*-----------------------------------------------------------------------
 *  rapid_ta.c
 *
 *  Trusted-Application: incremental SHA-256 hash-chain using only
 *  the GlobalPlatform TEE Internal Core API (no mbedTLS).
 *---------------------------------------------------------------------*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "rapid_ta.h"

/* Persistent state (secure world only) */
static uint8_t chain_state[32];
static bool    chain_init = false;

/* Helper: SHA256( A || B ) → dst (32 bytes) */
static void sha256_concat(const void *a, size_t a_len,
                          const void *b, size_t b_len,
                          void       *dst)
{
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    if (TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0))
        TEE_Panic(0);

    if (a_len) TEE_DigestUpdate(op, a, a_len);
    if (b_len) TEE_DigestUpdate(op, b, b_len);

    uint32_t out_len = 32;
    TEE_DigestDoFinal(op, NULL, 0, dst, &out_len);
    TEE_FreeOperation(op);
}

/* Mandatory GP entry points (boiler-plate) */
TEE_Result TA_CreateEntryPoint(void)                       { return TEE_SUCCESS; }
void       TA_DestroyEntryPoint(void)                      {}
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused ptype,
                                    const TEE_Param __unused params[4],
                                    void **sess_ctx)
{ (void)ptype; (void)sess_ctx; return TEE_SUCCESS; }
void TA_CloseSessionEntryPoint(void *sess_ctx)             { (void)sess_ctx; }

/* Dispatcher */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;

    /* ---------- Reset chain ---------- */
    if (cmd_id == CMD_HASH_RESET) {
        if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE))
            return TEE_ERROR_BAD_PARAMETERS;

        TEE_MemFill(chain_state, 0, sizeof(chain_state));
        chain_init = false;
        return TEE_SUCCESS;
    }

    /* ---------- Update chain ---------- */
    if (cmd_id == CMD_HASH_UPDATE) {
        if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                           TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE))
            return TEE_ERROR_BAD_PARAMETERS;

        const void *buf = params[0].memref.buffer;
        size_t      len = params[0].memref.size;

        if (chain_init)
            sha256_concat(chain_state, 32, buf, len, chain_state);
        else
            sha256_concat(NULL, 0, buf, len, chain_state);

        chain_init = true;

        if (params[1].memref.size >= 32)
            TEE_MemMove(params[1].memref.buffer, chain_state, 32);

        return TEE_SUCCESS;
    }

    /* ---------- Get current digest ---------- */
    if (cmd_id == CMD_HASH_GET_STATE) {
        if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE,
                                           TEE_PARAM_TYPE_NONE))
            return TEE_ERROR_BAD_PARAMETERS;

        if (params[0].memref.size < 32)
            return TEE_ERROR_SHORT_BUFFER;

        TEE_MemMove(params[0].memref.buffer, chain_state, 32);
        return TEE_SUCCESS;
    }

    /* Unknown command */
    return TEE_ERROR_NOT_SUPPORTED;
}
