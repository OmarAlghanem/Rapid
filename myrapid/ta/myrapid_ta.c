#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "myrapid_ta.h"

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("TA CreateEntryPoint has been called");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("TA DestroyEntryPoint has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4],
    void **session_context)
{
    (void)&param_types;
    (void)&params;
    (void)&session_context;

    IMSG("Hello! MyRapid TA Session Opened");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)&session_context;
    IMSG("Goodbye! MyRapid TA Session Closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t param_types, TEE_Param params[4])
{
    (void)&session_context;
    (void)&param_types;
    (void)&params;

    switch (cmd_id) {
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

