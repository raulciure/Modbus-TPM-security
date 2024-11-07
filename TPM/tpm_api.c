#include <stdio.h>
#include <stdlib.h>
#include "tpm_api.h"
#include "tpm_operations.h"

#define SUCCESS_CODE 0
#define FAIL_CODE 1


int GetRandom(uint8_t* buffer, uint32_t len)
{
    int rc;

    rc = TPM_GetRandom(NULL, buffer, len);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int StoreNV(uint8_t* data, uint32_t dataSize, uint32_t nvIndexOffset)
{
    int rc;
    
    rc = TPM_StoreNV(NULL, data, dataSize, nvIndexOffset);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int ReadNV(uint8_t* data, uint32_t* dataSize, uint32_t nvIndexOffset)
{
    int rc;

    rc = TPM_ReadNV(NULL, data, dataSize, nvIndexOffset);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int DeleteNV(uint32_t nvIndexOffset)
{
    int rc;

    rc = TPM_DeleteNV(NULL, nvIndexOffset);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}