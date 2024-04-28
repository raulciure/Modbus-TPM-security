#include <stdio.h>
#include "tpm_api.h"
#include "tpm_operations.h"

#define SUCCESS_CODE 0
#define FAIL_CODE 1

int GenerateRsaKey(const char* keyOutputFile, uint8_t* keyPubBuffer, uint32_t* keyPubBufferSize)
{
    int rc;

    rc = TPM_Keygen(NULL, keyOutputFile, keyPubBuffer, keyPubBufferSize);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int GenerateRsaKey2(const char* keyOutputFile, uint8_t* keyPubBuffer, uint32_t* keyPubBufferSize, uint8_t* keyPrivBuffer, uint32_t* keyPrivBufferSize)
{
    int rc;

    rc = TPM_Keygen2(NULL, keyOutputFile, keyPubBuffer, keyPubBufferSize, keyPrivBuffer, keyPrivBufferSize);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int LoadRsaKey(const char* keyLoadFile)
{
    int rc;

    rc = TPM_Keyload(NULL, "");
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int ImportRsaPublicKey()
{
    int rc;
    
    rc = TPM_Keyimport(NULL, "");
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int RsaEncrypt(const uint8_t* keyBuffer, uint32_t keyBufferSize, const uint8_t* msg, int msgSize, uint8_t* out, int* outSize)
{
    int rc;
    //const uint8_t *localMsg = msg;

    rc = TPM_RsaEncrypt(NULL, keyBuffer, keyBufferSize, msg, msgSize, out, outSize);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int RsaDecrypt(const char* keyFile, const uint8_t* in, int inSize, uint8_t* msg, int* msgSize)
{
    int rc;

    rc = TPM_RsaDecrypt(NULL, keyFile, in, inSize, msg, msgSize);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int RsaDecrypt2(const uint8_t* keyPubBuffer, uint32_t keyPubBufferSize, const uint8_t* keyPrivBuffer, uint32_t keyPrivBufferSize, const uint8_t* in, int inSize, uint8_t* msg, int* msgSize)
{
    int rc;

    rc = TPM_RsaDecrypt2(NULL, keyPubBuffer, keyPrivBufferSize, keyPrivBuffer, keyPrivBufferSize, in, inSize, msg, msgSize);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}

int GetRandom(uint8_t* buffer, uint32_t len)
{
    int rc;

    rc = TPM_GetRandom(NULL, buffer, len);
    if(rc == SUCCESS_CODE) return SUCCESS_CODE;
    return FAIL_CODE;
}