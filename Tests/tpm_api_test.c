#include <stdio.h>
#include "tpm_api.h"

#define KEYFILE "keyblob.bin"

int main()
{
    int rc, i;
    uint8_t keyPubBuffer[512];
    uint32_t keyPubBufferSize = 512;
    uint8_t keyPrivBuffer[512];
    uint32_t keyPrivBufferSize = 512;
    uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    // uint8_t msg[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a};
    uint32_t msgSize = sizeof(msg);
    uint8_t msgOutput[100];
    // uint32_t msgOutputSize = 100;
    uint8_t output[400];
    uint32_t outputSize = 400;

    uint8_t randomBuffer[20];
    uint32_t randomBufferLen = 20;

    rc = GetRandom(randomBuffer, randomBufferLen);
    if(rc != 0) // Error
    {
        printf("Error with GetRandom\n");
    }

    printf("randomBuffer:\n");
    for(i = 0; i < randomBufferLen; ++i)
    {
        printf("%d ", randomBuffer[i]);
    }
    printf("\n\n");

    printf("msg:\n");
    for(i = 0; i < msgSize; ++i)
    {
        printf("%c", msg[i]);
    }
    printf("\n\n");

    // rc = GenerateRsaKey(KEYFILE, keyPubBuffer, &keyPubBufferSize);
    rc = GenerateRsaKey2(KEYFILE, keyPubBuffer, &keyPubBufferSize, keyPrivBuffer, &keyPrivBufferSize);
    if(rc != 0)
    {
        printf("Error with GenerateRsaKey\n");
    }

    printf("keyPubBufferSize = %d\n", keyPubBufferSize);
    printf("keyPubBuffer:\n");
    for(i = 0; i < keyPubBufferSize; ++i)
    {
        printf("%x ", keyPubBuffer[i]);
    }
    printf("\n\n");

    printf("keyPrivBufferSize = %d\n", keyPrivBufferSize);
    printf("keyPrivBuffer:\n");
    for(i = 0; i < keyPrivBufferSize; ++i)
    {
        printf("%x ", keyPrivBuffer[i]);
    }
    printf("\n\n");

    rc = RsaEncrypt(keyPubBuffer, keyPubBufferSize, msg, msgSize, &output, &outputSize);
    if(rc != 0)
    {
        printf("Error with RsaEncrypt\n");
    }

    printf("outputSize = %d\n", outputSize);
    printf("output:\n");
    for(i = 0; i < outputSize; ++i)
    {
        printf("%x ", output[i]);
    }
    printf("\n\n");

    // rc = RsaDecrypt(KEYFILE, output, outputSize, msgOutput, &outputSize);
    rc = RsaDecrypt2(keyPubBuffer, keyPubBufferSize, keyPrivBuffer, keyPrivBufferSize, output, outputSize, msgOutput, &outputSize);
    if(rc != 0)
    {
        printf("Error with RsaDecrypt\n");
    }

    printf("outputSize = %d\n", outputSize);
    printf("decrypted msg:\n");
    for(i = 0; i < outputSize; ++i)
    {
        printf("%c", msgOutput[i]);
    }
    printf("\n\n");

    return 0;
}