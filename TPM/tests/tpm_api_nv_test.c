#include <stdio.h>
#include "../tpm_api.h"

#define NV_INDEX 0

int main()
{
    int rc, i;
    uint8_t randomBuffer[256];
    uint32_t randomBufferLen = 256;

    uint8_t auxBuffer[256] = {0};
    uint32_t auxBufferLen = 256;

    rc = GetRandom(randomBuffer, randomBufferLen);
    if(rc != 0) // Error
    {
        printf("Error with GetRandom\n");
        return 1;
    }

    printf("randomBuffer:\n");
    for(i = 0; i < randomBufferLen; ++i)
    {
        printf("%d ", randomBuffer[i]);
    }
    printf("\n\n");

    rc = DeleteNV(NV_INDEX);
    if(rc != 0) // Error
    {
        printf("Error with DeleteNV\n");
        // return 4;
    }

    rc = StoreNV(randomBuffer, randomBufferLen, NV_INDEX);
    if(rc != 0) // Error
    {
        printf("Error with StoreNV\n");
        return 2;
    }

    rc = ReadNV(auxBuffer, &auxBufferLen, NV_INDEX);
    if(rc != 0) // Error
    {
        printf("Error with ReadNV\n");
        return 3;
    }

    printf("Read Buffer:\n");
    for(i = 0; i < auxBufferLen; ++i)
    {
        printf("%d ", auxBuffer[i]);
    }
    printf("\n\n");

    return 0;
}