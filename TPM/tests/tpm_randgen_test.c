#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolftpm/tpm2_wrap.h>

int main(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    unsigned char rnd[32];

    memset(&dev, 0, sizeof(dev));
    memset(rnd, 0, sizeof(rnd));

    rc = wolfTPM2_Init(&dev, NULL, NULL);
    printf("wolfTPM2_Init rc = 0x%x\n", rc);
    if (rc != 0)
        return 1;

    rc = wolfTPM2_GetRandom(&dev, rnd, (int)sizeof(rnd));
    printf("wolfTPM2_GetRandom rc = 0x%x\n", rc);
    if (rc == 0) {
        size_t i;
        for (i = 0; i < sizeof(rnd); i++)
            printf("%02x", rnd[i]);
        printf("\n");
    }

    rc = wolfTPM2_Cleanup(&dev);
    printf("wolfTPM2_Cleanup rc = 0x%x\n", rc);

    return 0;
}