#include <stdio.h>
#include <stdlib.h>
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/settings.h>
#include <wolftpm/tpm2_wrap.h>
#include "tpm_operations.h"

#if CALLBACK_POINTER != 0
    #include <wolftpm/tpm_io.h>
    #include <wolftpm/tpm2.h>
#endif


int TPM_GetRandom(void* userCtx, byte* buffer, word32 len)
{
    int rc;
    WOLFTPM2_DEV dev;

    // Initialize the TPM
    rc = wolfTPM2_Init(&dev, CALLBACK_POINTER, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        #if DEBUG_MESSAGES == 1
            printf("\nwolfTPM2_Init failed\n");
        #endif
        goto exit;
    }

    // Get random buffer
    rc = wolfTPM2_GetRandom(&dev, buffer, len);
    if (rc != TPM_RC_SUCCESS) {
        #if DEBUG_MESSAGES == 1
            printf("\nwolfTPM2_GetRandom failed\n");
        #endif
        goto exit;
    }

exit:

    #if DEBUG_MESSAGES == 1
        if (rc != 0) {
            printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
        }
    #endif

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_StoreNV(void* userCtx, byte* data, word32 dataSize, word32 indexOffset)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER;
    int paramEncAlg = TPM_ALG_CFB;
    // int offset = 0;
    word32 nvIndex = TPM_DEFAULT_NV_INDEX + indexOffset;
    byte* auth = (byte*)nvAuthPassword;
    word32 authSz = (word32)sizeof(nvAuthPassword) - 1;

    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));

    rc = wolfTPM2_Init(&dev, CALLBACK_POINTER, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        #if DEBUG_MESSAGES == 1
            printf("\nwolfTPM2_Init failed\n");
        #endif
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
                TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        #if DEBUG_MESSAGES == 1
            printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
                (word32)tpmSession.handle.hndl);
        #endif
        /* Set TPM session attributes for parameter encryption */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Prepare NV_AUTHWRITE and NV_AUTHREAD attributes necessary for password */
    parent.hndl = authHandle;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != 0) goto exit;

    // Create index using
    rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
            nvAttributes, TPM_MAX_NV_INDEX_SIZE, auth, authSz);
    if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;

    #if DEBUG_MESSAGES == 1
        printf("Storing key at TPM NV index 0x%x with password protection\n\n", nvIndex);
    #endif

    // Store data at NV index
    // Separate data in two buffers so that it fits in MAX_NV_BUFFER_SIZE (TPM limitation)
    if(dataSize > MAX_NV_BUFFER_SIZE)
    {
        int i;
        uint8_t buffer1[MAX_NV_BUFFER_SIZE];
        uint32_t buffer1Size;
        uint8_t buffer2[MAX_NV_BUFFER_SIZE];
        uint32_t buffer2Size;

        for(i = 0; i < MAX_NV_BUFFER_SIZE; ++i)
            buffer1[i] = data[i];
        buffer1Size = MAX_NV_BUFFER_SIZE;

        for(; i < dataSize; ++i)
            buffer2[i - MAX_NV_BUFFER_SIZE] = data[i];
        buffer2Size = i - buffer1Size;

        // Store each buffer one after another
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, buffer1, buffer1Size, 0);
        if (rc != 0) goto exit;

        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, buffer2, buffer2Size, MAX_NV_BUFFER_SIZE);
        if (rc != 0) goto exit;
    }
    else
    {
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, data, dataSize, 0);
        if (rc != 0) goto exit;
    }

    #if DEBUG_MESSAGES == 1
        printf("Stored key to TPM NV memory\n");
    #endif

exit:

    #if DEBUG_MESSAGES == 1
        if (rc != 0) {
            printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
        }
    #endif

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

int TPM_ReadNV(void* userCtx, byte* data, word32* dataSize, word32 indexOffset)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPM2B_AUTH auth;
    int paramEncAlg = TPM_ALG_CFB;
    // int offset = 0;
    word32 nvIndex = TPM_DEFAULT_NV_INDEX + indexOffset;

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&auth, 0, sizeof(auth));

    rc = wolfTPM2_Init(&dev, CALLBACK_POINTER, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        #if DEBUG_MESSAGES == 1
            printf("\nwolfTPM2_Init failed\n");
        #endif
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
                TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        #if DEBUG_MESSAGES == 1
            printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
                (word32)tpmSession.handle.hndl);
        #endif
        /* Set TPM session attributes for parameter encryption */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    auth.size = sizeof(nvAuthPassword) - 1;
    XMEMCPY(auth.buffer, nvAuthPassword, auth.size);

    /* Prepare auth for NV Index */
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = nvIndex;
    nv.handle.auth.size = auth.size;
    XMEMCPY(nv.handle.auth.buffer, auth.buffer, auth.size);

    // Read data at NV index
    // Separate reading in two buffers so that it does not exceed MAX_NV_BUFFER_SIZE (TPM limitation)
    if(*dataSize > MAX_NV_BUFFER_SIZE)
    {
        int i;
        uint8_t buffer1[MAX_NV_BUFFER_SIZE];
        uint32_t buffer1Size = MAX_NV_BUFFER_SIZE;
        uint8_t buffer2[MAX_NV_BUFFER_SIZE];
        uint32_t buffer2Size = MAX_NV_BUFFER_SIZE;

        // Read each buffer one after another
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, buffer1, &buffer1Size, 0);
        if (rc != 0) goto exit;

        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, buffer2, &buffer2Size, MAX_NV_BUFFER_SIZE);
        if (rc != 0) goto exit;

        *dataSize = 0;
        for(i = 0; i < buffer1Size; ++i)
            data[(*dataSize)++] = buffer1[i];
        for(i = 0; i < buffer2Size; ++i)
            data[(*dataSize)++] = buffer2[i];
    }
    else
    {
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, data, dataSize, 0);
        if (rc != 0) goto exit;
    }

    #if DEBUG_MESSAGES == 1
        printf("Read key from TPM NV memory\n");
    #endif
    
exit:

    #if DEBUG_MESSAGES == 1
        if (rc != 0) {
            printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
        }
    #endif

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

int TPM_DeleteNV(void* userCtx, word32 indexOffset)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE parent;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER;
    word32 nvIndex = TPM_DEFAULT_NV_INDEX + indexOffset;

    // Initialize the TPM
    rc = wolfTPM2_Init(&dev, CALLBACK_POINTER, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        #if DEBUG_MESSAGES == 1
            printf("\nwolfTPM2_Init failed\n");
        #endif
        goto exit;
    }

    // Delete NV index
    /* auth 0 is owner, no auth */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);
    wolfTPM2_UnsetAuth(&dev, 1);

    parent.hndl = authHandle;
    rc = wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
    if (rc != 0) goto exit;

    #if DEBUG_MESSAGES == 1
        printf("NV index 0x%x deleted!\n", nvIndex);
    #endif

exit:

    #if DEBUG_MESSAGES == 1
        if (rc != 0) {
            printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
        }
    #endif

    wolfTPM2_Cleanup(&dev);
    return rc;
}
