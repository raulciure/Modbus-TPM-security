#include <stdio.h>
#include <stdlib.h>
#include "wolftpm/tpm2_wrap.h"
#include "wolftpm/tpm2.h"
#include "tpm_io.h"
#include "tpm_test.h"
#include "tpm_test_keys.h"
#include "tpm_operations.h"


int TPM_Keygen(void* userCtx, const char* outputFile, byte* keyPubBuffer, word32* keyPubBufferSize)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEY aesKey; /* Symmetric key */
    WOLFTPM2_KEYBLOB newKeyBlob; /* newKey as WOLFTPM2_KEYBLOB */
    WOLFTPM2_KEYBLOB primaryBlob; /* Primary key as WOLFTPM2_KEYBLOB */
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* default, see usage() for options */
    TPM_ALG_ID algSym = TPM_ALG_CTR; /* default Symmetric Cipher, see usage */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB; /* AES-CFB cypher for parameter encryption (other option: TPM_ALG_XOR) */
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    int pemFiles = 0;
    int keyBits = 256;
    // char *outputFile = "keyblob.bin";
    const char *srkPubFile = "srk.pub";
    const char *pubFilename = NULL;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    const char *nameFile = "ak.name"; /* Name Digest for attestation purposes */
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    const char *pemFilename = NULL;
    #endif
#endif
    size_t len = 0;
    char symMode[] = "aesctr";

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    XMEMSET(&newKeyBlob, 0, sizeof(newKeyBlob));
    XMEMSET(&primaryBlob, 0, sizeof(primaryBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    printf("TPM2.0 Key generation\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    if(alg == TPM_ALG_SYMCIPHER) {
        printf("\t\t %s mode, %d keybits\n", symMode, keyBits);
    }
    printf("\tTemplate: %s\n",  "Default");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    pubFilename = srkPubFile;
    primary = &storage;
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, primary, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("HMAC Session: Handle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the primary key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Create new key */
    if (alg == TPM_ALG_RSA) {
        printf("RSA template\n");
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    }
    else if (alg == TPM_ALG_ECC) {
        printf("ECC template\n");
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                    TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    }
    else if (alg == TPM_ALG_SYMCIPHER) {
        printf("Symmetric template\n");
        rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, keyBits,
                algSym, YES, YES);
    }
    else if (alg == TPM_ALG_KEYEDHASH) {
        printf("Keyed Hash template\n");
        rc = wolfTPM2_GetKeyTemplate_KeyedHash(&publicTemplate,
            TPM_ALG_SHA256, YES, NO);
        publicTemplate.objectAttributes |= TPMA_OBJECT_sensitiveDataOrigin;
    }
    else {
        rc = BAD_FUNC_ARG;
    }

    /* set session for authorization key */
    auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    if (rc != 0) goto exit;

    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));

    rc = wolfTPM2_CreateKey(&dev, &newKeyBlob, &primary->handle,
                            &publicTemplate, auth.buffer, auth.size);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    rc = wolfTPM2_LoadKey(&dev, &newKeyBlob, &primary->handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }

    printf("New key created and loaded (pub %d, priv %d bytes)\n",
        newKeyBlob.pub.size, newKeyBlob.priv.size);


    // Copy generated key to keyBuffer
    rc = TPM_KeyBlobPublicToBuffer(&newKeyBlob, keyPubBuffer, keyPubBufferSize);
    if (rc != TPM_RC_SUCCESS) goto exit;
    

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &newKeyBlob);
    /* Generate key artifacts needed for remote attestation */
    if (rc != TPM_RC_SUCCESS) goto exit;
#else
    if (alg == TPM_ALG_SYMCIPHER) {
        printf("The Public Part of a symmetric key contains only meta data\n");
    }
    printf("Key Public Blob %d\n", newKeyBlob.pub.size);
    TPM2_PrintBin((const byte*)&newKeyBlob.pub.publicArea, newKeyBlob.pub.size);
    printf("Key Private Blob %d\n", newKeyBlob.priv.size);
    TPM2_PrintBin(newKeyBlob.priv.buffer, newKeyBlob.priv.size);
#endif

    /* Save EK public key as PEM format file to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    if (pemFiles) {
        byte pem[MAX_RSA_KEY_BYTES];
        word32 pemSz;

        pemFilename = pemFileSrk;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_RsaKey_TpmToPemPub(&dev, primary, pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        if (rc != 0) goto exit;

        //pemFilename = pemFileKey;
        pemFilename = (const char*) outputFile;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_RsaKey_TpmToPemPub(&dev, (WOLFTPM2_KEY*)&newKeyBlob,
            pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);

    #if 0
        /* example for loading public pem to TPM */
        rc = wolfTPM2_RsaKey_PubPemToTpm(&dev, (WOLFTPM2_KEY*)&newKeyBlob, pem, pemSz);
        printf("wolfTPM2_RsaKey_PubPemToTpm rc=%d\n", rc);
        rc = 0;
    #endif
    }
#else
    (void)pemFiles;
    (void)pubFilename;
    printf("Unable to store EK pub as PEM file. Lack of file support\n");
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_Keygen2(void* userCtx, const char* outputFile, byte* keyPubBuffer, word32* keyPubBufferSize, byte* keyPrivBuffer, word32* keyPrivBufferSize)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEY aesKey; /* Symmetric key */
    WOLFTPM2_KEYBLOB newKeyBlob; /* newKey as WOLFTPM2_KEYBLOB */
    WOLFTPM2_KEYBLOB primaryBlob; /* Primary key as WOLFTPM2_KEYBLOB */
    TPMT_PUBLIC publicTemplate;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA; /* default, see usage() for options */
    TPM_ALG_ID algSym = TPM_ALG_CTR; /* default Symmetric Cipher, see usage */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB; /* AES-CFB cypher for parameter encryption (other option: TPM_ALG_XOR) */
    WOLFTPM2_SESSION tpmSession;
    TPM2B_AUTH auth;
    int pemFiles = 0;
    int keyBits = 256;
    // char *outputFile = "keyblob.bin";
    const char *srkPubFile = "srk.pub";
    const char *pubFilename = NULL;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    const char *nameFile = "ak.name"; /* Name Digest for attestation purposes */
    #if !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    const char *pemFilename = NULL;
    #endif
#endif
    size_t len = 0;
    char symMode[] = "aesctr";

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&aesKey, 0, sizeof(aesKey));
    XMEMSET(&newKeyBlob, 0, sizeof(newKeyBlob));
    XMEMSET(&primaryBlob, 0, sizeof(primaryBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&auth, 0, sizeof(auth));

    printf("TPM2.0 Key generation\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    if(alg == TPM_ALG_SYMCIPHER) {
        printf("\t\t %s mode, %d keybits\n", symMode, keyBits);
    }
    printf("\tTemplate: %s\n",  "Default");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    pubFilename = srkPubFile;
    primary = &storage;
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, primary, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("HMAC Session: Handle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the primary key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Create new key */
    if (alg == TPM_ALG_RSA) {
        printf("RSA template\n");
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    }
    else if (alg == TPM_ALG_ECC) {
        printf("ECC template\n");
        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
                    TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
                    TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
                    TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    }
    else if (alg == TPM_ALG_SYMCIPHER) {
        printf("Symmetric template\n");
        rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, keyBits,
                algSym, YES, YES);
    }
    else if (alg == TPM_ALG_KEYEDHASH) {
        printf("Keyed Hash template\n");
        rc = wolfTPM2_GetKeyTemplate_KeyedHash(&publicTemplate,
            TPM_ALG_SHA256, YES, NO);
        publicTemplate.objectAttributes |= TPMA_OBJECT_sensitiveDataOrigin;
    }
    else {
        rc = BAD_FUNC_ARG;
    }

    /* set session for authorization key */
    auth.size = (int)sizeof(gKeyAuth)-1;
    XMEMCPY(auth.buffer, gKeyAuth, auth.size);
    if (rc != 0) goto exit;

    printf("Creating new %s key...\n", TPM2_GetAlgName(alg));

    rc = wolfTPM2_CreateKey(&dev, &newKeyBlob, &primary->handle,
                            &publicTemplate, auth.buffer, auth.size);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_CreateKey failed\n");
        goto exit;
    }
    rc = wolfTPM2_LoadKey(&dev, &newKeyBlob, &primary->handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }

    printf("New key created and loaded (pub %d, priv %d bytes)\n",
        newKeyBlob.pub.size, newKeyBlob.priv.size);


    // Copy generated key to buffers
    rc = TPM_KeyBlobToBuffer(&newKeyBlob, keyPubBuffer, keyPubBufferSize, keyPrivBuffer, keyPrivBufferSize);
    if (rc != TPM_RC_SUCCESS) goto exit;
    

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &newKeyBlob);
    /* Generate key artifacts needed for remote attestation */
    if (rc != TPM_RC_SUCCESS) goto exit;
#else
    if (alg == TPM_ALG_SYMCIPHER) {
        printf("The Public Part of a symmetric key contains only meta data\n");
    }
    printf("Key Public Blob %d\n", newKeyBlob.pub.size);
    TPM2_PrintBin((const byte*)&newKeyBlob.pub.publicArea, newKeyBlob.pub.size);
    printf("Key Private Blob %d\n", newKeyBlob.priv.size);
    TPM2_PrintBin(newKeyBlob.priv.buffer, newKeyBlob.priv.size);
#endif

    /* Save EK public key as PEM format file to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT) && !defined(NO_RSA)
    if (pemFiles) {
        byte pem[MAX_RSA_KEY_BYTES];
        word32 pemSz;

        pemFilename = pemFileSrk;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_RsaKey_TpmToPemPub(&dev, primary, pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        if (rc != 0) goto exit;

        //pemFilename = pemFileKey;
        pemFilename = (const char*) outputFile;
        pemSz = (word32)sizeof(pem);
        rc = wolfTPM2_RsaKey_TpmToPemPub(&dev, (WOLFTPM2_KEY*)&newKeyBlob,
            pem, &pemSz);
        if (rc == 0) {
            rc = writeBin(pemFilename, pem, pemSz);
        }
        wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);

    #if 0
        /* example for loading public pem to TPM */
        rc = wolfTPM2_RsaKey_PubPemToTpm(&dev, (WOLFTPM2_KEY*)&newKeyBlob, pem, pemSz);
        printf("wolfTPM2_RsaKey_PubPemToTpm rc=%d\n", rc);
        rc = 0;
    #endif
    }
#else
    (void)pemFiles;
    (void)pubFilename;
    printf("Unable to store EK pub as PEM file. Lack of file support\n");
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_Keyload(void* userCtx, const char* inFile)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEYBLOB newKey;
    WOLFTPM2_KEY persistKey;
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    WOLFTPM2_SESSION tpmSession;
    const char* inputFile = "keyblob.bin";
    int persistent = 0;
    int endorseKey = 0;

    // set inputFile from function argument
    // if inputFile is provided
    if(XSTRCMP("", inFile) != 0) inputFile = inFile;

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&persistKey, 0, sizeof(persistKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Key load\n");
    printf("\tKey Blob: %s\n", inputFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;
    primary = &storage;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter
         * encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Load encrypted key from the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = readKeyBlob(inputFile, &newKey);
    if (rc != 0) goto exit;
#else
    /* TODO: Option to load hex blob */
    printf("Loading blob from disk not supported. Enable wolfcrypt support.\n");
    goto exit;
#endif

    if (newKey.priv.size == 0) {
        rc = wolfTPM2_LoadPublicKey(&dev, (WOLFTPM2_KEY*)&newKey, &newKey.pub);
    }
    else {
        rc = wolfTPM2_LoadKey(&dev, &newKey, &primary->handle);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("Load Key failed!\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n", (word32)newKey.handle.hndl);

    /* Make the TPM key persistent, so it remains loaded after example exit */
    if (persistent) {
        /* Prepare key in the format expected by the wolfTPM wrapper */
        persistKey.handle.hndl = newKey.handle.hndl;
        XMEMCPY((BYTE*)&persistKey.pub, (BYTE*)&newKey.pub, sizeof(persistKey.pub));
        
        /* Delete previous key */
        /*rc = wolfTPM2_NVDeleteKey(&dev, TPM_RH_OWNER, &persistKey);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVDeleteKey failed\n");
            goto exit;
        }*/

        /* Make key persistent */
        rc = wolfTPM2_NVStoreKey(&dev, TPM_RH_OWNER, &persistKey, TPM2_DEMO_PERSISTENT_KEY_HANDLE);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_NVStoreKey failed\n");
            goto exit;
        }
        printf("Key was made persistent at 0x%X\n", persistKey.handle.hndl);
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    /* newKey.handle is already flushed by wolfTPM2_NVStoreKey */
    if (!persistent) {
        wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    }
    /* EK policy is destroyed after use, flush parameter encryption session */
    if (!endorseKey) {
        wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_Keyimport(void* userCtx, const char* importFile)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEYBLOB impKey;
    TPMI_ALG_PUBLIC alg = TPM_ALG_RSA, srkAlg; /* TPM_ALG_ECC */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    WOLFTPM2_SESSION tpmSession;
    const char* outputFile = "keyblob.bin";
    const char* impFile = NULL; /* File name of imported key */
    int encType = ENCODING_TYPE_ASN1;
    const char* password = NULL;
    TPMA_OBJECT attributes;
    byte* buf = NULL;
    size_t bufSz = 0;
    int isPublicKey = 1;
    const char* impFileEnd;

    // set import file from function argument
    impFile = importFile;

    impFileEnd = XSTRSTR(impFile, ".pem");
    if (impFileEnd != NULL && impFileEnd[XSTRLEN(".pem")] == '\0') {
        encType = ENCODING_TYPE_PEM;
    }

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&impKey, 0, sizeof(impKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Key Import\n");
    printf("\tKey Blob: %s\n", outputFile);
    printf("\tAlgorithm: %s\n", TPM2_GetAlgName(alg));
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));
    printf("\tpassword: %s\n", password);

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    srkAlg = alg;

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, srkAlg);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter
         * encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* setup an auth value */
    if (password != NULL) {
        impKey.handle.auth.size = (int)XSTRLEN(password);
        XMEMCPY(impKey.handle.auth.buffer, password, impKey.handle.auth.size);
    }

    attributes = (TPMA_OBJECT_restricted |
             TPMA_OBJECT_sensitiveDataOrigin |
             TPMA_OBJECT_decrypt |
             TPMA_OBJECT_userWithAuth |
             TPMA_OBJECT_noDA);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    if (impFile != NULL) {
        printf("Loading %s%s key file: %s\n",
            encType == ENCODING_TYPE_PEM ? "PEM" : "DER",
            isPublicKey ? " public" : "", impFile);
        rc = loadFile(impFile, &buf, &bufSz);
        if (rc == 0) {
            if (isPublicKey) {
                rc = wolfTPM2_ImportPublicKeyBuffer(&dev, alg,
                    (WOLFTPM2_KEY*)&impKey, encType,
                    (const char*)buf, (word32)bufSz, attributes
                );
            }
            else { /* private key */
                rc = wolfTPM2_ImportPrivateKeyBuffer(&dev, &storage,
                    alg, &impKey, encType, (const char*)buf, (word32)bufSz,
                    password, attributes, NULL, 0
                );
            }
        }
    }
    else
#endif
    {
        printf("Import file is NULL!");
        goto exit;
    }
    if (rc != 0) goto exit;

    printf("Imported %s key (pub %d, priv %d bytes)\n",
        TPM2_GetAlgName(alg), impKey.pub.size, impKey.priv.size);

    /* Save key as encrypted blob to the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(NO_WRITE_TEMP_FILES)
    rc = writeKeyBlob(outputFile, &impKey);
#else
    printf("Key Public Blob %d\n", impKey.pub.size);
    TPM2_PrintBin((const byte*)&impKey.pub.publicArea, impKey.pub.size);
    printf("Key Private Blob %d\n", impKey.priv.size);
    TPM2_PrintBin(impKey.priv.buffer, impKey.priv.size);
#endif

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &impKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

// int TPM_RsaEncrypt(void* userCtx, const char* keyFile, const byte* msg, int msgSize, byte* out, int* outSize)
// {
//     int rc;
//     WOLFTPM2_DEV dev;
//     WOLFTPM2_KEY storage; /* SRK */
//     WOLFTPM2_KEY *primary = NULL;
//     WOLFTPM2_KEYBLOB newKey;
//     WOLFTPM2_KEY persistKey;
//     TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
//     WOLFTPM2_SESSION tpmSession;
//     const char* inputFile = "keyblob.bin";
//     int endorseKey = 0;
//     TPM_ALG_ID paddingScheme = TPM_ALG_OAEP;

//     // set inputFile from function argument
//     // if inputFile is provided
//     if(XSTRCMP("", keyFile) != 0) inputFile = keyFile;

//     XMEMSET(&storage, 0, sizeof(storage));
//     XMEMSET(&newKey, 0, sizeof(newKey));
//     XMEMSET(&persistKey, 0, sizeof(persistKey));
//     XMEMSET(&tpmSession, 0, sizeof(tpmSession));

//     printf("TPM2.0 Key load\n");
//     printf("\tKey Blob: %s\n", inputFile);
//     printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

//     rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
//     if (rc != TPM_RC_SUCCESS) {
//         printf("\nwolfTPM2_Init failed\n");
//         goto exit;
//     }

//     rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
//     if (rc != 0) goto exit;
//     primary = &storage;

//     if (paramEncAlg != TPM_ALG_NULL) {
//         /* Start an authenticated session (salted / unbound) with parameter
//          * encryption */
//         rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
//             TPM_SE_HMAC, paramEncAlg);
//         if (rc != 0) goto exit;
//         printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
//             (word32)tpmSession.handle.hndl);

//         /* set session for authorization of the storage key */
//         rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
//             (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
//              TPMA_SESSION_continueSession));
//         if (rc != 0) goto exit;
//     }

//     /* Load encrypted key from the disk */
// #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
//     rc = readKeyBlob(inputFile, &newKey);
//     if (rc != 0) goto exit;
// #else
//     /* TODO: Option to load hex blob */
//     printf("Loading blob from disk not supported. Enable wolfcrypt support.\n");
//     goto exit;
// #endif

//     if (newKey.priv.size == 0) {
//         rc = wolfTPM2_LoadPublicKey(&dev, (WOLFTPM2_KEY*)&newKey, &newKey.pub);
//     }
//     else {
//         rc = wolfTPM2_LoadKey(&dev, &newKey, &primary->handle);
//     }
//     if (rc != TPM_RC_SUCCESS) {
//         printf("Load Key failed!\n");
//         goto exit;
//     }
//     printf("Loaded key to 0x%x\n", (word32)newKey.handle.hndl);

//     /******************************************************************************/
//     /* --- BEGIN RSA Encryption -- */
//     /******************************************************************************/

//     rc = wolfTPM2_RsaEncrypt(&dev, (WOLFTPM2_KEY*)&newKey, paddingScheme, msg, msgSize, out, outSize);
//     if(rc != TPM_RC_SUCCESS) {
//         printf("RSA encryption failed!\n");
//         goto exit;
//     }

//     // print result
//     printf("RSA encryption successful!\n");
//     printf("Encrypted text: ");
//     for(int i = 0; i < *outSize; ++i) {
//         printf("%x", *(out + i));
//     }

//     /******************************************************************************/
//     /* --- END RSA Encryption -- */
//     /******************************************************************************/

// exit:

//     if (rc != 0) {
//         printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
//     }

//     /* Close key handles */
//     wolfTPM2_UnloadHandle(&dev, &primary->handle);
//     wolfTPM2_UnloadHandle(&dev, &newKey.handle);
//     /* EK policy is destroyed after use, flush parameter encryption session */
//     if (!endorseKey) {
//         wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
//     }

//     wolfTPM2_Cleanup(&dev);
//     return rc;
// }

int TPM_RsaEncrypt(void* userCtx, byte* keyPubBuffer, word32 keyPubBufferSize, const byte* msg, const int msgSize, byte* out, int* outSize)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY formatedKey;
    // WOLFTPM2_KEYBLOB keyBlob;
    TPM_ALG_ID paddingScheme = TPM_ALG_OAEP;
    word32 rsaExponent = RSA_DEFAULT_PUBLIC_EXPONENT;

    XMEMSET(&formatedKey, 0, sizeof(formatedKey));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    // extract modulus from public key
    byte *keyModulus = (byte*)malloc(sizeof(byte) * 256);
    word32 keyModulusSize = 256;
    for(int i = 26; i < keyPubBufferSize; ++i)
    {
        *(keyModulus + i - 26) = *(keyPubBuffer + i);
    }

    //byte keyExponentBytes[3] = {keyPubBuffer[0], keyPubBuffer[1], keyPubBuffer[2]};

    // printf("Key exponent bytes: ");
    // for(int i = 0; i < 3; ++i)
    // {
    //     printf("%d ", keyExponentBytes[i]);
    // }
    // printf("\n");

    // word32 keyExponent;
    // XMEMCPY(&keyExponent, keyExponentBytes, sizeof(word32));
    // printf("\nKey exponent: %d\n", keyExponent);
    // printf("Default exponent: %d\n", rsaExponent);

    rc = wolfTPM2_LoadRsaPublicKey(&dev, &formatedKey, keyModulus, keyModulusSize, rsaExponent);
    free(keyModulus);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_LoadRsaPublicKey failed\n");
        goto exit;
    }

    // rc = TPM_SetKeyBlobFromBuffer(&keyBlob, keyPubBuffer, keyPubBufferSize);
    // if (rc != TPM_RC_SUCCESS) goto exit;

    /******************************************************************************/
    /* --- BEGIN RSA Encryption -- */
    /******************************************************************************/

    rc = wolfTPM2_RsaEncrypt(&dev, &formatedKey, paddingScheme, msg, msgSize, out, outSize);
    if(rc != TPM_RC_SUCCESS) {
        printf("RSA encryption failed!\n");
        goto exit;
    }

    /******************************************************************************/
    /* --- END RSA Encryption -- */
    /******************************************************************************/

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &formatedKey.handle);
    // wolfTPM2_UnloadHandle(&dev, &keyBlob.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_RsaDecrypt(void* userCtx, const char* keyFile, const byte* in, const int inSize, byte* msg, int* msgSize)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage; /* SRK */
    WOLFTPM2_KEY *primary = NULL;
    WOLFTPM2_KEYBLOB newKey;
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    WOLFTPM2_SESSION tpmSession;
    // const char* inputFile = "keyblob.bin";
    TPM_ALG_ID paddingScheme = TPM_ALG_OAEP;

    // set inputFile from function argument
    // if inputFile is provided
    // if(XSTRCMP("", keyFile) != 0) strcpy(inputFile, keyFile);

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    printf("TPM2.0 Key load\n");
    printf("\tKey Blob: %s\n", keyFile);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;
    primary = &storage;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter
         * encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
             TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* Load encrypted key from the disk */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    rc = readKeyBlob(keyFile, &newKey);
    if (rc != 0) goto exit;
#else
    /* TODO: Option to load hex blob */
    printf("Loading blob from disk not supported. Enable wolfcrypt support.\n");
    goto exit;
#endif

    if (newKey.priv.size == 0) {
        rc = wolfTPM2_LoadPublicKey(&dev, (WOLFTPM2_KEY*)&newKey, &newKey.pub);
    }
    else {
        rc = wolfTPM2_LoadKey(&dev, &newKey, &primary->handle);
    }
    if (rc != TPM_RC_SUCCESS) {
        printf("Load Key failed!\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n", (word32)newKey.handle.hndl);

    /******************************************************************************/
    /* --- BEGIN RSA Decryption -- */
    /******************************************************************************/

    rc = wolfTPM2_RsaDecrypt(&dev, (WOLFTPM2_KEY*)&newKey, paddingScheme, in, inSize, msg, msgSize);
    if(rc != TPM_RC_SUCCESS) {
        printf("RSA decryption failed!\n");
        goto exit;
    }

    /******************************************************************************/
    /* --- END RSA Decryption -- */
    /******************************************************************************/

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &primary->handle);
    /* newKey.handle is already flushed by wolfTPM2_NVStoreKey */
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    /* EK policy is destroyed after use, flush parameter encryption session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

int TPM_RsaDecrypt2(void* userCtx, const byte* keyPubBuffer, const word32 keyPubBufferSize, const byte* keyPrivBuffer,
                    const word32 keyPrivBufferSize, const byte* in, int inSize, byte* msg, int* msgSize)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY newKey;
    TPM_ALG_ID paddingScheme = TPM_ALG_OAEP;
    word32 rsaExponent = RSA_DEFAULT_PUBLIC_EXPONENT;

    // XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&newKey, 0, sizeof(newKey));
    //XMEMSET(&tpmSession, 0, sizeof(tpmSession));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    // extract modulus from public key
    byte *keyPubModulus = (byte*)malloc(sizeof(byte) * 256);
    word32 keyPubModulusSize = 256;
    for(int i = 26; i < keyPubBufferSize; ++i)
    {
        *(keyPubModulus + i - 26) = *(keyPubBuffer + i);
    }

    // extract modulus from private key
    // byte *keyPrivModulus = (byte*)malloc(sizeof(byte) * 220);
    // word32 keyPrivModulusSize = 220;
    // for(int i = 4; i < keyPrivBufferSize; ++i)
    // {
    //     *(keyPrivModulus + i - 4) = *(keyPrivBuffer + i);
    // }

    // Load key from buffers
    rc = wolfTPM2_LoadRsaPrivateKey(&dev, NULL, &newKey, keyPubModulus, keyPubModulusSize, rsaExponent, keyPrivBuffer, keyPrivBufferSize);
    free(keyPubModulus);
    // free(keyPrivModulus);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_LoadRsaPrivateKey failed\n");
        goto exit;
    }

    /******************************************************************************/
    /* --- BEGIN RSA Decryption -- */
    /******************************************************************************/

    rc = wolfTPM2_RsaDecrypt(&dev, &newKey, paddingScheme, in, inSize, msg, msgSize);
    if(rc != TPM_RC_SUCCESS) {
        printf("RSA decryption failed!\n");
        goto exit;
    }

    /******************************************************************************/
    /* --- END RSA Decryption -- */
    /******************************************************************************/

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close key handles */
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

// int TPM_KeyBlobFileToBuffer(void* userCtx, const char* keyFile, byte* pubBuffer, word32* pubBufferSize)
// {
//     /* not implemented */
//     return;
// }

// int TPM_SetKeyBlobFileFromBuffer(void* userCtx, const char* outFile, byte *buffer, word32 bufferSz)
// {
//     /* not implemented */
//     return;
// }

int TPM_KeyBlobPublicToBuffer(WOLFTPM2_KEYBLOB* key, byte* pubBuffer, word32* pubBufferSize)
{
    int rc;
    byte privBuffer[1024];
    word32 privBufferSize = 1024;

    rc = wolfTPM2_GetKeyBlobAsSeparateBuffers(pubBuffer, pubBufferSize, privBuffer, &privBufferSize, key);
    if(rc != TPM_RC_SUCCESS)
    {
        printf("\nwolfTPM2_GetKeyBlobAsSeparateBuffers failed\n");
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    return rc;
}

int TPM_KeyBlobToBuffer(WOLFTPM2_KEYBLOB* key, byte* pubBuffer, word32* pubBufferSize, byte* privBuffer, word32* privBufferSize)
{
    int rc;

    rc = wolfTPM2_GetKeyBlobAsSeparateBuffers(pubBuffer, pubBufferSize, privBuffer, privBufferSize, key);
    if(rc != TPM_RC_SUCCESS)
    {
        printf("\nwolfTPM2_GetKeyBlobAsSeparateBuffers failed\n");
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    return rc;
}

int TPM_SetKeyBlobFromBuffer(WOLFTPM2_KEYBLOB* key, byte *buffer, word32 bufferSize)
{
    int rc;

    rc = wolfTPM2_SetKeyBlobFromBuffer(key, buffer, bufferSize);
    if(rc != TPM_RC_SUCCESS)
    {
        printf("\nwolfTPM2_SetKeyBlobFromBuffer failed\n");
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }
    return rc;
}

int TPM_GetRandom(void* userCtx, byte* buffer, word32 len)
{
    int rc;
    WOLFTPM2_DEV dev;

    // Initialize the TPM
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    // Get random buffer
    rc = wolfTPM2_GetRandom(&dev, buffer, len);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_GetRandom failed\n");
        goto exit;
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    /* Close handles */
    // wolfTPM2_UnloadHandle(&dev, &primary->handle);
    // wolfTPM2_UnloadHandle(&dev, &newKeyBlob.handle);
    // wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

// int main(int argc, char* argv[])
// {
//     int rc;

//     byte keyPubBuffer[512];
//     word32 keyPubBufferSize;
//     byte msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21};
//     word32 msgSize = sizeof(msg);
//     byte output[100];
//     word32 outputSize;
    
//     if(argc == 2)
//     {
//         if(XSTRCMP(argv[1], "-keygen") == 0)
//             rc = TPM_Keygen(NULL, "keyblob.bin");
//         else if(XSTRCMP(argv[1], "-keyload") == 0)
//             rc = TPM_Keyload(NULL, "keyblob.bin");
//         else if(XSTRCMP(argv[1], "-keyimport") == 0)
//             rc = TPM_Keyimport(NULL, "RSAkey_public.pem");
//         else if(XSTRCMP(argv[1], "-rsaEncrypt") == 0)
//         {
//             char msg[100] = "test message";
//             int msgSize = sizeof(msg);
//             rc = TPM_RsaEncrypt(NULL, "keyblob.bin", msg, msgSize, output, outputSize);
//         }
//         else if(XSTRCMP(argv[1], "-rsaDecrypt") == 0)
//         {
//             byte input[100] = "";
//             word32 inputSize = sizeof(input);
//             rc = TPM_RsaDecrypt(NULL, "keyblob.bin", input, inputSize, msg, msgSize);
//         }
//         else if(XSTRCMP(argv[1], "-getRandom") == 0)
//         {
//             byte buffer[5];
//             word32 bufferLen = 5;
//             rc = TPM_GetRandom(NULL, &buffer, bufferLen);

//             printf("Random number generated:\n");
//             for(int i = 0; i <= bufferLen; ++i)
//             {
//                 printf("%u", buffer[i]);
//             }
//             printf("\n");
//         }
//     }
    
//     printf("TPM2_RC = %d\n", rc);
    
//     return 0;
// }
