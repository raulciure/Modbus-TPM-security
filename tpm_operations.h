#include "wolftpm/tpm2_types.h" // include wolfTPM types definition for using byte type (as well as others)
#include "wolftpm/tpm2_wrap.h"


int TPM_Keygen(void* userCtx, const char* outFile, byte* keyPubBuffer, word32* keyPubBufferSize); // generates key and outputs it to outfile as WOLFTPM2_KEYBLOB and public part to keyPubBuffer
int TPM_Keygen2(void* userCtx, const char* outFile, byte* keyPubBuffer, word32* keyPubBufferSize, byte* keyPrivBuffer, word32* keyPrivBufferSize); // generates key and outputs it to outfile as WOLFTPM2_KEYBLOB and public & private parts to keyPubBuffer / keyPrivBuffer
int TPM_Keyload(void* userCtx, const char* inFile);
int TPM_Keyimport(void* userCtx, const char* importFile);

// Loads key from keyFile to TPM and encrypts/decrypts message using it
//int TPM_RsaEncrypt(void* userCtx, const char* keyFile, const byte* msg, int msgSize, byte* out, int* outSize);
int TPM_RsaEncrypt(void* userCtx, byte* keyBuffer, word32 keyBufferSize, const byte* msg, const int msgSize, byte* out, int* outSize);
int TPM_RsaDecrypt(void* userCtx, const char* keyFile, const byte* in, const int inSize, byte* msg, int* msgSize);
int TPM_RsaDecrypt2(void* userCtx, const byte* keyPubBuffer, const word32 keyPubBufferSize, const byte* keyPrivBuffer,
                    const word32 keyPrivBufferSize, const byte* in, int inSize, byte* msg, int* msgSize);

// Functions for converting WOLFTPM2_KEYBLOB to buffer and vice versa
// With 2 versions for each operation: to/from file, to/from passed variable pointer
// int TPM_KeyBlobFileToBuffer(void* userCtx, const char* keyFile, byte* pubBuffer, word32* pubBufferSize);
// int TPM_SetKeyBlobFileFromBuffer(void* userCtx, const char* outFile, byte *buffer, word32 bufferSz);
int TPM_KeyBlobPublicToBuffer(WOLFTPM2_KEYBLOB* key, byte* pubBuffer, word32* pubBufferSize);
int TPM_KeyBlobToBuffer(WOLFTPM2_KEYBLOB* key, byte* pubBuffer, word32* pubBufferSize, byte* privBuffer, word32* privBufferSize);
int TPM_SetKeyBlobFromBuffer(WOLFTPM2_KEYBLOB* key, byte *buffer, word32 bufferSz);

// Generate random number
int TPM_GetRandom(void* userCtx, byte* buffer, word32 len);