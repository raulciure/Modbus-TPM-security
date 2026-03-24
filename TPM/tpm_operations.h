#include <wolftpm/tpm2_types.h> // include wolfTPM types definition for using byte type (as well as others)

#define DEBUG_MESSAGES 0  // set to 1 for showing debug messages

#define TPM_MAX_NV_INDEX_SIZE 1536
#define TPM_DEFAULT_NV_INDEX 0x01800202
#define MAX_NV_BUFFER_SIZE 768

#define HAL_CALLBACK_POINTER TPM2_IoCb
#define CALLBACK_POINTER 0 // change this to HAL_CALLBACK_POINTER to use direct TPM interfacing


static const char nvAuthPassword[] = "Nv <<>> auth - password";

// Generate random number
int TPM_GetRandom(void* userCtx, byte* buffer, word32 len);

// Creates a new nvIndex and stores data at that location.
// indexOffset = the wanted NV_Index relative to TPM_DEFAULT_NV_INDEX
int TPM_StoreNV(void* userCtx, byte* data, word32 dataSize, word32 indexOffset);

// Reads data from provided index and loads it in data and dataSize arguments.
int TPM_ReadNV(void* userCtx, byte* data, word32* dataSize, word32 indexOffset);

// Destroys nvIndex and its data
int TPM_DeleteNV(void* userCtx, word32 indexOffset);