#include <stdint.h>

int GenerateRsaKey(const char* keyOutputFile, uint8_t* keyPubBuffer, uint32_t* keyPubBufferSize);
int GenerateRsaKey2(const char* keyOutputFile, uint8_t* keyPubBuffer, uint32_t* keyPubBufferSize, uint8_t* keyPrivBuffer, uint32_t* keyPrivBufferSize);
int LoadRsaKey(const char* keyLoadFile);
int ImportRsaPublicKey();

// int RsaEncrypt(const char* keyFile, const uint8_t* msg, int msgSize, uint8_t* out, int* outSize);
int RsaEncrypt(const uint8_t* keyBuffer, uint32_t keyBufferSize, const uint8_t* msg, int msgSize, uint8_t* out, int* outSize);
int RsaDecrypt(const char* keyFile, const uint8_t* in, int inSize, uint8_t* msg, int* msgSize);
int RsaDecrypt2(const uint8_t* keyPubBuffer, uint32_t keyPubBufferSize, const uint8_t* keyPrivBuffer, uint32_t keyPrivBufferSize, const uint8_t* in, int inSize, uint8_t* msg, int* msgSize);

int GetRandom(uint8_t* buffer, uint32_t len);

int StoreNV(uint8_t* data, uint32_t dataSize);
int ReadNV(uint8_t* data, uint32_t* dataSize);
int DeleteNV();