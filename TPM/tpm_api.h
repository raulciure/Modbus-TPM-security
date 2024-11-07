#include <stdint.h>


int GetRandom(uint8_t* buffer, uint32_t len);

int StoreNV(uint8_t* data, uint32_t dataSize, uint32_t nvIndexOffset);
int ReadNV(uint8_t* data, uint32_t* dataSize, uint32_t nvIndexOffset);
int DeleteNV(uint32_t nvIndexOffset);