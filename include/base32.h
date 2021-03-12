#ifndef BASE32_H
#define BASE32_H

#define BASE32_LENGTH(bytes) (((bytes) * 8 + 4) / 5)

#include <stdint.h>
#include <sys/types.h>

size_t base32decsize(size_t count);

int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize);

int base32_encode(const uint8_t *data, int length, uint8_t *result,
                  int bufSize);

#endif