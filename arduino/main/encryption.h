#include <stdint.h>
#include "WProgram.h"

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"

// TODO: hash RNG using SHA-256
// random number generator, copied from:
// https://github.com/kmackay/micro-ecc/blob/master/examples/ecc_test/ecc_test.ino
int RNG(uint8_t *dest, unsigned size);

// SHA-256 Setup

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(uECC_HashContext *base);

void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size);

void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result);