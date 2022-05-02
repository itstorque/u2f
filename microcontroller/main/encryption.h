// TODO: hash RNG using SHA-256
// random number generator, copied from:
// https://github.com/kmackay/micro-ecc/blob/master/examples/ecc_test/ecc_test.ino
int RNG(uint8_t *dest, unsigned size) {
	// Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
	// random noise). This can take a long time to generate random data if the result of analogRead(0)
	// doesn't change very frequently.

	while (size) {
		uint8_t val = 0;
		for (unsigned i = 0; i < 8; ++i) {
			int init = analogRead(0);
			int count = 0;
			while (analogRead(0) == init) {
				++count;
			}

			if (count == 0) {
				val = (val << 1) | (init & 0x01);
			} else {
				val = (val << 1) | (count & 0x01);
			}
		}
		*dest = val;
		++dest;
		--size;
	}

	return 1;

}

// SHA-256 Setup

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}

void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}

void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256

struct EncryptionKey
{
    byte key[128];
    uint8_t size;
};

struct KeyPair
{
    EncryptionKey publicKey;
    EncryptionKey privateKey;
};

struct Handle
{
    int size;
    byte *data; // data is app_hash + k_priv
};

struct Cert
{
    byte *data;
    int size;
};

struct KeyPair generateKeyPair(uECC_Curve curve)
{
    KeyPair k;
    uECC_make_key(k.publicKey.key, k.privateKey.key, curve);
    k.publicKey.size = uECC_curve_public_key_size(curve);
    k.privateKey.size = uECC_curve_private_key_size(curve);
    return k;
}