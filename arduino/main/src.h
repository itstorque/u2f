#ifndef src_h
#define src_h
#include <stdint.h>

struct EncryptionKey
{
    uint8_t key[32];
};

struct KeyPair
{
    EncryptionKey publicKey;
    EncryptionKey privateKey;
};
struct Origin
{
};
struct Hash
{
};

struct Handle
{
};

struct RegistrationInput
{
    Origin origin;
    Hash c;
};

struct Encryptable
{
};

struct Signature
{
};

Signature sign(Origin, Handle h, Hash c);

Handle encrypt(EncryptionKey K_wrap, Encryptable origin);

KeyPair generateKeyPair(uECC_Curve curve);

int RNG(uint8_t *dest, unsigned size);

#endif