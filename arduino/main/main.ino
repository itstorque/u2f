#include <src.h>
#include <micro-ecc/uECC.h>
// include arduino
// language: cpp

struct EncryptionKey K_wrap;

struct EncryptionKey K_app;

struct EncryptionKey Priv_attest;
// generate key pair
void setup()
{
    // Serial.begin(9600);
    // Serial.println("Generating key pair...");
    // Serial.println("Key pair generated!");
    K_wrap = {{0}};      // secret wrapping key of this security key
    K_app = {{0}};       // secret application key of this security key
    Priv_attest = {{0}}; // private key of this security key
}

void loop()
{
}
// Register: Given this command, the Security Key generates a fresh asymmet- ric key pair and returns the public key. The server associates this public key with a user account.
void registerOrigin(RegistrationInput input)
{
    uECC_Curve curve = uECC_secp256r1();
    KeyPair k = generateKeyPair(curve);
    Origin o = input.origin;
    Hash c = input.c;
    Handle H = store(o, k.privateKey);
}

// create handle

// store(origin, k_priv)
// the private key and origin are encrypted via K_wrap
// The handle is sent to the server and is stored there.
Handle store(Origin origin, EncryptionKey k_priv)
{
    Encryptable origin_enc; // generate using origin
    Handle obscure_o = encrypt(K_app, origin_enc);
    // interleave the obfuscated origin with the private key, encrypt it with K_wrap
    // that is the plaintext
    Encryptable plaintext;
    Handle h = encrypt(K_wrap, plaintext);
    return h;
}

// send attestations cert, batched