#ifndef src_h
#define src_h
#include <stdint.h>
#include <uECC.h>
#include <sha256.h>
typedef unsigned char byte;
struct EncryptionKey
{
    byte key[32];
    u_int8_t size;
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
    int size;
    byte *data; // data is app_hash + k_priv
};

struct RegistrationInput
{
    Origin origin;
    Hash c;
};

struct Encryptable
{
    int size;
    byte data[size];
};

struct Signature
{
};

struct Cert
{
    byte *data;
    int size;
};

Signature sign(Origin, Handle h, Hash c);

byte encrypt(EncryptionKey K_wrap, Encryptable origin);

KeyPair generateKeyPair(uECC_Curve curve);

int RNG(uint8_t *dest, unsigned size);

/**
 * The registration request message has two parts:
The challenge parameter [32 bytes]. The challenge parameter is the SHA­256 hash of the Client Data, a stringified JSON data structure that the FIDO Client prepares. Among other things, the Client Data contains the challenge from the relying party (hence the name of the parameter). See below for a detailed explanation of Client Data.
The application parameter [32 bytes]. The application parameter is the SHA­256 hash of the application identity of the application requesting the registration. (See [FIDOAppIDAndFacets] in bibliography for details.)

This message is output by the U2F token once it created a new keypair in response to the registration request message.

Its raw representation is the concatenation of the following:
A reserved byte [1 byte], which for legacy reasons has the value 0x05.
A user public key [65 bytes]. This is the (uncompressed) x,y­representation of a curve point on the P­256 NIST elliptic curve.
A key handle length byte [1 byte], which specifies the length of the key handle (see below).
A key handle [length specified in previous field]. This a handle that allows the U2F token to identify the generated key pair. U2F tokens MAY wrap the generated private key and the application id it was generated for, and output that as the key handle.
An attestation certificate [variable length]. This is a certificate in X.509 DER format. Parsing of the X.509 certificate unambiguously establishes its ending.
The remaining bytes in the message are
a signature. This is a ECDSA (see [ECDSA­ANSI] in bibliography) signature (on P­256) over the following byte string:
A byte reserved for future use [1 byte] with the value 0x00. This will evolve into a byte that will allow RPs to track known­good applet
version of U2F tokens from specific vendors.
The application parameter [32 bytes] from the registration request message.
The challenge parameter [32 bytes] from the registration request message.
The above key handle [variable length]. (Note that the key handle length is not included in the signature base string.
This doesn't cause confusion in the signature base string, since all other parameters in the signature base string are fixed­length.)
The above user public key [65 bytes].
 */
byte *register_origin(byte *message, int size);

/**
 * @brief stores the application/origin hash and the private key in the Handle.
 *
 * currently is unencrypted TODO: encrypt
 *
 * @param app_hash
 * @param k_priv
 * @return byte
 */
void store(byte *app_hash, int hash_len, EncryptionKey k_priv, Handle *h);

/**
 * @brief decodes the handle and returns the private key
 *
 * @param k_priv
 * @return byte
 */
void retrieve(Handle *h, byte *app_hash, int hash_len, EncryptionKey k_priv);

/**
 * @brief write a random certificate in X.509 DER format
 *
 * @param cert
 */
void get_certificate(Cert *cert);

/**
 message = control byte + challenge + app_id + key_handle_len + key_handle

control byte:
0x07 ("check­only"): if the control byte is set to 0x07 by the FIDO Client, the U2F token is supposed to simply check whether the provided key handle was originally created by this token, and whether it was created for the provided application parameter. If so, the U2F token MUST respond with an authentication response
message:error:test­of­user­presence­required (note that despite the name this signals a success condition). If the key handle was not created by this U2F token, or if it was created for a different application parameter, the token MUST respond with an authentication response message:error:bad­key­handle.
0x03 ("enforce­user­presence­and­sign"): If the FIDO client sets the control byte to 0x03, then the U2F token is supposed to perform a real signature and respond with either an authentication response message:success or an appropriate error response (see below). The signature SHOULD only be provided if user presence could be validated.


response =  user_presence_byte + counter + signature
signature = sign( app_id, user_presence_byte,  counter, challenge )

 */
byte *authenticate_origin(byte *message, int size);

#endif