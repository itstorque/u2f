#include <src.h>
#include <uECC.h>
#include <sha256.h>
#include <stdlib.h>
#include <cstring>
KeyPair generateKeyPair(uECC_Curve curve)
{
    KeyPair k;
    uECC_make_key(k.publicKey.key, k.privateKey.key, curve);
    return k;
}

int RNG(uint8_t *dest, unsigned size)
{
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
    // random noise). This can take a long time to generate random data if the result of analogRead(0)
    // doesn't change very frequently.
    while (size)
    {
        uint8_t val = 0;
        for (unsigned i = 0; i < 8; ++i)
        {
            int init = analogRead(0);
            int count = 0;
            while (analogRead(0) == init)
            {
                ++count;
            }

            if (count == 0)
            {
                val = (val << 1) | (init & 0x01);
            }
            else
            {
                val = (val << 1) | (count & 0x01);
            }
        }
        *dest = val;
        ++dest;
        --size;
    }
    // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
    return 1;
}

// random data
byte certificate[52] = {
    's',
    'e',
    'c',
    'r',
    'e',
    't',
    ' ',
    'c',
    'e',
    'r',
    't',
    'i',
    'f',
    'i',
    'c',
    'a',
    't',
    'e',
    ' ',
    'c',
    'o',
    'n',
    't',
    'e',
    'n',
    't',
    ' ',
    'i',
    'n',
    ' ',
    'c',
    'o',
    'm',
    'p',
    'l',
    'e',
    'x',
};

byte *register_origin(byte *message, int size)
{
    byte *challange;
    byte *application;
    // signature must be 2*curve_size long
    byte *signature;
    Cert cert;
    Handle h;
    uECC_Curve curve = uECC_secp256r1();
    KeyPair kp = generateKeyPair(curve);

    byte *response;

    challange = message; // TODO: check if this is correct, maybe needs to be +1
    application = challange + 32;

    // generating signature

    signature = (byte *)malloc(2 * uECC_curve_private_key_size(curve));

    int data_to_sign_len = 1 + 32 + 32 + h.size + 65;
    byte *data_to_sign = (byte *)malloc(data_to_sign_len);

    *data_to_sign = 0x00;
    memcpy(data_to_sign + 1, application, 32);
    memcpy(data_to_sign + 33, challange, 32);
    memcpy(data_to_sign + 65, h.data, h.size);
    memcpy(data_to_sign + 65 + h.size, kp.publicKey.key, 65);

    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, hash);

    uECC_sign(kp.privateKey.key, hash, 32, signature, curve);

    // generating cert

    get_certificate(&cert);

    // generate response = byte + public key + handle len + handle + certificate + signature

    response = (byte *)malloc(1 + 65 + 1 + h.size + cert.size + 2 * uECC_curve_private_key_size(curve));

    *response = 0x05;
    memcpy(response + 1, kp.publicKey.key, 65);
    *(response + 66) = h.size;
    memcpy(response + 67, h.data, h.size);
    memcpy(response + 67 + h.size, cert.data, cert.size);
    memcpy(response + 67 + h.size + cert.size, signature, 2 * uECC_curve_private_key_size(curve));

    return response;
}

void store(byte *app_hash, int hash_len, EncryptionKey k_priv, Handle *h)
{
    byte *data;
    int data_len;
    // copy the app_hash and k_priv into data
    data_len = hash_len + k_priv.size;
    data = (byte *)malloc(data_len);

    memcpy(data, app_hash, hash_len);
    memcpy(data + hash_len, k_priv.key, k_priv.size);

    // write into handle
    h->size = data_len;
    h->data = data;
}

void retrieve(Handle *h, byte *app_hash, int hash_len, EncryptionKey k_priv)
{
    byte *data;
    k_priv.size = h->size - hash_len;
    data = h->data;

    // copy k_priv from data into k_priv
    memcpy(k_priv.key, data + hash_len, k_priv.size);
}

void get_certificate(Cert *cert)
{
    // write a random certificate in X.509 DER format

    byte *cert_data;
    int cert_data_len;

    cert_data_len = 52;
    cert_data = (byte *)malloc(cert_data_len);

    // write certificate
    memcpy(cert_data, certificate, 52);

    cert->data = cert_data;
    cert->size = cert_data_len;
}

byte *authenticate_origin(byte *message, int size)
{
    byte *challange;
    byte *application;
    byte control;
    // signature must be 2*curve_size long
    byte *signature;
    Handle h;

    // check control byte
    control = *message;
    if (control != 0x03)
    {
        return NULL;
    }
    else if (control == 0x07)
    {
        // TODO: handle this
        return NULL;
    }

    byte *response;
}
