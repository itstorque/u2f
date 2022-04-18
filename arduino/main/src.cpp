#include "src.h"
#include <stdlib.h>
#include <cstring>

#include "sha256/sha256.h"
#include "uECC/uECC.h"
KeyPair generateKeyPair(uECC_Curve curve)
{
    KeyPair k;
    uECC_make_key(k.publicKey.key, k.privateKey.key, curve);
    k.publicKey.size = uECC_curve_public_key_size(curve);
    k.privateKey.size = uECC_curve_private_key_size(curve);
    return k;
}

int RNG(uint8_t *dest, unsigned size)
{
    for (int i = 0; i < size; i++)
    {
        dest[i] = rand();
    }
    return 1;
}

void HexDump(const char *c, int size)
{

    for (int i = 0; i < size; i++)
    {
        printf("%02x ", (u_int8_t)c[i]);
    }
    printf("\n");
    return;
    {
        for (int i = 0; i < size; i++)
        {
            std::cout << std::hex << (unsigned int)c[i] << " ";
        }
        std::cout << std::endl;
    }
}

// 'u', 'w' repeated 52 times
byte certificate[52] = {
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u',
    'w',
    'u',
    'u', 'w', 'u',
    'u', 'w', 'u',
    'u', 'w', 'u',
    'u', 'w', 'u', '.'};

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

    // generate handle

    store(application, 32, kp.publicKey, &h);

    int data_to_sign_len = 1 + 32 + 32 + h.size + kp.publicKey.size;
    byte *data_to_sign;
    data_to_sign = (byte *)malloc(data_to_sign_len);

    if (data_to_sign == NULL)
    {
        char *c = "hello 2, malloc failed";
        response = (byte *)c;
        return response;
    }

    // copy zero in the first place
    char zero = '\0';
    memccpy(data_to_sign, &zero, 0, 1);
    memcpy(data_to_sign + 1, application, 32);
    memcpy(data_to_sign + 33, challange, 32);
    memcpy(data_to_sign + 65, h.data, h.size);
    memcpy(data_to_sign + 65 + h.size, kp.publicKey.key, kp.publicKey.size);

    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, hash);

    printf("\ndata_to_sign: ");
    HexDump((char *)data_to_sign, data_to_sign_len);
    printf("\n\n");

    printf("\npublic key: ");
    HexDump((char *)kp.publicKey.key, 32);
    printf("\n\n");

    printf("\nhash: ");
    HexDump((char *)hash, 32);
    printf("\n\n");

    printf("\nhandle: ");
    HexDump((char *)h.data, h.size);
    printf("\n\n");

    free(data_to_sign);

    uECC_sign(kp.privateKey.key, hash, 32, signature, curve);

    printf("\nsignature: ");
    HexDump((char *)signature, 2 * uECC_curve_private_key_size(curve));
    printf("\n\n");

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

    printf("\nresponse size: ");
    printf("%d", 1 + 65 + 1 + h.size + cert.size + 2 * uECC_curve_private_key_size(curve));
    printf("\n\n");

    free(signature);

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
