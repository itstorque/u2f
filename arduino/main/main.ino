
// send attestations cert, batched
// persistent memory lib
#include <EEPROM.h>

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"

// #include "src.h"

// debug state
#undef DEBUG
#define DEBUG

#ifdef DEBUG

#define DISPLAY_IF_DEBUG(X) Serial.println(X)
#define DISPLAY_HEX_IF_DEBUG(X) Serial.println(X, HEX)

void debug_dump_hex(byte *buffer, int len)
{

    for (int i = 0; i < len; i++)
    {

        if (buffer[i] <= 0xf)
        {
            Serial.print(0);
        }

        Serial.print(buffer[i], HEX);
        Serial.print(" ");
    }

    Serial.println();
}

void debug_hex_loop(byte *data, int start, int end)
{

    for (int i = start; i < end; i++)
    {
        if (data[i] <= 0xf)
        {
            Serial.print(0);
        }
        Serial.print(data[i], HEX);
        Serial.print(" ");
    }
    DISPLAY_IF_DEBUG("");
}

#else

#define DISPLAY_IF_DEBUG(X) \
    do                      \
    {                       \
    } while (0) // do nothing avoiding empty statements
#define DISPLAY_HEX_IF_DEBUG(X) \
    do                          \
    {                           \
    } while (0) // do nothing avoiding empty statements

void debug_dump_hex(byte *buffer, int len)
{
}
void debug_hex_loop(byte *data, int start, int end) {}

#endif

#pragma mark - managing communication channel

#define CHANNEL_COUNT 4

enum CHANNEL_STATE
{
    Available,
    Wait_init,
    Wait_cont,
    Timeout,
    Large
};

struct CHANNEL_STATUS
{
    int channel_id;
    enum CHANNEL_STATE state;
    int last_millis;
};

CHANNEL_STATUS channel_status[CHANNEL_COUNT];

#pragma mark - packet helpers

// PACKETS ARE DEFINED AS INITIAL AND CONTINUATION WHERE

// INIT PACKET:
// 4 for channel id
// 1 for command identifier
// 1 for BCNTH
// 1 for BCNTL
// 57 for payload

// CONT PACKET:
// 4 for channel id
// 1 for packet sequence
// 59 for payload

// we can calculate this from max packet size of 64 bytes for
// full-speed devices, so payload size is at max
// 64 - 7 + 128 * (64 - 5) = 7609 bytes.
#define MAX_PACKET_LENGTH 7609

// initial packet size is 64 - 7
#define MAX_PACKET_LENGTH_INIT 57

// continuation packet size is 64 - 5
#define MAX_PACKET_LENGTH_CONT 59

#define IS_CONTINUATION_PACKET(x) ((x) < 0x80)

#define SET_MSG_LEN(b, v)           \
    do                              \
    {                               \
        (b)[5] = ((v) >> 8) & 0xff; \
        (b)[6] = (v)&0xff;          \
    } while (0)

#define PACKET_DELAY_US 2500

#pragma mark - u2f hid transport headers from
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h
// TODO: move these into a header file later...

// Size of HID reports

#define HID_RPT_SIZE 64 // Default size of raw HID report

// Frame layout - command- and continuation frames

#define CID_BROADCAST 0xffffffff // Broadcast channel id

#define TYPE_MASK 0x80 // Frame type mask
#define TYPE_INIT 0x80 // Initial frame identifier
#define TYPE_CONT 0x00 // Continuation frame identifier

// typedef struct {
//   uint32_t cid;                        // Channel identifier
//   union {
//     uint8_t type;                      // Frame type - b7 defines type
//     struct {
//       uint8_t cmd;                     // Command - b7 set
//       uint8_t bcnth;                   // Message byte count - high part
//       uint8_t bcntl;                   // Message byte count - low part
//       uint8_t data[HID_RPT_SIZE - 7];  // Data payload
//     } init;
//     struct {
//       uint8_t seq;                     // Sequence number - b7 cleared
//       uint8_t data[HID_RPT_SIZE - 5];  // Data payload
//     } cont;
//   };
// } U2FHID_FRAME;

#define FRAME_TYPE(f) ((f).type & TYPE_MASK)
#define FRAME_CMD(f) ((f).init.cmd & ~TYPE_MASK)
#define MSG_LEN(f) ((f).init.bcnth * 256 + (f).init.bcntl)
#define FRAME_SEQ(f) ((f).cont.seq & ~TYPE_MASK)

// HID usage- and usage-page definitions

#define FIDO_USAGE_PAGE 0xf1d0   // FIDO alliance HID usage page
#define FIDO_USAGE_U2FHID 0x01   // U2FHID usage for top-level collection
#define FIDO_USAGE_DATA_IN 0x20  // Raw IN data report
#define FIDO_USAGE_DATA_OUT 0x21 // Raw OUT data report

// General constants

#define U2FHID_IF_VERSION 2       // Current interface implementation version
#define U2FHID_TRANS_TIMEOUT 3000 // Default message timeout in ms

// U2FHID native commands

#define U2FHID_PING (TYPE_INIT | 0x01)  // Echo data through local processor only
#define U2FHID_MSG (TYPE_INIT | 0x03)   // Send U2F message frame
#define U2FHID_LOCK (TYPE_INIT | 0x04)  // Send lock channel command
#define U2FHID_INIT (TYPE_INIT | 0x06)  // Channel initialization
#define U2FHID_WINK (TYPE_INIT | 0x08)  // Send device identification wink
#define U2FHID_SYNC (TYPE_INIT | 0x3c)  // Protocol resync command
#define U2FHID_ERROR (TYPE_INIT | 0x3f) // Error response

#define U2FHID_VENDOR_FIRST (TYPE_INIT | 0x40) // First vendor defined command
#define U2FHID_VENDOR_LAST (TYPE_INIT | 0x7f)  // Last vendor defined command

// U2FHID_INIT command defines

#define INIT_NONCE_SIZE 8 // Size of channel initialization challenge
#define CAPFLAG_WINK 0x01 // Device supports WINK command

typedef struct
{
    uint8_t nonce[INIT_NONCE_SIZE]; // Client application nonce
} U2FHID_INIT_REQ;

typedef struct
{
    uint8_t nonce[INIT_NONCE_SIZE]; // Client application nonce
    uint32_t cid;                   // Channel identifier
    uint8_t versionInterface;       // Interface version
    uint8_t versionMajor;           // Major version number
    uint8_t versionMinor;           // Minor version number
    uint8_t versionBuild;           // Build version number
    uint8_t capFlags;               // Capabilities flags
} U2FHID_INIT_RESP;

// U2FHID_SYNC command defines

typedef struct
{
    uint8_t nonce; // Client application nonce
} U2FHID_SYNC_REQ;

typedef struct
{
    uint8_t nonce; // Client application nonce
} U2FHID_SYNC_RESP;

// Low-level error codes. Return as negatives.

#define ERR_NONE 0x00          // No error
#define ERR_INVALID_CMD 0x01   // Invalid command
#define ERR_INVALID_PAR 0x02   // Invalid parameter
#define ERR_INVALID_LEN 0x03   // Invalid message length
#define ERR_INVALID_SEQ 0x04   // Invalid message sequencing
#define ERR_MSG_TIMEOUT 0x05   // Message has timed out
#define ERR_CHANNEL_BUSY 0x06  // Channel busy
#define ERR_LOCK_REQUIRED 0x0a // Command requires channel lock
#define ERR_SYNC_FAIL 0x0b     // SYNC command failed
#define ERR_OTHER 0x7f         // Other unspecified error

#pragma mark - u2f raw message format header from
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f.h
// TODO: move into a separate header file too

// U2F native commands

#define U2F_REGISTER 0x01     // Registration command
#define U2F_AUTHENTICATE 0x02 // Authenticate/sign command
#define U2F_VERSION 0x03      // Read version string command

#define U2F_VENDOR_FIRST 0x40 // First vendor defined command
#define U2F_VENDOR_LAST 0xbf  // Last vendor defined command

// U2F_CMD_REGISTER command defines

#define U2F_REGISTER_ID 0x05      // Version 2 registration identifier
#define U2F_REGISTER_HASH_ID 0x00 // Version 2 hash identintifier

// Authentication control byte

#define U2F_AUTH_ENFORCE 0x03    // Enforce user presence and sign
#define U2F_AUTH_CHECK_ONLY 0x07 // Check only
#define U2F_AUTH_FLAG_TUP 0x01   // Test of user presence set

// Command status responses

#define U2F_SW_NO_ERROR 0x9000                 // SW_NO_ERROR
#define U2F_SW_WRONG_DATA 0x6A80               // SW_WRONG_DATA
#define U2F_SW_CONDITIONS_NOT_SATISFIED 0x6985 // SW_CONDITIONS_NOT_SATISFIED
#define U2F_SW_COMMAND_NOT_ALLOWED 0x6986      // SW_COMMAND_NOT_ALLOWED
#define U2F_SW_INS_NOT_SUPPORTED 0x6D00        // SW_INS_NOT_SUPPORTED

#pragma mark - Command status responses
// Sourced from ISO-7816
#define SW_NO_ERROR 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA 0x6A80
#define SW_WRONG_LENGTH 0x6700
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00

#define ADD_SW_OK(x)   \
    do                 \
    {                  \
        (*x++) = 0x90; \
        (*x++) = 0x00; \
    } while (0)

#define ADD_SW_COND(x) \
    do                 \
    {                  \
        (*x++) = 0x69; \
        (*x++) = 0x85; \
    } while (0)

#define ADD_SW_WRONG_DATA(x) \
    do                 \
    {                  \
        (*x++) = 0x6A; \
        (*x++) = 0x80; \
    } while (0)

#pragma mark - i/o buffers

byte recieved[64];
byte response[64];

// in case long msg, require subdividing using cont packets
byte expected_next_packet;
int cont_data_len;
int cont_data_offset;

byte cont_recieved[1024];
byte cont_response[1024];

uint32_t universal_counter = 0;

// uECC_Curve curve = uECC_secp256r1();
const struct uECC_Curve_t * curve = uECC_secp256r1(); //P-256

#pragma mark - button setup

#ifdef NO_BUTTON
// simulate button without hardware...
int button_pressed = 0;
#endif

#pragma mark - COUNTER
// using EEPROM to keep a counter

int getCounter()
{

    unsigned int address = 0;
    unsigned int value;

    EEPROM.get(address, value);

    return value;
}

void setCounter(int value)
{

    unsigned int address = 0;

    EEPROM.put(address, value);
}

#pragma mark - SETUP

// TODO: hash RNG using SHA-256
// random number generator, copied from:
// https://github.com/kmackay/micro-ecc/blob/master/examples/ecc_test/ecc_test.ino
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

    return 1;
}
#pragma mark - U2F Protocol

typedef struct SHA256_HashContext
{
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(uECC_HashContext *base)
{
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}

void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size)
{
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}

void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result)
{
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

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

// attestation key:  f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664
const char attestation_key[] = "\xf3\xfc\xcc\x0d\x00\xd8\x03\x19\x54\xf9\x08\x64\xd4\x3c\x24\x7f\x4b\xf5\xf0\x66\x5c\x6b\x50\xcc\x17\x74\x9a\x27\xd1\xcf\x76\x64";

// attestation cert: 3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df
const char attestation_DER_cert[] = "\x30\x82\x01\x3c\x30\x81\xe4\xa0\x03\x02\x01\x02\x02\x0a\x47\x90\x12\x80\x00\x11\x55\x95\x73\x52\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\x17\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x47\x6e\x75\x62\x62\x79\x20\x50\x69\x6c\x6f\x74\x30\x1e\x17\x0d\x31\x32\x30\x38\x31\x34\x31\x38\x32\x39\x33\x32\x5a\x17\x0d\x31\x33\x30\x38\x31\x34\x31\x38\x32\x39\x33\x32\x5a\x30\x31\x31\x2f\x30\x2d\x06\x03\x55\x04\x03\x13\x26\x50\x69\x6c\x6f\x74\x47\x6e\x75\x62\x62\x79\x2d\x30\x2e\x34\x2e\x31\x2d\x34\x37\x39\x30\x31\x32\x38\x30\x30\x30\x31\x31\x35\x35\x39\x35\x37\x33\x35\x32\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x8d\x61\x7e\x65\xc9\x50\x8e\x64\xbc\xc5\x67\x3a\xc8\x2a\x67\x99\xda\x3c\x14\x46\x68\x2c\x25\x8c\x46\x3f\xff\xdf\x58\xdf\xd2\xfa\x3e\x6c\x37\x8b\x53\xd7\x95\xc4\xa4\xdf\xfb\x41\x99\xed\xd7\x86\x2f\x23\xab\xaf\x02\x03\xb4\xb8\x91\x1b\xa0\x56\x99\x94\xe1\x01\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x47\x00\x30\x44\x02\x20\x60\xcd\xb6\x06\x1e\x9c\x22\x26\x2d\x1a\xac\x1d\x96\xd8\xc7\x08\x29\xb2\x36\x65\x31\xdd\xa2\x68\x83\x2c\xb8\x36\xbc\xd3\x0d\xfa\x02\x20\x63\x1b\x14\x59\xf0\x9e\x63\x30\x05\x57\x22\xc8\xd8\x9b\x7f\x48\x88\x3b\x90\x89\xb8\x8d\x60\xd1\xd9\x79\x59\x02\xb3\x04\x10\xdf";


void get_certificate(struct Cert *cert)
{
    // write a random certificate in X.509 DER format

    byte *cert_data;
    int cert_data_len;

    cert_data_len = sizeof(attestation_DER_cert);
    cert_data = (byte *)malloc(cert_data_len);

    // write certificate
    memcpy(cert_data, attestation_DER_cert, cert_data_len);

    cert->data = cert_data;
    cert->size = cert_data_len;
    return;
}

const char handlekey[] = "owo_uWu_OwO_uwu_UwU";
void store(byte *app_hash, int hash_len, struct EncryptionKey k_priv,struct Handle *h)
{
    // TODO: improve
    byte *data;
    int data_len;
    // copy the app_hash and k_priv into data
    data_len = hash_len + k_priv.size;
    data = (byte *)malloc(data_len);
    DISPLAY_IF_DEBUG("store: hash_len");
    DISPLAY_IF_DEBUG(hash_len);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("store: k_priv.size");
    DISPLAY_IF_DEBUG(k_priv.size);
    DISPLAY_IF_DEBUG("\n");


    memcpy(data, app_hash, hash_len);
    memcpy(data + hash_len, k_priv.key, k_priv.size);

    // encrypt data with key using xor
    byte *encrypted_data;
    int encrypted_data_len;
    encrypted_data_len = data_len;
    encrypted_data = (byte *)malloc(encrypted_data_len);

    for (int i = 0; i < data_len; i++)
    {
        encrypted_data[i] = data[i] ^ handlekey[i % (sizeof(handlekey)-1)];
    }

    // write into handle
    h->size = data_len;
    h->data = encrypted_data;
}

int retrieve(byte *app_hash, byte*buffer,struct Handle h ,struct EncryptionKey*k_priv)
{
    // TODO: improve using encryption
    // get k_priv from handle
    byte *data;
    // int data_len;
    // data_len = h.size;
    data = (byte *)malloc(h.size);

    memcpy(data, h.data, h.size);

    // decrypt data with key using xor
    byte *decrypted_data;
    // int decrypted_data_len;
    // decrypted_data_len = data_len;
    decrypted_data = (byte *)malloc(h.size);

    for (int i = 0; i < h.size; i++)
    {
        decrypted_data[i] = data[i] ^ handlekey[i % (sizeof(handlekey) - 1)];
    }

    memcpy(k_priv->key, decrypted_data + 32, k_priv->size);


    if (memcmp(decrypted_data, app_hash, 32) != 0)
    {
        DISPLAY_IF_DEBUG("check_handle: priv_k is not a valid private key");
        DISPLAY_IF_DEBUG("\n");
        // reply with  Response Message: Error: Invalid Handle
        byte*end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return 0 ;
    }
    DISPLAY_IF_DEBUG("check_handle: priv_k is a valid private key");
    DISPLAY_IF_DEBUG("\n");

    return 1;

    // memcpy(k_priv->key, h.data + hash_len, k_priv->size);

}
struct KeyPair generateKeyPair(uECC_Curve curve)
{
    KeyPair k;
    uECC_make_key(k.publicKey.key, k.privateKey.key, curve);
    k.publicKey.size = uECC_curve_public_key_size(curve);
    k.privateKey.size = uECC_curve_private_key_size(curve);
    return k;
}

uint8_t private_k[36]; //32
uint8_t public_k[68]; //64
byte handle[64];
byte sha256_hash[32];


void append_sign(byte* signature,int*packet_length){

	//convert signature format
	//http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

	cont_response[(*packet_length)++] = 0x30; //header: compound structure

	uint8_t *total_len = &cont_response[*packet_length];
	
    cont_response[*packet_length] = 0x44; //total length (32 + 32 + 2 + 2)
    *packet_length += 1;

	cont_response[(*packet_length)++] = 0x02;  //header: integer


	if (signature[0]>0x7f) {
   	cont_response[(*packet_length)++] = 33;  //33 byte
		cont_response[(*packet_length)++] = 0;
		(*total_len)++; //update total length
        DISPLAY_IF_DEBUG("append_sign: signature[0]>0x7f");
	}  else {
        DISPLAY_IF_DEBUG("append_sign: signature[0]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte
	}


	memcpy(cont_response+*packet_length, signature, 32); //R value
	*packet_length +=32;
	cont_response[(*packet_length)++] = 0x02;  //header: integer

	if (signature[32]>0x7f) {
        DISPLAY_IF_DEBUG("append_sign: signature[32]>0x7f");
		cont_response[(*packet_length)++] = 33;  //32 byte
		cont_response[(*packet_length)++] = 0;

		(*total_len)++;	//update total length

	} else {
        DISPLAY_IF_DEBUG("append_sign: signature[32]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte

	}


	memcpy(cont_response+*packet_length, signature+32, 32); //R value
	*packet_length +=32;
    DISPLAY_IF_DEBUG("FINISHED APPENDING SIGN");
    return;
}

void *register_origin(byte*buffer,byte *message, int size)
{


    // signature must be 2*curve_size long
    Cert cert;
    Handle h;
    // uECC_Curve curve = uECC_secp256r1();
    KeyPair kp = generateKeyPair(curve);
    h.size = 64;

    byte* challange = message; 
    byte *application = challange + 32;

    DISPLAY_IF_DEBUG("challange:");
    debug_dump_hex(challange, 32);
    DISPLAY_IF_DEBUG("application:");
    debug_dump_hex(application, 32);

    store(application, 32, kp.privateKey, &h); // TODO: this is also an importannt part, reimplement with encryption

    // int data_to_sign_len = 1 + 32 + 32 + h.size + kp.publicKey.size;
    // byte *data_to_sign;
    // data_to_sign = (byte *)malloc(data_to_sign_len);

    // if (data_to_sign == NULL)
    // {
    //     DISPLAY_IF_DEBUG("register_origin: malloc failed");
    //     return;
    // }

    // copy zero in the first place TODO: this is the importatnt part, this actually gets encrpyted
    byte* actual_p_key = (byte *)malloc(kp.publicKey.size+1);
    actual_p_key[0] = 0x04;
    memcpy(actual_p_key+1, kp.publicKey.key, kp.publicKey.size);
    char zero = '\0';

    SHA256_CTX ctx;


    sha256_init(&ctx);
    sha256_update(&ctx, &zero, 1);
    sha256_update(&ctx, application, 32);
    sha256_update(&ctx, challange, 32);
    sha256_update(&ctx, h.data, h.size);
    sha256_update(&ctx, actual_p_key, kp.publicKey.size+1);
    // sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, sha256_hash);


    byte *signature = (byte *)malloc(2*uECC_curve_private_key_size(curve));
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

    DISPLAY_IF_DEBUG("deterministic sign");
	uECC_sign_deterministic((uint8_t *) attestation_key,
                                    sha256_hash,
                                    32,
                                    &ectx.uECC,
                                    signature,
                                    curve);

    
    int packet_length = 0;
    *cont_response = 0x05;
    packet_length++;
    memcpy(cont_response + 1,actual_p_key, 65);
    packet_length += 65;
    *(cont_response + 66) = h.size;
    packet_length++;
    memcpy(cont_response + 67, h.data, h.size);
    packet_length += h.size;

    memcpy(cont_response+packet_length, attestation_DER_cert, sizeof(attestation_DER_cert));

	packet_length += sizeof(attestation_DER_cert)-1;

    DISPLAY_IF_DEBUG("signature:");
    debug_dump_hex(signature, 2 * uECC_curve_private_key_size(curve));
    DISPLAY_IF_DEBUG("\n");

    append_sign(signature,&packet_length);


    DISPLAY_IF_DEBUG("handle:");
    DISPLAY_IF_DEBUG(h.size);
    debug_dump_hex(h.data, h.size);
    DISPLAY_IF_DEBUG("\n");



    //free(signature);

    byte*end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length +=2;
    send_response_cont(buffer, packet_length);
}
// ref: https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.pdf
// message size distribution : 1,32,32,1,L
// control byte, challenge, application, handle len L, handle
void authenticate_origin(byte*buffer,byte *message, int size, int*out_size)
{
    
    byte* challange = message;
    byte* application = challange + 32;
    byte* handle_len = application + 32;
    byte* handle = handle_len + 1;

    DISPLAY_IF_DEBUG("challange:");
    debug_dump_hex(challange, 32);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("application:");
    debug_dump_hex(application, 32);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("handle_len:");
    debug_dump_hex(handle_len, 1);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("handle:");
    debug_dump_hex(handle, *handle_len);
    DISPLAY_IF_DEBUG("\n");

    // byte*endof = cont_response;
    // ADD_SW_WRONG_DATA(endof);
    // send_response_cont(buffer, 2);
    // return;

    // // if (*CB == 0x07)
    // {
    //     DISPLAY_IF_DEBUG("authenticate_origin: CB = 0x07");
    //     // reply with  Response Message: Error: Test­of­User­Presence Required
    //     byte*end = cont_response;
    //     ADD_SW_COND(end);
    //     send_response_cont(buffer, 2);
    //     return;

    // }


    Handle h;
    h.data = handle;
    h.size = *handle_len;

    EncryptionKey k_priv;
    k_priv.size = uECC_curve_private_key_size(curve);
    if (retrieve(application, buffer, h,&k_priv)==0){
        DISPLAY_IF_DEBUG("authenticate_origin: retrieve failed");
        return;
    }
    byte user_presence = 0x01; // TODO: change this to a button press
    uint32_t user_presence_counter = universal_counter++;

    uint8_t *signature = response;
    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, application, 32);
    sha256_update(&ctx, &user_presence, 1);
    sha256_update(&ctx, (byte*)&user_presence_counter, 4);
    sha256_update(&ctx, challange, 32);



    sha256_final(&ctx, sha256_hash);


	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

    DISPLAY_IF_DEBUG("deterministic sign");
	uECC_sign_deterministic((uint8_t *) k_priv.key,
                                        sha256_hash,
                                        32,
                                        &ectx.uECC,
                                        signature,
                                        curve);

    // generate response
    int packet_length = 0;
    memcpy(cont_response, &user_presence, 1);
    packet_length++;
    memcpy(cont_response + 1, &user_presence_counter, 4);
    packet_length += 4;

    DISPLAY_IF_DEBUG("signature:");
    debug_dump_hex(signature, 1 + 4 + 2 * uECC_curve_private_key_size(curve));
    DISPLAY_IF_DEBUG("\n");

    append_sign(signature, &packet_length);

    //memcpy(cont_response + 5, signature, 2 * uECC_curve_private_key_size(curve));



    DISPLAY_IF_DEBUG("authenticate_origin: response:");
    DISPLAY_IF_DEBUG(packet_length);
    debug_dump_hex(cont_response, packet_length);

    DISPLAY_IF_DEBUG("SENDING RESPONSE");
    byte*end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length += 2;
    send_response_cont(buffer,packet_length );
    return;
}

void check_handle(byte*buffer,byte *message, int size, int*out_size){
    byte* application = message+32;
    
    byte handle_len = *(message + 32 + 32);
    byte *handle = message + 32 + 32 + 1;

    DISPLAY_IF_DEBUG("check_handle: handle_len:");
    DISPLAY_IF_DEBUG(handle_len);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("check_handle: handle:");
    debug_dump_hex(handle, handle_len);
    DISPLAY_IF_DEBUG("\n");

    // decode handle using handlekey

    for (int i = 0; i < handle_len; i++)
    {
        handle[i] ^= handlekey[i % (sizeof(handlekey)-1)];
    }

    byte * h_app = handle;

    DISPLAY_IF_DEBUG("check_handle: h_app:");
    debug_dump_hex(h_app, 32);
    DISPLAY_IF_DEBUG("\n");

    // check if priv_k is a valid private key
    // by comparing the application parameter

    if (memcmp(h_app, application, 32) != 0)
    {
        DISPLAY_IF_DEBUG("check_handle: priv_k is not a valid private key");
        DISPLAY_IF_DEBUG("\n");
        // reply with  Response Message: Error: Invalid Handle
        byte*end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return;
    } else {
        DISPLAY_IF_DEBUG("check_handle: priv_k is a valid private key");
        DISPLAY_IF_DEBUG("\n");

        // reply with  Response Message: TEST OF USER PRESENCE REQUIRED (this means success)
        byte*end = cont_response;
        ADD_SW_COND(end);
        send_response_cont(buffer, 2);
        return; 
    }


}


#pragma mark - SHA-256 Setup

#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32

void setup()
{

    Serial.begin(9600);
    uECC_set_rng(&RNG);

    Serial.println("U2F");
}

#pragma mark - COMMUNICATION

int init_response(byte *buffer)
{
    // TODO: Implement this

    DISPLAY_IF_DEBUG("init_response");

    int channel_id = *(int *)buffer;

    DISPLAY_HEX_IF_DEBUG(channel_id);

    int packet_length = buffer[5] << 8 | buffer[6];

    int i;

    memcpy(response, buffer, 5);

    SET_MSG_LEN(response, 17);

    memcpy(response + 7, buffer + 7, packet_length); // nonce

    i = 7 + packet_length;

    if (channel_id == -1)
    {

        channel_id = allocate_channel(0);
    }
    else
    {

        DISPLAY_IF_DEBUG("using existing channel id");

        allocate_channel(channel_id);
    }

    memcpy(response + i, &channel_id, 4);

    i += 4;

    response[i++] = U2FHID_IF_VERSION;
    response[i++] = 1; // major
    response[i++] = 0;
    response[i++] = 1; // build
    response[i++] = 0; // capabilities

    DISPLAY_IF_DEBUG("SENT RESPONSE");

    RawHID.send(response, 100);

    DISPLAY_HEX_IF_DEBUG(channel_id);

    return channel_id;
}

void process_packet(byte *buffer)
{

    DISPLAY_IF_DEBUG("process_packet");

    unsigned char cmd = buffer[4]; // cmd or continuation

    DISPLAY_HEX_IF_DEBUG((int)cmd);

    int packet_length = buffer[5] << 8 | buffer[6];

    if (cmd > U2FHID_INIT || cmd == U2FHID_LOCK)
    {
        return error_invalid_cmd();
    }

    if (cmd == U2FHID_PING)
    {

        if (packet_length <= MAX_PACKET_LENGTH_INIT)
        {

            DISPLAY_IF_DEBUG("Sending ping response");
            RawHID.send(buffer, 100);
        }
        else
        {

            // when packet large, send first one

            DISPLAY_IF_DEBUG("SENT RESPONSE");

            RawHID.send(buffer, 100);

            packet_length -= MAX_PACKET_LENGTH_INIT;

            byte p = 0;

            int offset = 7 + MAX_PACKET_LENGTH_INIT;

            while (packet_length > 0)
            {

                memcpy(response, buffer, 4); // copy channel id

                response[4] = p++;

                response[4] = p;

                RawHID.send(response, 100);

                packet_length -= MAX_PACKET_LENGTH_CONT;

                packet_length -= MAX_PACKET_LENGTH_CONT;
                offset += MAX_PACKET_LENGTH_CONT;

                p++;

                delayMicroseconds(PACKET_DELAY_US);
            }

            DISPLAY_IF_DEBUG("Sending large ping response");
        }
    }

    if (cmd == U2FHID_MSG)
        process_message(buffer);

    // if (cmd == U2FHID_MSG) //. TODO: @torq 
    //     process_message(buffer);
}

void process_message(byte *buffer)
{

    int packet_length = buffer[5] << 8 | buffer[6];

    DISPLAY_IF_DEBUG("message in");
    DISPLAY_IF_DEBUG(packet_length);

    byte *message = buffer + 7;

    DISPLAY_IF_DEBUG("DATA:");
    debug_hex_loop(buffer, 7, 7 + packet_length);

    // todo: check CLA = 0
    byte CLA = message[0];

    if (CLA != 0)
    {
        respondErrorPDU(buffer, SW_CLA_NOT_SUPPORTED);
        return;
    }

    byte INST = message[1];

    byte PAYLOAD = message[2];

    // byte PAYLOAD2 = message[3];

    int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

    byte *data = &message[7];

    DISPLAY_IF_DEBUG("INST:");
    DISPLAY_HEX_IF_DEBUG(INST);

    switch (INST)
    {

    case U2F_REGISTER:
    {
        DISPLAY_IF_DEBUG("U2F_REGISTER");
        register_origin(buffer,data, reqlength);
        //working_register(buffer,data);
        // DISPLAY_IF_DEBUG("SENDING RESPONSE");
        
        // byte*end = cont_response + size;
        // ADD_SW_OK(end);
        // size +=2;
        // send_response_cont(buffer, size);
        // return;
    }
    break;

    case U2F_AUTHENTICATE:
    {
        DISPLAY_IF_DEBUG("U2F_AUTHENTICATE");
        // if cb == 07 authenticate handle
        // if cb == 03 authenticate origin
        byte cb = PAYLOAD;
        if (cb == U2F_AUTH_CHECK_ONLY)
        {
            // message:error:test­of­user­presence­required (note that despite the name this signals a success condition).
            // If the key handle was not created by this U2F token, or if it was created for a different application 
            //parameter, the token MUST respond with an authentication response message:error:bad­key­handle.
            int size;
            DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_HANDLE");  
            check_handle(buffer,data, reqlength, &size);
            return;


        }
        else if (cb == U2F_AUTH_ENFORCE)
        {
        int size;
            DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_ORIGIN");
            authenticate_origin(buffer,data, reqlength, &size);
        }
        else
        {
            DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_UNKNOWN");
            respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
            return;
        }
    }
    break;

    case U2F_VERSION:
    {

        if (reqlength != 0)
        {
            respondErrorPDU(buffer, SW_WRONG_LENGTH);
            return;
        }

        SET_MSG_LEN(buffer, 8); // len("U2F_V2") + 2 byte SW

        byte *datapart = buffer + 7;

        memcpy(datapart, "U2F_V2", 6);

        datapart += 6;

        ADD_SW_OK(datapart);

        RawHID.send(buffer, 100);
    }
    break;

    default:
    {
        respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
    };
    }
}

void send_response_cont(byte *request, int packet_length)
{
    // send message with cont. packets

    DISPLAY_IF_DEBUG("send_response of length");
    DISPLAY_IF_DEBUG(packet_length);

    debug_hex_loop(cont_response, 0, packet_length);
    DISPLAY_IF_DEBUG("\n\n\n\n");

    // copy channel id
    // note that this will always sit in our msg at index 4,
    // so no need to recopy it in cont. packets
    memcpy(response, request, 4);

    response[4] = U2FHID_MSG;

    int r = min(packet_length, MAX_PACKET_LENGTH_INIT);

    SET_MSG_LEN(response, packet_length);

    memcpy(response + 7, cont_response, r);

    RawHID.send(response, 100);

    packet_length -= r;

    byte p = 0;

    int offset = MAX_PACKET_LENGTH_INIT;

    while (packet_length > 0)
    {

        response[4] = p++;

        memcpy(response + 5, cont_response + offset, MAX_PACKET_LENGTH_CONT);

        RawHID.send(response, 100);

        packet_length -= MAX_PACKET_LENGTH_CONT;
        offset += MAX_PACKET_LENGTH_CONT;

        delayMicroseconds(PACKET_DELAY_US);
    }
}

#pragma mark - CHANNEL MANAGERS

int find_channel_index(int channel_id)
{

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {

        if (channel_status[i].channel_id == channel_id)
        {

            channel_status[i].last_millis = millis();

            return i;
        }
    }

    return -1;
}

int allocate_new_channel()
{
    // alloace new channel_id
    int channel_id = 1;

    while (true)
    {

        bool found = false;

        for (int i = 0; i < CHANNEL_COUNT; i++)
        {

            if (channel_status[i].state != Available)
            {

                if (channel_status[i].channel_id == channel_id)
                {

                    found = true;
                    channel_id++;

                    break;
                }
            }
        }

        if (!found)
            break;
    }

    return channel_id;
}

int allocate_channel(int channel_id)
{

    bool free_slot = false;

    if (channel_id == 0)
        channel_id = allocate_new_channel();

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {

        if (channel_status[i].state == Available)
        {

            free_slot = true;
            break;
        }
    }

    if (!free_slot)
        cleanup_timeout();

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {

        CHANNEL_STATUS &c = channel_status[i];

        if (c.state == Available)
        {

            c.channel_id = channel_id;
            c.state = Wait_init;
            c.last_millis = millis();

            return channel_id;
        }
    }

    return 0;
}

// HELPER FUNCTIONS

void set_other_timeout()
{

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {

        if (channel_status[i].state == Wait_cont)
        {

            DISPLAY_IF_DEBUG("set_other_timeout");

            channel_status[i].state = Timeout;
        }
    }
}

void cleanup_timeout()
{

    for (int i = 0; i < CHANNEL_COUNT; i++)
    {

        CHANNEL_STATUS &c = channel_status[i];

        int m = millis();

        if (c.state != Available)
        {

            // hmmm... using U2FHID_TRANS_TIMEOUT for timeout as of now, but
            // we may want to modify it later...

            if ((m - c.last_millis) > U2FHID_TRANS_TIMEOUT)
                c.state = Available;
        }
    }
}

// ERROR HANDLING

void respondErrorPDU(byte *buffer, int err)
{

    SET_MSG_LEN(buffer, 2); // len("") + 2 byte SW

    byte *datapart = buffer + 7;

    (*datapart++) = (err >> 8) & 0xff;
    (*datapart++) = err & 0xff;

    RawHID.send(buffer, 100);
}

void send_u2f_error(byte *buffer, int code)
{

    memcpy(response, buffer, 4);

    response[4] = U2FHID_ERROR;

    SET_MSG_LEN(response, 1);

    response[7] = code & 0xff;

    DISPLAY_IF_DEBUG("u2f error:");
    DISPLAY_IF_DEBUG(code);

    RawHID.send(response, 100);
}

void error_invalid_channel_id()
{
    return send_u2f_error(recieved, ERR_SYNC_FAIL);
}

void error_timeout()
{
    return send_u2f_error(recieved, ERR_MSG_TIMEOUT);
}

void error_invalid_length()
{
    return send_u2f_error(recieved, ERR_INVALID_LEN);
}

void error_invalid_seq()
{
    return send_u2f_error(recieved, ERR_INVALID_SEQ);
}

void error_channel_busy()
{
    return send_u2f_error(recieved, ERR_CHANNEL_BUSY);
}

void error_invalid_cmd()
{
    return send_u2f_error(recieved, ERR_INVALID_CMD);
}

void loop()
{

    int recv = RawHID.recv(recieved, 0);

    if (recv > 0)
    {

        DISPLAY_IF_DEBUG("recieved packet");
        debug_dump_hex(recieved, recv);

        int channel_id;
        memcpy(&channel_id, recieved, sizeof(channel_id));

        DISPLAY_IF_DEBUG("\nchannel_id:");
        DISPLAY_HEX_IF_DEBUG(channel_id);

        if (channel_id == 0)
            return error_invalid_channel_id();

        unsigned char is_cont_packet = recieved[4];

        int packet_length = (recieved[5]) << 8 | recieved[6];

        if (!IS_CONTINUATION_PACKET(is_cont_packet))
        {

            DISPLAY_IF_DEBUG("LENGTH");
            DISPLAY_IF_DEBUG(packet_length);
        }

        if (is_cont_packet == U2FHID_INIT)
        {

            set_other_timeout();

            channel_id = init_response(recieved);

            int channel_idx = find_channel_index(channel_id);

            channel_status[channel_idx].state = Wait_init;

            return;
        }

        if (channel_id == -1)
            return error_invalid_channel_id();

        int channel_index = find_channel_index(channel_id);

        if (channel_index == -1)
        {

            DISPLAY_IF_DEBUG("allocating new channel_id");

            allocate_channel(channel_id);

            channel_index = find_channel_index(channel_id);

            if (channel_index == -1)
                return error_invalid_channel_id();
        }

        if (!IS_CONTINUATION_PACKET(is_cont_packet))
        {

            if (packet_length > MAX_PACKET_LENGTH)
                return error_invalid_length();

            if (packet_length > MAX_PACKET_LENGTH_INIT)
            {

                for (int i = 0; i < CHANNEL_COUNT; i++)
                {

                    if (channel_status[i].state == Wait_cont)
                    {

                        if (i == channel_index)
                        {

                            channel_status[i].state = Wait_init;

                            return error_invalid_seq();
                        }
                        else
                        {

                            return error_channel_busy();
                        }
                    }
                }

                // no other channel is waiting
                channel_status[channel_index].state = Wait_cont;

                memcpy(cont_recieved, recieved, 64);

                cont_data_len = packet_length;

                cont_data_offset = MAX_PACKET_LENGTH_INIT;

                expected_next_packet = 0;

                return;
            }

            set_other_timeout();

            process_packet(recieved);

            channel_status[channel_index].state = Wait_init;
        }
        else
        {

            if (channel_status[channel_index].state != Wait_cont)
            {

                DISPLAY_IF_DEBUG("ignore stray packet");
                DISPLAY_HEX_IF_DEBUG(channel_id);

                return;
            }

            // this is a continuation
            if (is_cont_packet != expected_next_packet)
            {

                channel_status[channel_index].state = Wait_init;

                return error_invalid_seq();
            }
            else
            {

                memcpy(cont_recieved + cont_data_offset + 7, recieved + 5, MAX_PACKET_LENGTH_CONT);

                cont_data_offset += MAX_PACKET_LENGTH_CONT;

                if (cont_data_offset < cont_data_len)
                {

                    expected_next_packet++;

                    DISPLAY_IF_DEBUG("waiting for a cont packet");

                    return;
                }

                DISPLAY_IF_DEBUG("completed");

                channel_status[channel_index].state = Wait_init;

                return process_packet(cont_recieved);
            }
        }
    }
    else
    {

        for (int i = 0; i < CHANNEL_COUNT; i++)
        {

            if (channel_status[i].state == Timeout)
            {

                DISPLAY_IF_DEBUG("send timeout");
                DISPLAY_HEX_IF_DEBUG(channel_status[i].channel_id);

                memcpy(recieved, &channel_status[i].channel_id, 4);

                // RETURN TIMEOUT ERROR
                error_timeout();

                channel_status[i].state = Wait_init;
            }

            if (channel_status[i].state == Wait_cont)
            {

                int now = millis();

                if ((now - channel_status[i].last_millis) > 500)
                {

                    DISPLAY_IF_DEBUG("SET timeout");

                    channel_status[i].state = Timeout;
                }
            }
        }
    }
}




void working_register(byte*buffer,byte*message){
    	byte *challenge = message;
	byte *app_param = message+32;

	memset(public_k, 0, sizeof(public_k));
	memset(private_k, 0, sizeof(private_k));

	uECC_make_key(public_k + 1, private_k, curve); //so we ca insert 0x04

	public_k[0] = 0x04;

	DISPLAY_IF_DEBUG("PUBLIC KEY");
	debug_hex_loop(public_k, 0, sizeof(public_k));
	DISPLAY_IF_DEBUG("\nPRIV KEY");
	debug_hex_loop(private_k, 0, sizeof(private_k));
	DISPLAY_IF_DEBUG("\n\n");

	//construct hash
	memcpy(handle, app_param, 32);
	memcpy(handle+32, private_k, 32);

	for (int i =0; i < 64; i++) {
		handle[i] ^= handlekey[i % (sizeof(handlekey)-1)];
	}

	SHA256_CTX ctx;
	sha256_init(&ctx);

	cont_response[0] = 0x00;

	sha256_update(&ctx, cont_response, 1);

	DISPLAY_IF_DEBUG("APP_PARAM");
	debug_hex_loop(app_param, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, app_param, 32);

	DISPLAY_IF_DEBUG("CHALLENGE");
	debug_hex_loop(challenge, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, challenge, 32);

	DISPLAY_IF_DEBUG("HANDLE");
	debug_hex_loop(handle, 0, 64);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, handle, 64);

	sha256_update(&ctx, public_k, 65);

	DISPLAY_IF_DEBUG("PUBLIC KEY");
	debug_hex_loop(public_k, 0, 65);
	DISPLAY_IF_DEBUG("\n");

	sha256_final(&ctx, sha256_hash);

	DISPLAY_IF_DEBUG("HASH");
	debug_hex_loop(sha256_hash, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	uint8_t *signature = response;

	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

	uECC_sign_deterministic((uint8_t *) attestation_key,
																			sha256_hash,
																			32,
																			&ectx.uECC,
																			signature,
																			curve);

	int packet_length = 0;

	cont_response[packet_length++] = 0x05;

	memcpy(cont_response + packet_length, public_k, 65);

	packet_length += 65;

	cont_response[packet_length++] = 64; //length of handle

	memcpy(cont_response+packet_length, handle, 64);

	packet_length += 64;

    //append_cert(signature, &packet_length);
    
    
	memcpy(cont_response+packet_length, attestation_DER_cert, sizeof(attestation_DER_cert));

	packet_length += sizeof(attestation_DER_cert)-1;

    append_sign(signature, &packet_length);
	//convert signature format
	//http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
/*
	cont_response[packet_length++] = 0x30; //header: compound structure
	uint8_t *total_len = &cont_response[packet_length];
	cont_response[packet_length++] = 0x44; //total length (32 + 32 + 2 + 2)
	cont_response[packet_length++] = 0x02;  //header: integer

	if (signature[0]>0x7f) {
   	cont_response[packet_length++] = 33;  //33 byte
		cont_response[packet_length++] = 0;
		(*total_len)++; //update total length
	}  else {
		cont_response[packet_length++] = 32;  //32 byte
	}

	memcpy(cont_response+packet_length, signature, 32); //R value
	packet_length +=32;
	cont_response[packet_length++] = 0x02;  //header: integer

	if (signature[32]>0x7f) {

		cont_response[packet_length++] = 33;  //32 byte
		cont_response[packet_length++] = 0;

		(*total_len)++;	//update total length

	} else {

		cont_response[packet_length++] = 32;  //32 byte

	}

	memcpy(cont_response+packet_length, signature+32, 32); //R value
	packet_length +=32;
    */
    DISPLAY_IF_DEBUG("sending response");

    byte*end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length += 2;
    send_response_cont(buffer,packet_length );
}