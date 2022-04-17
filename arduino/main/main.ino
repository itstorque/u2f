#include <src.h>
#include <micro-ecc/uECC.h>
// include arduino
// language: cpp

struct EncryptionKey K_wrap;

struct EncryptionKey K_app;

struct EncryptionKey Priv_attest;
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
byte store(byte origin, EncryptionKey k_priv)
{
    Encryptable origin_enc; // generate using origin
    byte obscure_o = encrypt(K_app, origin_enc);
    // interleave the obfuscated origin with the private key, encrypt it with K_wrap
    // that is the plaintext
    Encryptable plaintext;
    Handle h = encrypt(K_wrap, plaintext);
    return h;
}

// send attestations cert, batched
// persistent memory lib
#include <EEPROM.h>

// encryption libs
#include "sha256.h"
#include "uECC.h"

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
        Serial.print(data[i], HEX);
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

// managing communication channel

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

// packet helpers

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

// u2f hid transport headers from
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

// u2f raw message format header from
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

// Command status responses
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

// i/o buffers

byte recieved[64];
byte response[64];

// in case long msg, require subdividing using cont packets
byte expected_next_packet;
int cont_data_len;
int cont_data_offset;

byte cont_recieved[1024];
byte cont_response[1024];

// button setup

#ifdef NO_BUTTON
// simulate button without hardware...
int button_pressed = 0;
#endif

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

void setup()
{

    Serial.begin(9600);
    uECC_set_rng(&RNG);

    Serial.println("U2F");
}

// COMMUNICATION

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

                memcpy(response + 5, buffer + offset, MAX_PACKET_LENGTH_CONT);

                RawHID.send(response, 100);

                packet_length -= MAX_PACKET_LENGTH_CONT;

                offset += MAX_PACKET_LENGTH_CONT;

                delayMicroseconds(2500);
            }

            DISPLAY_IF_DEBUG("Sending large ping response");
        }
    }

    if (cmd == U2FHID_MSG)
        process_message(buffer);
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

    int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

    switch (INST)
    {

    case U2F_REGISTER:
    {
        register_origin(PAYLOAD, reqlength);
        // TODO: implement register
    }
    break;

    case U2F_AUTHENTICATE:
    {

        // TODO: implement authenticate
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

// CHANNEL MANAGERS

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

                memcpy(cont_recieved + cont_data_offset + 7, cont_data_offset + 5, MAX_PACKET_LENGTH_CONT);

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
