#include <stdint.h>
#include "WProgram.h"

#ifndef protocol_file
#define protocol_file

#include "debug.h"

#include "message_headers.h"
#include "error_handling.h"

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"

#ifndef encryption
#define encryption
#include "encryption.h"
#endif

extern struct uECC_Curve_t * curve; //P-256

// buffers

extern byte recieved[64];
extern byte response[64];

// in case long msg, require subdividing using cont packets
extern byte expected_next_packet;
extern int cont_data_len;
extern int cont_data_offset;

extern byte cont_recieved[1024];
extern byte cont_response[1024];

// keys

extern uint8_t private_k[36]; //32
extern uint8_t public_k[68]; //64

extern byte handle[64];
extern byte sha256_hash[32];

extern char attestation_key[303];
extern char attestation_DER_cert[304];
extern char handlekey[20];

void protocol_register(byte (*respond)(byte, int), byte *buffer, byte *message, int reqlength);

void protocol_authenticate(byte (*respond)(byte, int));

#endif