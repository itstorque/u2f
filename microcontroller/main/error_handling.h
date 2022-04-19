#include <stdint.h>
#include "WProgram.h"

#include "debug.h"

extern byte recieved[64];
extern byte response[64];

// in case long msg, require subdividing using cont packets
extern byte expected_next_packet;
extern int cont_data_len;
extern int cont_data_offset;

extern byte cont_recieved[1024];
extern byte cont_response[1024];

#include "packets.h"

// ERROR HANDLING

void respondErrorPDU(byte *buffer, int err);

void send_u2f_error(byte *buffer, int code);

void error_invalid_channel_id();

void error_timeout();

void error_invalid_length();

void error_invalid_seq();

void error_channel_busy();

void error_invalid_cmd();
