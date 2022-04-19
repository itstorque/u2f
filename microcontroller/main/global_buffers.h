#ifndef BUFFERS_DEFINED
#define BUFFERS_DEFINED

#include "WProgram.h"

#pragma mark - i/o buffers

byte recieved[64];
byte response[64];

// in case long msg, require subdividing using cont packets
byte expected_next_packet;
int cont_data_len;
int cont_data_offset;

byte cont_recieved[1024];
byte cont_response[1024];

#endif
