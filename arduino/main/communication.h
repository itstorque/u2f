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

#include "channels.h"

extern CHANNEL_STATUS channel_status[CHANNEL_COUNT];

#include "message_headers.h"
#include "packets.h"

// END CHANNELS

#include "error_handling.h"

int init_response(byte *buffer);

void process_packet(byte *buffer);

void process_message(byte *buffer);

void send_response_cont(byte *request, int packet_length);

int find_channel_index(int channel_id);

int allocate_new_channel();

int allocate_channel(int channel_id);

// HELPER FUNCTIONS

void set_other_timeout();

void cleanup_timeout();
