// debug state
#undef DEBUG
#define DEBUG

#include "main.h"

#pragma mark - button setup

#ifdef NO_BUTTON
	// simulate button without hardware...
	int button_pressed = 0;
#endif

#pragma mark - COUNTER
// using EEPROM to keep a counter

int getCounter() {

	unsigned int address = 0;
	unsigned int value;

	EEPROM.get(address, value);

	return value;

}

void setCounter(int value) {

	unsigned int address = 0;

	EEPROM.put(address, value);

}

#pragma mark - SETUP

// TODO: hash RNG using SHA-256
// random number generator, copied from:
// https://github.com/kmackay/micro-ecc/blob/master/examples/ecc_test/ecc_test.ino
int RNG(uint8_t *dest, unsigned size) {
	// Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
	// random noise). This can take a long time to generate random data if the result of analogRead(0)
	// doesn't change very frequently.

	while (size) {
		uint8_t val = 0;
		for (unsigned i = 0; i < 8; ++i) {
			int init = analogRead(0);
			int count = 0;
			while (analogRead(0) == init) {
				++count;
			}

			if (count == 0) {
				val = (val << 1) | (init & 0x01);
			} else {
				val = (val << 1) | (count & 0x01);
			}
		}
		*dest = val;
		++dest;
		--size;
	}

	return 1;

}
#pragma mark - SHA-256 Setup

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

void init_SHA256(uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}

void update_SHA256(uECC_HashContext *base,
                   const uint8_t *message,
                   unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, message_size);
}

void finish_SHA256(uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash_result);
}

void setup() {

	Serial.begin(9600);
	uECC_set_rng(&RNG);

	Serial.println("U2F");

}

void loop() {

	int recv = RawHID.recv(recieved, 0);

	if (recv > 0) {

		DISPLAY_IF_DEBUG("recieved packet");
		debug_dump_hex(recieved, recv);

		int channel_id;
		memcpy(&channel_id, recieved, sizeof(channel_id));

		DISPLAY_IF_DEBUG("\nchannel_id:");
		DISPLAY_HEX_IF_DEBUG(channel_id);

		if (channel_id==0) return error_invalid_channel_id();

		unsigned char is_cont_packet = recieved[4];

		int packet_length = (recieved[5]) << 8 | recieved[6];

		if (!IS_CONTINUATION_PACKET( is_cont_packet )) {

			DISPLAY_IF_DEBUG("LENGTH");
			DISPLAY_IF_DEBUG(packet_length);

		}

		if (is_cont_packet == U2FHID_INIT) {

			set_other_timeout();

			channel_id = init_response(recieved);

			int channel_idx = find_channel_index(channel_id);

			channel_status[channel_idx].state = Wait_init;

			return;

		}

		if (channel_id == -1) return error_invalid_channel_id();

		int channel_index = find_channel_index(channel_id);

		if (channel_index == -1) {

			DISPLAY_IF_DEBUG("allocating new channel_id");

			allocate_channel(channel_id);

			channel_index = find_channel_index(channel_id);

			if (channel_index == -1) return error_invalid_channel_id();

		}

		if (!IS_CONTINUATION_PACKET( is_cont_packet )) {

			if (packet_length > MAX_PACKET_LENGTH) return error_invalid_length();

			if (packet_length > MAX_PACKET_LENGTH_INIT) {

				for (int i = 0; i < CHANNEL_COUNT; i++) {

					if (channel_status[i].state == Wait_cont) {

						if (i == channel_index) {

							channel_status[i].state = Wait_init;

							return error_invalid_seq();

						} else {

							return error_channel_busy();

						}

					}

				}

				//no other channel is waiting
				channel_status[channel_index].state = Wait_cont;

				memcpy(cont_recieved, recieved, 64);

				cont_data_len = packet_length;

				cont_data_offset = MAX_PACKET_LENGTH_INIT;

				expected_next_packet = 0;

				return;

			}

			set_other_timeout();

			process_packet(recieved);

			channel_status[channel_index].state= Wait_init;

		} else {

			if (channel_status[channel_index].state != Wait_cont) {

				DISPLAY_IF_DEBUG("ignore stray packet");
				DISPLAY_HEX_IF_DEBUG(channel_id);

				return;

			}

			//this is a continuation
			if (is_cont_packet != expected_next_packet) {

				channel_status[channel_index].state = Wait_init;

				return error_invalid_seq();

			} else {

				memcpy(cont_recieved + cont_data_offset + 7, cont_data_offset + 5, MAX_PACKET_LENGTH_CONT);

				cont_data_offset += MAX_PACKET_LENGTH_CONT;

				if (cont_data_offset < cont_data_len) {

					expected_next_packet++;

					DISPLAY_IF_DEBUG("waiting for a cont packet");

					return;

				}

				DISPLAY_IF_DEBUG("completed");

				channel_status[channel_index].state = Wait_init;

				return process_packet(cont_recieved);

			}

		}

	} else {

		for (int i = 0; i < CHANNEL_COUNT; i++) {

			if (channel_status[i].state == Timeout) {

				DISPLAY_IF_DEBUG("send timeout");
				DISPLAY_HEX_IF_DEBUG(channel_status[i].channel_id);

				memcpy(recieved, &channel_status[i].channel_id, 4);

				// RETURN TIMEOUT ERROR
				error_timeout();

				channel_status[i].state = Wait_init;

			}

			if (channel_status[i].state == Wait_cont) {

				int now = millis();

				if ((now - channel_status[i].last_millis)>500) {

					DISPLAY_IF_DEBUG("SET timeout");

					channel_status[i].state = Timeout;

				}

			}

		}

	}

}
