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

void setup() {

	Serial.begin(9600);
	uECC_set_rng(&RNG);

	Serial.println("U2F");

}

void loop() {

	int recv = RawHID.recv(recieved, 0);

	if (recv > 0) {

		DISPLAY_IF_DEBUG("recieved packet");
		DEBUG_DUMP_HEX(recieved, recv);

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
