#include "communication.h"

#pragma mark - COMMUNICATION

int init_response(byte *buffer) {
	// TODO: Implement this

	DISPLAY_IF_DEBUG("init_response");

	int channel_id = *(int*) buffer;

	DISPLAY_HEX_IF_DEBUG(channel_id);

	int packet_length = buffer[5] << 8 | buffer[6];

	int i;

	memcpy(response, buffer, 5);

	SET_MSG_LEN(response, 17);

	memcpy(response + 7, buffer + 7, packet_length); //nonce

	i = 7 + packet_length;

	if (channel_id == -1) {

		channel_id = allocate_channel(0);

	} else {

		DISPLAY_IF_DEBUG("using existing channel id");

		allocate_channel(channel_id);

	}

	memcpy(response + i, &channel_id, 4);

	i += 4;

	response[i++] = U2FHID_IF_VERSION;
	response[i++] = 1; //major
	response[i++] = 0;
	response[i++] = 1; //build
	response[i++] = 0; //capabilities

	DISPLAY_IF_DEBUG("SENT RESPONSE");

	RawHID.send(response, 100);

	DISPLAY_HEX_IF_DEBUG(channel_id);

	return channel_id;

}

void process_packet(byte *buffer) {

	DISPLAY_IF_DEBUG("process_packet");

	unsigned char cmd = buffer[4]; //cmd or continuation

	DISPLAY_HEX_IF_DEBUG((int) cmd);

	int packet_length = buffer[5] << 8 | buffer[6];

	if (cmd > U2FHID_INIT || cmd == U2FHID_LOCK) {
		return error_invalid_cmd();
	}

	if (cmd == U2FHID_PING) {

		if (packet_length <= MAX_PACKET_LENGTH_INIT) {

			DISPLAY_IF_DEBUG("Sending ping response");
			RawHID.send(buffer, 100);

		} else {

			//when packet large, send first one

			DISPLAY_IF_DEBUG("SENT RESPONSE");

			RawHID.send(buffer, 100);

			packet_length -= MAX_PACKET_LENGTH_INIT;

			byte p = 0;

			int offset = 7 + MAX_PACKET_LENGTH_INIT;

			while (packet_length > 0) {

				memcpy(response, buffer, 4); //copy channel id

				response[4] = p;

				memcpy(response + 5, buffer + offset, MAX_PACKET_LENGTH_CONT);

				RawHID.send(response, 100);

				packet_length -= MAX_PACKET_LENGTH_CONT;
				offset        += MAX_PACKET_LENGTH_CONT;

				p++;

				delayMicroseconds(PACKET_DELAY_US);

			}

			DISPLAY_IF_DEBUG("Sending large ping response");

		}

	}

	if (cmd == U2FHID_MSG) process_message(buffer);

}

void process_message(byte *buffer) {

	int packet_length = buffer[5] << 8 | buffer[6];

	DISPLAY_IF_DEBUG("message in");
	DISPLAY_IF_DEBUG(packet_length);

	byte *message = buffer + 7;

	DISPLAY_IF_DEBUG("DATA:");
	DEBUG_HEX_LOOP(buffer, 7, 7+packet_length);

	//todo: check CLA = 0
	byte CLA = message[0];

	if (CLA != 0) {
		respondErrorPDU(buffer, SW_CLA_NOT_SUPPORTED);
		return;
	}

	byte INST = message[1];

	byte PAYLOAD = message[2];

	int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

	switch (INST) {

		case U2F_REGISTER: {

			return ;//protocol_register(buffer, message, reqlength);

			} break;

		case U2F_AUTHENTICATE: {

			return ;//protocol_authenticate();

			} break;

		case U2F_VERSION: {

				if (reqlength!=0) {
					respondErrorPDU(buffer, SW_WRONG_LENGTH);
					return;
				}

				SET_MSG_LEN(buffer, 8); //len("U2F_V2") + 2 byte SW

				byte *payload = buffer + 7;

				memcpy(payload, "U2F_V2", 6);

				payload += 6;

				ADD_SW_OK(payload);

				RawHID.send(buffer, 100);

			} break;

		default: { respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED); };

	}

}

void send_response_cont(byte *request, int packet_length) {
	// send message with cont. packets

	DISPLAY_IF_DEBUG("send_response of length");
	DISPLAY_IF_DEBUG(packet_length);

	DEBUG_HEX_LOOP(cont_response, 0, packet_length);
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

	while (packet_length > 0) {

		response[4] = p++;

		memcpy(response + 5, cont_response + offset, MAX_PACKET_LENGTH_CONT);

		RawHID.send(response, 100);

		packet_length -= MAX_PACKET_LENGTH_CONT;
		offset        += MAX_PACKET_LENGTH_CONT;

		delayMicroseconds(PACKET_DELAY_US);

	}

}

#pragma mark - CHANNEL MANAGERS

int find_channel_index(int channel_id) {

	for (int i = 0;  i < CHANNEL_COUNT; i++) {

		if (channel_status[i].channel_id == channel_id) {

			channel_status[i].last_millis = millis();

			return i;

		}

	}

	return -1;

}

int allocate_new_channel() {
	//alloace new channel_id
	int channel_id = 1;

	while (true) {

		bool found = false;

		for (int i = 0;  i < CHANNEL_COUNT; i++) {

			if (channel_status[i].state != Available) {

				if (channel_status[i].channel_id == channel_id) {

					found = true;
					channel_id++;

					break;

				}

			}

		}

		if (!found) break;

	}

	return channel_id;

}

int allocate_channel(int channel_id) {

	bool free_slot = false;

	if (channel_id==0) channel_id = allocate_new_channel();

	for (int i = 0;  i < CHANNEL_COUNT; i++) {

		if (channel_status[i].state == Available) {

			free_slot = true;
			break;

		}

	}

	if (!free_slot) cleanup_timeout();

	for (int i = 0;  i < CHANNEL_COUNT; i++) {

		CHANNEL_STATUS &c = channel_status[i];

		if (c.state == Available) {

			c.channel_id = channel_id;
			c.state = Wait_init;
			c.last_millis = millis();

			return channel_id;

		}

	}

	return 0;
}

// HELPER FUNCTIONS

void set_other_timeout() {

	for (int i = 0; i < CHANNEL_COUNT; i++) {

		if (channel_status[i].state == Wait_cont) {

			DISPLAY_IF_DEBUG("set_other_timeout");

			channel_status[i].state = Timeout;

		}

	}

}

void cleanup_timeout() {

	for (int i = 0;  i < CHANNEL_COUNT; i++) {

		CHANNEL_STATUS &c = channel_status[i];

		int m = millis();

		if (c.state != Available) {

			// hmmm... using U2FHID_TRANS_TIMEOUT for timeout as of now, but
			// we may want to modify it later...

			if ((m - c.last_millis) > U2FHID_TRANS_TIMEOUT) c.state = Available;

		}

	}

}
