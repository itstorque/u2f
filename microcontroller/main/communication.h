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

void send_response_cont(byte *request, int packet_length) {
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

	while (packet_length > 0) {

		response[4] = p++;

		memcpy(response + 5, cont_response + offset, MAX_PACKET_LENGTH_CONT);

		RawHID.send(response, 100);

		packet_length -= MAX_PACKET_LENGTH_CONT;
		offset        += MAX_PACKET_LENGTH_CONT;

		delayMicroseconds(PACKET_DELAY_US);

	}

}

void await_packet() {

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

void received_packet(int recv) {

	DISPLAY_IF_DEBUG("recieved packet");
	debug_dump_hex(recieved, recv);

	int channel_id;
	memcpy(&channel_id, recieved, sizeof(channel_id));

	DISPLAY_IF_DEBUG("\nchannel_id:");
	DISPLAY_HEX_IF_DEBUG(channel_id);

	if (channel_id==0) return error_invalid_channel_id();

	unsigned char is_cont_packet = recieved[4];

	int packet_length = (recieved[5]) << 8 | recieved[6];

	if (IS_NOT_CONTINUATION_PACKET( is_cont_packet )) {

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

	if (IS_NOT_CONTINUATION_PACKET( is_cont_packet )) {

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

			// DISPLAY_IF_DEBUG(" >>>> >>>> >>>> >>>> NOT EXPECTED PACKET...");

			channel_status[channel_index].state = Wait_init;

			return error_invalid_seq();

		} else {

			// DISPLAY_IF_DEBUG(" >>>> >>>> >>>> >>>> ISS EXPECTED PACKET...");

			memcpy(cont_recieved + cont_data_offset + 7, recieved + 5, MAX_PACKET_LENGTH_CONT);
			// memcpy(large_buffer + large_data_offset + 7, recv_buffer + 5);

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

}