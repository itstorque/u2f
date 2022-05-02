#pragma mark - CHANNEL MANAGERS

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

// channel allocation

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