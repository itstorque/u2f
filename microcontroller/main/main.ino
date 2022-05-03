// persistent memory lib
#include <EEPROM.h>

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"

// debug state
#undef DEBUG
#define DEBUG

#include "debug.h"

#include "channels.h"

#include "packets.h"

#include "buffers.h"

#include "channel_manager.h"

#include "error_handling.h"

#include "counter.h"

#pragma mark - SETUP

#include "keys.h"

#include "encryption.h"

#include "button.h"

void setup() {

	Serial.begin(9600);
	uECC_set_rng(&RNG);

	Serial.println("U2F");

	pinMode(BUTTON_PIN, INPUT);

}

// TODO: use EEPROM (counter.h methods) instead of this variable
int universal_counter = 0;

#include "protocol.h"

#include "message_processing.h"

#include "communication.h"

void loop() {

	int recv = RawHID.recv(recieved, 0);

	if (recv > 0) {

		received_packet(recv);

	} else {

		await_packet();

	}

}
