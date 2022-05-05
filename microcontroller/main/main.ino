// persistent memory lib
#include <EEPROM.h>

// encryption libs
#include "src/sha256/sha256.h"
#include "src/uECC/uECC.h"
#include "src/Crypto/src/Crypto.h"
#include "src/Crypto/src/AES.h"

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


#include "protocol.h"

void setup() {

	Serial.begin(9600);
	uECC_set_rng(&RNG);


	Serial.println("U2F_V2");
	// byte plaintext[64] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64};
	// byte ciphertext[64];


	// // encrypt(plaintext, ciphertext);

	// Serial.println("ciphertext:");
	// debug_hex_loop(ciphertext, 0, 64);

	// // decrypt(ciphertext, plaintext);

	// Serial.println("plaintext:");
	// debug_hex_loop(plaintext, 0, 64);
	// return;

	// // test aes encryption
	// byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    // aes128.setKey(key, aes128.keySize());


	// byte plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    //                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	// byte ciphertext[100] = {0};
	// //{0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
    //                 //0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
	// byte decrypted[16] = {0};

	// encrypt(&aes128, plaintext, ciphertext);
	// decrypt(&aes128, ciphertext, decrypted);

	// Serial.println("AES test");
	// Serial.println("decrypted: ");
	// for (int i = 0; i < 16; i++) {
	// 	Serial.print(decrypted[i]);
	// 	Serial.print(" ");
	// }
	// Serial.println("");
	// Serial.println("ciphertext: ");
	// for (int i = 0; i < 16; i++) {
	// 	Serial.print(ciphertext[i]);
	// 	Serial.print(" ");
	// }
	// Serial.println("");

	
    

	pinMode(BUTTON_PIN, INPUT);

}


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
