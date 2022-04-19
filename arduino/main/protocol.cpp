#include "protocol.h"

void protocol_register(byte (*respond)(byte, int), byte *buffer, byte *message, int reqlength) {
	// test implementation of u2f register for debugging

	if (reqlength!=64) {
		respondErrorPDU(buffer, SW_WRONG_LENGTH);
		return;
	}

	byte *payload = message + 7;
	byte *challenge = payload;
	byte *app_param = payload+32;

	memset(public_k, 0, sizeof(public_k));
	memset(private_k, 0, sizeof(private_k));

	uECC_make_key(public_k + 1, private_k, curve); //so we ca insert 0x04

	public_k[0] = 0x04;

	DISPLAY_IF_DEBUG("PUBLIC KEY");
	DEBUG_HEX_LOOP(public_k, 0, sizeof(public_k));
	DISPLAY_IF_DEBUG("\nPRIV KEY");
	DEBUG_HEX_LOOP(private_k, 0, sizeof(private_k));
	DISPLAY_IF_DEBUG("\n\n");

	//construct hash
	memcpy(handle, app_param, 32);
	memcpy(handle+32, private_k, 32);

	for (int i =0; i < 64; i++) {
		handle[i] ^= handlekey[i % (sizeof(handlekey)-1)];
	}

	SHA256_CTX ctx;
	sha256_init(&ctx);

	cont_response[0] = 0x00;

	sha256_update(&ctx, cont_response, 1);

	DISPLAY_IF_DEBUG("APP_PARAM");
	DEBUG_HEX_LOOP(app_param, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, app_param, 32);

	DISPLAY_IF_DEBUG("CHALLENGE");
	DEBUG_HEX_LOOP(challenge, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, challenge, 32);

	DISPLAY_IF_DEBUG("HANDLE");
	DEBUG_HEX_LOOP(handle, 0, 64);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, handle, 64);

	sha256_update(&ctx, public_k, 65);

	DISPLAY_IF_DEBUG("PUBLIC KEY");
	DEBUG_HEX_LOOP(public_k, 0, 65);
	DISPLAY_IF_DEBUG("\n");

	sha256_final(&ctx, sha256_hash);

	DISPLAY_IF_DEBUG("HASH");
	DEBUG_HEX_LOOP(sha256_hash, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	uint8_t *signature = response;

	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

	uECC_sign_deterministic((uint8_t *) attestation_key,
																			sha256_hash,
																			32,
																			&ectx.uECC,
																			signature,
																			curve);

	int packet_length = 0;

	cont_response[packet_length++] = 0x05;

	memcpy(cont_response + packet_length, public_k, 65);

	packet_length += 65;

	cont_response[packet_length++] = 64; //length of handle

	memcpy(cont_response+packet_length, handle, 64);

	packet_length += 64;

	memcpy(cont_response+packet_length, attestation_DER_cert, sizeof(attestation_DER_cert));

	packet_length += sizeof(attestation_DER_cert)-1;

	//convert signature format
	//http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

	cont_response[packet_length++] = 0x30; //header: compound structure
	uint8_t *total_len = &cont_response[packet_length];
	cont_response[packet_length++] = 0x44; //total length (32 + 32 + 2 + 2)
	cont_response[packet_length++] = 0x02;  //header: integer

	if (signature[0]>0x7f) {
   	cont_response[packet_length++] = 33;  //33 byte
		cont_response[packet_length++] = 0;
		(*total_len)++; //update total length
	}  else {
		cont_response[packet_length++] = 32;  //32 byte
	}

	memcpy(cont_response+packet_length, signature, 32); //R value
	packet_length +=32;
	cont_response[packet_length++] = 0x02;  //header: integer

	if (signature[32]>0x7f) {

		cont_response[packet_length++] = 33;  //32 byte
		cont_response[packet_length++] = 0;

		(*total_len)++;	//update total length

	} else {

		cont_response[packet_length++] = 32;  //32 byte

	}

	memcpy(cont_response+packet_length, signature+32, 32); //R value
	packet_length +=32;

	byte *last = cont_response+packet_length;
	ADD_SW_OK(last);
	packet_length += 2;

	respond(buffer, packet_length);

}

void protocol_authenticate(byte (*respond)(byte, int)) {
	// test implementation of u2f authenticate for debugging


}
