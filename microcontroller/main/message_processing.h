void process_message(byte *buffer) {

	int packet_length = buffer[5] << 8 | buffer[6];

	DISPLAY_IF_DEBUG("message in");
	DISPLAY_IF_DEBUG(packet_length);

	byte *message = buffer + 7;

	DISPLAY_IF_DEBUG("DATA:");
	debug_hex_loop(buffer, 7, 7+packet_length);

	//todo: check CLA = 0
	byte CLA = message[0];

	if (CLA != 0) {
		respondErrorPDU(buffer, SW_CLA_NOT_SUPPORTED);
		return;
	}

	byte INST = message[1];

	byte PAYLOAD = message[2];

	int reqlength = (message[4] << 16) | (message[5] << 8) | message[6];

	byte *data = &message[7];

    DISPLAY_IF_DEBUG("INST:");
    DISPLAY_HEX_IF_DEBUG(INST);

	switch (INST) {

		case U2F_REGISTER: {

			DISPLAY_IF_DEBUG("U2F_REGISTER");
			return register_origin(buffer,data, reqlength);

			// return protocol_register(buffer, message, reqlength);

			// DISPLAY_IF_DEBUG("U2F_REGISTER");
			// int size;
			// register_origin(data, reqlength, &size);
			// DISPLAY_IF_DEBUG("SENDING RESPONSE");
			
			// byte *end = cont_response + size;
			// ADD_SW_OK(end);
			// size +=2;
			// send_response_cont(buffer, size);
			// return;

		} break;

		case U2F_AUTHENTICATE: {

			byte cb = PAYLOAD;
			if (cb == U2F_AUTH_CHECK_ONLY)
			{
				// message:error:test­of­user­presence­required (note that despite the name this signals a success condition).
				// If the key handle was not created by this U2F token, or if it was created for a different application 
				//parameter, the token MUST respond with an authentication response message:error:bad­key­handle.
				int size;
				DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_HANDLE");  
				check_handle(buffer,data, reqlength, &size);
				return;


			}
			else if (cb == U2F_AUTH_ENFORCE)
			{
			int size;
				DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_ORIGIN");
				return authenticate_origin(buffer,data, reqlength, &size);
			}
			else
			{
				DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_UNKNOWN");
				respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
				return;
			}

			// DISPLAY_IF_DEBUG("U2F_AUTHENTICATE");
			// // if cb == 07 authenticate handle
			// // if cb == 03 authenticate origin
			// byte cb = PAYLOAD;
			// if (cb == U2F_AUTH_CHECK_ONLY)
			// {
			// 	// message:error:test­of­user­presence­required (note that despite the name this signals a success condition).
			// 	// If the key handle was not created by this U2F token, or if it was created for a different application 
			// 	//parameter, the token MUST respond with an authentication response message:error:bad­key­handle.
			// 	int size;
			// 	DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_HANDLE");  
			// 	check_handle(buffer, data, reqlength, &size);
			// 	return;


			// }
			// else if (cb == U2F_AUTH_ENFORCE)
			// {
			// int size;
			// 	DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_ORIGIN");
			// 	authenticate_origin(buffer,data, reqlength, &size);
			// }
			// else
			// {
			// 	DISPLAY_IF_DEBUG("U2F_AUTHENTICATE_UNKNOWN");
			// 	respondErrorPDU(buffer, SW_INS_NOT_SUPPORTED);
			// 	return;
			// }

			// return protocol_authenticate(buffer, message, reqlength, PAYLOAD);

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