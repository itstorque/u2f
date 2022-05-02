// ERROR HANDLING

void respondErrorPDU(byte *buffer, int err) {

	SET_MSG_LEN(buffer, 2); //len("") + 2 byte SW

	byte *datapart = buffer + 7;

	(*datapart++) = (err >> 8) & 0xff;
	(*datapart++) =  err 	   & 0xff;

	RawHID.send(buffer, 100);

}

void send_u2f_error(byte *buffer, int code) {

	memcpy(response, buffer, 4);

  response[4] = U2FHID_ERROR;

  SET_MSG_LEN(response, 1);

  response[7] = code & 0xff;

	DISPLAY_IF_DEBUG("u2f error:");
	DISPLAY_IF_DEBUG(code);

	RawHID.send(response, 100);
}

void error_invalid_channel_id() {
	return send_u2f_error(recieved, ERR_SYNC_FAIL);
}

void error_timeout() {
	return send_u2f_error(recieved, ERR_MSG_TIMEOUT);
}

void error_invalid_length() {
	return send_u2f_error(recieved, ERR_INVALID_LEN);
}

void error_invalid_seq() {
	return send_u2f_error(recieved, ERR_INVALID_SEQ);
}

void error_channel_busy() {
	return send_u2f_error(recieved, ERR_CHANNEL_BUSY);
}

void error_invalid_cmd() {
	return send_u2f_error(recieved, ERR_INVALID_CMD);
}