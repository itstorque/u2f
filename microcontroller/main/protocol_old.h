#pragma mark - U2F PROTOCOL

// defined in communication.h
void send_response_cont(byte *request, int packet_length);

void protocol_register(byte *buffer, byte *message, int reqlength) {
	// test implementation of u2f register for debugging

  Serial.println("REGREG");

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
	debug_hex_loop(public_k, 0, sizeof(public_k));
	DISPLAY_IF_DEBUG("\nPRIV KEY");
	debug_hex_loop(private_k, 0, sizeof(private_k));
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
	debug_hex_loop(app_param, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, app_param, 32);

	DISPLAY_IF_DEBUG("CHALLENGE");
	debug_hex_loop(challenge, 0, 32);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, challenge, 32);

	DISPLAY_IF_DEBUG("HANDLE");
	debug_hex_loop(handle, 0, 64);
	DISPLAY_IF_DEBUG("\n");

	sha256_update(&ctx, handle, 64);

	sha256_update(&ctx, public_k, 65);

	DISPLAY_IF_DEBUG("PUBLIC KEY");
	debug_hex_loop(public_k, 0, 65);
	DISPLAY_IF_DEBUG("\n");

	sha256_final(&ctx, sha256_hash);

	DISPLAY_IF_DEBUG("HASH");
	debug_hex_loop(sha256_hash, 0, 32);
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

	send_response_cont(buffer, packet_length);

}

int retrieve(byte *app_hash, byte*buffer,struct Handle h ,struct EncryptionKey*k_priv)
{
    // TODO: improve using encryption
    // get k_priv from handle
    byte *data;
    // int data_len;
    // data_len = h.size;
    data = (byte *)malloc(h.size);

    memcpy(data, h.data, h.size);

    // decrypt data with key using xor
    byte *decrypted_data;
    // int decrypted_data_len;
    // decrypted_data_len = data_len;
    decrypted_data = (byte *)malloc(h.size);

    for (int i = 0; i < h.size; i++)
    {
        decrypted_data[i] = data[i] ^ handlekey[i % (sizeof(handlekey) - 1)];
    }

    memcpy(k_priv->key, decrypted_data + 32, k_priv->size);


    if (memcmp(decrypted_data, app_hash, 32) != 0)
    {
        DISPLAY_IF_DEBUG("check_handle: priv_k is not a valid private key");
        DISPLAY_IF_DEBUG("\n");
        // reply with  Response Message: Error: Invalid Handle
        byte*end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return 0 ;
    }
    return 1;

    // memcpy(k_priv->key, h.data + hash_len, k_priv->size);

}

void authenticate_origin(byte*buffer,byte *message, int size, int*out_size)
{

    Serial.println("AUTHAUITHAUTHAUITHAUTHAUITHAUTHAUITHAUTHAUITHAUTHAUITHAUTHAUITH");

    byte* challange = message;
    byte* application = challange + 32;
    byte* handle_len = application + 32;
    byte* handle = handle_len + 1;

    DISPLAY_IF_DEBUG("challange:");
    debug_dump_hex(challange, 32);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("application:");
    debug_dump_hex(application, 32);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("handle_len:");
    debug_dump_hex(handle_len, 1);
    DISPLAY_IF_DEBUG("\n");
    DISPLAY_IF_DEBUG("handle:");
    debug_dump_hex(handle, *handle_len);
    DISPLAY_IF_DEBUG("\n");

    // byte*endof = cont_response;
    // ADD_SW_WRONG_DATA(endof);
    // send_response_cont(buffer, 2);
    // return;

    // // if (*CB == 0x07)
    // {
    //     DISPLAY_IF_DEBUG("authenticate_origin: CB = 0x07");
    //     // reply with  Response Message: Error: Test­of­User­Presence Required
    //     byte*end = cont_response;
    //     ADD_SW_COND(end);
    //     send_response_cont(buffer, 2);
    //     return;

    // }


    Handle h;
    h.data = handle;
    h.size = *handle_len;

    EncryptionKey k_priv;
    k_priv.size = uECC_curve_private_key_size(curve);
    if (retrieve(application, buffer, h,&k_priv)==0){
        DISPLAY_IF_DEBUG("authenticate_origin: retrieve failed");
        return;
    }


    // response size = 1 + 4 + X
    // response = user_presence + user_presence_counter + signature
    // the signature is of : application + user_presence + user_presence_counter + challange

    byte user_presence = 0x01; // TODO: change this to a button press
    uint32_t user_presence_counter = universal_counter++;

    byte *signature;
    signature = (byte *)malloc(1 + 4 + 2 * uECC_curve_private_key_size(curve));

    int data_to_sign_len = 32 + 1 + 4 + 32;
    byte *data_to_sign;
    data_to_sign = (byte *)malloc(data_to_sign_len);

    // byte* response = (byte *)malloc(1 + 4 + 2 * uECC_curve_private_key_size(curve));
    if (data_to_sign == NULL)
    {
        DISPLAY_IF_DEBUG("authenticate_origin: malloc failed");
        return;
    }
    // construct data to sign
    memcpy(data_to_sign, application, 32);
    memcpy(data_to_sign + 32, &user_presence, 1);
    memcpy(data_to_sign + 33, &user_presence_counter, 4);
    memcpy(data_to_sign + 37, challange, 32);


    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, hash);

    free(data_to_sign);

    uECC_sign(k_priv.key, hash, 32, signature, curve);

    // generate response

    memcpy(cont_response, &user_presence, 1);
    memcpy(cont_response + 1, &user_presence_counter, 4);
    memcpy(cont_response + 5, signature, 2 * uECC_curve_private_key_size(curve));

    *out_size = 1 + 4 + 2 * uECC_curve_private_key_size(curve);
    free(signature);


    DISPLAY_IF_DEBUG("authenticate_origin: response:");
    DISPLAY_IF_DEBUG(*out_size);
    debug_dump_hex(cont_response, *out_size);

    DISPLAY_IF_DEBUG("SENDING RESPONSE");
    byte*end = cont_response + size;
    ADD_SW_OK(end);
    size +=2;
    send_response_cont(buffer, size);
    return;
    // return response;
}