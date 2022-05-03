#pragma mark - U2F PROTOCOL

// defined in communication.h
void send_response_cont(byte *request, int packet_length);

void u2f_version(byte *buffer, int reqlength)
{

    if (reqlength != 0)
    {
        respondErrorPDU(buffer, SW_WRONG_LENGTH);
        return;
    }

    SET_MSG_LEN(buffer, 8); // len("U2F_V2") + 2 byte SW

    byte *payload = buffer + 7;

    memcpy(payload, "U2F_V2", 6);

    payload += 6;

    ADD_SW_OK(payload);

    RawHID.send(buffer, 100);
}

void store(byte *app_hash, int hash_len, struct EncryptionKey k_priv, struct Handle *h)
{
        byte *data;
    int data_len;
    // copy the app_hash and k_priv into data
    data_len = hash_len + k_priv.size;
    data = (byte *)malloc(data_len);
    DISPLAY_IF_DEBUG("store: hash_len");
    DISPLAY_IF_DEBUG(hash_len);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("store: k_priv.size");
    DISPLAY_IF_DEBUG(k_priv.size);
    DISPLAY_IF_DEBUG("\n");

    memcpy(data, app_hash, hash_len);
    memcpy(data + hash_len, k_priv.key, k_priv.size);

    // encrypt data with key using xor
    byte *encrypted_data;
    int encrypted_data_len;
    encrypted_data_len = data_len;
    encrypted_data = (byte *)malloc(encrypted_data_len);

    for (int i = 0; i < data_len; i++)
    {
        encrypted_data[i] = data[i] ^ handlekey[i % (sizeof(handlekey) - 1)];
    }

    // write into handle
    h->size = data_len;
    h->data = encrypted_data;
}

int retrieve(byte *app_hash, byte *buffer, struct Handle h, struct EncryptionKey *k_priv)
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
        // reply with  Response Message: Error: Invalid Handle
        byte *end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return 0;
    }
    DISPLAY_IF_DEBUG("check_handle: priv_k is a valid private key");
    DISPLAY_IF_DEBUG("\n");

    return 1;
}

void append_signature(byte* signature,int*packet_length){


    // convert signature format
    // http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

    cont_response[(*packet_length)++] = 0x30; // header: compound structure

	if (signature[0]>0x7f) {
   	cont_response[(*packet_length)++] = 33;  //33 byte
		cont_response[(*packet_length)++] = 0;
		(*total_len)++; //update total length
        DISPLAY_IF_DEBUG("append_sign: signature[0]>0x7f");
	}  else {
        DISPLAY_IF_DEBUG("append_sign: signature[0]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte

    cont_response[*packet_length] = 0x44; // total length (32 + 32 + 2 + 2)
    *packet_length += 1;

	memcpy(cont_response+*packet_length, signature, 32); //R value
	if (signature[32]>0x7f) {
        DISPLAY_IF_DEBUG("append_sign: signature[32]>0x7f");
		cont_response[(*packet_length)++] = 33;  //32 byte
		cont_response[(*packet_length)++] = 0;

    memcpy(cont_response + *packet_length, signature, 32); // R value
    *packet_length += 32;
    cont_response[(*packet_length)++] = 0x02; // header: integer

	} else {
        DISPLAY_IF_DEBUG("append_sign: signature[32]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte

        (*total_len)++; // update total length
    }
    else
    {

        cont_response[(*packet_length)++] = 32; // 32 byte
    }

    memcpy(cont_response + *packet_length, signature + 32, 32); // R value
    *packet_length += 32;
    DISPLAY_IF_DEBUG("FINISHED APPENDING SIGN");
    return;
	
}

void *register_origin(byte *message, int size, int *out_size)
{

    // signature must be 2*curve_size long
    Cert cert;
    Handle h;
    // uECC_Curve curve = uECC_secp256r1();
    KeyPair kp = generateKeyPair(curve);
    h.size = 64;

    byte *challange = message;
    byte *application = challange + 32;

    DISPLAY_IF_DEBUG("challange:");
    debug_dump_hex(challange, 32);
    DISPLAY_IF_DEBUG("application:");
    debug_dump_hex(application, 32);

    store(application, 32, kp.privateKey, &h); // TODO: this is also an importannt part, reimplement with encryption

 // copy zero in the first place TODO: this is the importatnt part, this actually gets encrpyted
    byte* actual_p_key = (byte *)malloc(kp.publicKey.size+1);
    actual_p_key[0] = 0x04;
    memcpy(actual_p_key + 1, kp.publicKey.key, kp.publicKey.size);
    char zero = '\0';

    SHA256_CTX ctx;


    sha256_init(&ctx);
    sha256_update(&ctx, &zero, 1);
    sha256_update(&ctx, application, 32);
    sha256_update(&ctx, challange, 32);
    sha256_update(&ctx, h.data, h.size);
    sha256_update(&ctx, actual_p_key, kp.publicKey.size+1);
    // sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, sha256_hash);


    byte *signature = (byte *)malloc(2*uECC_curve_private_key_size(curve));
	uint8_t tmp[32 + 32 + 64];
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};

    DISPLAY_IF_DEBUG("deterministic sign");
	uECC_sign_deterministic((uint8_t *) attestation_key,
                                    sha256_hash,
                                    32,
                                    &ectx.uECC,
                                    signature,
                                    curve);

    
    int packet_length = 0;
    *cont_response = 0x05;
    packet_length++;
    memcpy(cont_response + 1, actual_p_key, 65);
    packet_length += 65;
    *(cont_response + 66) = h.size;
    packet_length++;
    memcpy(cont_response + 67, h.data, h.size);
    packet_length += h.size;

    memcpy(cont_response + packet_length, attestation_DER_cert, sizeof(attestation_DER_cert));

    DISPLAY_IF_DEBUG("signature:");
    debug_dump_hex(signature, 2 * uECC_curve_private_key_size(curve));
    DISPLAY_IF_DEBUG("\n");

    append_sign(signature,&packet_length);


    DISPLAY_IF_DEBUG("handle:");
    DISPLAY_IF_DEBUG(h.size);
    debug_dump_hex(h.data, h.size);
    DISPLAY_IF_DEBUG("\n");



    //free(signature);

    byte*end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length +=2;
    send_response_cont(buffer, packet_length);
   
}
// ref: https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.pdf
// message size distribution : 1,32,32,1,L
// control byte, challenge, application, handle len L, handle
void authenticate_origin(byte *buffer, byte *message, int size, int *out_size)
{
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
    //     ADD_SW_COND(en

    Handle h;
    h.data = handle;
    h.size = *handle_len;

    EncryptionKey k_priv;
    k_priv.size = uECC_curve_private_key_size(curve);
    if (retrieve(application, buffer, h, &k_priv) == 0)
    {
        DISPLAY_IF_DEBUG("authenticate_origin: retrieve failed");
        return;
    }
    byte user_presence = 0x01; // TODO: change this to a button press
    uint32_t user_presence_counter = universal_counter++;

    uint8_t *signature = response;
    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, application, 32);
    sha256_update(&ctx, &user_presence, 1);
    sha256_update(&ctx, (byte*)&user_presence_counter, 4);
    sha256_update(&ctx, challange, 32);


    sha256_final(&ctx, sha256_hash);

	uint8_t tmp[32 + 32 + 64];
	uECC_sign_deterministic((uint8_t *) k_priv.key,
                                        sha256_hash,
                                        32,
                                        &ectx.uECC,
                                        signature,
                                        curve);

    // generate response
    int packet_length = 0;
    memcpy(cont_response, &user_presence, 1);
    packet_length++;
    memcpy(cont_response + 1, &user_presence_counter, 4);
    packet_length += 4;

    DISPLAY_IF_DEBUG("signature:");
    debug_dump_hex(signature, 1 + 4 + 2 * uECC_curve_private_key_size(curve));
    DISPLAY_IF_DEBUG("\n");

    append_sign(signature, &packet_length);

    // memcpy(cont_response + 5, signature, 2 * uECC_curve_private_key_size(curve));


    DISPLAY_IF_DEBUG("authenticate_origin: response:");
    DISPLAY_IF_DEBUG(packet_length);
    debug_dump_hex(cont_response, packet_length);

    DISPLAY_IF_DEBUG("SENDING RESPONSE");
    byte *end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length += 2;
    send_response_cont(buffer, packet_length);
    return;
}

void check_handle(byte*buffer,byte *message, int size, int*out_size){
 byte* application = message+32;
    
    byte handle_len = *(message + 32 + 32);
    byte *handle = message + 32 + 32 + 1;

    DISPLAY_IF_DEBUG("check_handle: handle_len:");
    DISPLAY_IF_DEBUG(handle_len);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("check_handle: handle:");
    debug_dump_hex(handle, handle_len);
    DISPLAY_IF_DEBUG("\n");

    // decode handle using handlekey

    for (int i = 0; i < handle_len; i++)
    {
        handle[i] ^= handlekey[i % (sizeof(handlekey) - 1)];
    }

    byte *h_app = handle;

    DISPLAY_IF_DEBUG("check_handle: h_app:");
    debug_dump_hex(h_app, 32);
    DISPLAY_IF_DEBUG("\n");

    // check if priv_k is a valid private key
    // by comparing the application parameter

    if (memcmp(h_app, application, 32) != 0)
    {
        DISPLAY_IF_DEBUG("check_handle: priv_k is not a valid private key");
        DISPLAY_IF_DEBUG("\n");
        // reply with  Response Message: Error: Invalid Handle
        byte *end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return;
    }
    else
    {
        DISPLAY_IF_DEBUG("check_handle: priv_k is a valid private key");
        DISPLAY_IF_DEBUG("\n");

        // reply with  Response Message: TEST OF USER PRESENCE REQUIRED (this means success)
        byte *end = cont_response;
        ADD_SW_COND(end);
        send_response_cont(buffer, 2);
        return;
    }
}