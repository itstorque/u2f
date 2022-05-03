#pragma mark - U2F PROTOCOL HELPERS

void store(byte *app_hash, int hash_len, struct EncryptionKey k_priv, struct Handle *h)
{
    byte *data;
    int data_len;
    // copy the app_hash and k_priv into data
    data_len = hash_len + k_priv.size;
    data = (byte *)malloc(data_len);
    // DISPLAY_IF_DEBUG("store: hash_len");
    // DISPLAY_IF_DEBUG(hash_len);
    // DISPLAY_IF_DEBUG("\n");

    // DISPLAY_IF_DEBUG("store: k_priv.size");
    // DISPLAY_IF_DEBUG(k_priv.size);
    // DISPLAY_IF_DEBUG("\n");

    memcpy(data, app_hash, hash_len);
    memcpy(data + hash_len, k_priv.key, k_priv.size);

    // encrypt data with key using xor
    byte *encrypted_data;
    int encrypted_data_len;
    encrypted_data_len = data_len;
    encrypted_data = (byte *)malloc(encrypted_data_len);


    //aes128.setKey(K_app, aes128.keySize());
    // encpyt data in blocks of 


    // encrypt(data, encrypted_data);

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
    uint8_t *total_len = &cont_response[(*packet_length)];
    cont_response[*packet_length] = 0x44; // total length (32 + 32 + 2 + 2)
    *packet_length += 1;

    cont_response[(*packet_length)++] = 0x02; // length of r

	if (signature[0]>0x7f) {
   	cont_response[(*packet_length)++] = 33;  //33 byte
		cont_response[(*packet_length)++] = 0;
		(*total_len)++; //update total length
        DISPLAY_IF_DEBUG("append_sign: signature[0]>0x7f");
	}  else {
        DISPLAY_IF_DEBUG("append_sign: signature[0]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte
    }

	memcpy(cont_response+*packet_length, signature, 32); //S value
    *packet_length += 32;
    cont_response[(*packet_length)++] = 0x02; // length of r

	if (signature[32]>0x7f) {
        DISPLAY_IF_DEBUG("append_sign: signature[32]>0x7f");
		cont_response[(*packet_length)++] = 33;  //32 byte
		cont_response[(*packet_length)++] = 0;

        (*total_len)++; // update total length

	} else {
        DISPLAY_IF_DEBUG("append_sign: signature[32]<=0x7f");
		cont_response[(*packet_length)++] = 32;  //32 byte

    }
    memcpy(cont_response + *packet_length, signature + 32, 32); // R value
    *packet_length += 32;
    DISPLAY_IF_DEBUG("FINISHED APPENDING SIGN");
    return;
    // memcpy(cont_response + *packet_length, signature, 32); // R value
    // *packet_length += 32;
    // cont_response[(*packet_length)++] = 0x02; // header: integer
	
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