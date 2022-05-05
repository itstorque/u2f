#pragma mark - U2F PROTOCOL HELPERS

AESSmall128 aes128;

// encrypt a 32 or 64 byte array by chopping plaintext into 4 16byte arrays, encrypting each block and putting into ciphertext
void encrypt(byte* key, byte*plaintext, byte*ciphertext, bool is32bytes = true)
{
    Serial.println("encrypting...");
    int numChunks = is32bytes ? 2 : 4; 

    aes128.clear();
    aes128.setKey(key, aes128.keySize());
    crypto_feed_watchdog();

    DISPLAY_IF_DEBUG("key:");
    debug_dump_hex(key, 16);
    DISPLAY_IF_DEBUG("plaintext:");
    debug_dump_hex(plaintext, numChunks * 16);

    byte plaintext_chunks[numChunks][16];
    byte ciphertext_chunks[numChunks][16];

    for (int i = 0; i < numChunks; i++) {
        
        for (int j = 0; j < 16; j++) {
            plaintext_chunks[i][j] = plaintext[i*16+j];
        }
        aes128.encryptBlock(plaintext_chunks[i], ciphertext_chunks[i]);

        for (int j = 0; j < 16; j++) {
            ciphertext[i*16+j] = ciphertext_chunks[i][j];
        }
        
    }
}

// decrypt a 64 byte array by chopping ciphertext into 4 16byte arrays, decrypting each block and putting into plaintext
void decrypt(byte* key,  byte*ciphertext, byte*plaintext, bool is32bytes = true)
{
    Serial.println("decrypting...");
    int numChunks = is32bytes ? 2 : 4; 

    aes128.clear();
    aes128.setKey(key, aes128.keySize());
    crypto_feed_watchdog();

    byte ciphertext_chunks[numChunks][16];
    byte plaintext_chunks[numChunks][16];
    
    for (int i = 0; i < numChunks; i++) {

        for (int j = 0; j < 16; j++) {
            ciphertext_chunks[i][j] = ciphertext[i*16+j];
        }

        aes128.decryptBlock(ciphertext_chunks[i], plaintext_chunks[i]);

        for (int j = 0; j < 16; j++) {
            plaintext[i*16+j] = plaintext_chunks[i][j];
        }

    }
    Serial.println("Finished decrypting");

}

// interleaves 2 32 byte arrays and puts output in a 64 byte array
void interleave(byte* a, byte*b, byte*interleaved){
    Serial.println("interleaving...");
    for (int i = 0; i < 32; i++) {
        interleaved[2*i] = a[i];
        interleaved[2*i+1] = b[i];
    }
}

void deinterleave(byte* interleaved, byte*a, byte*b){
    Serial.println("deinterleaving...");
    for (int i = 0; i < 32; i++) {
        a[i] = interleaved[2*i];
        b[i] = interleaved[2*i+1];
    }
}

void store(byte *app_hash, int hash_len, struct EncryptionKey k_priv, struct Handle *h)
{
    Serial.println("storing...");
    byte *data;
    data = (byte *)malloc(64);

    // encrypt data with key using xor
    byte *app_prime;
    app_prime = (byte *)malloc(32);

    // is32bytes is true!
    encrypt(K_app, app_hash, app_prime, 1);

    DISPLAY_IF_DEBUG("app_hash store");
    debug_hex_loop(app_hash, 0 ,32);

    DISPLAY_IF_DEBUG("store: app_prime: ");
    debug_hex_loop(app_prime, 0, 32);
    interleave(app_prime, k_priv.key, data);
    
    byte* encrypted_data;
    encrypted_data = (byte *)malloc(64);
    // is 32bytes is false! so 64 bytes
    // encrypt(K_wrap, data, encrypted_data, 0);   

    // write into handle
    h->size = 64;
    h->data = encrypted_data;
}

int retrieve(byte *app_hash, byte *buffer, struct Handle h, struct EncryptionKey *k_priv)
{

    Serial.println("retrieving...");

    byte *data;
    data = (byte *)malloc(64);

    // encrypt data with key using xor
    byte *app_prime;
    app_prime = (byte *)malloc(32);

    byte * app_prime_prime;
    app_prime_prime = (byte *)malloc(32);

    // is32bytes is true!
    encrypt(K_app, app_hash, app_prime, 1);
    DISPLAY_IF_DEBUG("app_hash retrieve");
    debug_hex_loop(app_hash, 0 ,32);

    decrypt(K_wrap, h.data, data, 0);


    deinterleave(data, app_prime_prime, k_priv->key);

    DISPLAY_IF_DEBUG("retireve: app_prime: ");
    debug_hex_loop(app_prime, 0, 32);
    DISPLAY_IF_DEBUG("retireve: app_prime_prime: ");
    debug_hex_loop(app_prime_prime, 0, 32);
    DISPLAY_IF_DEBUG("\n");
    if (memcmp(app_prime, app_prime_prime, 32) != 0) 
    {
        DISPLAY_IF_DEBUG("retrieve: priv_k is not a valid private key");
        DISPLAY_IF_DEBUG("\n");
        // reply with  Response Message: Error: Invalid Handle
        byte *end = cont_response;
        ADD_SW_WRONG_DATA(end);
        send_response_cont(buffer, 2);

        return 0;
    }
    DISPLAY_IF_DEBUG("retrieve: priv_k is a valid private key");


    return 1;

    // // get k_priv from handle
    // byte *data;
    // data = (byte *)malloc(h.size);

    // memcpy(data, h.data, h.size);

    // // decrypt data with key using xor
    // byte *decrypted_data;
    // decrypted_data = (byte *)malloc(h.size);

    // // for (int i = 0; i < h.size; i++)
    // // {
    // //     decrypted_data[i] = data[i] ^ handlekey[i % (sizeof(handlekey) - 1)];
    // // }

    // memcpy(k_priv->key, decrypted_data + 32, k_priv->size);

    // if (memcmp(decrypted_data, app_hash, 32) != 0)
    // {
    //     DISPLAY_IF_DEBUG("check_handle: priv_k is not a valid private key");
    //     DISPLAY_IF_DEBUG("\n");
    //     // reply with  Response Message: Error: Invalid Handle
    //     byte *end = cont_response;
    //     ADD_SW_WRONG_DATA(end);
    //     send_response_cont(buffer, 2);

    //     return 0;
    // }
    // DISPLAY_IF_DEBUG("check_handle: priv_k is a valid private key");
    // DISPLAY_IF_DEBUG("\n");

    // return 1;

}


void check_handle(byte* buffer, byte*message, int size, int*out_size)
{
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