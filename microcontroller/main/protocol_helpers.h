#pragma mark - U2F PROTOCOL HELPERS


AESSmall128 aes128;

// encrypt a 32 or 64 byte array by chopping plaintext into 4 16byte arrays, encrypting each block and putting into ciphertext
void encrypt(byte* key, byte*plaintext, byte*ciphertext, bool is32bytes = true)
{
    int numChunks = is32bytes ? 2 : 4; 

    aes128.clear();
    aes128.setKey(key, aes128.keySize());
//    crypto_feed_watchdog();

    byte plaintext_chunks[numChunks][16];
    byte ciphertext_chunks[numChunks][16];

    for (int i = 0; i < numChunks; i++) {
        
        for (int j = 0; j < 16; j++) {
            plaintext_chunks[i][j] = plaintext[i*16+j];
        }
        aes128.encryptBlock(ciphertext_chunks[i], plaintext_chunks[i]);

        for (int j = 0; j < 16; j++) {
            ciphertext[i*16+j] = ciphertext_chunks[i][j];
        }
        
    }

}

// decrypt a 64 byte array by chopping ciphertext into 4 16byte arrays, decrypting each block and putting into plaintext
void decrypt(byte* key,  byte*ciphertext, byte*plaintext, bool is32bytes = true)
{
    int numChunks = is32bytes ? 2 : 4; 

    aes128.clear();
    aes128.setKey(key, aes128.keySize());
//    crypto_feed_watchdog();

    byte ciphertext_chunks[numChunks][16];
    byte plaintext_chunks[numChunks][16];


    for (int i = 0; i < numChunks; i++) {

        for (int j = 0; j < 16; j++) {
            ciphertext_chunks[i][j] = ciphertext[i*16+j];
        }

        aes128.decryptBlock(plaintext_chunks[i], ciphertext_chunks[i]);

        for (int j = 0; j < 16; j++) {
            plaintext[i*16+j] = plaintext_chunks[i][j];
        }


    }

}

// interleaves 2 32 byte arrays and puts output in a 64 byte array
void interleave(byte* a, byte*b, byte*interleaved){
    for (int i = 0; i < 32; i++) {
        interleaved[2*i] = a[i];
        interleaved[2*i+1] = b[i];
    }
}

void deinterleave(byte* interleaved, byte*a, byte*b){
    for (int i = 0; i < 32; i++) {
        a[i] = interleaved[2*i];
        b[i] = interleaved[2*i+1];
    }
}

void store(byte *app_hash, int hash_len, struct EncryptionKey k_priv, struct Handle *h)
{
    byte *data;
    int data_len = 64;

    // copy the app_hash and k_priv into data
    data_len = hash_len + k_priv.size;
    data = (byte *)malloc(data_len);

    byte *app_prime;
    app_prime = (byte *)malloc(32);

    // is32bytes is true!
    encrypt(K_app, app_hash, app_prime, 1);

    interleave(app_prime, k_priv.key, data);

    byte* encrypted_data;
    encrypted_data = (byte *)malloc(64);

    // is 32bytes is false! so 64 bytes
    encrypt(K_wrap, data, encrypted_data, 0);   

    // write into handle
    h->size = data_len;
    h->data = encrypted_data;
}

int retrieve(byte *app_hash, byte *buffer, struct Handle h, struct EncryptionKey *k_priv)
{

    byte *data;
    data = (byte *)malloc(64);

    // encrypt data with key using xor
    byte *app_prime;
    app_prime = (byte *)malloc(32);

    byte * app_prime_prime;
    app_prime_prime = (byte *)malloc(32);

    // is32bytes is true!
    encrypt(K_app, app_hash, app_prime, 1);

    decrypt(K_wrap, h.data, data, 0);

    deinterleave(data, app_prime_prime, k_priv->key);

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
    byte* app_hash= message+32;
    
    byte handle_len = *(message + 32 + 32);
    byte *handle = message + 32 + 32 + 1;


    byte *data = (byte *)malloc(64);

    // encrypt data with key using xor
    byte *app_prime = (byte *)malloc(32);

    byte * app_prime_prime = (byte *)malloc(32);

    encrypt(K_app, app_hash, app_prime, 1);

    decrypt(K_wrap, handle, data, 0);

    byte * temp = (byte *)malloc(32);

    deinterleave(data, app_prime_prime, temp);


    DISPLAY_IF_DEBUG("check_handle: handle_len:");
    DISPLAY_IF_DEBUG(handle_len);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("check_handle: handle:");
    debug_dump_hex(handle, handle_len);
    DISPLAY_IF_DEBUG("\n");

    // decode handle using handlekey

    // check if priv_k is a valid private key
    // by comparing the application parameter

    if (memcmp(app_prime, app_prime_prime, 32) != 0) 
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
