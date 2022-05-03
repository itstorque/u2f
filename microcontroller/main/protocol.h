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
    return;
    // TODO: improve
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
    return 0;
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

    // memcpy(k_priv->key, h.data + hash_len, k_priv->size);
}

void append_cert(byte *signature, int *packet_length)
{

    return;

    // convert signature format
    // http://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

    cont_response[(*packet_length)++] = 0x30; // header: compound structure

    uint8_t *total_len = &cont_response[*packet_length];

    cont_response[*packet_length] = 0x44; // total length (32 + 32 + 2 + 2)
    *packet_length += 1;

    cont_response[(*packet_length)++] = 0x02; // header: integer

    if (signature[0] > 0x7f)
    {
        cont_response[(*packet_length)++] = 33; // 33 byte
        cont_response[(*packet_length)++] = 0;
        (*total_len)++; // update total length
    }
    else
    {
        cont_response[(*packet_length)++] = 32; // 32 byte
    }

    memcpy(cont_response + *packet_length, signature, 32); // R value
    *packet_length += 32;
    cont_response[(*packet_length)++] = 0x02; // header: integer

    if (signature[32] > 0x7f)
    {

        cont_response[(*packet_length)++] = 33; // 32 byte
        cont_response[(*packet_length)++] = 0;

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
    byte *signature;
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
    // generating signature

    signature = (byte *)malloc(2 * uECC_curve_private_key_size(curve));

    // generate handle

    store(application, 32, kp.privateKey, &h); // TODO: this is also an importannt part, reimplement with encryption

    int data_to_sign_len = 1 + 32 + 32 + h.size + kp.publicKey.size;
    byte *data_to_sign;
    data_to_sign = (byte *)malloc(data_to_sign_len);

    if (data_to_sign == NULL)
    {
        DISPLAY_IF_DEBUG("register_origin: malloc failed");
        return;
    }

    // copy zero in the first place TODO: this is the importatnt part, this actually gets encrpyted
    byte *actual_p_key = (byte *)malloc(kp.publicKey.size + 1);
    actual_p_key[0] = 0x04;
    memcpy(actual_p_key + 1, kp.publicKey.key, kp.publicKey.size);
    char zero = '\0';
    memccpy(data_to_sign, &zero, 0, 1);
    memcpy(data_to_sign + 1, application, 32);
    memcpy(data_to_sign + 33, challange, 32);
    memcpy(data_to_sign + 65, h.data, h.size);
    memcpy(data_to_sign + 65 + h.size, actual_p_key, kp.publicKey.size + 1);
    // memcpy(data_to_sign + 65 + h.size, kp.publicKey.key, kp.publicKey.size);

    SHA256_CTX ctx;

    byte hash[32];

    sha256_init(&ctx);
    sha256_update(&ctx, data_to_sign, data_to_sign_len);
    sha256_final(&ctx, hash);

    free(data_to_sign);

    uECC_sign(kp.privateKey.key, hash, 32, signature, curve);

    // generating cert

    // get_certificate(&cert);

    // generate response = byte + actual public key + handle len + handle + certificate + signature

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

    packet_length += sizeof(attestation_DER_cert) - 1;

    append_cert(signature, &packet_length);

    DISPLAY_IF_DEBUG("handle:");
    DISPLAY_IF_DEBUG(h.size);
    debug_dump_hex(h.data, h.size);

    free(signature);

    *out_size = packet_length;
}
// ref: https://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.pdf
// message size distribution : 1,32,32,1,L
// control byte, challenge, application, handle len L, handle
void authenticate_origin(byte *buffer, byte *message, int size, int *out_size)
{

    byte *challange = message;
    byte *application = challange + 32;
    byte *handle_len = application + 32;
    byte *handle = handle_len + 1;

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
    if (retrieve(application, buffer, h, &k_priv) == 0)
    {
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
    int packet_length = 0;
    memcpy(cont_response, &user_presence, 1);
    packet_length++;
    memcpy(cont_response + 1, &user_presence_counter, 4);
    packet_length += 4;

    append_cert(signature, &packet_length);

    // memcpy(cont_response + 5, signature, 2 * uECC_curve_private_key_size(curve));

    free(signature);

    DISPLAY_IF_DEBUG("authenticate_origin: response:");
    DISPLAY_IF_DEBUG(packet_length);
    debug_dump_hex(cont_response, packet_length);

    DISPLAY_IF_DEBUG("SENDING RESPONSE");
    byte *end = cont_response + packet_length;
    ADD_SW_OK(end);
    packet_length += 2;
    send_response_cont(buffer, packet_length);
    return;
    // return response;
}

void check_handle(byte *buffer, byte *message, int size, int *out_size)
{
    byte *application = message + 32;

    byte *handle_len = message + 32 + 32;
    byte *handle = *handle_len + 1;

    DISPLAY_IF_DEBUG("check_handle: handle_len:");
    debug_dump_hex(handle_len, 1);
    DISPLAY_IF_DEBUG("\n");

    DISPLAY_IF_DEBUG("check_handle: handle:");
    debug_dump_hex(handle, *handle_len);
    DISPLAY_IF_DEBUG("\n");

    // decode handle using handlekey

    for (int i = 0; i < *handle_len; i++)
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