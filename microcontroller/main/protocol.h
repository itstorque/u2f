#pragma mark - U2F PROTOCOL

// defined in communication.h
void send_response_cont(byte *request, int packet_length);

// TODO: move this to keys.h
byte K_wrap[16] = {};
byte K_app[16] = {};

#include "protocol_helpers.h"

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

void register_origin(byte*buffer,byte *message, int size)
{

    byte user_presence = confirm_user_presence(); 

    if (user_presence != 0x01) return;

    // signature must be 2*curve_size long
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

    packet_length += sizeof(attestation_DER_cert)-1;

    append_signature(signature,&packet_length);


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
    byte user_presence = confirm_user_presence(); 

    if (user_presence != 0x01) return;

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
	SHA256_HashContext ectx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
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

    append_signature(signature, &packet_length);

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