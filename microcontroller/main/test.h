void testCipher()
{
    crypto_feed_watchdog();
    Serial.print(" Encryption ... ");
    
    // create a 16 byte key
    byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    byte plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
                    
    byte encryptedText[16];

    aes128.setKey(key, aes128.keySize());

    // (output, input)
    aes128.encryptBlock(encryptedText, plaintext);

    byte decryptedText[16];

    Serial.print(" Decryption ... ");
    aes128.decryptBlock(decryptedText, encryptedText);
    if (memcmp(decryptedText, plaintext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

// function which tests encrypt() and decrypt()
void test_encrypt_decrypt_32_bytes(){
    byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // create a 32 byte random plaintext
    byte plaintext[32] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62};

    // create a 32 byte array to hold the ciphertext
    byte ciphertext[32];

    // encrypt the plaintext
    encrypt(key, plaintext, ciphertext, true);

    // create a 32 byte array to hold the decrypted plaintext
    byte decrypted_plaintext[32];

    // decrypt the ciphertext
    decrypt(key, ciphertext, decrypted_plaintext, true);

    // compare the plaintexts
    if (memcmp(plaintext, decrypted_plaintext, 32) != 0) {
        Serial.println("encrypt/decrypt test failed");
    } else {
        Serial.println("encrypt/decrypt test passed");
    }
}

// function which tests encrypt() and decrypt()
void test_encrypt_decrypt_64_bytes(){
    byte key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // create a 64 byte random plaintext
    byte plaintext[64] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63};

    // create a 64 byte array to hold the ciphertext
    byte ciphertext[64];

    // encrypt the plaintext
    encrypt(key, plaintext, ciphertext, false);

    // create a 32 byte array to hold the decrypted plaintext
    byte decrypted_plaintext[64];

    // decrypt the ciphertext
    decrypt(key, ciphertext, decrypted_plaintext, false);

    // compare the plaintexts
    if (memcmp(plaintext, decrypted_plaintext, 64) != 0) {
        Serial.println("encrypt/decrypt test failed");
    } else {
        Serial.println("encrypt/decrypt test passed");
    }
}

// function to test interleave and deinterleave with byte array a and b
void test_interleave_deinterleave_32_bytes(){
    byte a[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    byte b[32] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    byte interleaved[64];

    byte aprime[32];
    byte bprime[32];

    interleave(a, b, interleaved);
    deinterleave(interleaved, aprime, bprime);

    if (memcmp(a, aprime, 32) != 0 || memcmp(a, aprime, 32) != 0) {
        Serial.println("interleave/deinterleave test failed");
    } else {
        Serial.println("interleave/deinterleave test passed");
    }
}
