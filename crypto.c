#include <stdint.h>
#include "cyhal.h"
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

// Constants defining the sizes for AES keys and blocks
#define BLOCK_SIZE 16
#define MAX_TAG_LEN 16
#define MAX_PT_LEN 64

// Declaration of the key variables and their sizes
size_t key_size;
unsigned char *key;

unsigned char input[] = "TextToEncrypt123";

// AES keys for different encryption standards (128, 192, and 256 bits)
unsigned char key_128[16] = "KeyForAES128Bits"; // 16 bytes for AES-128
unsigned char key_192[24] = "KeyForAES192BitsLength"; // 24 bytes for AES-192
unsigned char key_256[32] = "KeyForAES256BitsLengthThatIs"; // 32 bytes for AES-256

// Initialization vector for AES encryption
unsigned char iv[BLOCK_SIZE] = "YourIVvector!!!!";

// Function prototypes
int aes_crypt(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_size,  const unsigned char *iv, int mode, size_t mode_choice);
void computeSHA(const char *input, int sha_choice);
void crypto_gen_random(void *context, uint8_t *output, size_t output_size);

// Function to print a buffer as hex values
void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        if (i < (size_t)INT_MAX){
            printf("%02X", buf[i]);
        }
        else{
            printf("Index out of range");
            break;
        }
    }
    printf("\n");
}

// PKCS#7 padding function: Pads the buffer to a multiple of the block size
cy_rslt_t pad_buffer(unsigned char *buffer, size_t input_length, size_t buffer_size) {
    size_t padding_size = BLOCK_SIZE - (input_length % BLOCK_SIZE);
    size_t new_length = input_length + padding_size;
    if (new_length > buffer_size) return 0; // Buffer too small

    for (size_t i = 0; i < padding_size; i++) {
        buffer[input_length + i] = (unsigned char)padding_size;
    }
    return new_length; // Return the new length after padding
}

// The main function that processes user input to select the cryptographic operation
void processInput() {
    int algorithm_choice, key_choice, sha_choice, mode_choice;
    uint8_t OUTPUT[128]; // Buffer for output

    // User interaction for algorithm selection
    printf("Select Algorithm:\n");
    printf("1. AES\n");
    printf("2. SHA\n");
    printf("3. Random number generator\n");
    printf("Enter choice (1-3): \n\n");

    // Error handling for user input
    if (scanf("%d", &algorithm_choice) != 1) {
        printf("Error reading Algorithm choice. Please enter a valid number.\n");
        return;
    }

    switch(algorithm_choice){
        case 1:
        {
            printf("Select AES key:\n");
            printf("1. AES-128\n");
            printf("2. AES-192\n");
            printf("3. AES-256\n");
            printf("Enter choice (1-3): \n\n");

            if (scanf("%d", &key_choice) != 1) {
                printf("Error reading Key choice. Please enter a valid number.\n");
                return;
            }

            switch (key_choice) {
                case 1:
                    key = key_128;
                    key_size = 16;
                    break;
                case 2:
                    key = key_192;
                    key_size = 24;
                    break;
                case 3:
                    key = key_256;
                    key_size = 32;
                    break;
                default:
                    printf("Invalid choice, please select correct key size \n");
                    return;
            }

            printf("Select AES mode:\n");
            printf("1. AES_CBC\n");
            printf("2. AES_CTR\n");
            printf("3. AES_OFB\n");
            printf("4. AES_ECB\n");
            printf("Enter choice (1-3): \n\n");

            if (scanf("%d", &mode_choice) != 1) {
                printf("Error reading Mode choice. Please enter a valid number.\n");
                return;
            }

            if(mode_choice>4)
            {
                printf("Invalid mode choice! AES encryption failed.\n");
                return;
            }


            // Input data
            size_t input_len = strlen((char *)input);
            size_t buffer_size = input_len + BLOCK_SIZE - (input_len % BLOCK_SIZE);
            unsigned char *encrypted = malloc(buffer_size);

            if (encrypted == NULL) {
                printf("Memory allocation failed for encrypted buffer. Exiting...\n");
                return;
            }

            printf("Original text: %s\n", input);

            // Encrypt
            int encrypted_length = aes_crypt(input, input_len, encrypted, buffer_size,  iv, MBEDTLS_AES_ENCRYPT, mode_choice);

            if (encrypted_length < 0) {
                printf("AES encryption failed. Please handle the error condition.\n");
            }
            else{
                print_hex("Encrypted text:", encrypted, encrypted_length);
            }

            printf("\n\n");
            free(encrypted);
            break;
        }
        case 2:
        {
            printf("Select SHA key:\n");
            printf("1. SHA1\n");
            printf("2. SHA224\n");
            printf("3. SHA256\n");
            printf("4. SHA384\n");
            printf("5. SHA512\n");
            printf("6. SHA512/224\n");
            printf("7. SHA512/256\n");
            printf("Enter choice (1-7): \n\n");

            if (scanf("%d", &sha_choice) != 1) {
                printf("Error reading SHA choice. Please enter a valid number.\n");
                return;
            }

            if (sha_choice < 1 || sha_choice > 7) {
                printf("Invalid SHA algorithm choice!\n");
                return;
            }

            computeSHA((const char*)input, sha_choice);
            break;
        }
        case 3:
        {
            crypto_gen_random(NULL,OUTPUT,8);
            printf("Random number: 0x%0llx\n\n", *((uint64_t *)OUTPUT));
            break;
        }
        default:
        {
            printf("Invalid algorithm choice! Execution terminated. \n");
            return;
        }
    }
}

int aes_crypt(const unsigned char *input, size_t input_len,
        unsigned char *output, size_t output_size, const unsigned char *iv, int mode, size_t mode_choice) {

    if (input_len % BLOCK_SIZE != 0 && mode == MBEDTLS_AES_DECRYPT) {
        return -1; // Input length should be multiple of block size for decryption
    }

    mbedtls_aes_context aes;
    unsigned char iv_copy[BLOCK_SIZE];
    memcpy(iv_copy, iv, BLOCK_SIZE);

    mbedtls_aes_init(&aes);
    int status = (mode == MBEDTLS_AES_ENCRYPT) ? mbedtls_aes_setkey_enc(&aes, key, key_size * 8) : mbedtls_aes_setkey_dec(&aes, key, key_size * 8);

    if (status != 0) {
        mbedtls_aes_free(&aes);
        return -1;
    }

    memcpy(output, input, input_len);

    unsigned char *buffer = output;
    if (mode == MBEDTLS_AES_ENCRYPT) {
        size_t padded_length = pad_buffer(output, input_len, output_size);
        if (padded_length == 0) {
            mbedtls_aes_free(&aes);
            return -1; // Output buffer too small for padding
        }
        memcpy(output, input, input_len);
        input_len = padded_length;
    }
    else {
        memcpy(output, input, input_len); // Copy input to output buffer as mbedtls_aes_crypt_cbc uses in-place decryption
    }

    switch(mode_choice)
    {
        case 1:
            status = mbedtls_aes_crypt_cbc(&aes, mode, input_len, iv_copy, buffer, output);
            break;
        case 2:
            status = mbedtls_aes_crypt_ctr(&aes, input_len, NULL, iv_copy, NULL, buffer, output);
            break;
        case 3:
            status = mbedtls_aes_crypt_ofb(&aes, input_len, NULL, iv_copy, buffer, output);
            break;
        case 4:
            for (int i = 0; i < input_len; i += 16) {
            status = mbedtls_aes_crypt_ecb(&aes, mode, &buffer[i], &output[i]);
            }
            break;
        default:
            printf("Invalid mode choice! AES encryption failed.\n");
            return -1;
    }
    mbedtls_aes_free(&aes);

    if (status != 0) {
        return -1; // Encryption / Decryption failed
    }
    return input_len; // Return length after padding
}

void computeSHA(const char *input, int sha_choice) {
    unsigned char output[64]; // Maximum size needed for SHA-512
    size_t output_length;

    switch(sha_choice) {
        case 1: // SHA1
            output_length = 20;
            mbedtls_sha1((const unsigned char *)input, strlen(input), output);
            break;
        case 2: // SHA224
            output_length = 28;
            mbedtls_sha256((const unsigned char *)input, strlen(input), output, 1);
            break;
        case 3: // SHA256
            output_length = 32;
            mbedtls_sha256((const unsigned char *)input, strlen(input), output, 0);
            break;
        case 4: // SHA384
            output_length = 48;
            mbedtls_sha512((const unsigned char *)input, strlen(input), output, 1);
            break;
        case 5: // SHA512
            output_length = 64;
            mbedtls_sha512((const unsigned char *)input, strlen(input), output, 0);
            break;
        case 6: // SHA512/224
            output_length = 28;
            mbedtls_sha512((const unsigned char *)input, strlen(input), output, 3);
            break;
        case 7: // SHA512/256
            output_length = 32;
            mbedtls_sha512((const unsigned char *)input, strlen(input), output, 4);
            break;
        default:
            printf("Invalid SHA algorithm choice! Execution terminated. \n");
            return;
    }
    print_hex("SHA hash of the input is: \n", output, output_length);
    printf("\n\n");
}

