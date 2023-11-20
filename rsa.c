#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
 * @file rsa.c
 *
 * @brief This file contains the implementation of the RSA algorithm
 *
 * @date 2023-11-16
 *
 * @author Ana Raquel Neves Vidal
 * @author Simão Augusto Ferreira Andrade
 *
 */

/**
 * @brief This function generates a pseudo-random byte array,
 *
 * @param array_size The size of the byte array to be generated
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 * @param output The output byte array
 *
 */
void randgen(size_t array_size, uint8_t *password, uint8_t *confusion_string, int iterations, uint8_t *output)
{
    const EVP_CIPHER *cipher = EVP_aes_256_ctr();
    const int key_len = EVP_CIPHER_key_length(cipher);
    const int iv_len = EVP_CIPHER_iv_length(cipher);

    uint8_t key[key_len];
    uint8_t iv[iv_len];
    uint8_t bootstrap_seed[key_len + iv_len];

    // 1.1 Derive the key and IV from the password
    if (!PKCS5_PBKDF2_HMAC((const char *)password, strlen((const char *)password), confusion_string, strlen((const char *)confusion_string), iterations, EVP_sha256(), key_len + iv_len, bootstrap_seed))
    {
        fprintf(stderr, "Error deriving key and IV from password\n");
        exit(1);
    }

    // 1.2 Split the bootstrap seed into key and IV
    memcpy(key, bootstrap_seed, key_len);
    memcpy(iv, bootstrap_seed + key_len, iv_len);

    // 2. Transform the confusion string into an equal sequence of bytes (confusion pattern)
    uint8_t confusion_pattern[array_size];
    int confusion_string_index = 0;
    for (int confusion_pattern_index = 0; confusion_pattern_index < array_size; confusion_pattern_index++)
    {
        confusion_pattern[confusion_pattern_index] = confusion_string[confusion_string_index];
        confusion_string_index = (confusion_string_index + 1) % strlen((const char *)confusion_string);
    }

    // 3. Initialize the PRNG with the bootstrap seed
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error initializing the PRNG\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // 4. Start a loop that 'iterations' times where:
    for (int index = 0; index < iterations; index++)
    {
        // 4.1 Use the PRNG to produce a pseudo-random byte array of size 'array_size'
        uint8_t pseudo_random_byte_array[array_size];
        int out_len;
        if (EVP_EncryptUpdate(ctx, pseudo_random_byte_array, &out_len, confusion_pattern, array_size) != 1)
        {
            fprintf(stderr, "Error generating pseudo-random byte array\n");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // 4.2 Check if the confusion pattern is a substring of the generated array
        if (strstr((const char *)pseudo_random_byte_array, (const char *)confusion_pattern) != NULL)
        {
            memcpy(output, pseudo_random_byte_array, array_size);
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        // 4.3 Use a hash function to produce a new seed and use that seed to reinitialize the PRNG
        SHA256(pseudo_random_byte_array, array_size, key);
    }

    EVP_CIPHER_CTX_free(ctx);
}

/**
 * @brief This function generates a RSA key pair
 *
 * @param key_size The size of the key to be generated
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 * @param public_key The public key to be generated
 * @param private_key The private key to be generated
 *
 */
void rsagen(size_t key_size, uint8_t *password, uint8_t *confusion_string, int iterations, uint8_t *public_key, uint8_t *private_key)
{
    // TODO: Implement this function
}

int main(int argc, char **argv)
{
    // Example usage
    size_t array_size = 16;
    uint8_t password[] = "MySecretPassword";
    uint8_t confusion_string[] = "MyS1cretConfusionStri";
    int iterations = 10000;
    uint8_t output[array_size];

    // Generate a pseudo-random byte array
    randgen(array_size, password, confusion_string, iterations, output);

    // Print the generated array
    printf("Generated Array: ");
    for (size_t i = 0; i < array_size; ++i)
    {
        printf("%02X ", output[i]);
    }
    printf("\n");

    // TODO: Usage => ./rsa <key_size> <password> <confusion_string> <iterations>

    return 0;
}