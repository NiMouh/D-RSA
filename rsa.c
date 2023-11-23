// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// OpenSSL libraries
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// Constants
#define RSA_KEY_SIZE 2048
#define RANDGEN_OUTPUT_SIZE 32

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
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 * @param output The output byte array
 *
 */
void randgen(const char *password, const char *confusion_string, int iterations, uint8_t *output) // The setup of such a generator should be long and complex, in order to complicate its cryptanalysis (discovery of the actual seed).
{
    // 1. Compute a bootstrap seed from the password, the confusion string and the iteration count. Consider, for instance, using the PBKDF2 method;
    uint8_t bootstrap_seed[SHA256_DIGEST_LENGTH];
    if(!PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *)confusion_string, strlen(confusion_string), iterations, EVP_sha256(), SHA256_DIGEST_LENGTH, bootstrap_seed))
    {
        fprintf(stderr, "Error generating bootstrap seed\n");
        exit(1);
    }

    // 2. Transform the confusion string into an equal length sequence of bytes (confusion pattern). These resulting bytes should be able to have any value;
    uint8_t confusion_pattern[strlen(confusion_string)];
    for(int index = 0; index < strlen(confusion_string); index++)
    {
        confusion_pattern[index] = confusion_string[index] ^ bootstrap_seed[index];
    }

    // 3. Initialize the generator with the bootstrap seed;
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_ecb(); // Use the AES-256 cipher in ECB mode

    // Initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        fprintf(stderr, "Error creating context\n");
        exit(1);
    }

    if (EVP_CipherInit_ex(ctx, cipher, NULL, bootstrap_seed, NULL, 1) != 1)
    {
        fprintf(stderr, "Error initializing cipher\n");
        exit(1);
    }

    int output_length; // Declare the variable for output length
    // For the number of iterations:
    for (int iteration = 0; iteration < iterations; iteration++)
    {
        // 4. Use the generator to produce a pseudo-random stream of bytes
        if (EVP_CipherUpdate(ctx, output, &output_length, output, SHA256_DIGEST_LENGTH) != 1)
        {
            fprintf(stderr, "Error generating pseudo-random stream\n");
            exit(1);
        }

        // 5. Stopping when the confusion pattern is found in the pseudo-random stream;
        if (memcmp(output, confusion_pattern, sizeof(confusion_pattern)) == 0)
        {
            // 6. Use the generator to produce a new seed and use that seed to re-initialize the generator;
            if (EVP_CipherInit_ex(ctx, cipher, NULL, output, NULL, 1) != 1)
            {
                fprintf(stderr, "Error initializing cipher\n");
                exit(1);
            }
        }
    }
}

/**
 * @brief This function stores the RSA key pair in a PEM file.
 *
 * @param key_pair The RSA key pair to be stored
 * @param private_key_filename The name of the file to store the key pair
 * @param public_key_filename The name of the file to store the key pair
 */
void storekey(RSA *key_pair, const char *private_key_filename, const char *public_key_filename)
{
    FILE *private_key_file = fopen(private_key_filename, "wb");
    if (!private_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // TODO: Store the RSA key pair in a PEM file

    fclose(private_key_file);

    FILE *public_key_file = fopen(public_key_filename, "wb");
    if (!public_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // TODO: Store the RSA key pair in a PEM file

    fclose(public_key_file);

}

/**
 * @brief This function generates a RSA key pair using the randgen() function to generate random byte values, and stores it in a PEM file.
 *
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 *
 */
void rsagen(const char *password, const char *confusion_string, int iterations)
{
    // Generate a pseudo-random byte array
    uint8_t output[RSA_KEY_SIZE];
    randgen(password, confusion_string, iterations, output);

    // TODO: Generate the RSA key pair

    // Store the RSA key pair in a PEM file
    // storekey(rsa, "private_key.pem", "public_key.pem");
}

int main(int argc, char **argv) // TODO: Usage => ./rsa <key_size> <password> <confusion_string> <iterations>
{
    // Example usage
    char password[] = "MySecretPassword";
    char confusion_string[] = "MySecretConfusionStri";
    int iterations = 10000;
    uint8_t output[RANDGEN_OUTPUT_SIZE];


    // Generate a pseudo-random byte array
    randgen(password, confusion_string, iterations, output);

    // Print the generated array
    for (int index = 0; index < RANDGEN_OUTPUT_SIZE; index++)
    {
        printf("%02x", output[index]);
    }
    printf("\n");

    // Generate the RSA key pair
    // rsagen(password, confusion_string, iterations);

    return 0;
}