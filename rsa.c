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
 * @author Ana Raquel Neves Vidal (118408)
 * @author Simão Augusto Ferreira Andrade (118345)
 *
 */

/**
 * @brief This function checks if a subarray is contained in an array
 *
 * @param subarray The subarray to be checked
 * @param subarray_length The length of the subarray
 * @param array The array to be checked
 * @param array_length The length of the array
 * @return 1 if the subarray is contained in the array, 0 otherwise
 */
int pattern_found(uint8_t *subarray, int subarray_length, uint8_t *array, int array_length)
{
    if (subarray_length > array_length)
    {
        fprintf(stderr, "Subarray length is bigger than array length\n");
        return 0;
    }

    for (int index = 0; index < array_length - subarray_length; index++)
    {
        if (memcmp(subarray, array + index, subarray_length) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Function to initialize the generator with the bootstrap seed
 *
 * @param seed value that will start the generator
 */
void initialize_generator(const uint8_t *seed)
{
    // TODO: Implement the initialization of the generator using the bootstrap seed
    RAND_seed(seed, SHA256_DIGEST_LENGTH);
}

/**
 * @brief Function to use the generator to produce a pseudo-random stream of bytes
 *
 * @param stream a pointer to an array where the bytes will be allocated
 * @param stream_size the size of the array
 *
 */
void generate_pseudo_random_stream(uint8_t *stream, int stream_size)
{
    // TODO: Implement the logic to generate a pseudo-random stream
    // Example:
    RAND_bytes(stream, stream_size);
}

/**
 * @brief This function generates a pseudo-random byte stream
 *
 * @param size The size of the byte stream to be generated
 * @param password The password to be used
 * @param confusion_string The confusion string to be used
 * @param iterations The number of iterations to be used
 * @param bytes The output byte array
 *
 */
void randgen(int size, const char *password, const char *confusion_string, int iterations, uint8_t *bytes)
{
    // 1. Compute a bootstrap seed from the password, the confusion string and the iteration count. Consider, for instance, using the PBKDF2 method;
    uint8_t bootstrap_seed[SHA256_DIGEST_LENGTH];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *)confusion_string, strlen(confusion_string), iterations, EVP_sha256(), SHA256_DIGEST_LENGTH, bootstrap_seed))
    {
        fprintf(stderr, "Error generating bootstrap seed\n");
        exit(1);
    }

    // 2. Transform the confusion string into an equal length sequence of bytes (confusion pattern). These resulting bytes should be able to have any value;
    int confusion_pattern_length = strlen(confusion_string);
    uint8_t confusion_pattern[confusion_pattern_length];
    for (int index = 0; index < confusion_pattern_length; index++)
    {
        confusion_pattern[index] = confusion_string[index];
    }

    uint8_t pseudo_random_stream[size];

    // Initialize the generator with the bootstrap seed
    initialize_generator(bootstrap_seed);

    for (int iteration = 0; iteration < iterations; iteration++)
    {
        while (!pattern_found(confusion_pattern, confusion_pattern_length, pseudo_random_stream, size))
        {
            // Use the generator to produce a pseudo-random stream of bytes
            generate_pseudo_random_stream(pseudo_random_stream, size);
        }

        // If it's found then the pseudo-random stream becomes the new seed
        printf("Found confusion pattern in pseudo-random stream\n");
        memcpy(bootstrap_seed, pseudo_random_stream, size);

        // Re-initialize the generator with the updated seed for the next iteration
        initialize_generator(bootstrap_seed);
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
    randgen(RSA_KEY_SIZE, password, confusion_string, iterations, output);

    // TODO: Generate the RSA key pair

    // Store the RSA key pair in a PEM file
    // storekey(rsa, "private_key.pem", "public_key.pem");
}

int main(int argc, char **argv) // TODO: Usage => ./rsa <key_size> <password> <confusion_string> <iterations>
{
    // Example usage
    char password[] = "MySecretPassword";
    char confusion_string[] = "foafjaklfnhakfj";
    int iterations = 3;
    uint8_t output[RANDGEN_OUTPUT_SIZE];

    // Generate a pseudo-random byte array
    randgen(RANDGEN_OUTPUT_SIZE, password, confusion_string, iterations, output);

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