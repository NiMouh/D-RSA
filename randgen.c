/**
 * @file randgen.c
 * @author Ana Raquel Neves Vidal (118408)
 * @author Simão Augusto Ferreira Andrade (118345)
 * @brief This file contains the implementation of the randgen algorithm in C.
 * @date 2023-12-20
 *
 * @copyright Copyright (c) 2023
 *
 */

// Standard libraries
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// OpenSSL libraries
#include <openssl/sha.h>
#include <openssl/evp.h>

// Constants
#define SEED_SIZE 32     // bytes
#define BUFFER_SIZE 4096 // bytes

/**
 * @brief Function to check if A is a subarray of B
 *
 * @param A reference array A
 * @param a_size size of A
 * @param B reference array B
 * @param b_size size of B
 *
 * @return 1 if A is a subarray of B, 0 otherwise
 */
int pattern_found(uint8_t A[], int a_size, uint8_t B[], int b_size)
{
    if (a_size > b_size)
    {
        fprintf(stderr, "A is longer than B\n");
        return 0;
    }

    for (int i = 0; i <= b_size - a_size; i++)
    {
        int match = 1;
        for (int j = 0; j < a_size; j++)
        {
            if (B[i + j] != A[j])
            {
                match = 0;
                break; // mismatch
            }
        }

        if (match)
        {
            return 1;
        }
    }

    return 0; // A is not a subarray of B
}

/**
 * @brief Function to use the generator to produce a pseudo-random stream of bytes
 *
 * @param stream a pointer to an array where the bytes will be allocated
 * @param stream_size the size of the array
 * @param seed value that will start the generator
 */
void generate_pseudo_random_stream(uint8_t *stream, int stream_size, uint8_t seed[SEED_SIZE])
{
    uint8_t hash_output[SHA256_DIGEST_LENGTH];

    for (int index = 0; index < stream_size; index += SHA256_DIGEST_LENGTH)
    {
        SHA256(seed, SEED_SIZE, hash_output); // hash the seed

        // Copy the hash output to the stream
        int bytes_to_copy = (index + SHA256_DIGEST_LENGTH <= stream_size) ? SHA256_DIGEST_LENGTH : stream_size - index;
        memcpy(stream + index, hash_output, bytes_to_copy);

        memcpy(seed, hash_output, SHA256_DIGEST_LENGTH); // seed = hash_output
    }
}

/**
 * @brief This function generates arbirtary a pseudo-random byte stream
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
    uint8_t key_derivator[SEED_SIZE + strlen(confusion_string)];
    uint8_t seed[SEED_SIZE];
    uint8_t confusion_pattern[strlen(confusion_string)];

    // generate the key derivator
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *)confusion_string, strlen(confusion_string), iterations, EVP_sha256(), SEED_SIZE + strlen(confusion_string), key_derivator) != 1)
    {
        fprintf(stderr, "Error generating key derivator\n");
        exit(1);
    }

    // get the seed and the confusion pattern from the key derivator
    memcpy(seed, key_derivator, SEED_SIZE);
    memcpy(confusion_pattern, key_derivator + SEED_SIZE, strlen(confusion_string));

    for (int iteration = 0; iteration < iterations; iteration++)
    {
        uint8_t temp_buffer[size];
        while (1)
        {
            generate_pseudo_random_stream(temp_buffer, size, seed);

            if (pattern_found(confusion_pattern, strlen(confusion_string), temp_buffer, size))
            {
                break;
            }
        }

        memcpy(bytes, temp_buffer, size);
        memcpy(seed, bytes + size - SEED_SIZE, SEED_SIZE);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 4) // ./randgen <password> <confusion_string> <iterations>
    {
        fprintf(stderr, "Usage: %s <password> <confusion_string> <iterations>\n", argv[0]);
        exit(1);
    }

    const char *password = argv[2];
    const char *confusion_string = argv[3];
    int iterations = atoi(argv[4]);

    uint8_t bytes[BUFFER_SIZE];

    randgen(BUFFER_SIZE, password, confusion_string, iterations, bytes);

    fwrite(bytes, sizeof(uint8_t), BUFFER_SIZE, stdout);

    return 0;
}
