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
#define SEED_SIZE 32

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
 * @brief Function to check if A is a subarray of B
 * 
 * @param A reference array A
 * @param a_size size of A
 * @param B reference array B
 * @param b_size size of B
 * 
 * @return 1 if A is a subarray of B, 0 otherwise
 */
int pattern_found(uint8_t A[], int a_size, uint8_t B[], int b_size) {
    if (a_size > b_size) {
        printf("A is longer than B\n");
        return 0;  // A cannot be a subarray of B if A is longer than B
    }

    for (int i = 0; i <= b_size - a_size; i++) {
        int j;
        for (j = 0; j < a_size; j++) {
            if (B[i + j] != A[j]) {
                break;  // Break if there is a mismatch
            }
        }

        if (j == a_size) {
            return 1;
        }
    }

    return 0;  // A is not a subarray of B
}

/**
 * @brief Function to initialize the generator with the bootstrap seed
 *
 * @param seed value that will start the generator
 */
void initialize_generator(const uint8_t *seed)
{
    // TODO: Implement the initialization of the generator using the bootstrap seed
    RAND_seed(seed, SEED_SIZE);
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
    // Use a separate buffer for each iteration
    uint8_t temp_buffer[stream_size];
    RAND_bytes(temp_buffer, stream_size);
    memcpy(stream, temp_buffer, stream_size);
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
    uint8_t key_derivator[SEED_SIZE + strlen(confusion_string)];
    uint8_t seed[SEED_SIZE];
    uint8_t confusion_pattern[strlen(confusion_string)];

    // PBKDF2 to generate the key derivator
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *)confusion_string, strlen(confusion_string), iterations, EVP_sha256(), SEED_SIZE + strlen(confusion_string), key_derivator) != 1)
    {
        fprintf(stderr, "Error generating key derivator\n");
        exit(1);
    }

    // Get the seed and the confusion pattern from the key derivator
    memcpy(seed, key_derivator, SEED_SIZE);
    memcpy(confusion_pattern, key_derivator + SEED_SIZE, strlen(confusion_string));

    initialize_generator(seed);
    for (int iteration = 0; iteration < iterations; iteration++)
    {
        uint8_t temp_buffer[size];
        while (1)
        {
            generate_pseudo_random_stream(temp_buffer, size);

            // Check for the pattern
            if (pattern_found(confusion_pattern, strlen(confusion_string), temp_buffer, size))
            {
                break;
            }
        }
        
        memcpy(bytes, temp_buffer, size);
        initialize_generator(bytes + size - SEED_SIZE);
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
    FILE *public_key_file = fopen(public_key_filename, "wb");

    if (!private_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // Store the RSA key pair in a PEM file
    if (PEM_write_RSAPrivateKey(private_key_file, key_pair, NULL, NULL, 0, NULL, NULL) != 1)
    {
        fprintf(stderr, "Error writing private key\n");
        exit(1);
    }

    fclose(private_key_file);

    if (!public_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // Store the RSA key pair in a PEM file
    if(PEM_write_RSAPublicKey(public_key_file, key_pair) != 1)
    {
        fprintf(stderr, "Error writing public key\n");
        exit(1);
    }

    fclose(public_key_file);
}

/**
 * @brief This function generates a RSA key pair using the randgen() function to generate random byte values, and stores it in a PEM file.
 *
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 *
 * @return The RSA key pair
 */
RSA* rsagen(const char *password, const char *confusion_string, int iterations)
{
    BIGNUM *big_number = BN_new();
    RSA *key_pair = RSA_new();

    uint8_t output[RSA_KEY_SIZE];
    randgen(RSA_KEY_SIZE, password, confusion_string, iterations, output);

    if (!BN_bin2bn(output, RSA_KEY_SIZE, big_number)) {
        fprintf(stderr, "Error converting binary to BIGNUM\n");
        BN_free(big_number);
        exit(EXIT_FAILURE);
    }

    // Set the public exponent
    BIGNUM *exponent = BN_new();
    BN_set_word(exponent, RSA_F4);  // 65537 or 2^16 + 1

    if (!RSA_generate_key_ex(key_pair, RSA_KEY_SIZE, exponent, NULL)) {
        fprintf(stderr, "Error generating RSA key pair\n");
        ERR_print_errors_fp(stderr);
        BN_free(exponent);
        BN_free(big_number);
        exit(EXIT_FAILURE);
    }

    BN_free(exponent);
    BN_free(big_number);
    return key_pair;
}


int main(int argc, char **argv)
{
    if (argc != 5) // Usage => ./rsa <password> <confusion_string> <iterations>
    {
        fprintf(stderr, "Usage: ./rsa <password> <confusion_string> <iterations>\n");
        exit(1);
    }

    const char *password = argv[2];
    const char *confusion_string = argv[3];
    int iterations = atoi(argv[4]);

    // Generate the RSA key pair
    RSA *key_pair = rsagen(password, confusion_string, iterations);
    if (!key_pair){
        fprintf(stderr, "Error generating RSA key pair\n");
        exit(1);
    }

    // Store the RSA key pair
    storekey(key_pair, "private_key.pem", "public_key.pem");

    // Free the RSA key pair
    RSA_free(key_pair);

    return 0;
}