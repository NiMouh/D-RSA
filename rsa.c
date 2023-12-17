// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// OpenSSL libraries
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Constants
#define RSA_KEY_SIZE 2048 // bits
#define SEED_SIZE 32 // bytes

// Struct for RSA key pair
typedef struct rsa_key_pair
{
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
} RSA_KEY_PAIR;

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
int pattern_found(uint8_t A[], int a_size, uint8_t B[], int b_size)
{
    if (a_size > b_size)
    {
        fprintf(stderr,"A is longer than B\n");
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

/**
 * @brief This function encodes a byte array in base64
 * 
 * @param input  The byte array to be encoded
 * @param length The length of the byte array
 * @return char* The encoded byte array
 */
char *base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *base64;
    BUF_MEM *buffer_pointer;

    base64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    base64 = BIO_push(base64, bmem);
    BIO_write(base64, input, length);
    BIO_flush(base64);
    BIO_get_mem_ptr(base64, &buffer_pointer);

    char *buffer = (char *)malloc(buffer_pointer->length + 1);
    memcpy(buffer, buffer_pointer->data, buffer_pointer->length);
    buffer[buffer_pointer->length] = 0;

    BIO_free_all(base64);

    return buffer;
}

/**
 * @brief This function stores the RSA key pair in a PEM file.
 *
 * @param key_pair The RSA key pair to be stored
 * @param private_key_filename The name of the file to store the key pair
 * @param public_key_filename The name of the file to store the key pair
 */
void storekey(RSA_KEY_PAIR key_pair, const char *private_key_filename, const char *public_key_filename)
{
    FILE *private_key_file = fopen(private_key_filename, "wb");
    FILE *public_key_file = fopen(public_key_filename, "wb");

    // Private key
    if (!private_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    fprintf(private_key_file, "-----BEGIN PRIVATE KEY-----\n");

    int private_key_data_len = BN_num_bytes(key_pair.n) + BN_num_bytes(key_pair.d);

    unsigned char *private_key_data = (unsigned char *)malloc(private_key_data_len);
    if (!private_key_data)
    {
        fprintf(stderr, "Error allocating memory\n");
        exit(1);
    }

    BN_bn2bin(key_pair.n, private_key_data);
    BN_bn2bin(key_pair.d, private_key_data + BN_num_bytes(key_pair.n));

    char *private_key_data_base64 = base64_encode(private_key_data, private_key_data_len);
    fprintf(private_key_file, "%s", private_key_data_base64);

    free(private_key_data);

    fprintf(private_key_file, "-----END PRIVATE KEY-----\n");

    fclose(private_key_file);

    if (!public_key_file)
    {
        fprintf(stderr, "Error opening file\n");
        exit(1);
    }

    // Public key 
    fprintf(public_key_file, "-----BEGIN PUBLIC KEY-----\n");

    int public_key_data_len = BN_num_bytes(key_pair.n) + BN_num_bytes(key_pair.e);

    unsigned char *public_key_data = (unsigned char *)malloc(public_key_data_len);
    if (!public_key_data)
    {
        fprintf(stderr, "Error allocating memory\n");
        exit(1);
    }

    BN_bn2bin(key_pair.n, public_key_data);
    BN_bn2bin(key_pair.e, public_key_data + BN_num_bytes(key_pair.n));

    char *public_key_data_base64 = base64_encode(public_key_data, public_key_data_len);
    fprintf(public_key_file, "%s", public_key_data_base64);

    free(public_key_data);

    fprintf(public_key_file, "-----END PUBLIC KEY-----\n");

    fclose(public_key_file);
}

/**
 * @brief This function generates an RSA key pair from a Pseudo-Random Byte Stream
 *
 * @param bytes The pseudo-random byte array that will be used to generate the key pair
 *
 * @return The RSA key pair
 */
RSA_KEY_PAIR rsagen(uint8_t *bytes)
{
    RSA_KEY_PAIR key_pair = {NULL, NULL, NULL};

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!p || !q || !n || !e || !d || !ctx)
    {
        fprintf(stderr, "Error initializing BIGNUM variables\n");
        goto cleanup;
    }

    // Divide the pseudo-random bytes in two halves
    uint8_t *bytes_p = bytes;
    uint8_t *bytes_q = bytes + RSA_KEY_SIZE / 16;


    if (!BN_bin2bn(bytes_p, RSA_KEY_SIZE / 16, p)) // p value
    {
        fprintf(stderr, "Error setting P value\n");
        goto cleanup;
    }

    if (!BN_bin2bn(bytes_q, RSA_KEY_SIZE / 16, q)) // q value
    {
        fprintf(stderr, "Error setting Q value\n");
        goto cleanup;
    }

    while (!BN_is_prime_ex(p, BN_prime_checks, ctx, NULL) || !BN_is_prime_ex(q, BN_prime_checks, ctx, NULL) || BN_cmp(p, q) == 0)
    {
        if (!BN_add_word(p, 1))
        {
            fprintf(stderr, "Error incrementing P\n");
            goto cleanup;
        }

        if (!BN_add_word(q, 1))
        {
            fprintf(stderr, "Error incrementing Q\n");
            goto cleanup;
        }
    }

    if (!BN_mul(n, p, q, ctx)) // n = p * q
    {
        fprintf(stderr, "Error calculating modulus\n");
        goto cleanup;
    }

    if (!BN_set_word(e, RSA_F4)) // 2^16 + 1
    {
        fprintf(stderr, "Error setting exponent\n");
        goto cleanup;
    }

    if (!BN_mod_inverse(d, e, n, ctx)) // d = e^-1 mod n
    {
        fprintf(stderr, "Error calculating private exponent\n");
        goto cleanup;
    }

    key_pair.n = n;
    key_pair.e = e;
    key_pair.d = d;

// Free variables
cleanup:
    BN_free(p);
    BN_free(q);

    if (ctx)
        BN_CTX_free(ctx);

    if (ferror(stderr))
        exit(EXIT_FAILURE);

    return key_pair;
}

int main(int argc, char **argv)
{
    if (argc != 4) // Usage => ./rsa <password> <confusion_string> <iterations>
    {
        fprintf(stderr, "Usage: ./rsa <password> <confusion_string> <iterations>\n");
        exit(1);
    }

    const char *password = argv[1];
    const char *confusion_string = argv[2];
    int iterations = atoi(argv[3]);

    // Generate random bytes
    uint8_t bytes[RSA_KEY_SIZE / 8];
    randgen(RSA_KEY_SIZE / 8, password, confusion_string, iterations, bytes);

    // Generate RSA key pair
    RSA_KEY_PAIR key_pair = rsagen(bytes);

    storekey(key_pair, "private_key.pem", "public_key.pem");

    return 0;
}