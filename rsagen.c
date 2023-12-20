/**
 * @file rsa.c
 * @brief This file contains the implementation of the D-RSA algorithm in C.
 * @date 2023-11-16
 * @author Ana Raquel Neves Vidal (118408)
 * @author Simão Augusto Ferreira Andrade (118345)
 *
 * @copyright Copyright (c) 2023
 *
 */

// Standard libraries
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// OpenSSL libraries
#include <openssl/bn.h>
#include <openssl/pem.h>

// Constants
#define RSA_BYTE_KEY_SIZE 256

/**
 * @struct RSA_KEY_PAIR
 * @brief Represents an RSA key pair.
 */
typedef struct rsa_key_pair
{
    BIGNUM *n; // modulus
    BIGNUM *e; // public exponent
    BIGNUM *d; // private exponent
} RSA_KEY_PAIR;

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
 * @brief This function stores the RSA key pair in a .PEM file.
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
    BIGNUM *phi_n = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!p || !q || !n || !e || !d || !phi_n || !ctx)
    {
        fprintf(stderr, "Error initializing BIGNUM variables\n");
        goto cleanup;
    }

    // Divide the pseudo-random bytes in two halves
    uint8_t *bytes_p = bytes;
    uint8_t *bytes_q = bytes + RSA_BYTE_KEY_SIZE / 2;

    if (!BN_bin2bn(bytes_p, RSA_BYTE_KEY_SIZE / 2, p)) // p value
    {
        fprintf(stderr, "Error setting P value\n");
        goto cleanup;
    }

    if (!BN_bin2bn(bytes_q, RSA_BYTE_KEY_SIZE / 2, q)) // q value
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

    if (!BN_sub_word(p, 1)) // p = p - 1
    {
        fprintf(stderr, "Error decrementing P\n");
        goto cleanup;
    }

    if (!BN_sub_word(q, 1)) // q = q - 1
    {
        fprintf(stderr, "Error decrementing Q\n");
        goto cleanup;
    }

    if (!BN_mul(phi_n, p, q, ctx)) // phi(n) = (p - 1) * (q - 1)
    {
        fprintf(stderr, "Error calculating phi(n)\n");
        goto cleanup;
    }

    if (!BN_set_word(e, RSA_F4)) // 2^16 + 1
    {
        fprintf(stderr, "Error setting exponent\n");
        goto cleanup;
    }

    if (!BN_mod_inverse(d, e, phi_n, ctx))
    {
        fprintf(stderr, "Error calculating d\n");
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

int main(void)
{

    // get the bytes from stdin
    uint8_t bytes[RSA_BYTE_KEY_SIZE];
    if (fread(bytes, sizeof(uint8_t), RSA_BYTE_KEY_SIZE, stdin) != RSA_BYTE_KEY_SIZE)
    {
        fprintf(stderr, "Error reading bytes from stdin\n");
        exit(1);
    }

    // Generate RSA key pair
    RSA_KEY_PAIR key_pair = rsagen(bytes);

    // Store key pair in PEM file
    storekey(key_pair, "private_key.pem", "public_key.pem");

    return 0;
}