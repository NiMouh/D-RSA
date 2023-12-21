/**
 * @file performance.c
 * @author Ana Raquel Neves Vidal (118408)
 * @author Simão Augusto Ferreira Andrade (118345)
 * @brief This file contains the performance tests of the setup of the D-RSA in C.
 * @date 2023-12-21
 *
 * @copyright Copyright (c) 2023
 *
 */

// Standard libraries
#include <stdio.h>
#include <string.h>
#include <time.h>

// OpenSSL libraries
#include <openssl/evp.h>
#include <openssl/sha.h>

// Constants
#define SEED_SIZE 32 // bytes

/**
 * @brief This function generates the pbkdf2
 *
 * @param password The password to be used
 * @param salt The salt to be used
 * @param iterations The number of iterations to be used
 * @param key_derivator The output pbkdf2
 *
 * @return 1 if the pbkdf2 was generated successfully, 0 otherwise
 */
int pbkdf2(const char password[], const char salt[], int iterations, uint8_t key_derivator[])
{

    if (password == NULL || salt == NULL)
    {
        fprintf(stderr, "Invalid input: password or salt is NULL\n");
        return 0;
    }

    size_t password_len = strlen(password);
    size_t salt_len = strlen(salt);

    if (PKCS5_PBKDF2_HMAC(password, password_len, (const unsigned char *)salt, salt_len, iterations, EVP_sha256(), SEED_SIZE, key_derivator) != 1)
    {
        fprintf(stderr, "Error generating key derivator\n");
        return 0;
    }

    return 1;
}

/**
 * @brief Function to use the generator to produce a pseudo-random stream of bytes
 *
 * @param buffer a pointer to an array where the bytes will be allocated
 * @param size  the size of the array
 */
void generate_random_bytes(void *buffer, size_t size)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL)
    {
        perror("Error opening /dev/urandom");
        exit(EXIT_FAILURE);
    }

    if (fread(buffer, 1, size, urandom) != size)
    {
        perror("Error reading random bytes from /dev/urandom");
        fclose(urandom);
        exit(EXIT_FAILURE);
    }

    fclose(urandom);
}

/**
 * @brief this function is used to test the speed on the pbkdf2 function (consider using the /dev/urandom to generate random bytes to test)
 * and send the time results to stdout
 *
 * @param password_size_interval An array with the password sizes to be tested
 * @param salt_size_interval An array with the salt sizes to be tested
 * @param iterations_interval An array with the number of iterations to be tested
 * @param password_size_count The number of password sizes to be tested
 * @param salt_size_count The number of salt sizes to be tested
 * @param iterations_count The number of iterations to be tested
 *
 */
void setup_performance(int password_size_interval[], int salt_size_interval[], int iterations_interval[], int password_size_count, int salt_size_count, int iterations_count)
{
    printf("%-15s%-15s%-15s%-20s\n", "Password size", "Salt size", "Iterations", "Time spent (seconds)"); // header

    for (int password_index = 0; password_index < password_size_count; password_index++)
    {
        for (int salt_index = 0; salt_index < salt_size_count; salt_index++)
        {
            for (int iterations_index = 0; iterations_index < iterations_count; iterations_index++)
            {
                char password[password_size_interval[password_index]];
                char salt[salt_size_interval[salt_index]];
                uint8_t key_derivator[SEED_SIZE];

                generate_random_bytes(password, password_size_interval[password_index]);
                generate_random_bytes(salt, salt_size_interval[salt_index]);

                clock_t start = clock();
                pbkdf2(password, salt, iterations_interval[iterations_index], key_derivator);
                clock_t end = clock();

                double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

                printf("%-15d%-15d%-15d%-20f\n", password_size_interval[password_index], salt_size_interval[salt_index], iterations_interval[iterations_index], time_spent); // line
            }
        }
    }
}

int main()
{
    // values to be tested
    int password_sizes[] = {5, 50, 200};
    int salt_sizes[] = {5, 50, 200};
    int iteration_counts[] = {1, 10, 100};

    int password_size_count = sizeof(password_sizes) / sizeof(password_sizes[0]);
    int salt_size_count = sizeof(salt_sizes) / sizeof(salt_sizes[0]);
    int iteration_count = sizeof(iteration_counts) / sizeof(iteration_counts[0]);

    setup_performance(password_sizes, salt_sizes, iteration_counts, password_size_count, salt_size_count, iteration_count);

    return 0;
}
