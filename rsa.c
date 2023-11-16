#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

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
 * @param size The size of the byte array to be generated
 * @param password The password to be used as seed
 * @param confusion_string The confusion string to be used as seed
 * @param iterations The number of iterations to be used as seed
 * @param output The output byte array
 * 
 */
void randgen(size_t size, uint8_t *password, uint8_t *confusion_string, int iterations, uint8_t *output){
    // TODO: Implement this function
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
void rsagen(size_t key_size, uint8_t *password, uint8_t *confusion_string, int iterations, uint8_t *public_key, uint8_t *private_key){
    // TODO: Implement this function
}

int main(void){ // int argc, char **argv

    // TODO: Usage => ./rsa <key_size> <password> <confusion_string> <iterations>

    return 0;
}