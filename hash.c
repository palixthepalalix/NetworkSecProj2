/*
 * Alix Cook
 * amc2316
 * sha256 hash
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>


int hash(char *plaintext, char buffer[])
{
   
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(hash, &sha256);
   
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(buffer + (i *2), "%02x", hash[i]);
    }
    buffer[64] = 0;
  
 
    return 1;
}
