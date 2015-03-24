/*
 * Alix Cook
 * amc2316
 * aes encryption functions
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static unsigned char *iv = "01234567890123456";

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();


    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;


    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);


    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;
   

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_encrypt(char *key, char *message, unsigned char *cipherBuff)
{ 
    int ciphertext_len;
    char *p = "1234567890123456";
    
       
 
   
//    ERR_load_crypto_strings();
 //   OpenSSL_add_all_algorithms();
  //  OPENSSL_config(NULL);

    ciphertext_len = encrypt(message, strlen(message),  key, iv, cipherBuff);
    EVP_cleanup();
    ERR_free_strings();
    return ciphertext_len;
}
int aes(char *key, unsigned char *changetext, int text_len, unsigned char *buffer, int do_encrypt)
{
  
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    int result_len;
    if(do_encrypt)
        result_len = encrypt(changetext, text_len,  key, iv, buffer);
    else {
        result_len = decrypt(changetext, text_len, key, iv, buffer);
        buffer[result_len] = '\0';
    }

    EVP_cleanup();
    ERR_free_strings();
    return result_len;
}
int aes_decrypt(char *key, unsigned char *ciphertext, int cipherlen, unsigned char *decrypted)
{

   
  
 
   // ERR_load_crypto_strings();
    //OpenSSL_add_all_algorithms();
   // OPENSSL_config(NULL);
    int decrypt_len;

    decrypt_len = decrypt(ciphertext, cipherlen, key, iv, decrypted);
    decrypted[decrypt_len] = '\0';
    EVP_cleanup();
    ERR_free_strings();
    return decrypt_len;
}

