/*
 * ECB encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int encrypt(unsigned char *input, int len, unsigned char *key, int klen);

/*
 * ECB decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int decrypt(unsigned char *input, int len, unsigned char *key, int klen);


/*
 * CBC encryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains ciphertext on exit
 * 'iv' must hold a 16 byte initialization vector
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int encryptCBC(unsigned char *input, int len, unsigned char *key, 
               int klen, unsigned char *iv);

/*
 * CBC decryption routine
 * size of 'input' has to be multiple of 16
 * 'input' contains cleartext on exit
 * 'iv' must hold the same 16 byte initialization vector
 * that has been used to encrypt the cleartext
 * returns 0 if parameters are invalid and 1 otherwise 
 */  
int decryptCBC(unsigned char *input, int len, unsigned char *key, 
               int klen, unsigned char *iv);

/*
 * key should not have and \r or \n 
 * character at the end to ensure compatibility
 */
void trimKey(char *key);
int aesdec(SSH *ssh, FILE *outfile, char *key);
int aesenc(FILE *infp, SSL *ssl, char *key);
