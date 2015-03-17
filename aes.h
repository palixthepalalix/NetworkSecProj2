//Alix Cook
//aes header

//returns length of ciphertext
int aes_encrypt(char *key, char *message, unsigned char *cipherBuff);

//returns length of plaintext
int aes_decrypt(char *key, unsigned char *ciphertext, int cipher_len, unsigned char *decrypt);
int aes(char *key, unsigned char *changetext, int text_len, unsigned char *buffer, int encrypt);
