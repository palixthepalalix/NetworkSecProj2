#include <openssl/ssl.h>
#include <openssl/bio.h>

#define MAX_FILESIZE 1000000

struct Data {
    char iv[16];
    char content[MAX_FILESIZE];
    unsigned char hash[2048/8];
};

struct Header {
    char request[1000];
    int size;
};


int Recv(SSL *ssh, void *data, int size);
int Send(SSL *ssh, void *data, int size);
int validateHash(char hashval[], char *data);
int RecvFile(char *filename, int sock, int encrypted, char *pswd);
char *randKey(char *password, char *k);
