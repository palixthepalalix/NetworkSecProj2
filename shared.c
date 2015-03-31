#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "hash.h"
#include <stdlib.h>


char *randomNum(char *pswd)
{
    char *randnum = malloc(16 * sizeof(char*) + 1);
    
    int i, len;
    int seed = atoi(pswd);
    srand(seed);
    for(i = 0; i < 16; i++) {
        //srand((int) seed[i]);
        int r = rand() % 10;
        char buf[2];
        sprintf(buf, "%d", r);
        strcat(randnum, buf);
    }
    randnum[16] = '\0';
    printf("key\n%s\n", randnum);
    return randnum;
}

int Recv(SSL *ssl, void *buf, int size)
{

    ssize_t result;
    result = SSL_read(ssl, buf, size);
    if(result < 0) {
        perror("recv() failed");
        if(errno == ECONNRESET) {
            printf("connection bad or whatever");
        }
        return -1;
    }
    else
        return result;

}

int Send(SSL *ssl, void *data, int size)
{
    ssize_t result;
    result = SSL_write(ssl, data, size);
    if(result != size) {
        perror("send() failed");
        return -1;
    }
    else
        return result;
}


int validateHash(char hashval[], char *data)
{
    char hashBuf[2048/8];
    hash(data, hashBuf);
    if(strcmp(hashBuf, hashval) == 0)
        return 1;
    return 0;
}

void RecvFile(char *filename, int sock, int encrypted, char *pswd)
{
    unsigned int sizeNet, size;
    char *data, hashBuf[2048/8], hashCmp[2048/8];
    int x = Recv(sock, hashBuf, 64);
    char *key = randomNum("hello");
    hashBuf[x] = '\0';
    Recv(sock, &sizeNet, sizeof(unsigned int));
    size = ntohs(sizeNet);
    printf("size %d\n", size);
    data = malloc(size);
    Recv(sock, data, size-1);
    if(!encrypted)
        data[size] = '\0';
    if(encrypted) {
        char *decrypted = malloc(size);
        printf("key %s\n", key);
        aes(key, data, size - 1, decrypted, 0);
        data = decrypted;
        printf("DECRYPT\n%s\n", decrypted);
        size = strlen(decrypted);
        free(key);
    }
    if(validateHash(hashBuf, data) == 1)
        printf("valid\n");
    else {
        printf("invalid\n");
        return;
    }
    FILE *writef = fopen(filename, "wb");
    fwrite(data, size-1, 1, writef);
    fclose(writef);
    free(data);
}
/*
int main()
{
    char *pass, *randnum;
    pass = "hellohello";
    randnum = randomNum(pass);

    printf("%s\n", randnum);
    char *pass2 = "hellohello";
    free(randnum);
    randnum = randomNum(pass2);
    printf("%s\n", randnum);
}
*/

    
