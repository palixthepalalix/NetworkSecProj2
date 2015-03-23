#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int Recv(int sock, void *buf, int size)
{
    ssize_t result;
    result = recv(sock, buf, size, 0);
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

int Send(int sock, void *data, int size)
{
    ssize_t result;
    result = send(sock, data, size, 0);
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
