/*
 * Alix Cook
 * amc2316
 * server
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <strings.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "hash.h"
#include "aes.h"
#include "shared.h"


void die( char *msg )
{
    printf("%s\n", msg);
    exit(1);
}

int create_client_sock(int portno)
{
    int sockfd, newsockfd, clientlen;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if ( sockfd < 0 )
        die("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if ( bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0 )
        die("ERROR binding client socket");
    return sockfd;
}    

void handlePut(char *filename, int clntsock)
{
    unsigned int sizeNet, size;
    char *data, hashBuf[2048/8];
    // recv SHA256 of data
    int x = Recv(clntsock, hashBuf, 64);
    hashBuf[x] = '\0';

    // recv size of data that is to be written to file 
    Recv(clntsock, &sizeNet, sizeof(unsigned int));
    size = ntohs(sizeNet);
    data = malloc(size);
    
    //recv file data
    Recv(clntsock, data, size);//-1);
    //data[size] = '\0';

    //now write the data to file
    FILE *writef = fopen(filename, "wb");
    fwrite(data, size, 1, writef);
    fclose(writef);
    free(data);

    //append .sha256 to filename
    char shafile[strlen(filename) + strlen(".sha256")];
    strcpy(shafile, filename);
    strcat(shafile, ".sha256");
    //write hash to {filename}.sha256
    FILE *sha256 = fopen(shafile, "wb");
    fwrite(hashBuf, 64, 1, sha256);
    fclose(sha256);
}


/*
void RecvFile(char *filename, int clntsock)
{
    unsigned int sizeNet, size;
    char *data, hashBuf[2048/8], hashCmp[2048/8];
    Recv(clntsock, &sizeNet, sizeof(unsigned int));
    size = ntohs(sizeNet);
    printf("size of pack: %d\n", size);
    data = malloc(size);
    int x = Recv(clntsock, hashBuf, 64);
    hashBuf[x] = '\0';
    Recv(clntsock, data, size -1);
    data[size] = '\0';
    if(validateHash(hashBuf, data) == 1)
        printf("valid\n");
    else
        printf("invalid\n");
    FILE *writef = fopen("newfile", "wb");
    fwrite(data, size - 1, 1, writef);
    fclose(writef);
    
    free(data);
}
*/

void handleRequest(char *request, int sock)
{
    int isPut, isEnc;
    char *token_seperators = "\t \r\n";
    char *method = "";
    char *requestFile = "";
    char *mode = "";
    char *pswd = "";
    
    method = strtok(request, token_seperators);
    requestFile = strtok(NULL, token_seperators);
    mode = strtok(NULL, token_seperators);
    pswd = strtok(NULL, token_seperators);
    printf("request %s\n", request);

    if(strcmp(method, "get") == 0) {
        isPut = 0;
    }
    else {
        isPut = 1;
    }
    if(strcmp(mode, "N") == 0) {
        isEnc = 0;
    }
    else {
        isEnc = 1;
    }
    handlePut(requestFile, sock);
    
}

int main(int argc, char **argv)
{
    int sockfd, clntSock, portno, clientlen;
    char request[1000];
    struct sockaddr_in serv_addr, client_addr;
    int n;
    if( argc < 2 )
        die("usage: exe portno");
    sockfd = create_client_sock(atoi(argv[1]));
    listen(sockfd, 5);
    for(;;) {
        printf("beginning of for loop\n");
        clientlen = sizeof(client_addr);
        printf("accepting\n");
        clntSock = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&clientlen);
        printf("accepted client\n");
        if(clntSock < 0)
            die("ERROR on accept");
        //recv encrypted key
        int y;
        while((y = Recv(clntSock, request, 4000)) > 0) {
            printf("here\n");
            if(errno == ECONNRESET){
                break;
            }
            //handle request
            if(strlen(request) < 1)
                continue;
            request[y] = '\0'; 
            printf("request: %s\n", request);
            int isPut, isEnc;
            char *token_seperators = "\t \r\n";
            char *method = "";
            char *requestFile = "";
            char *mode = "";
            char *pswd = "";
    
            method = strtok(request, token_seperators);
            requestFile = strtok(NULL, token_seperators);
            mode = strtok(NULL, token_seperators);
            pswd = strtok(NULL, token_seperators);

            if(strcmp(method, "get") == 0) {
                isPut = 0;
            }
            else {
                isPut = 1;
            }
            if(strcmp(mode, "N") == 0) {
                isEnc = 0;
            }
            else {
                isEnc = 1;
            }
            handlePut(requestFile, clntSock);
            
            printf("done handling clnt\n");
        }
    }

    close(sockfd);
    return 0;
}
