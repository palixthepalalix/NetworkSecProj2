#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <netinet/in.h>
#include "hash.h"
#include "aes.h"

void die(char *msg)
{
    perror(msg);
    exit(1);
}

int create_clnt_sock(int portno)
{
    int sockfd, clientlen;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        die("socket() error");
    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if( bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        die("bind() error");
    return sockfd;
}

int main(int argc, char **argv)
{
    int sockfd, clntsock, portno, clientlen;
    struct sockaddr_in client_addr;

    sockfd = create_clnt_sock(atoi(argv[1]));
    listen(sockfd, 5); //wtf is this right?!
    clientlen = sizeof(client_addr);
    for(;;) {
        if((clntsock = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)clientlen)) < 0)
            die("accept() error");
        printf("connected to client");
        char buffer[200];
        while(recv(clntsock, buffer, sizeof(buffer), 0) > 0)
            printf("%s", buffer);
        close(clntsock);
    }
    close(sockfd);
    return 0;
}
