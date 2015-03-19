#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"
#include "aes.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#define DISK_IO_BUF_SIZE 4096

static unsigned char *iv = "01234567890123456"; // make sure this is the right length?
void handlePutRequest(char *fileName, int encrypted, char *pswd, int sock);
void handleGetRequest(char *fileName, int encrypted, char *pswd, int sock);

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void printError(const char *err)
{
    printf("ERROR: %s\n", err);
}

int connect_to_server(char *address, char *port)
{
    int sockfd, n, portno;
    struct sockaddr_in servaddr;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    bzero(&servaddr, sizeof servaddr);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((rv = getaddrinfo(address, port, &hints, &servinfo)) != 0)
        die("Addr info error");
    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if(sockfd < 0)
        die("socket() error");

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(portno);
    if(connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0)
        die("connect() error");
    return sockfd;
}

void parseRequest(char *request, int sock)
{
    char *token_seperators = "\t \r\n";
    char *method = "";
    char *requestFile = "";
    char *mode = "";
    char *pswd = "";
    int putRequest, encrypted;

    //use tokenizer to parse request line
    method = strtok(request, token_seperators);
    requestFile = strtok(NULL, token_seperators);
    mode = strtok(NULL, token_seperators);
    pswd = strtok(NULL, token_seperators);

    // make sure minumum fields are specified
    if(method == NULL || requestFile == NULL || mode == NULL) {
        printError("Missing parameters, a minimum of a filename and \"N\" or \"E\" is required");
        return;
    }

    //get request type
    if(strcmp(method, "get") == 0) {
        printf("get request\n");
        putRequest = 0;
    }
    else if(strcmp(method, "put") == 0) {
        printf("put request\n");
        putRequest = 1;
    }
    else {
        printError("Invalid commands, options are \"get\" \"put\" \"stop\"");
        return;
    }

    //get mode type
    if(strcmp(mode, "E") == 0) {
        printf("encrypt mode\n");
        if(pswd == NULL) {
            //make sure password is specified when in E mode
            printError("Missing parameters,  \"E\" requires password\n");
            return;
        }
        encrypted = 1;
    }
    else if (strcmp(mode, "N") == 0) {
        printf("no encryption\n");
        encrypted = 0;
    }
    else {
        printError("Valid modes are N and E");
        return;
    }
    printf("trying to print request\n");
    printf("%s\n", request);
    send(1, request, strlen(request), 0);
    printf("hi\n");
    if(putRequest)
        handlePutRequest(requestFile, encrypted, pswd, sock);
    else
        handleGetRequest(requestFile, encrypted, pswd, sock);
}

void makeKey(char *pswd, char *buf)
{
    strcpy(buf, "1234567890123456");
}

void handlePutRequest(char *fileName, int encrypted, char *pswd, int sock)
{
    //generate SHA256 hash of plaintext file

    printf("handling put request\n");
    unsigned char *ftext, hashBuff[2048/8];
    char *ciphertext, buf[2000], key[16];
    int ciphLen, fsize;
    //send PUT {filename} {E or N}
    //make sure handling different directories
    //and handling binary and ascii files
    FILE *f;
    f = fopen(fileName, "rb");
    if(f == NULL) {
        printError("File cannot be transferred");
        return;
    }
    int n;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    ftext = malloc(fsize + 1);
    fread(ftext, fsize, 1, f);
    fclose(f);
    printf("%s", ftext);
    //can only use hash on clic machines
    hash(ftext, hashBuff);

    //if encrypted, use password as seed to random number generator
 
    if(encrypted) {
        //encrypt this shit
        makeKey(pswd, key);
        ciphertext = malloc(fsize + 256); // size of file plus aes block size
        //gotta prepend that mutha fuggin IV
        //ciphLen = aes(key, ftext, strlen(buf), ciphertext, 1);
    }
    //send file (with iv prepended if valid) and hash to server
    //send(sock, ciphertext, ciphLen, 0);
    //send(sock, hashBuff, sizeof(hashBuff), 0);
    printf("transfer of %s complete", fileName);
}

void handleGetRequest(char *fileName, int encrypted, char *pswd, int sock)
{

    //recv file
    //decrypt if need be
    //compute hash
    //hash(txt, buf)
    //compare
    //if valid, write that shit to directory
    //not valid, display msg to user
    printf("handling get request\n");


    printf("retrieval of %s complete", fileName);
}

int main(int argc, char **argv)
{
    char requestLine[200];
    if(argc < 3)
        die("USAGE exe {ip address} {port no}");

    int sockfd;
    //sockfd = connect_to_server(argv[1], argv[2]);
    char b[20];
    sprintf(b, "hiiiii", 7);
    send(2, b, strlen(b), 0);

    printf(">>");
    while(1) {
        if(fgets(requestLine, sizeof(requestLine), stdin) == NULL)
            printError("something wrong with getting stdin");
        requestLine[strlen(requestLine) - 1] = '\0';
        char *stop;
        stop = "stop";
        if(strcmp(requestLine, stop) == 0)
            break;
        parseRequest(requestLine, sockfd);
        printf(">>");
    }

    return 1;
}
