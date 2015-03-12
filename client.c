#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libs/hash.h"
#include "libs/aes.h"

void handlePutRequest(char *fileName, int encrypted, char *pswd);
void handleGetRequest(char *fileName, int encrypted, char *pswd);

static void die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void printError(const char *err)
{
    printf("ERROR: %s\n", err);
}

void parseRequest(char *request)
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
    if(putRequest)
        handlePutRequest(requestFile, encrypted, pswd);
    else
        handleGetRequest(requestFile, encrypted, pswd);
}

void handlePutRequest(char *fileName, int encrypted, char *pswd)
{
    printf("handling put request\n");
}

void handleGetRequest(char *fileName, int encrypted, char *pswd)
{
    printf("handling get request\n");
}

int main(int argc, char **argv)
{
    char requestLine[200];
    if(argc < 3)
        die("USAGE exe {ip address} {port no}");

    printf(">>");
    while(1) {
        if(fgets(requestLine, sizeof(requestLine), stdin) == NULL)
            printError("something wrong with getting stdin");
        requestLine[strlen(requestLine) - 1] = '\0';
        char *stop;
        stop = "stop";
        if(strcmp(requestLine, stop) == 0)
            break;
        parseRequest(requestLine);
        printf(">>");
    }

    return 1;
}
