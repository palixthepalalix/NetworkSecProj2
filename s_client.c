
/* A simple SSL client.

   It connects and then forwards data from/to the terminal
   to/from the server
   */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

const char *PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
void print_san_name(const char* label, X509* const cert);
void print_cn_name(const char* label, X509_NAME* const name);
#define HOSTNAME "www.random.org"
#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"
#define PRIVATE_KEY "sprivate.pem"
#define CERTIFICATE "scert.pem"


int connect_to_server(char *address, char *port)
{
    int sockfd, clntsock;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if((rv = getaddrinfo(address, port, &hints, &servinfo))!=0)
        exit(1);
    
    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if(sockfd<0) {
        exit(1);
    }
    if(connect(sockfd, servinfo->ai_addr,servinfo->ai_addrlen) < 0)
        exit(1);
    return sockfd;
}


void init_libs() {
    (void)SSL_library_init();

    SSL_load_error_strings();

    OPENSSL_config(NULL);
}
void die(char *msg) {
    printf("%s\n", msg);
}

void parseRequest(char *request, SSL *ssl)
{
    char *token_seperators = "\t \r\n";
    char *method = "";
    char *requestFile = "";
    char *mode = "";
    char *pswd = "";
    int putRequest, encrypted;
    char reqPack[200];
    strcpy(reqPack, request);

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
        pswd[strlen(pswd)] = '\0';
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
    printf("%s\n", reqPack);
    strcat(reqPack, "\n");
    Send(ssl, (void *)reqPack, strlen(reqPack));
    printf("hi\n");
    if(putRequest)
        handlePutRequest(requestFile, encrypted, pswd, ssl);
    else
        handleGetRequest(requestFile, encrypted, pswd, ssl);
}

void makeKey(char *pswd, char *buf)
{
    strcpy(buf, "1234567890123456");
}

void handlePutRequest(char *fileName, int encrypted, char *pswd, SSL *ssl)
{
    //generate SHA256 hash of plaintext file

    printf("handling put request\n");
    unsigned char *ftext, hashBuff[2048/8];
    char *ciphertext, buf[2000];
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
    printf("filesize: %d\n", fsize);
    unsigned int sendSize = htons(fsize + 1);
    //Send(sock, &sendSize, sizeof(unsigned int));

    printf("b");
    ftext = malloc(fsize + 1); 
    printf("c");
    fread(ftext, fsize, 1, f);
    fclose(f);
    
    hash(ftext, hashBuff);
    Send(ssl, hashBuff, strlen(hashBuff));
    if(!encrypted) {
        Send(ssl, &sendSize, sizeof(unsigned int));
        Send(ssl, ftext, sendSize);
    }
    else if(encrypted) {
        //encrypt this shit
        char *key;
        key = getrand(pswd);
        
        printf("password: %s\n", pswd);
        ciphertext = malloc(fsize + 256); // size of file plus aes block size
        //gotta prepend that mutha fuggin IV
        ciphLen = aes(key, ftext, fsize, ciphertext, 1);
        sendSize = htons(ciphLen+1);
        
        printf("ciphlen %d\n", ciphLen);
        Send(ssl, &sendSize, sizeof(unsigned int));
        //Send(sock, ciphertext, ciphLen);
        int p = Send(ssl, ciphertext, ciphLen);
        char *d = malloc(ciphLen);
        aes(key, ciphertext, ciphLen, d, 0);
        printf("decrypt\n%s\n", d);
    }
    //send file (with iv prepended if valid) and hash to server
    //send(sock, ciphertext, ciphLen, 0);
    //Send(sock, hashBuff, strlen(hashBuff));
    printf("\nhash: %s\n", hashBuff);
    printf("transfer of %s complete", fileName);
}

void handleGetRequest(char *fileName, int encrypted, char *pswd, SSL *ssl)
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

int main(int argc,char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio, *bbio, *acpt, *out;
    int sock, res;
    unsigned long sslerr = 0;
    if(argc < 3) {
        printf("port\n");
        exit(1);
    }
    char *host = argv[1];
    char *port = argv[2];

    init_libs();

    printf("1\n");
    /* Build our SSL context*/
    ctx = SSL_CTX_new(SSLv23_client_method());

    //need own certificate, CA certificate optional
    //SSL_CTX_use_certificate_chain_file(ctx, "server.pem");
    if(!SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) ||
    !SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM) ||
    !SSL_CTX_check_private_key(ctx)) {
        printf("cert errorors");
        exit(1);
    }
    // not really sure what this does
    // SSL_CTX_set_session_id_context(ctx, sid, 4);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    ssl = SSL_new(ctx);

    sock = connect_to_server(host, port);
    //this loads the certificates
    SSL_CTX_load_verify_locations(ctx, "rootCA.pem", NULL);
    //SSL_set_session_id_context(ssl, sid, 4);
    //sbio = BIO_new_ssl(ctx, 0);

    printf("connected\n");

    sbio = BIO_new(BIO_s_socket());
    BIO_set_fd(sbio, sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    
    //handshake on server
    SSL_connect(ssl);
    if(SSL_get_verify_result(ssl) != X509_V_OK)
        printf("certificate not verified");
/*
    X509 *peer = SSL_get_peer_certificate(ssl);
    char peer_CN[256];
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
            NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN, host))
        printf("comm name does not match host name");
*/

    printf(">>");
    while(1) {
        if(fgets(requestLine, sizeof(requestLine), stdin) == NULL)
            printError("something wrong with getting stdin");
        requestLine[strlen(requestLine)] = '\0';
        char *stop;
        stop = "stop";
        if(strcmp(requestLine, stop) == 0)
            break;
        printf("parsing request: %s\n", requestLine);
        parseRequest(requestLine, ssl);
        printf(">>");
    }

   
}



int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);
    
    /* Issuer is the authority we trust that warrants nothing useful */
    print_cn_name("Issuer (cn)", iname);
    
    /* Subject is who the certificate is issued to by the authority  */
    print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        print_san_name("Subject (san)", cert);
    }
    
    if(preverify == 0)
    {
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }

#if !defined(NDEBUG)
    return 1;
#else
    return preverify;
#endif
}
void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }

    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
    
}
