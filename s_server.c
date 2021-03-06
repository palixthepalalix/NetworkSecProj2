
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
#include "aeslib.h"

const char *PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx);
void print_san_name(const char* label, X509* const cert);
void print_cn_name(const char* label, X509_NAME* const name);
#define HOSTNAME "www.random.org"
#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"
#define PRIVATE_KEY "sprivate.pem"
#define CERTIFICATE "scert.pem"
#define BUFSIZE 512

void serv_put(SSL *ssl, char *filename);
void serv_get(SSL *ssl, char *filename);

void die(char *msg) {
    perror( msg);
    exit(1);
}

int create_client_sock(int portno)
{
    int sockfd, clntsock, clntlen;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd<0) {
        die("socket error");
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        die("bind() error");
    return sockfd;
}

void serv_get(SSL *ssl, char *filename){
    chdir("serverfiles");;
    printf("SERVER IS TRANSMITTING GET FILE\n");
    char buffer[512];
    FILE *infile = fopen(filename, "rb");
    int n;
    int datasize = 0;

    printf("writing\n");
    while((n = fread(buffer, sizeof(buffer), 1, infile))>0) {
        printf("%s", buffer);
    
        SSL_write(ssl, buffer, sizeof(buffer));
        memset(buffer, 0, sizeof(buffer));
    }
    printf("done\n");
    fclose(infile);
    
    char hashBuf[2048/8];

    char shafname[strlen(filename) + strlen(".sha256") + 1];
    sprintf(shafname, "%s.sha256", filename);

    FILE *sha = fopen(shafname, "rb");
    fwrite(hashBuf, 65, 1, sha);
    hashBuf[64] = '\0';
    fclose(sha);
    printf("write hashbuf\n");
    SSL_write(ssl, hashBuf, 65);
    printf("done write hashbuf\n");
    chdir("../");

}
void serv_put(SSL *ssl, char *filename) {
    chdir("serverfiles");
    printf("SERVER IS RECIEVING PUT FILE\n");
    char buffer[512];
    FILE *outfile = fopen(filename, "wb");
    int n;
    int datasize = 0;

    printf("waiting on read data\n");
    while((n = SSL_read(ssl, buffer, sizeof(buffer)))>0) {
        printf("%s", buffer);
        
        fwrite(buffer, sizeof(buffer), 1, outfile);
        datasize+=n;
        memset(buffer, 0, sizeof(buffer));
    }
    printf("done reading data\n");
    fclose(outfile);
    FILE *rfp = fopen(filename, "rb");
    char *data = malloc(datasize + 1);
    fread(data, sizeof(data), 1, rfp);
    fclose(rfp);
    char hashBuf[2048/8];
    printf("reading hash buf data\n");
    SSL_read(ssl, hashBuf, 65);
    printf("done reading hash buf data\n");

    char shafname[strlen(filename) + strlen(".sha256") + 1];
    sprintf(shafname, "%s.sha256", filename);

    FILE *sha = fopen(shafname, "wb");
    fwrite(hashBuf, strlen(hashBuf), 1, sha);
    fclose(sha);

    free(data);
    chdir("../");
}

void handlePut(char *filename, SSL *ssl)
{
    /*
    chdir("serverfiles");
    unsigned int sizeNet, size;
    char *data, hashBuf[2048/8];
    // recv SHA256 of data
    int x = Recv(ssl, hashBuf, 64);
    hashBuf[x] = '\0';

    // recv size of data that is to be written to file 
    Recv(ssl, &sizeNet, sizeof(unsigned int));
    size = ntohs(sizeNet);
    data = malloc(size);
    
    //recv file data
    Recv(ssl, data, size);//-1);
    //data[size] = '\0';

    //now write the data to file
    FILE *writef = fopen(filename, "wb");
    fwrite(data, size-1, 1, writef);
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
    chdir("../");
    */
}

void handleGet(char *filename, SSL *ssl)
{
    /*
    chdir("serverfiles");
    char shafile[strlen(filename) + strlen(".sha256")];
    char *data;
    strcpy(shafile, filename);
    strcat(shafile, ".sha256");
    //write hash to {filename}.sha256
    FILE *sha256 = fopen(shafile, "rb");
    char hashBuf[2048/8];
    fgets(hashBuf, 70, sha256);
    fclose(sha256);
    hashBuf[64] = '\0';
    printf("hash buf %s\n", hashBuf);

    FILE *f = fopen(filename, "rb");
    int fsize;
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned int sendSize = htons(fsize + 1);
    
    data = malloc(fsize + 1);
    fread(data, fsize, 1, f);
    fclose(f);
    Send(ssl, hashBuf, strlen(hashBuf));
    Send(ssl, &sendSize, sizeof( unsigned int ));
    Send(ssl, data, sendSize);
    free(data);
    chdir("../");
    */
 
}

void handleRequest(char *request, SSL *ssl)
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
    handlePut(requestFile, ssl);
    
}



void init_libs() {
    (void)SSL_library_init();

    SSL_load_error_strings();

    OPENSSL_config(NULL);
}


typedef struct connection {
    BIO *read;
    BIO *write;
    SSL *ssl;
    SSL_CTX *ctx;
} connection;

void handle_send(connection *sender, connection *receiver)
{
    char buffer[1024];
    int read = BIO_read(sender->write, buffer, 1024);
    int written = read > 0 ? BIO_write(receiver->read, buffer, read) : -1;

    if(written > 0) {
        if(!SSL_is_init_finished(receiver->ssl))
            SSL_do_handshake(receiver->ssl);
        else {
            read = SSL_read(receiver->ssl, buffer, 1024);
            printf("message: %s\n", buffer);
        }
    }
}

int main(int argc,char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio, *bbio, *acpt, *out;
    int sock, res;
    unsigned long sslerr = 0;
    if(argc < 2) {
        printf("port\n");
        exit(1);
    }
    char *port = argv[1];

    init_libs();

    printf("1\n");
    /* Build our SSL context*/
    ctx = SSL_CTX_new(SSLv23_server_method());

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

    SSL_CTX_load_verify_locations(ctx, "rootCA.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 1);
    ssl = SSL_new(ctx);

    sock = create_client_sock(atoi(port));
    //this loads the certificates

    //SSL_set_session_id_context(ssl, sid, 4);
    //sbio = BIO_new_ssl(ctx, 0);
    if(listen(sock, 5) < 0)
        die("listen() failed");
    for(;;) {
        printf("back to accepting\n");
        struct sockaddr_in client_addr;
        int clntlen, clntSock;
        clntSock = accept(sock, (struct sockaddr *)&client_addr, (socklen_t *)&clntlen);
        if(clntSock < 0)
            die("failed accept");
        printf("accepted client\n");

        sbio = BIO_new(BIO_s_socket());
        BIO_set_fd(sbio, clntSock, BIO_NOCLOSE);
        SSL_set_bio(ssl, sbio, sbio);
        
        //handshake on server
        SSL_accept(ssl);
        char request[BUFSIZE];
        int s = 0;
        while((s = SSL_read(ssl, request, sizeof(request))) > 0) {
            request[s] = '\0';
            printf("s %d, strlen %d", s, strlen(request));
            if(strlen(request) != s)
                continue;
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
            if(isPut) 
                serv_put(ssl, requestFile);
            else
                serv_get( ssl, requestFile);
            
            printf("done handling clnt\n");
        }

        //get peer certificate?
        //peer_cert = SSL_get_peer_certificate(ssl);
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
