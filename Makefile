# Alix Cook 
# amc2316
# makefile

CC=gcc
CFLAGS=-Wno-deprecated -Wno-deprecated-declarations -I.
DEPS = aes.h hash.h shared.h
OBJCL1 = openssl-bio-fetch.o
OBJSER = openssl-server.o
OBJsserv = s_server.o aes.o hash.o shared.o
OBJcli = s_client.o aes.o hash.o shared.o
OBJtest = aeslib.o hash.o shared.o
TESTCLI = testclient.o $(OBJtest)
TESTSER = testserver.o $(OBJtest)


EXE = s_server s_client
LIBS = -lcrypto -lssl



%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all: $(EXE) 

test: testserver testclient

openssl-bio-fetch: $(OBJCL1)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

openssl-server: $(OBJSER)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

s_server: $(OBJsserv)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

s_client: $(OBJcli)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

testclient: $(TESTCLI)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


testserver: $(TESTSER) 
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

csr: 
		openssl req -new -nodes -keyout sprivate.pem -out srequest.csr -days 365

cert: ca csr
		openssl x509 -req -days 500 -in srequest.csr -CA rootCA.pem -CAkey rootCA.key -out scert.pem

ca:
		openssl req -new -x509 -days 3650 -extensions v3_ca -keyout rootCA.key -out rootCA.pem 

.PHONY: clean

clean:
		rm -f *.o *~ a.out core $(EXE)
