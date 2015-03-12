# Alix Cook 
# amc2316
# makefile

CC=gcc
CFLAGS=-I.
DEPS = client_sockets.h hash.h aes.h rsa.h
OBJCLNT = client.o hash.o aes.o
OBJSER = server.o

EXE = client server 
LIBS = -lcrypto



%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all: $(EXE) 

client1: $(OBJCLNT)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

server: $(OBJSER) 
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


.PHONY: clean

clean:
		rm -f *.o *~ a.out core $(EXE)
