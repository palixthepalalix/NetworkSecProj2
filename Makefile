# Alix Cook 
# amc2316
# makefile

CC=gcc
CFLAGS=-I.
DEPS = hash.h aes.h
OBJCL1 = client.o hash.o aes.o
OBJSER = server.o aes.o hash.o
OBJCL2 = client2.o client_sockets.o hash.o aes.o rsa.o

EXE = client server
LIBS = -lcrypto



%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all: $(EXE) 

client: $(OBJCL1)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

client2: $(OBJCL2)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


server: $(OBJSER) 
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


.PHONY: clean

clean:
		rm -f *.o *~ a.out core $(EXE)
