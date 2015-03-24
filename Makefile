# Alix Cook 
# amc2316
# makefile

CC=gcc
CFLAGS=-I. -g
DEPS = hash.h aes.h shared.h
OBJCL1 = client.o hash.o aes.o shared.o
OBJSER = server.o aes.o hash.o shared.o
OBJCL2 = hash.o
OBJTEST = test.o aes.o hash.o shared.o

EXE = client server
LIBS = -lcrypto



%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all: $(EXE) 

client: $(OBJCL1)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

test: $(OBJTEST)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)

hash: $(OBJCL2)
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


server: $(OBJSER) 
		gcc -o $@ $^ $(CFLAGS) $(LIBS)


.PHONY: clean

clean:
		rm -f *.o *~ a.out core $(EXE)
