CC = gcc
flags = -Wall -lssl -lcrypto -g 
encrypt:
	$(CC) -o ./a.out encrypt_decrypt.c $(flags)
all: encrypt
clean:
	rm ./a.out
.PHONY: clean all encrypt
