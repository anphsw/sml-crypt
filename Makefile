#CFLAGS=-lcrypto -Wall -O2 -s
CFLAGS+=-lcrypto -Wall -O0 -ggdb -DDEBUG

all: clean smlcrypt

smlcrypt:
	$(CC) $(CFLAGS) smlcrypt.c -o smlcrypt

clean:
	$(RM) smlcrypt
