CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g -I .
LDFLAGS = -L . -L ./libkmem -lkmem -lssl -lcrypto

.PHONY: all clean run

all: libkmem test

kmem:
	$(MAKE) -C libkmem all

test: kmem
	$(CC) words.c main.c -o test $(CFLAGS) $(LDFLAGS)

run: test
	LD_LIBRARY_PATH=./libkmem ./test

clean:
	$(MAKE) -C libkmem clean
	rm -f test *.o decryptedSecrets
