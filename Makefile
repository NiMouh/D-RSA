CC = gcc
JAVAC = javac
CFLAGS = -Wall -Wextra
LDFLAGS = -lcrypto

all: rsagen randgen performance rsa.class

rsagen: rsagen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

randgen: randgen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

performance: performance.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

rsa.class: rsa.java
	$(JAVAC) $< -d .

clean:
	rm -f rsagen randgen performance rsa.class
