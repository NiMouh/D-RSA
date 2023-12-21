CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcrypto

all: rsagen randgen performance

rsagen: rsagen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

randgen: randgen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

performance: performance.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f rsagen randgen performance
