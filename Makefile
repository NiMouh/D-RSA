CC = gcc
JAVAC = javac
CFLAGS = -Wall -Wextra
LDFLAGS = -lcrypto

all: rsagen randgen performance jrsagen.class jrandgen.class

rsagen: rsagen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

randgen: randgen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

performance: performance.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

jrsagen.class: jrsagen.java
	$(JAVAC) $< -d .

jrandgen.class: jrandgen.java
	$(JAVAC) $< -d .

clean_results:
	rm -f *.csv

clean:
	rm -f rsagen randgen performance *.class
