CC = gcc
CFLAGS = -std=c99 -O2 -Wall -Wstrict-prototypes
# IFLAGS = -I/usr/include/python2.7
# LFLAGS = -lgmp -lpython2.7
MAIN = test

test: test.o _poly1305.o _chacha20.o
	$(CC) $(CFLAGS) $(IFLAGS) -o $(MAIN) test.o _poly1305.o _chacha20.o $(LFLAGS)
test.o: test.c _poly1305.h _chacha20.h
	$(CC) $(CFLAGS) $(IFLAGS) -c test.c
_poly1305.o: _poly1305.c _poly1305.h
	$(CC) $(CFLAGS) $(IFLAGS) -c _poly1305.c
_chacha20.o: _chacha20.c _chacha20.h
	$(CC) $(CFLAGS) $(IFLAGS) -c _chacha20.c
clean:
	$(RM) $(MAIN) *.o
