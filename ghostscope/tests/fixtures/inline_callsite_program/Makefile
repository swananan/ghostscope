CC = gcc
BASE_CFLAGS = -Wall -Wextra -g
CFLAGS = $(BASE_CFLAGS) -O2

all: inline_callsite_program

inline_callsite_program: inline_callsite_program.o
	$(CC) $(CFLAGS) -o $@ inline_callsite_program.o

inline_callsite_program.o: inline_callsite_program.c
	$(CC) $(CFLAGS) -c -o $@ inline_callsite_program.c

clean:
	rm -f *.o inline_callsite_program

.PHONY: clean all
