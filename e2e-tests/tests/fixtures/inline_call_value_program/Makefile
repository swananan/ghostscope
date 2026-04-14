CC = gcc
BASE_CFLAGS = -Wall -Wextra -g
CFLAGS = $(BASE_CFLAGS) -O3 -fno-ipa-cp

all: inline_call_value_program

inline_call_value_program: inline_call_value_program.o
	$(CC) $(CFLAGS) -o $@ inline_call_value_program.o

inline_call_value_program.o: inline_call_value_program.c
	$(CC) $(CFLAGS) -c -o $@ inline_call_value_program.c

clean:
	rm -f *.o inline_call_value_program

.PHONY: clean all
