CC = gcc
BASE_CFLAGS = -Wall -Wextra -g
CFLAGS = $(BASE_CFLAGS) -O0

all: late_globals_program

late_globals_program: late_globals_program.o
	$(CC) $(CFLAGS) -o $@ late_globals_program.o

late_globals_program.o: late_globals_program.c
	$(CC) $(CFLAGS) -c -o $@ late_globals_program.c

clean:
	rm -f *.o late_globals_program

.PHONY: clean all
