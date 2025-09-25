# Simple Makefile for sample program with multiple optimization levels
CC = gcc
BASE_CFLAGS = -Wall -Wextra -g

# Default debug build (O0)
CFLAGS = $(BASE_CFLAGS) -O0

# Build simple static binary for testing (default: debug)
sample_program: sample_program.o sample_lib.o
	$(CC) $(CFLAGS) -o sample_program sample_program.o sample_lib.o

sample_program.o: sample_program.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_program.c

sample_lib.o: sample_lib.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_lib.c

# Optimized builds with different levels
sample_program_o1: sample_program_o1.o sample_lib_o1.o
	$(CC) $(BASE_CFLAGS) -O1 -o $@ $^

sample_program_o2: sample_program_o2.o sample_lib_o2.o
	$(CC) $(BASE_CFLAGS) -O2 -o $@ $^

sample_program_o3: sample_program_o3.o sample_lib_o3.o
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -o $@ $^

# Object file rules for optimized builds
sample_program_o1.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ sample_program.c

sample_program_o2.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ sample_program.c

sample_program_o3.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ sample_program.c

sample_lib_o1.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ sample_lib.c

sample_lib_o2.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ sample_lib.c

sample_lib_o3.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ sample_lib.c

# Build all optimization levels
all: sample_program sample_program_o1 sample_program_o2 sample_program_o3

clean:
	rm -f *.o sample_program sample_program_o*

.PHONY: clean all sample_program_o1 sample_program_o2 sample_program_o3