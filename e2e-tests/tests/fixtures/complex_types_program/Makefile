CC = gcc
BASE_CFLAGS = -Wall -Wextra -g

# Default debug build (O0)
CFLAGS = $(BASE_CFLAGS) -O0

complex_types_program: complex_types_program.o
	$(CC) $(CFLAGS) -o complex_types_program complex_types_program.o

complex_types_program.o: complex_types_program.c complex_types_program.h
	$(CC) $(CFLAGS) -c -o $@ complex_types_program.c

# Optimized builds
complex_types_program_o1: complex_types_program_o1.o
	$(CC) $(BASE_CFLAGS) -O1 -o $@ $^

complex_types_program_o2: complex_types_program_o2.o
	$(CC) $(BASE_CFLAGS) -O2 -o $@ $^

complex_types_program_o3: complex_types_program_o3.o
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -o $@ $^

complex_types_program_o1.o: complex_types_program.c complex_types_program.h
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ complex_types_program.c

complex_types_program_o2.o: complex_types_program.c complex_types_program.h
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ complex_types_program.c

complex_types_program_o3.o: complex_types_program.c complex_types_program.h
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ complex_types_program.c

all: complex_types_program complex_types_program_o1 complex_types_program_o2 complex_types_program_o3

clean:
	rm -f *.o complex_types_program complex_types_program_o* complex_types_program_nopie

.PHONY: clean all complex_types_program_o1 complex_types_program_o2 complex_types_program_o3

# Non-PIE build (ET_EXEC) for offset conversion tests
complex_types_program_nopie: complex_types_program_nopie.o
	$(CC) $(BASE_CFLAGS) -no-pie -o $@ $^

complex_types_program_nopie.o: complex_types_program.c complex_types_program.h
	$(CC) $(BASE_CFLAGS) -O0 -fno-pie -c -o $@ complex_types_program.c

