CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= scalar_types_program
OBJ ?= $(BINARY).o

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): scalar_types_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

scalar_types_program_o1: scalar_types_program_o1.o
	$(CC) $(BASE_CFLAGS) -O1 -o $@ $^

scalar_types_program_o2: scalar_types_program_o2.o
	$(CC) $(BASE_CFLAGS) -O2 -o $@ $^

scalar_types_program_o3: scalar_types_program_o3.o
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -o $@ $^

scalar_types_program_o1.o: scalar_types_program.c
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ $<

scalar_types_program_o2.o: scalar_types_program.c
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ $<

scalar_types_program_o3.o: scalar_types_program.c
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ $<

all: $(BINARY) scalar_types_program_o1 scalar_types_program_o2 scalar_types_program_o3

clean:
	rm -f *.o scalar_types_program scalar_types_program_o*

.PHONY: all clean scalar_types_program_o1 scalar_types_program_o2 scalar_types_program_o3
