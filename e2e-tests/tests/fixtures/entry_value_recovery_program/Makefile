CC ?= gcc
BASE_CFLAGS = -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O3
BINARY ?= entry_value_recovery_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

$(OBJ): entry_value_recovery_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o entry_value_recovery_program entry_value_recovery_program_clang_dwarf5

.PHONY: all clean
