CC ?= gcc
CFLAGS ?= -Wall -Wextra -g -O0
BINARY ?= static_scope_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): static_scope_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o static_scope_program static_scope_program_clang_dwarf5

.PHONY: all clean
