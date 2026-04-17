CC ?= gcc
CFLAGS ?= -Wall -Wextra -g -O3
BINARY ?= inline_callsite_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): inline_callsite_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o inline_callsite_program inline_callsite_program_clang_dwarf5

.PHONY: clean all
