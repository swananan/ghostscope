CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= scalar_types_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): scalar_types_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o scalar_types_program

.PHONY: all clean
