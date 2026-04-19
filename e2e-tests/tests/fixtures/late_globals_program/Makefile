CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= late_globals_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): late_globals_program.c
	$(CC) $(CFLAGS) -c -o $@ late_globals_program.c

clean:
	rm -f *.o late_globals_program

.PHONY: clean all
