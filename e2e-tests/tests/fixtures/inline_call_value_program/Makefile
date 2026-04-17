CC ?= gcc
BASE_CFLAGS = -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O3 -fno-ipa-cp
BINARY ?= inline_call_value_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): inline_call_value_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o inline_call_value_program

.PHONY: clean all
