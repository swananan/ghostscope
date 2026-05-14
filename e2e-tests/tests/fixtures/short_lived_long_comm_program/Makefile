CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= short_lived_long_comm_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): short_lived_long_comm_program.c
	$(CC) $(CFLAGS) -c -o $@ short_lived_long_comm_program.c

clean:
	rm -f *.o short_lived_long_comm_program

.PHONY: clean all
