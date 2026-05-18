CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g -pthread
CFLAGS ?= $(BASE_CFLAGS) -O0
LDFLAGS ?= -pthread
BINARY ?= c_multithread_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJ): c_multithread_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o c_multithread_program

.PHONY: all clean
