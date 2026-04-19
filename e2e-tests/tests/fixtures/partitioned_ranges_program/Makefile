CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g -O3 -DNDEBUG -freorder-blocks-and-partition
BINARY ?= partitioned_ranges_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(BASE_CFLAGS) -o $@ $^

$(OBJ): partitioned_ranges_program.c
	$(CC) $(BASE_CFLAGS) -c -o $@ $<

clean:
	rm -f *.o partitioned_ranges_program

.PHONY: clean all
