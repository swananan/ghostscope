CC ?= gcc
CFLAGS ?= -Wall -Wextra -g -O3 -DNDEBUG -freorder-blocks-and-partition
BINARY ?= partitioned_ranges_program
OBJ ?= $(BINARY).o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): partitioned_ranges_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o partitioned_ranges_program partitioned_ranges_program_*

.PHONY: clean all
