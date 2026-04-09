CC = gcc
BASE_CFLAGS = -Wall -Wextra -g -O3 -DNDEBUG -freorder-blocks-and-partition

all: partitioned_ranges_program

partitioned_ranges_program: partitioned_ranges_program.o
	$(CC) $(BASE_CFLAGS) -o $@ $^

partitioned_ranges_program.o: partitioned_ranges_program.c
	$(CC) $(BASE_CFLAGS) -c -o $@ $<

clean:
	rm -f *.o partitioned_ranges_program

.PHONY: clean all
