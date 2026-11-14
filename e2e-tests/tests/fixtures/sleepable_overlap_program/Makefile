CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -g -O0 -fno-omit-frame-pointer -pthread

all: sleepable_overlap_program

sleepable_overlap_program: main.c
	$(CC) $(CFLAGS) -o $@ $< -pthread

clean:
	rm -f sleepable_overlap_program

.PHONY: all clean
