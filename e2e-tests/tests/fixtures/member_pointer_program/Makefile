CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g

CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= member_pointer_program
OBJ ?= $(BINARY).o

$(BINARY): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): member_pointer_program.c
	$(CC) $(CFLAGS) -c -o $@ member_pointer_program.c

member_pointer_program_o1: member_pointer_program_o1.o
	$(CC) $(BASE_CFLAGS) -O1 -o $@ $^

member_pointer_program_o2: member_pointer_program_o2.o
	$(CC) $(BASE_CFLAGS) -O2 -fno-omit-frame-pointer -o $@ $^

member_pointer_program_o3: member_pointer_program_o3.o
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -fno-omit-frame-pointer -o $@ $^

member_pointer_program_o1.o: member_pointer_program.c
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ member_pointer_program.c

member_pointer_program_o2.o: member_pointer_program.c
	$(CC) $(BASE_CFLAGS) -O2 -fno-omit-frame-pointer -c -o $@ member_pointer_program.c

member_pointer_program_o3.o: member_pointer_program.c
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -fno-omit-frame-pointer -c -o $@ member_pointer_program.c

all: $(BINARY) member_pointer_program_o1 member_pointer_program_o2 member_pointer_program_o3

clean:
	rm -f *.o member_pointer_program member_pointer_program_o*

.PHONY: clean all member_pointer_program_o1 member_pointer_program_o2 member_pointer_program_o3
