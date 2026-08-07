CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0 -fomit-frame-pointer
BINARY ?= backtrace_hot_program
OBJ ?= $(BINARY).o
REGISTER_RA_OBJ ?= backtrace_register_ra.o
UNDEFINED_RA_OBJ ?= backtrace_undefined_ra.o
UNSUPPORTED_CFI_OBJ ?= backtrace_unsupported_cfi.o

all: $(BINARY)

$(BINARY): $(OBJ) $(REGISTER_RA_OBJ) $(UNDEFINED_RA_OBJ) $(UNSUPPORTED_CFI_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): backtrace_hot_program.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(REGISTER_RA_OBJ): backtrace_register_ra.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(UNDEFINED_RA_OBJ): backtrace_undefined_ra.S
	$(CC) $(CFLAGS) -c -o $@ $<

$(UNSUPPORTED_CFI_OBJ): backtrace_unsupported_cfi.S
	$(CC) $(CFLAGS) -c -o $@ $<

backtrace_hot_program_nopie: backtrace_hot_program_nopie.o $(REGISTER_RA_OBJ) $(UNDEFINED_RA_OBJ) $(UNSUPPORTED_CFI_OBJ)
	$(CC) $(BASE_CFLAGS) -no-pie -o $@ $^

backtrace_hot_program_nopie.o: backtrace_hot_program.c
	$(CC) $(BASE_CFLAGS) -O0 -fomit-frame-pointer -fno-pie -c -o $@ $<

clean:
	rm -f *.o backtrace_hot_program backtrace_hot_program_nopie

.PHONY: all clean
