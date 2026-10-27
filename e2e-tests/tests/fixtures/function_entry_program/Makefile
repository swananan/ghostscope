CC = gcc
CFLAGS ?= -Wall -Wextra -g
BINARY ?= function_entry_program

# Avoid a distribution-default ENDBR instruction masking the entry/statement
# overlap that this fixture exercises.
ENTRY_CFLAGS = -fcf-protection=none

all: $(BINARY) $(BINARY)_o2 $(BINARY)_omit_fp

$(BINARY): function_entry_program.c
	$(CC) $(CFLAGS) $(ENTRY_CFLAGS) -O0 -o $@ $<

$(BINARY)_o2: function_entry_program.c
	$(CC) $(CFLAGS) $(ENTRY_CFLAGS) -O2 -o $@ $<

$(BINARY)_omit_fp: function_entry_program.c
	$(CC) $(CFLAGS) $(ENTRY_CFLAGS) -O0 -fomit-frame-pointer -o $@ $<

clean:
	rm -f function_entry_program function_entry_program_o2 function_entry_program_clang_dwarf5 function_entry_program_clang_dwarf5_o2
	rm -f function_entry_program_omit_fp function_entry_program_clang_dwarf5_omit_fp

.PHONY: all clean
