CC ?= gcc
CFLAGS ?= -Wall -Wextra -g -O3 -DNDEBUG -freorder-blocks-and-partition
BINARY ?= partitioned_ranges_program
OBJ ?= $(BINARY).o

# LLVM 18 basic-block sections are x86-only. The ARM equivalent preserves
# native code and location lists while making function ranges indexed.
ARM_RNGLISTX := $(and $(findstring aarch64,$(shell $(CC) -dumpmachine)),$(findstring -fbasic-block-sections=all,$(CFLAGS)))
EFFECTIVE_CFLAGS = $(if $(ARM_RNGLISTX),$(filter-out -fbasic-block-sections=all,$(CFLAGS)),$(CFLAGS))
PYTHON ?= python3

all: $(BINARY)

$(BINARY): $(OBJ) arm64_rnglistx.py
	$(CC) $(EFFECTIVE_CFLAGS) -o $@ $(OBJ)
	$(if $(ARM_RNGLISTX),$(PYTHON) arm64_rnglistx.py $@,@:)

$(OBJ): partitioned_ranges_program.c
	$(CC) $(EFFECTIVE_CFLAGS) -c -o $@ $<

clean:
	rm -f *.o partitioned_ranges_program partitioned_ranges_program_*

.PHONY: clean all
