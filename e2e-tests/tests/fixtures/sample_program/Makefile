# Simple Makefile for sample program with multiple optimization levels
CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
OBJCOPY ?= objcopy

# Default debug build (O0)
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= sample_program
OBJ ?= $(BINARY).o
LIB_OBJ ?= sample_lib.o
STRIPPED_BINARY ?= sample_program_stripped
STRIPPED_DEBUG ?= $(STRIPPED_BINARY).debug
# Keep stripped objects separate so concurrent test builds do not race.
STRIPPED_OBJ ?= $(STRIPPED_BINARY).o
STRIPPED_LIB_OBJ ?= sample_lib_stripped.o
STRIPPED_UNSTRIPPED ?= $(STRIPPED_BINARY).unstripped

# Build simple static binary for testing (default: debug)
$(BINARY): $(OBJ) $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ): sample_program.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_program.c

$(LIB_OBJ): sample_lib.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_lib.c

# Build stripped binary with separate debug file (.gnu_debuglink)
$(STRIPPED_BINARY): $(STRIPPED_UNSTRIPPED) $(STRIPPED_DEBUG)
	cp $(STRIPPED_UNSTRIPPED) $@
	$(OBJCOPY) --strip-debug $@
	$(OBJCOPY) --add-gnu-debuglink=$(notdir $(STRIPPED_DEBUG)) $@
	@echo "Created stripped binary: $@"
	@echo "Debug info in: $(STRIPPED_DEBUG)"
	@readelf -x .gnu_debuglink $@ 2>/dev/null || true

$(STRIPPED_DEBUG): $(STRIPPED_UNSTRIPPED)
	$(OBJCOPY) --only-keep-debug $< $@

$(STRIPPED_UNSTRIPPED): $(STRIPPED_OBJ) $(STRIPPED_LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

.INTERMEDIATE: $(STRIPPED_UNSTRIPPED)

$(STRIPPED_OBJ): sample_program.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_program.c

$(STRIPPED_LIB_OBJ): sample_lib.c sample_lib.h
	$(CC) $(CFLAGS) -c -o $@ sample_lib.c

# Optimized builds with different levels
sample_program_o1: sample_program_o1.o sample_lib_o1.o
	$(CC) $(BASE_CFLAGS) -O1 -o $@ $^

sample_program_o2: sample_program_o2.o sample_lib_o2.o
	$(CC) $(BASE_CFLAGS) -O2 -o $@ $^

sample_program_o3: sample_program_o3.o sample_lib_o3.o
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -o $@ $^

# Object file rules for optimized builds
sample_program_o1.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ sample_program.c

sample_program_o2.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ sample_program.c

sample_program_o3.o: sample_program.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ sample_program.c

sample_lib_o1.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O1 -c -o $@ sample_lib.c

sample_lib_o2.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O2 -c -o $@ sample_lib.c

sample_lib_o3.o: sample_lib.c sample_lib.h
	$(CC) $(BASE_CFLAGS) -O3 -DNDEBUG -c -o $@ sample_lib.c

# Build all optimization levels (including stripped version for .gnu_debuglink testing)
all: $(BINARY) sample_program_o1 sample_program_o2 sample_program_o3 $(STRIPPED_BINARY)

clean:
	rm -f *.o sample_program sample_program_o* $(STRIPPED_BINARY) $(STRIPPED_DEBUG) $(STRIPPED_UNSTRIPPED)

.PHONY: clean all sample_program_o1 sample_program_o2 sample_program_o3
