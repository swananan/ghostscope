CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g

# Default debug build (O0)
CFLAGS ?= $(BASE_CFLAGS) -O0 -fPIC
BINARY ?= globals_program
OBJ ?= $(BINARY).o
SHARED_LIB ?= libgvars.so
SHARED_OBJ ?= gvars_lib.o

all: $(BINARY) $(SHARED_LIB)

# Shared library
$(SHARED_LIB): $(SHARED_OBJ) globals_shared.h
	$(CC) -shared -o $@ $(SHARED_OBJ)

$(SHARED_OBJ): gvars_lib.c gvars_lib.h globals_shared.h
	$(CC) $(CFLAGS) -c -o $@ gvars_lib.c

# Executable linked against local shared library
$(BINARY): $(OBJ) $(SHARED_LIB)
	$(CC) $(BASE_CFLAGS) -O0 -o $@ $(OBJ) -L. -lgvars -Wl,-rpath,'$$ORIGIN'

$(OBJ): globals_program.c globals_program.h globals_shared.h gvars_lib.h
	$(CC) $(CFLAGS) -c -o $@ globals_program.c

clean:
	rm -f *.o globals_program libgvars.so

.PHONY: clean all
