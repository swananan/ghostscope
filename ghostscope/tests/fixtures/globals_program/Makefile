CC = gcc
BASE_CFLAGS = -Wall -Wextra -g

# Default debug build (O0)
CFLAGS = $(BASE_CFLAGS) -O0 -fPIC

all: globals_program libgvars.so

# Shared library
libgvars.so: gvars_lib.o globals_shared.h
	$(CC) -shared -o $@ gvars_lib.o

gvars_lib.o: gvars_lib.c gvars_lib.h globals_shared.h
	$(CC) $(CFLAGS) -c -o $@ gvars_lib.c

# Executable linked against local shared library
globals_program: globals_program.o libgvars.so
	$(CC) $(BASE_CFLAGS) -O0 -o $@ globals_program.o -L. -lgvars -Wl,-rpath,'$$ORIGIN'

globals_program.o: globals_program.c globals_program.h globals_shared.h gvars_lib.h
	$(CC) $(CFLAGS) -c -o $@ globals_program.c

clean:
	rm -f *.o globals_program libgvars.so

.PHONY: clean all

