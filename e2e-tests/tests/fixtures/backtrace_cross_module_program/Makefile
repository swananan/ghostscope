CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0 -fomit-frame-pointer -fPIC
BINARY ?= backtrace_cross_module_program
OBJ ?= $(BINARY).o
SHARED_LIB ?= libbacktrace_cross_module.so
SHARED_OBJ ?= backtrace_cross_module_lib.o

all: $(BINARY) $(SHARED_LIB)

$(BINARY): $(OBJ) $(SHARED_LIB)
	$(CC) $(BASE_CFLAGS) -O0 -fomit-frame-pointer -o $@ $(OBJ) -L. -lbacktrace_cross_module -Wl,-rpath,'$$ORIGIN'

$(OBJ): backtrace_cross_module_program.c backtrace_cross_module_lib.h
	$(CC) $(CFLAGS) -c -o $@ backtrace_cross_module_program.c

$(SHARED_LIB): $(SHARED_OBJ)
	$(CC) -shared -o $@ $(SHARED_OBJ)

$(SHARED_OBJ): backtrace_cross_module_lib.c backtrace_cross_module_lib.h
	$(CC) $(CFLAGS) -c -o $@ backtrace_cross_module_lib.c

clean:
	rm -f *.o backtrace_cross_module_program libbacktrace_cross_module.so

.PHONY: all clean
