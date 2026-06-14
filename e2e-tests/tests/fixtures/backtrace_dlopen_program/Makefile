CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g
CFLAGS ?= $(BASE_CFLAGS) -O0 -fomit-frame-pointer -fPIC
BINARY ?= backtrace_dlopen_program
OBJ ?= $(BINARY).o
SHARED_LIB ?= libbacktrace_dlopen_target.so
SHARED_OBJ ?= backtrace_dlopen_lib.o

all: $(BINARY) $(SHARED_LIB)

$(BINARY): $(OBJ)
	$(CC) $(BASE_CFLAGS) -O0 -fomit-frame-pointer -o $@ $(OBJ) -ldl

$(OBJ): backtrace_dlopen_program.c backtrace_dlopen_lib.h
	$(CC) $(CFLAGS) -c -o $@ backtrace_dlopen_program.c

$(SHARED_LIB): $(SHARED_OBJ)
	$(CC) -shared -o $@ $(SHARED_OBJ)

$(SHARED_OBJ): backtrace_dlopen_lib.c backtrace_dlopen_lib.h
	$(CC) $(CFLAGS) -c -o $@ backtrace_dlopen_lib.c

clean:
	rm -f *.o backtrace_dlopen_program libbacktrace_dlopen_target.so dlopen.trigger

.PHONY: all clean
