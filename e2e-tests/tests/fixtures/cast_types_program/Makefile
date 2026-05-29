CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra -g -fPIC
CFLAGS ?= $(BASE_CFLAGS) -O0
BINARY ?= cast_types_program
OBJ ?= $(BINARY).o
SHARED_LIB ?= libcast_types.so
SHARED_OBJ ?= cast_types_lib.o
EXTRA_SHARED_LIB ?= libcast_types_extra.so
EXTRA_SHARED_OBJ ?= cast_types_extra_lib.o

all: $(BINARY) $(SHARED_LIB) $(EXTRA_SHARED_LIB)

$(BINARY): $(OBJ) $(SHARED_LIB) $(EXTRA_SHARED_LIB)
	$(CC) $(BASE_CFLAGS) -O0 -o $@ $(OBJ) -L. -lcast_types -lcast_types_extra -Wl,-rpath,'$$ORIGIN'

$(OBJ): cast_types_program.c cast_types_program.h
	$(CC) $(CFLAGS) -c -o $@ cast_types_program.c

$(SHARED_LIB): $(SHARED_OBJ)
	$(CC) -shared -o $@ $(SHARED_OBJ)

$(SHARED_OBJ): cast_types_lib.c cast_types_program.h
	$(CC) $(CFLAGS) -c -o $@ cast_types_lib.c

$(EXTRA_SHARED_LIB): $(EXTRA_SHARED_OBJ)
	$(CC) -shared -o $@ $(EXTRA_SHARED_OBJ)

$(EXTRA_SHARED_OBJ): cast_types_extra_lib.c cast_types_program.h
	$(CC) $(CFLAGS) -c -o $@ cast_types_extra_lib.c

clean:
	rm -f *.o cast_types_program libcast_types.so libcast_types_extra.so

.PHONY: all clean
