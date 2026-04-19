CXX ?= g++
CXXFLAGS ?= -g -O0 -Wall -Wextra
BINARY ?= cpp_complex_program
OBJ ?= main.o

all: $(BINARY)

$(BINARY): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJ): main.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f cpp_complex_program main.o

.PHONY: all clean
