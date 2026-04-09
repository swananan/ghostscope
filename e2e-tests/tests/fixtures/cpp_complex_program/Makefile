CXX = g++
CXXFLAGS = -g -O0 -Wall -Wextra

all: cpp_complex_program

cpp_complex_program: main.o
	$(CXX) $(CXXFLAGS) -o $@ $^

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f cpp_complex_program main.o

.PHONY: all clean

