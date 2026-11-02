CC = gcc
CFLAGS = -Wall -Wextra -g -gdwarf-4

all: architecture_program_o0 architecture_program_o2 architecture_program_nopie

ifneq (,$(findstring aarch64,$(shell $(CC) -dumpmachine)))
all: architecture_program_pac_a architecture_program_pac_b
endif

architecture_program_pac_a: architecture_program.c
	$(CC) $(CFLAGS) -O0 -fPIE -pie -mbranch-protection=pac-ret+leaf -o $@ $<

architecture_program_pac_b: architecture_program.c
	$(CC) $(CFLAGS) -O0 -fPIE -pie -mbranch-protection=pac-ret+leaf+b-key -o $@ $<

architecture_program_o0: architecture_program.c
	$(CC) $(CFLAGS) -O0 -fPIE -pie -o $@ $<

architecture_program_o2: architecture_program.c
	$(CC) $(CFLAGS) -O2 -fPIE -pie -o $@ $<

architecture_program_nopie: architecture_program.c
	$(CC) $(CFLAGS) -O0 -fno-pie -no-pie -o $@ $<

clean:
	rm -f architecture_program_o0 architecture_program_o2 architecture_program_nopie architecture_program_pac_a architecture_program_pac_b

.PHONY: all clean
