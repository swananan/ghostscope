CC ?= gcc
OBJCOPY ?= objcopy

CFLAGS ?= -Wall -Wextra -g -O0 -fno-omit-frame-pointer
LDFLAGS ?= -Wl,--build-id=sha1

BINARY ?= debug_source_report
DEBUG_FILE ?= $(BINARY).debug
UNSTRIPPED ?= $(BINARY).unstripped
EMBEDDED_BINARY ?= debug_source_report_embedded
NO_DEBUGLINK_BINARY ?= debug_source_report_no_debuglink
NO_DEBUGLINK_UNSTRIPPED ?= $(NO_DEBUGLINK_BINARY).unstripped
MISSING_BINARY ?= debug_source_report_missing
MISSING_UNSTRIPPED ?= $(MISSING_BINARY).unstripped
BAD_DEBUG ?= bad.debug
SCRIPT_FILE ?= trace.gs

all: $(BINARY) $(EMBEDDED_BINARY) $(NO_DEBUGLINK_BINARY) $(MISSING_BINARY) $(BAD_DEBUG) $(SCRIPT_FILE)

$(UNSTRIPPED): debug_source_report.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(DEBUG_FILE): $(UNSTRIPPED)
	$(OBJCOPY) --only-keep-debug $< $@

$(BINARY): $(UNSTRIPPED) $(DEBUG_FILE)
	cp $(UNSTRIPPED) $@
	$(OBJCOPY) --strip-debug $@
	$(OBJCOPY) --add-gnu-debuglink=$(notdir $(DEBUG_FILE)) $@

$(EMBEDDED_BINARY): debug_source_report.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(NO_DEBUGLINK_UNSTRIPPED): debug_source_report.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(NO_DEBUGLINK_BINARY): $(NO_DEBUGLINK_UNSTRIPPED)
	cp $(NO_DEBUGLINK_UNSTRIPPED) $@
	$(OBJCOPY) --strip-debug $@

$(MISSING_UNSTRIPPED): debug_source_report.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(MISSING_BINARY): $(MISSING_UNSTRIPPED)
	cp $(MISSING_UNSTRIPPED) $@
	$(OBJCOPY) --strip-debug $@

$(BAD_DEBUG):
	printf 'not an ELF debug file\n' > $@

$(SCRIPT_FILE):
	printf '%s\n' 'trace debug_source_probe {' '    print "startup-load-report";' '}' > $@

clean:
	rm -f $(BINARY) $(DEBUG_FILE) $(UNSTRIPPED) $(EMBEDDED_BINARY) $(NO_DEBUGLINK_BINARY) $(NO_DEBUGLINK_UNSTRIPPED) $(MISSING_BINARY) $(MISSING_UNSTRIPPED) $(BAD_DEBUG) $(SCRIPT_FILE)

.PHONY: all clean
