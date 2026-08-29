#include "sample_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Global counter for tracking calls
static int call_counter = 0;

// Simple math operations
int add_numbers(int a, int b) {
    call_counter++;
    return a + b;
}

int multiply_numbers(int a, int b) {
    call_counter++;
    return a * b;
}

double calculate_average(int* numbers, int count) {
    call_counter++;
    if (count <= 0) {
        return 0.0;
    }
    
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += numbers[i];
    }
    double avg = (double)sum / count;
    return avg;
}

// String operations
void format_message(char* buffer, size_t size, const char* prefix, int value) {
    call_counter++;
    snprintf(buffer, size, "%s: value=%d, timestamp=%ld", prefix, value, time(NULL));
}

int get_string_length(const char* str) {
    call_counter++;
    int len = strlen(str);
    return len;
}

// Data processing
void process_record(DataRecord* record) {
    call_counter++;
    if (!record) {
        return;
    }
    
    // Simulate some processing
    record->value *= 1.1;  // Increase value by 10%
}

void print_record(const DataRecord* record) {
    call_counter++;
    if (!record) {
        return;
    }
    
}

// Utility functions
void log_activity(const char* activity, int level) {
    call_counter++;
    const char* level_str = (level >= 3) ? "HIGH" : (level >= 2) ? "MEDIUM" : "LOW";
}

int get_random_value(int min, int max) {
    call_counter++;
    if (min >= max) {
        return min;
    }
    
    int value = min + (rand() % (max - min + 1));
    return value;
}

// Library initialization function
void init_test_lib() {
    srand(time(NULL));
}

// Library cleanup function
void cleanup_test_lib() {
}

// Void pointer sink for pointer-arithmetic fallback tests
void sink_void(const void* p) {
    call_counter++;
    (void)p;
}

/*
 * Keep these fixture-only declarations below the existing code so hard-coded
 * sample_lib.c line probes remain stable.
 */
#include <stdint.h>
#include <sys/mman.h>

typedef struct {
    uint64_t value;
} EvictedPage;

static EvictedPage* evicted_page;
static size_t evicted_page_size;

// The body deliberately does not dereference page. Sleepable-uprobe tests
// attach here after the caller has confirmed that the page is nonresident.
__attribute__((noinline)) void process_evicted_page(const EvictedPage* page) {
    __asm__ volatile("" : : "r"(page) : "memory");
}

void trigger_evicted_page_probe(void) {
    if (evicted_page == NULL) {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            perror("sysconf(_SC_PAGESIZE)");
            return;
        }

        evicted_page_size = (size_t)page_size;
        evicted_page = mmap(NULL, evicted_page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (evicted_page == MAP_FAILED) {
            evicted_page = NULL;
            perror("mmap");
            return;
        }
    }

    // Materialize the page, discard it, and verify that no backing page is
    // resident before entering the probe target. MADV_DONTNEED makes the next
    // successful read fault in a zero-filled anonymous page.
    evicted_page->value = UINT64_C(0x1122334455667788);
    if (madvise(evicted_page, evicted_page_size, MADV_DONTNEED) != 0) {
        perror("madvise(MADV_DONTNEED)");
        return;
    }

    unsigned char residency = 1;
    if (mincore(evicted_page, evicted_page_size, &residency) != 0) {
        perror("mincore");
        return;
    }
    if ((residency & 1U) == 0) {
        process_evicted_page(evicted_page);
    }
}
