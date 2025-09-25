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
