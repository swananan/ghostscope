#ifndef TEST_LIB_H
#define TEST_LIB_H

#include <stddef.h>

// Function declarations for the test library

// Simple math operations
int add_numbers(int a, int b);
int multiply_numbers(int a, int b);
double calculate_average(int* numbers, int count);

// String operations
void format_message(char* buffer, size_t size, const char* prefix, int value);
int get_string_length(const char* str);

// Data processing
typedef struct {
    int id;
    char name[32];
    double value;
} DataRecord;

void process_record(DataRecord* record);
void print_record(const DataRecord* record);

// Utility functions
void log_activity(const char* activity, int level);
int get_random_value(int min, int max);

// Library lifecycle functions
void init_test_lib();
void cleanup_test_lib();

#endif // TEST_LIB_H
