#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include "sample_lib.h"

// Test function that we can attach uprobe to
void test_function(int value) {
    // printf("test_function called with value: %d\n", value);
}

// Another function for testing
int calculate_something(int a, int b) {
    int result = a * b + 42;
    // printf("calculate_something: %d * %d + 42 = %d\n", a, b, result);
    return result;
}

// Function that processes data
void process_data(const char* message) {
    printf("Processing: %s\n", message);
}

int main() {
    printf("Starting test program...\n");
    
    // Initialize the test library
    init_test_lib();
    
    int counter = 0;
    time_t start_time = time(NULL);
    
    // Create some test data
    int numbers[] = {10, 20, 30, 40, 50};
    DataRecord record = {1, "test_record", 100.0};
    
    // Main loop - runs for about 60 seconds or until interrupted
    while (counter < 20000) {  // Limit iterations for testing
        counter++;
        
        // Call our original test functions
        test_function(counter);
        int result = calculate_something(counter, counter + 5);
        
        // Call library functions for testing
        int sum = add_numbers(counter, counter * 2);
        int product = multiply_numbers(counter, 3);
        
        // Test string operations
        char message[256];
        format_message(message, sizeof(message), "Iteration", counter);
        int msg_len = get_string_length(message);
        
        // Test data processing
        process_record(&record);
        if (counter % 5 == 0) {
            print_record(&record);
        }
        
        // Test utility functions
        log_activity("main_loop", counter % 3 + 1);
        int random_val = get_random_value(1, 100);
        
        // Test array processing
        if (counter % 10 == 0) {
            double avg = calculate_average(numbers, 5);
        }
        
        // printf("Sleeping for 2 seconds...\n");
        sleep(2);  // Sleep for 2 seconds
    }
    
    // Cleanup
    cleanup_test_lib();
    
    time_t end_time = time(NULL);
    printf("\nTest program finished after %ld seconds, %d iterations\n", 
           end_time - start_time, counter);
    
    return 0;
}

