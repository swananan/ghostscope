#include <stdio.h>

typedef struct DebugSourceRecord {
    int id;
    long value;
} DebugSourceRecord;

int debug_source_probe(DebugSourceRecord *record) {
    record->value += record->id;
    return (int)record->value;
}

int main(void) {
    DebugSourceRecord record = {7, 35};
    int value = debug_source_probe(&record);
    printf("debug-source-report=%d\n", value);
    return value == 42 ? 0 : 1;
}
