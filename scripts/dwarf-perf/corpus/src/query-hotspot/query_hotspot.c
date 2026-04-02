#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum perf_mode {
    PERF_MODE_IDLE = 0,
    PERF_MODE_STREAM = 1,
    PERF_MODE_SNAPSHOT = 2,
};

typedef struct perf_vector {
    int32_t x;
    int32_t y;
    int32_t z;
} perf_vector_t;

typedef union perf_sample {
    perf_vector_t vector;
    uint64_t parts[2];
} perf_sample_t;

typedef struct perf_leaf {
    int32_t id;
    int64_t checksum;
    char label[24];
} perf_leaf_t;

typedef struct perf_payload {
    perf_leaf_t leaf;
    perf_sample_t sample;
    uint32_t depth;
    uint32_t flags;
    int32_t history[6];
} perf_payload_t;

typedef struct perf_metrics {
    int32_t frames[6];
    double ratios[4];
    char stream_name[24];
} perf_metrics_t;

static volatile int g_query_gate = 17;

static perf_payload_t g_seed_payload = {
    .leaf = {
        .id = 41,
        .checksum = 9001,
        .label = "seed-payload",
    },
    .sample = {
        .vector = {
            .x = 3,
            .y = 5,
            .z = 8,
        },
    },
    .depth = 2,
    .flags = 0x3u,
    .history = {4, 6, 8, 10, 12, 14},
};

static perf_metrics_t g_seed_metrics = {
    .frames = {11, 13, 17, 19, 23, 29},
    .ratios = {1.5, 2.5, 3.5, 4.5},
    .stream_name = "query-hotspot",
};

static int mix_values(int lhs, int rhs, int salt) {
    return (lhs * 31) + (rhs * 17) + salt;
}

__attribute__((noinline)) int dwarf_perf_query_hotspot(
    int seed,
    enum perf_mode mode
) {
    perf_metrics_t metrics = g_seed_metrics;
    perf_payload_t payloads[3] = {
        g_seed_payload,
        {
            .leaf = {.id = 52, .checksum = 19002, .label = "payload-b"},
            .sample = {.vector = {.x = 13, .y = 21, .z = 34}},
            .depth = 4,
            .flags = 0x7u,
            .history = {3, 9, 27, 81, 17, 33},
        },
        {
            .leaf = {.id = 63, .checksum = 29003, .label = "payload-c"},
            .sample = {.vector = {.x = 55, .y = 89, .z = 144}},
            .depth = 6,
            .flags = 0xbu,
            .history = {5, 10, 20, 40, 80, 160},
        },
    };
    char stream_alias[24] = "perf-baseline";
    int running_total = seed + (int) mode;

    for (int outer = 0; outer < 3; ++outer) {
        perf_payload_t *active_payload = &payloads[outer];
        perf_sample_t active_sample = active_payload->sample;
        int depth_bias = (int) active_payload->depth + outer;

        if ((outer % 2) == 0) {
            perf_metrics_t snapshot = metrics;
            int32_t local_frames[4] = {
                snapshot.frames[outer],
                snapshot.frames[outer + 1],
                active_payload->history[outer],
                active_payload->history[outer + 1],
            };
            char *alias_ptr = stream_alias;
            int frame_mix = mix_values(
                local_frames[0] + local_frames[1],
                active_sample.vector.x + active_sample.vector.y,
                depth_bias
            );
            volatile int sink = frame_mix + alias_ptr[0] + g_query_gate;

            int hotspot_total =
                sink + snapshot.frames[outer + 2] + active_payload->history[outer + 2]; /* DWARF_PERF_QUERY_HOTSPOT */

            running_total += sink + (int) strlen(active_payload->leaf.label);
            metrics.frames[outer] += hotspot_total;
        } else {
            perf_leaf_t copied_leaf = active_payload->leaf;
            int folded = mix_values(
                copied_leaf.id,
                active_payload->history[outer],
                (int) active_payload->flags
            );
            running_total += folded + (int) copied_leaf.checksum;
            metrics.ratios[outer % 4] += (double) folded / 16.0;
        }
    }

    return running_total + metrics.frames[1] + (int) metrics.ratios[2];
}

int main(void) {
    int result = dwarf_perf_query_hotspot(7, PERF_MODE_STREAM);
    printf("%d\n", result);
    return result == 0 ? 1 : 0;
}
