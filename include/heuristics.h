#ifndef HEURISTICS_H
#define HEURISTICS_H

#include "sentinel.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_REASONS 8
#define MAX_REASON_LEN 128
#define MAX_TRACKED_PIDS 1024
#define TS_WINDOW_SIZE 128
#define STALE_MAX_AGE_SEC 60

typedef struct {
    bool is_suspicious;
    uint32_t score;
    char reasons[MAX_REASONS][MAX_REASON_LEN];
    size_t reason_count;
} verdict_t;

typedef struct {
    uint32_t pid;
    struct timespec timestamps[TS_WINDOW_SIZE];
    size_t ts_head;
    size_t ts_count;
    struct timespec last_high_entropy;
    bool has_high_entropy;
    struct timespec last_seen;
    bool active;
} pid_record_t;

typedef struct {
    pid_record_t records[MAX_TRACKED_PIDS];
    size_t active_count;
} heuristics_engine_t;

void heuristics_init(heuristics_engine_t *engine);
verdict_t heuristics_evaluate(heuristics_engine_t *engine,
                              uint32_t pid,
                              const char *path,
                              const char *new_path,
                              event_type_t event_type,
                              double entropy);
void heuristics_cleanup_stale(heuristics_engine_t *engine, uint64_t max_age_sec);

#endif
