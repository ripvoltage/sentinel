#include "heuristics.h"
#include "entropy.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

static const char *SUSPICIOUS_EXTENSIONS[] = {
    "encrypted",
    "locked",
    "cry",
    "crypt",
    "locky",
    "cerber",
    "zepto",
    "thor",
    "aaa",
    "zzz",
    "micro",
    "enc",
    "crypted",
    "cryptolocker",
    NULL
};

static int64_t timespec_diff_ms(const struct timespec *a, const struct timespec *b) {
    int64_t sec = (int64_t)a->tv_sec - (int64_t)b->tv_sec;
    int64_t nsec = (int64_t)a->tv_nsec - (int64_t)b->tv_nsec;
    return sec * 1000 + nsec / 1000000;
}

static int64_t timespec_diff_sec(const struct timespec *a, const struct timespec *b) {
    return (int64_t)a->tv_sec - (int64_t)b->tv_sec;
}

static void extract_extension(const char *path, char *out, size_t out_size) {
    if (path == NULL || out == NULL || out_size == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return;
    }

    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');

    if (dot == NULL || (slash != NULL && dot < slash)) {
        out[0] = '\0';
        return;
    }

    dot++;
    size_t i = 0;
    while (dot[i] != '\0' && i + 1 < out_size) {
        out[i] = (char)tolower((unsigned char)dot[i]);
        i++;
    }
    out[i] = '\0';
}

static bool is_suspicious_extension(const char *ext) {
    if (ext == NULL || ext[0] == '\0') {
        return false;
    }

    for (size_t i = 0; SUSPICIOUS_EXTENSIONS[i] != NULL; i++) {
        if (strcmp(ext, SUSPICIOUS_EXTENSIONS[i]) == 0) {
            return true;
        }
    }
    return false;
}

void heuristics_init(heuristics_engine_t *engine) {
    if (engine == NULL) {
        return;
    }
    memset(engine, 0, sizeof(*engine));
}

static pid_record_t *get_or_create_record(heuristics_engine_t *engine, uint32_t pid, const struct timespec *now) {
    size_t oldest_idx = 0;
    int64_t oldest_time = 0;

    for (size_t i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (engine->records[i].active && engine->records[i].pid == pid) {
            engine->records[i].last_seen = *now;
            return &engine->records[i];
        }
    }

    for (size_t i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (!engine->records[i].active) {
            memset(&engine->records[i], 0, sizeof(pid_record_t));
            engine->records[i].pid = pid;
            engine->records[i].last_seen = *now;
            engine->records[i].active = true;
            engine->active_count++;
            return &engine->records[i];
        }

        int64_t age = timespec_diff_sec(now, &engine->records[i].last_seen);
        if (age > oldest_time) {
            oldest_time = age;
            oldest_idx = i;
        }
    }

    memset(&engine->records[oldest_idx], 0, sizeof(pid_record_t));
    engine->records[oldest_idx].pid = pid;
    engine->records[oldest_idx].last_seen = *now;
    engine->records[oldest_idx].active = true;
    return &engine->records[oldest_idx];
}

static void add_reason(verdict_t *verdict, const char *fmt, ...) {
    if (verdict->reason_count >= MAX_REASONS) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vsnprintf(verdict->reasons[verdict->reason_count], MAX_REASON_LEN, fmt, args);
    va_end(args);
    verdict->reason_count++;
}

verdict_t heuristics_evaluate(heuristics_engine_t *engine,
                              uint32_t pid,
                              const char *path,
                              const char *new_path,
                              event_type_t event_type,
                              double entropy) {
    verdict_t verdict;
    memset(&verdict, 0, sizeof(verdict));

    if (engine == NULL) {
        return verdict;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    pid_record_t *rec = get_or_create_record(engine, pid, &now);

    rec->timestamps[rec->ts_head] = now;
    rec->ts_head = (rec->ts_head + 1) % TS_WINDOW_SIZE;
    if (rec->ts_count < TS_WINDOW_SIZE) {
        rec->ts_count++;
    }

    size_t ops_last_100ms = 0;
    for (size_t i = 0; i < rec->ts_count; i++) {
        int64_t diff = timespec_diff_ms(&now, &rec->timestamps[i]);
        if (diff >= 0 && diff <= 100) {
            ops_last_100ms++;
        }
    }

    if (ops_last_100ms > 50) {
        add_reason(&verdict, "High I/O frequency: %zu ops/100ms", ops_last_100ms);
        verdict.score += 30;
    }

    if (entropy >= ENTROPY_THRESHOLD) {
        add_reason(&verdict, "High entropy write payload: %.2f (threshold: %.2f)", entropy, ENTROPY_THRESHOLD);
        verdict.score += 40;
        rec->last_high_entropy = now;
        rec->has_high_entropy = true;
    }

    if (event_type == EVENT_RENAME && new_path != NULL) {
        char ext[32];
        extract_extension(new_path, ext, sizeof(ext));
        if (is_suspicious_extension(ext)) {
            add_reason(&verdict, "Suspicious file extension modification to '.%s' (from '%s' to '%s')",
                       ext, path ? path : "", new_path);
            verdict.score += 20;
        }
    }

    if (event_type == EVENT_UNLINK && rec->has_high_entropy) {
        int64_t diff_sec = timespec_diff_sec(&now, &rec->last_high_entropy);
        if (diff_sec >= 0 && diff_sec <= 5) {
            add_reason(&verdict, "File deletion (unlink) following recent high-entropy write operation");
            verdict.score += 10;
        }
    }

    if (verdict.score > 0) {
        verdict.is_suspicious = true;
        if (verdict.score > 100) {
            verdict.score = 100;
        }
    }

    return verdict;
}

void heuristics_cleanup_stale(heuristics_engine_t *engine, uint64_t max_age_sec) {
    if (engine == NULL) {
        return;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (size_t i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (engine->records[i].active) {
            int64_t age = timespec_diff_sec(&now, &engine->records[i].last_seen);
            if (age >= (int64_t)max_age_sec) {
                engine->records[i].active = false;
                if (engine->active_count > 0) {
                    engine->active_count--;
                }
            }
        }
    }
}
