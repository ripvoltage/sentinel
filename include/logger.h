#ifndef LOGGER_H
#define LOGGER_H

#include "notification.h"
#include <stdint.h>
#include <stddef.h>

enum {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO = 1,
    LOG_LVL_WARN = 2,
    LOG_LVL_ERROR = 3
};

typedef struct {
    char timestamp[32];
    char timestamp_utc[32];
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    char exe_path[256];
    char cmdline[512];
    double entropy;
    char rule_triggered[256];
    char affected_files[MAX_AFFECTED_FILES][256];
    size_t affected_count;
    char action_taken[128];
} threat_event_t;

int logger_init(void);
void log_threat_event(const threat_event_t *event);
void log_msg(int level, const char *fmt, ...);

#endif
