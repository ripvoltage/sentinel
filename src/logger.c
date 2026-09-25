#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <pthread.h>

static FILE *log_file = NULL;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static int current_log_level = LOG_LVL_INFO;

static void get_iso8601_timestamps(char *local_buf, size_t local_sz, char *utc_buf, size_t utc_sz) {
    time_t now = time(NULL);
    struct tm tm_local, tm_utc;

    localtime_r(&now, &tm_local);
    strftime(local_buf, local_sz, "%Y-%m-%dT%H:%M:%S%z", &tm_local);

    gmtime_r(&now, &tm_utc);
    strftime(utc_buf, utc_sz, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

int logger_init(void) {
    pthread_mutex_lock(&log_lock);

    const char *env_lvl = getenv("SENTINEL_LOG");
    if (env_lvl != NULL) {
        if (strcmp(env_lvl, "debug") == 0) current_log_level = LOG_LVL_DEBUG;
        else if (strcmp(env_lvl, "warn") == 0) current_log_level = LOG_LVL_WARN;
        else if (strcmp(env_lvl, "error") == 0) current_log_level = LOG_LVL_ERROR;
    }

    const char *primary_dir = "/var/log/ransomware-detector";
    const char *primary_file = "/var/log/ransomware-detector/alerts.log";
    const char *fallback_dir = "./logs";
    const char *fallback_file = "./logs/alerts.log";

    mkdir(primary_dir, 0755);
    log_file = fopen(primary_file, "a");

    if (log_file == NULL) {
        mkdir(fallback_dir, 0755);
        log_file = fopen(fallback_file, "a");
    }

    pthread_mutex_unlock(&log_lock);
    return log_file != NULL ? 0 : -1;
}

void log_threat_event(const threat_event_t *event) {
    if (event == NULL) {
        return;
    }

    char ts_local[32], ts_utc[32];
    get_iso8601_timestamps(ts_local, sizeof(ts_local), ts_utc, sizeof(ts_utc));

    pthread_mutex_lock(&log_lock);

    if (log_file != NULL) {
        fprintf(log_file,
                "{\"timestamp\":\"%s\",\"timestamp_utc\":\"%s\","
                "\"pid\":%u,\"uid\":%u,\"gid\":%u,"
                "\"exe\":\"%s\",\"cmdline\":\"%s\","
                "\"entropy\":%.4f,\"rule\":\"%s\","
                "\"action\":\"%s\",\"affected_files\":[",
                ts_local, ts_utc,
                event->pid, event->uid, event->gid,
                event->exe_path, event->cmdline,
                event->entropy, event->rule_triggered,
                event->action_taken);

        for (size_t i = 0; i < event->affected_count; i++) {
            fprintf(log_file, "\"%s\"%s", event->affected_files[i],
                    (i + 1 < event->affected_count) ? "," : "");
        }
        fprintf(log_file, "]}\n");
        fflush(log_file);
    }

    fprintf(stderr,
            "[ALERT] RANSOMWARE THREAT CONFIRMED: PID %u (%s) - %s (Entropy: %.2f) - Action: %s\n",
            event->pid, event->exe_path, event->rule_triggered, event->entropy, event->action_taken);

    pthread_mutex_unlock(&log_lock);
}

void log_msg(int level, const char *fmt, ...) {
    if (level < current_log_level) {
        return;
    }

    const char *level_str = "INFO";
    if (level == LOG_LVL_DEBUG) level_str = "DEBUG";
    else if (level == LOG_LVL_WARN) level_str = "WARN";
    else if (level == LOG_LVL_ERROR) level_str = "ERROR";

    char ts[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    pthread_mutex_lock(&log_lock);
    fprintf(stderr, "[%s] [%s] ", ts, level_str);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    pthread_mutex_unlock(&log_lock);
}
