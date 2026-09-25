#ifndef NOTIFICATION_H
#define NOTIFICATION_H

#include <stdint.h>
#include <stddef.h>

#define MAX_AFFECTED_FILES 16
#define NOTIF_TEXT_LEN 1024

typedef struct {
    uint32_t pid;
    char exe_path[256];
    double entropy;
    char affected_files[MAX_AFFECTED_FILES][256];
    size_t affected_count;
    char action_taken[128];
    char cow_status[128];
} threat_info_t;

int send_critical_alert(const threat_info_t *threat);

#endif
