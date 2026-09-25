#ifndef PROC_INSPECTOR_H
#define PROC_INSPECTOR_H

#include "sentinel.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_CMDLINE_LEN 512

typedef struct {
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t parent_pid;
    char comm[MAX_COMM_LEN];
    char exe[MAX_PATH_LEN];
    char cmdline[MAX_CMDLINE_LEN];
} process_info_t;

int proc_inspect(uint32_t pid, process_info_t *info);
bool is_whitelisted_binary(const process_info_t *info);
bool is_trusted_process(const process_info_t *info);

#endif
