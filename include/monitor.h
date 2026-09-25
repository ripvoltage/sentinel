#ifndef MONITOR_H
#define MONITOR_H

#include "sentinel.h"
#include "ebpf_loader.h"
#include <stdbool.h>

typedef struct {
    ebpf_context_t bpf_ctx;
    int fanotify_fd;
    bool use_ebpf;
    event_callback_t callback;
    void *user_data;
} monitor_context_t;

int monitor_init(monitor_context_t *ctx, const char *ebpf_path, event_callback_t cb, void *user_data);
int monitor_poll(monitor_context_t *ctx, int timeout_ms);
void monitor_cleanup(monitor_context_t *ctx);

#endif
