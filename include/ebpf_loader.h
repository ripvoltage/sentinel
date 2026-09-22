#ifndef EBPF_LOADER_H
#define EBPF_LOADER_H

#include "sentinel.h"
#include <stdbool.h>

typedef void (*event_callback_t)(const io_event_t *event, void *ctx);

typedef struct {
    void *bpf_obj;
    void *ring_buf;
    int events_map_fd;
    int daemon_pid_map_fd;
    void *lib_handle;
    bool is_loaded;
} ebpf_context_t;

int ebpf_loader_init(ebpf_context_t *ctx, const char *obj_path);
int ebpf_register_daemon_pid(ebpf_context_t *ctx, uint32_t pid);
int ebpf_poll_events(ebpf_context_t *ctx, event_callback_t callback, void *user_data, int timeout_ms);
void ebpf_loader_cleanup(ebpf_context_t *ctx);

#endif
