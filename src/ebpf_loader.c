#include "ebpf_loader.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

typedef struct bpf_object bpf_object;
typedef struct bpf_program bpf_program;
typedef struct bpf_map bpf_map;
typedef struct bpf_link bpf_link;
typedef struct ring_buffer ring_buffer;

typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);

typedef bpf_object *(*fn_bpf_object__open_file)(const char *path, const void *opts);
typedef int (*fn_bpf_object__load)(bpf_object *obj);
typedef void (*fn_bpf_object__close)(bpf_object *obj);
typedef bpf_program *(*fn_bpf_object__find_program_by_name)(const bpf_object *obj, const char *name);
typedef bpf_link *(*fn_bpf_program__attach)(const bpf_program *prog);
typedef bpf_link *(*fn_bpf_program__attach_kprobe)(const bpf_program *prog, bool retprobe, const char *func_name);
typedef bpf_link *(*fn_bpf_program__attach_tracepoint)(const bpf_program *prog, const char *tp_category, const char *tp_name);
typedef bpf_map *(*fn_bpf_object__find_map_by_name)(const bpf_object *obj, const char *name);
typedef int (*fn_bpf_map__fd)(const bpf_map *map);
typedef int (*fn_bpf_map_update_elem)(int fd, const void *key, const void *value, uint64_t flags);
typedef ring_buffer *(*fn_ring_buffer__new)(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx, const void *opts);
typedef int (*fn_ring_buffer__poll)(ring_buffer *rb, int timeout_ms);
typedef void (*fn_ring_buffer__free)(ring_buffer *rb);

static fn_bpf_object__open_file p_bpf_object__open_file = NULL;
static fn_bpf_object__load p_bpf_object__load = NULL;
static fn_bpf_object__close p_bpf_object__close = NULL;
static fn_bpf_object__find_program_by_name p_bpf_object__find_program_by_name = NULL;
static fn_bpf_program__attach_kprobe p_bpf_program__attach_kprobe = NULL;
static fn_bpf_program__attach_tracepoint p_bpf_program__attach_tracepoint = NULL;
static fn_bpf_object__find_map_by_name p_bpf_object__find_map_by_name = NULL;
static fn_bpf_map__fd p_bpf_map__fd = NULL;
static fn_bpf_map_update_elem p_bpf_map_update_elem = NULL;
static fn_ring_buffer__new p_ring_buffer__new = NULL;
static fn_ring_buffer__poll p_ring_buffer__poll = NULL;
static fn_ring_buffer__free p_ring_buffer__free = NULL;

static void *load_libbpf(void) {
    void *h = dlopen("libbpf.so.1", RTLD_NOW);
    if (!h) {
        h = dlopen("libbpf.so", RTLD_NOW);
    }
    if (!h) {
        return NULL;
    }

    *(void **)(&p_bpf_object__open_file) = dlsym(h, "bpf_object__open_file");
    *(void **)(&p_bpf_object__load) = dlsym(h, "bpf_object__load");
    *(void **)(&p_bpf_object__close) = dlsym(h, "bpf_object__close");
    *(void **)(&p_bpf_object__find_program_by_name) = dlsym(h, "bpf_object__find_program_by_name");
    *(void **)(&p_bpf_program__attach_kprobe) = dlsym(h, "bpf_program__attach_kprobe");
    *(void **)(&p_bpf_program__attach_tracepoint) = dlsym(h, "bpf_program__attach_tracepoint");
    *(void **)(&p_bpf_object__find_map_by_name) = dlsym(h, "bpf_object__find_map_by_name");
    *(void **)(&p_bpf_map__fd) = dlsym(h, "bpf_map__fd");
    *(void **)(&p_bpf_map_update_elem) = dlsym(h, "bpf_map_update_elem");
    *(void **)(&p_ring_buffer__new) = dlsym(h, "ring_buffer__new");
    *(void **)(&p_ring_buffer__poll) = dlsym(h, "ring_buffer__poll");
    *(void **)(&p_ring_buffer__free) = dlsym(h, "ring_buffer__free");

    if (!p_bpf_object__open_file || !p_bpf_object__load || !p_ring_buffer__new || !p_ring_buffer__poll) {
        dlclose(h);
        return NULL;
    }
    return h;
}

typedef struct {
    event_callback_t callback;
    void *user_data;
} sample_context_t;

static int ring_buf_sample_handler(void *ctx, void *data, size_t size) {
    sample_context_t *sc = (sample_context_t *)ctx;
    if (sc && sc->callback && data && size >= sizeof(io_event_t)) {
        sc->callback((const io_event_t *)data, sc->user_data);
    }
    return 0;
}

int ebpf_loader_init(ebpf_context_t *ctx, const char *obj_path) {
    if (ctx == NULL || obj_path == NULL) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->events_map_fd = -1;
    ctx->daemon_pid_map_fd = -1;

    if (access(obj_path, R_OK) != 0) {
        return -1;
    }

    ctx->lib_handle = load_libbpf();
    if (ctx->lib_handle == NULL) {
        log_msg(LOG_LVL_WARN, "libbpf library not found on system");
        return -1;
    }

    bpf_object *obj = p_bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        log_msg(LOG_LVL_WARN, "Failed to open eBPF object %s", obj_path);
        dlclose(ctx->lib_handle);
        ctx->lib_handle = NULL;
        return -1;
    }
    ctx->bpf_obj = obj;

    if (p_bpf_object__load(obj) != 0) {
        log_msg(LOG_LVL_WARN, "Failed to load eBPF object into kernel");
        p_bpf_object__close(obj);
        ctx->bpf_obj = NULL;
        dlclose(ctx->lib_handle);
        ctx->lib_handle = NULL;
        return -1;
    }

    bpf_program *prog_vfs = p_bpf_object__find_program_by_name(obj, "vfs_write_entry");
    if (!prog_vfs) prog_vfs = p_bpf_object__find_program_by_name(obj, "vfs_write");
    if (prog_vfs && p_bpf_program__attach_kprobe) {
        p_bpf_program__attach_kprobe(prog_vfs, false, "vfs_write");
    }

    bpf_program *prog_rename = p_bpf_object__find_program_by_name(obj, "tracepoint_rename");
    if (!prog_rename) prog_rename = p_bpf_object__find_program_by_name(obj, "sys_enter_rename");
    if (prog_rename && p_bpf_program__attach_tracepoint) {
        p_bpf_program__attach_tracepoint(prog_rename, "syscalls", "sys_enter_renameat2");
    }

    bpf_program *prog_unlink = p_bpf_object__find_program_by_name(obj, "tracepoint_unlink");
    if (!prog_unlink) prog_unlink = p_bpf_object__find_program_by_name(obj, "sys_enter_unlinkat");
    if (prog_unlink && p_bpf_program__attach_tracepoint) {
        p_bpf_program__attach_tracepoint(prog_unlink, "syscalls", "sys_enter_unlinkat");
    }

    bpf_map *events_map = p_bpf_object__find_map_by_name(obj, "EVENTS");
    if (events_map && p_bpf_map__fd) {
        ctx->events_map_fd = p_bpf_map__fd(events_map);
    }

    bpf_map *daemon_map = p_bpf_object__find_map_by_name(obj, "DAEMON_PID");
    if (daemon_map && p_bpf_map__fd) {
        ctx->daemon_pid_map_fd = p_bpf_map__fd(daemon_map);
    }

    ctx->is_loaded = true;
    log_msg(LOG_LVL_INFO, "eBPF probes and maps attached successfully from %s", obj_path);
    return 0;
}

int ebpf_register_daemon_pid(ebpf_context_t *ctx, uint32_t pid) {
    if (!ctx || !ctx->is_loaded || ctx->daemon_pid_map_fd < 0 || !p_bpf_map_update_elem) {
        return -1;
    }
    uint32_t key = 0;
    return p_bpf_map_update_elem(ctx->daemon_pid_map_fd, &key, &pid, 0);
}

int ebpf_poll_events(ebpf_context_t *ctx, event_callback_t callback, void *user_data, int timeout_ms) {
    if (!ctx || !ctx->is_loaded || ctx->events_map_fd < 0 || !p_ring_buffer__new || !p_ring_buffer__poll) {
        return -1;
    }

    sample_context_t sc = {
        .callback = callback,
        .user_data = user_data
    };

    if (ctx->ring_buf == NULL) {
        ctx->ring_buf = p_ring_buffer__new(ctx->events_map_fd, ring_buf_sample_handler, &sc, NULL);
        if (!ctx->ring_buf) {
            return -1;
        }
    }

    return p_ring_buffer__poll((ring_buffer *)ctx->ring_buf, timeout_ms);
}

void ebpf_loader_cleanup(ebpf_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->ring_buf && p_ring_buffer__free) {
        p_ring_buffer__free((ring_buffer *)ctx->ring_buf);
        ctx->ring_buf = NULL;
    }
    if (ctx->bpf_obj && p_bpf_object__close) {
        p_bpf_object__close((bpf_object *)ctx->bpf_obj);
        ctx->bpf_obj = NULL;
    }
    if (ctx->lib_handle) {
        dlclose(ctx->lib_handle);
        ctx->lib_handle = NULL;
    }
    ctx->is_loaded = false;
}
