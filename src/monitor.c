#include "monitor.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <dirent.h>

void safe_strncpy(char *dst, const char *src, size_t dst_size) {
    if (dst == NULL || dst_size == 0) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < dst_size) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void mark_fanotify_path(int fanotify_fd, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return;
    }

    uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE;
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD, path) == 0) {
        log_msg(LOG_LVL_INFO, "fanotify: monitoring mount at %s", path);
        return;
    }

#ifdef FAN_MARK_FILESYSTEM
    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, AT_FDCWD, path) == 0) {
        log_msg(LOG_LVL_INFO, "fanotify: monitoring filesystem at %s", path);
        return;
    }
#endif

    if (fanotify_mark(fanotify_fd, FAN_MARK_ADD, mask, AT_FDCWD, path) == 0) {
        log_msg(LOG_LVL_INFO, "fanotify: monitoring directory at %s", path);
        return;
    }

    log_msg(LOG_LVL_WARN, "fanotify: failed to mark path %s: %s", path, strerror(errno));
}

int monitor_init(monitor_context_t *ctx, const char *ebpf_path, event_callback_t cb, void *user_data) {
    if (ctx == NULL) {
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->fanotify_fd = -1;
    ctx->callback = cb;
    ctx->user_data = user_data;

    if (ebpf_path != NULL && ebpf_loader_init(&ctx->bpf_ctx, ebpf_path) == 0) {
        ctx->use_ebpf = true;
        log_msg(LOG_LVL_INFO, "Primary monitoring engine: eBPF Ring Buffer");
    } else {
        ctx->use_ebpf = false;
        log_msg(LOG_LVL_INFO, "Falling back to native Linux fanotify monitoring engine");
    }

    ctx->fanotify_fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (ctx->fanotify_fd >= 0) {
        mark_fanotify_path(ctx->fanotify_fd, "/home");
        mark_fanotify_path(ctx->fanotify_fd, "/root");

        DIR *dir = opendir("/home");
        if (dir != NULL) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') {
                    continue;
                }
                char canary_dir[MAX_PATH_LEN];
                int n = snprintf(canary_dir, sizeof(canary_dir), "/home/%s/%s", entry->d_name, CANARY_DIR_NAME);
                if (n > 0 && (size_t)n < sizeof(canary_dir)) {
                    struct stat cst;
                    if (stat(canary_dir, &cst) == 0 && S_ISDIR(cst.st_mode)) {
                        uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE;
                        if (fanotify_mark(ctx->fanotify_fd, FAN_MARK_ADD, mask, AT_FDCWD, canary_dir) == 0) {
                            log_msg(LOG_LVL_INFO, "fanotify: registered honeypot canary directory %s", canary_dir);
                        }
                    }
                }
            }
            closedir(dir);
        }

        char root_canary[MAX_PATH_LEN];
        int n = snprintf(root_canary, sizeof(root_canary), "/root/%s", CANARY_DIR_NAME);
        if (n > 0 && (size_t)n < sizeof(root_canary)) {
            struct stat rcst;
            if (stat(root_canary, &rcst) == 0 && S_ISDIR(rcst.st_mode)) {
                uint64_t mask = FAN_MODIFY | FAN_CLOSE_WRITE;
                if (fanotify_mark(ctx->fanotify_fd, FAN_MARK_ADD, mask, AT_FDCWD, root_canary) == 0) {
                    log_msg(LOG_LVL_INFO, "fanotify: registered honeypot canary directory %s", root_canary);
                }
            }
        }
    } else {
        log_msg(LOG_LVL_ERROR, "fanotify_init failed: %s (requires CAP_SYS_ADMIN or root)", strerror(errno));
    }

    return 0;
}

static void process_fanotify_event(monitor_context_t *ctx, const struct fanotify_event_metadata *meta) {
    if (meta->fd < 0 || meta->pid <= 1 || meta->pid == (pid_t)getpid()) {
        if (meta->fd >= 0) close(meta->fd);
        return;
    }

    char procfd_path[64];
    snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", meta->fd);

    io_event_t event;
    memset(&event, 0, sizeof(event));
    event.pid = (uint32_t)meta->pid;
    event.event_type = EVENT_VFS_WRITE;

    ssize_t len = readlink(procfd_path, event.path, sizeof(event.path) - 1);
    if (len > 0) {
        event.path[len] = '\0';
    }

    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", event.pid);
    int comm_fd = open(comm_path, O_RDONLY);
    if (comm_fd >= 0) {
        ssize_t comm_len = read(comm_fd, event.comm, sizeof(event.comm) - 1);
        close(comm_fd);
        if (comm_len > 0) {
            while (comm_len > 0 && (event.comm[comm_len - 1] == '\n' || event.comm[comm_len - 1] == '\r')) {
                comm_len--;
            }
            event.comm[comm_len] = '\0';
        }
    }

    uint8_t buffer[BLOCK_SIZE];
    lseek(meta->fd, 0, SEEK_SET);
    ssize_t bytes_read = read(meta->fd, buffer, sizeof(buffer));
    close(meta->fd);

    if (bytes_read > 0) {
        event.data_len = (uint32_t)bytes_read;
        size_t sample_len = bytes_read > MAGIC_SAMPLE_LEN ? MAGIC_SAMPLE_LEN : (size_t)bytes_read;
        memcpy(event.magic_sample, buffer, sample_len);

        for (ssize_t i = 0; i < bytes_read; i++) {
            event.byte_counts[buffer[i]]++;
        }
    }

    if (ctx->callback) {
        ctx->callback(&event, ctx->user_data);
    }
}

int monitor_poll(monitor_context_t *ctx, int timeout_ms) {
    if (ctx == NULL) {
        return -1;
    }

    if (ctx->use_ebpf) {
        ebpf_poll_events(&ctx->bpf_ctx, ctx->callback, ctx->user_data, timeout_ms);
    }

    if (ctx->fanotify_fd < 0) {
        usleep((useconds_t)timeout_ms * 1000);
        return 0;
    }

    struct pollfd pfd;
    pfd.fd = ctx->fanotify_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int poll_timeout = ctx->use_ebpf ? 0 : timeout_ms;
    int ret = poll(&pfd, 1, poll_timeout);
    if (ret <= 0) {
        return ret;
    }

    if (pfd.revents & POLLIN) {
        char buf[4096];
        ssize_t len = read(ctx->fanotify_fd, buf, sizeof(buf));
        if (len > 0) {
            const struct fanotify_event_metadata *meta = (const struct fanotify_event_metadata *)buf;
            while (FAN_EVENT_OK(meta, len)) {
                if (meta->vers == FANOTIFY_METADATA_VERSION) {
                    process_fanotify_event(ctx, meta);
                }
                meta = FAN_EVENT_NEXT(meta, len);
            }
        }
    }

    return 0;
}

void monitor_cleanup(monitor_context_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->use_ebpf) {
        ebpf_loader_cleanup(&ctx->bpf_ctx);
    }
    if (ctx->fanotify_fd >= 0) {
        close(ctx->fanotify_fd);
        ctx->fanotify_fd = -1;
    }
}
