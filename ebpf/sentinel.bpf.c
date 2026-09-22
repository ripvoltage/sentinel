#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define BLOCK_SIZE 512
#define MAGIC_SAMPLE_LEN 64
#define SAMPLE_CHUNK_SIZE 128
#define MIN_MONITORED_PID 500

enum event_type {
    EVENT_VFS_WRITE = 0,
    EVENT_RENAME = 1,
    EVENT_UNLINK = 2
};

struct io_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u64 timestamp_ns;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
    __u8 magic_sample[MAGIC_SAMPLE_LEN];
    __u32 data_len;
    __u32 _pad;
    __u32 byte_counts[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} TRUSTED_PIDS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} DAEMON_PID SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct io_event);
} SCRATCH_EVENT SEC(".maps");

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, void *file, const char *buf, size_t count) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (pid < MIN_MONITORED_PID) {
        return 0;
    }

    if (bpf_map_lookup_elem(&TRUSTED_PIDS, &pid) != NULL) {
        return 0;
    }

    if (buf == NULL || count == 0) {
        return 0;
    }

    __u32 zero = 0;
    struct io_event *event = bpf_map_lookup_elem(&SCRATCH_EVENT, &zero);
    if (event == NULL) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->pid = pid;
    event->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    event->gid = (__u32)(uid_gid >> 32);
    event->event_type = EVENT_VFS_WRITE;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->data_len = count > BLOCK_SIZE ? BLOCK_SIZE : (__u32)count;
    event->_pad = 0;
    event->path[0] = '\0';
    event->new_path[0] = '\0';

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    #pragma unroll
    for (int i = 0; i < 256; i++) {
        event->byte_counts[i] = 0;
    }

    size_t sample_len = count > MAGIC_SAMPLE_LEN ? MAGIC_SAMPLE_LEN : count;
    if (sample_len > 0) {
        bpf_probe_read_user(event->magic_sample, sample_len, buf);
    }

    size_t bytes_to_sample = count > BLOCK_SIZE ? BLOCK_SIZE : count;
    size_t offset = 0;
    __u8 chunk[SAMPLE_CHUNK_SIZE];

    for (int iter = 0; iter < 4; iter++) {
        if (offset >= bytes_to_sample) {
            break;
        }

        size_t remaining = bytes_to_sample - offset;
        size_t read_len = remaining < SAMPLE_CHUNK_SIZE ? remaining : SAMPLE_CHUNK_SIZE;

        #pragma unroll
        for (int i = 0; i < SAMPLE_CHUNK_SIZE; i++) {
            chunk[i] = 0;
        }

        if (bpf_probe_read_user(chunk, read_len, buf + offset) != 0) {
            break;
        }

        #pragma unroll
        for (int j = 0; j < SAMPLE_CHUNK_SIZE; j++) {
            event->byte_counts[chunk[j]]++;
        }

        __u32 extra_zeros = (__u32)(SAMPLE_CHUNK_SIZE - read_len);
        event->byte_counts[0] -= extra_zeros;

        offset += read_len;
    }

    bpf_ringbuf_output(&EVENTS, event, sizeof(struct io_event), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint_rename(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (pid < MIN_MONITORED_PID) {
        return 0;
    }

    __u32 zero = 0;
    struct io_event *event = bpf_map_lookup_elem(&SCRATCH_EVENT, &zero);
    if (event == NULL) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->pid = pid;
    event->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    event->gid = (__u32)(uid_gid >> 32);
    event->event_type = EVENT_RENAME;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->data_len = 0;
    event->_pad = 0;
    event->path[0] = '\0';
    event->new_path[0] = '\0';

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    const char *oldname_ptr = NULL;
    const char *newname_ptr = NULL;

    bpf_probe_read_kernel(&oldname_ptr, sizeof(oldname_ptr), (const char *)ctx + 24);
    bpf_probe_read_kernel(&newname_ptr, sizeof(newname_ptr), (const char *)ctx + 40);

    if (oldname_ptr != NULL) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), oldname_ptr);
    }
    if (newname_ptr != NULL) {
        bpf_probe_read_user_str(event->new_path, sizeof(event->new_path), newname_ptr);
    }

    bpf_ringbuf_output(&EVENTS, event, sizeof(struct io_event), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_unlink(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    if (pid < MIN_MONITORED_PID) {
        return 0;
    }

    __u32 zero = 0;
    struct io_event *event = bpf_map_lookup_elem(&SCRATCH_EVENT, &zero);
    if (event == NULL) {
        return 0;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    event->pid = pid;
    event->uid = (__u32)(uid_gid & 0xFFFFFFFF);
    event->gid = (__u32)(uid_gid >> 32);
    event->event_type = EVENT_UNLINK;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->data_len = 0;
    event->_pad = 0;
    event->path[0] = '\0';
    event->new_path[0] = '\0';

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    const char *pathname_ptr = NULL;
    bpf_probe_read_kernel(&pathname_ptr, sizeof(pathname_ptr), (const char *)ctx + 24);

    if (pathname_ptr != NULL) {
        bpf_probe_read_user_str(event->path, sizeof(event->path), pathname_ptr);
    }

    bpf_ringbuf_output(&EVENTS, event, sizeof(struct io_event), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
