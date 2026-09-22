#ifndef SENTINEL_H
#define SENTINEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SENTINEL_VERSION "0.1.0"

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16
#define BLOCK_SIZE 512
#define MAGIC_SAMPLE_LEN 64
#define ENTROPY_THRESHOLD 7.92
#define CANARY_DIR_NAME ".canary_sentinel"
#define DEFAULT_EBPF_PATH "/usr/lib/sentinel/sentinel-ebpf.o"

typedef enum {
    EVENT_VFS_WRITE = 0,
    EVENT_RENAME = 1,
    EVENT_UNLINK = 2
} event_type_t;

typedef struct {
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t event_type;
    uint64_t timestamp_ns;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
    uint8_t magic_sample[MAGIC_SAMPLE_LEN];
    uint32_t data_len;
    uint32_t _pad;
    uint32_t byte_counts[256];
} io_event_t;

void safe_strncpy(char *dst, const char *src, size_t dst_size);

#endif
