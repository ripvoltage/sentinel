#ifndef COW_REMEDIATION_H
#define COW_REMEDIATION_H

#include <stddef.h>

typedef enum {
    COW_FS_BTRFS,
    COW_FS_ZFS,
    COW_FS_UNSUPPORTED
} cow_fs_type_t;

cow_fs_type_t detect_filesystem(const char *path);
int create_preventive_snapshot(const char *path, char *out_snapshot_id, size_t out_size);
int restore_snapshot(const char *snapshot_id, cow_fs_type_t fs_type, char *out_status, size_t out_size);

#endif
