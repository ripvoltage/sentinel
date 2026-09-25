#include "cow_remediation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifndef ZFS_SUPER_MAGIC
#define ZFS_SUPER_MAGIC 0x2fc12fc1
#endif

static int run_command_sync(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

cow_fs_type_t detect_filesystem(const char *path) {
    if (path == NULL) {
        return COW_FS_UNSUPPORTED;
    }

    struct statfs sfs;
    if (statfs(path, &sfs) == 0) {
        if ((unsigned long)sfs.f_type == (unsigned long)BTRFS_SUPER_MAGIC) {
            return COW_FS_BTRFS;
        }
        if ((unsigned long)sfs.f_type == (unsigned long)ZFS_SUPER_MAGIC) {
            return COW_FS_ZFS;
        }
    }

    FILE *f = fopen("/proc/mounts", "r");
    if (f != NULL) {
        char line[512];
        cow_fs_type_t detected = COW_FS_UNSUPPORTED;
        size_t best_len = 0;

        while (fgets(line, sizeof(line), f) != NULL) {
            char dev[128], mnt[128], type[32];
            if (sscanf(line, "%127s %127s %31s", dev, mnt, type) == 3) {
                size_t mnt_len = strlen(mnt);
                if (strncmp(path, mnt, mnt_len) == 0 && (path[mnt_len] == '/' || path[mnt_len] == '\0' || mnt_len == 1)) {
                    if (mnt_len > best_len || best_len == 0) {
                        best_len = mnt_len;
                        if (strcmp(type, "btrfs") == 0) {
                            detected = COW_FS_BTRFS;
                        } else if (strcmp(type, "zfs") == 0) {
                            detected = COW_FS_ZFS;
                        } else {
                            detected = COW_FS_UNSUPPORTED;
                        }
                    }
                }
            }
        }
        fclose(f);
        if (detected != COW_FS_UNSUPPORTED) {
            return detected;
        }
    }

    return COW_FS_UNSUPPORTED;
}

int create_preventive_snapshot(const char *path, char *out_snapshot_id, size_t out_size) {
    if (path == NULL) {
        return -1;
    }

    cow_fs_type_t fs_type = detect_filesystem(path);
    time_t now = time(NULL);
    char ts_str[32];
    snprintf(ts_str, sizeof(ts_str), "%ld", (long)now);

    if (fs_type == COW_FS_BTRFS) {
        char snap_dir[768];
        snprintf(snap_dir, sizeof(snap_dir), "%s/.snapshots", path);
        mkdir(snap_dir, 0700);

        char snap_path[1024];
        snprintf(snap_path, sizeof(snap_path), "%s/ransomware-guard-%s", snap_dir, ts_str);

        char *const argv[] = {
            "btrfs", "subvolume", "snapshot", "-r", (char *)path, snap_path, NULL
        };

        if (run_command_sync(argv) == 0) {
            if (out_snapshot_id && out_size > 0) {
                snprintf(out_snapshot_id, out_size, "%s", snap_path);
            }
            return 0;
        }
        return -1;
    }

    if (fs_type == COW_FS_ZFS) {
        char snap_id[512];
        snprintf(snap_id, sizeof(snap_id), "%s@ransomware-guard-%s", path, ts_str);

        char *const argv[] = {
            "zfs", "snapshot", snap_id, NULL
        };

        if (run_command_sync(argv) == 0) {
            if (out_snapshot_id && out_size > 0) {
                snprintf(out_snapshot_id, out_size, "%s", snap_id);
            }
            return 0;
        }
        return -1;
    }

    return -1;
}

int restore_snapshot(const char *snapshot_id, cow_fs_type_t fs_type, char *out_status, size_t out_size) {
    if (snapshot_id == NULL) {
        return -1;
    }

    if (fs_type == COW_FS_BTRFS) {
        char target[512];
        snprintf(target, sizeof(target), "%s-restored", snapshot_id);

        char *const argv[] = {
            "btrfs", "subvolume", "snapshot", (char *)snapshot_id, target, NULL
        };

        if (run_command_sync(argv) == 0) {
            if (out_status && out_size > 0) {
                snprintf(out_status, out_size, "Btrfs snapshot restored to %s", target);
            }
            return 0;
        }
        return -1;
    }

    if (fs_type == COW_FS_ZFS) {
        char *const argv[] = {
            "zfs", "rollback", "-r", (char *)snapshot_id, NULL
        };

        if (run_command_sync(argv) == 0) {
            if (out_status && out_size > 0) {
                snprintf(out_status, out_size, "ZFS snapshot rolled back successfully");
            }
            return 0;
        }
        return -1;
    }

    return -1;
}
