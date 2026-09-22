#include "proc_inspector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static const char *TRUSTED_BINARIES[] = {
    "tar", "gzip", "gunzip", "bzip2", "xz", "zstd", "lz4", "pigz",
    "gpg", "gpg2", "gpg-agent", "openssl", "age", "rsync", "cp", "mv",
    "dd", "ssh", "scp", "sftp", "rclone", "borg", "restic", "duplicity",
    "snap", "flatpak", "apt", "apt-get", "dpkg", "dnf", "yum", "pacman",
    "makepkg", "cargo", "rustc", "gcc", "g++", "clang", "make", "cmake",
    "ninja", "npm", "node", "python3", "pip", "java", "javac", "docker",
    "podman", "systemd-journald", "journalctl", "logrotate",
    NULL
};

static const char *SHELL_BINARIES[] = {
    "bash", "zsh", "fish", "dash", "sh",
    NULL
};

static const char *TERMINAL_BINARIES[] = {
    "gnome-terminal", "gnome-terminal-server", "konsole", "alacritty",
    "kitty", "tilix", "tmux", "screen",
    NULL
};

static const char *get_basename(const char *path) {
    if (path == NULL) {
        return "";
    }
    const char *slash = strrchr(path, '/');
    return slash ? (slash + 1) : path;
}

static bool matches_list(const char *name, const char **list) {
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    for (size_t i = 0; list[i] != NULL; i++) {
        if (strcmp(name, list[i]) == 0) {
            return true;
        }
    }
    return false;
}

static int parse_proc_stat(const char *stat_str, char *comm, size_t comm_size, uint32_t *ppid) {
    const char *open_paren = strchr(stat_str, '(');
    const char *close_paren = strrchr(stat_str, ')');

    if (open_paren == NULL || close_paren == NULL || close_paren <= open_paren) {
        return -1;
    }

    size_t comm_len = (size_t)(close_paren - open_paren - 1);
    if (comm_len >= comm_size) {
        comm_len = comm_size - 1;
    }
    memcpy(comm, open_paren + 1, comm_len);
    comm[comm_len] = '\0';

    const char *after = close_paren + 1;
    while (*after == ' ') {
        after++;
    }

    char state = *after;
    if (state == '\0') {
        return -1;
    }
    after++;
    while (*after == ' ') {
        after++;
    }

    *ppid = (uint32_t)strtoul(after, NULL, 10);
    return 0;
}

static void parse_proc_status_ids(const char *status_str, uint32_t *uid, uint32_t *gid) {
    *uid = 0;
    *gid = 0;

    const char *line = status_str;
    while (line != NULL && *line != '\0') {
        if (strncmp(line, "Uid:", 4) == 0) {
            const char *p = line + 4;
            while (*p == ' ' || *p == '\t') p++;
            *uid = (uint32_t)strtoul(p, NULL, 10);
        } else if (strncmp(line, "Gid:", 4) == 0) {
            const char *p = line + 4;
            while (*p == ' ' || *p == '\t') p++;
            *gid = (uint32_t)strtoul(p, NULL, 10);
        }
        line = strchr(line, '\n');
        if (line != NULL) {
            line++;
        }
    }
}

int proc_inspect(uint32_t pid, process_info_t *info) {
    if (info == NULL) {
        return -1;
    }
    memset(info, 0, sizeof(*info));
    info->pid = pid;

    char path_buf[MAX_PATH_LEN];
    snprintf(path_buf, sizeof(path_buf), "/proc/%u/stat", pid);

    int fd = open(path_buf, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    char stat_buf[1024];
    ssize_t bytes_read = read(fd, stat_buf, sizeof(stat_buf) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return -1;
    }
    stat_buf[bytes_read] = '\0';

    if (parse_proc_stat(stat_buf, info->comm, sizeof(info->comm), &info->parent_pid) != 0) {
        return -1;
    }

    snprintf(path_buf, sizeof(path_buf), "/proc/%u/status", pid);
    fd = open(path_buf, O_RDONLY);
    if (fd >= 0) {
        char status_buf[2048];
        bytes_read = read(fd, status_buf, sizeof(status_buf) - 1);
        close(fd);
        if (bytes_read > 0) {
            status_buf[bytes_read] = '\0';
            parse_proc_status_ids(status_buf, &info->uid, &info->gid);
        }
    }

    snprintf(path_buf, sizeof(path_buf), "/proc/%u/exe", pid);
    ssize_t link_len = readlink(path_buf, info->exe, sizeof(info->exe) - 1);
    if (link_len > 0) {
        info->exe[link_len] = '\0';
    } else {
        safe_strncpy(info->exe, info->comm, sizeof(info->exe));
    }

    snprintf(path_buf, sizeof(path_buf), "/proc/%u/cmdline", pid);
    fd = open(path_buf, O_RDONLY);
    if (fd >= 0) {
        bytes_read = read(fd, info->cmdline, sizeof(info->cmdline) - 1);
        close(fd);
        if (bytes_read > 0) {
            for (ssize_t i = 0; i < bytes_read - 1; i++) {
                if (info->cmdline[i] == '\0') {
                    info->cmdline[i] = ' ';
                }
            }
            info->cmdline[bytes_read] = '\0';
        } else {
            safe_strncpy(info->cmdline, info->comm, sizeof(info->cmdline));
        }
    } else {
        safe_strncpy(info->cmdline, info->comm, sizeof(info->cmdline));
    }

    return 0;
}

bool is_trusted_process(const process_info_t *info) {
    if (info == NULL) {
        return false;
    }

    const char *exe_base = get_basename(info->exe);
    const char *comm_base = get_basename(info->comm);

    if (matches_list(exe_base, TRUSTED_BINARIES) || matches_list(comm_base, TRUSTED_BINARIES)) {
        return true;
    }

    uint32_t current_pid = info->parent_pid;
    bool shell_found = false;

    for (int level = 0; level < 5; level++) {
        if (current_pid <= 1) {
            break;
        }

        process_info_t parent_info;
        if (proc_inspect(current_pid, &parent_info) != 0) {
            break;
        }

        const char *parent_exe = get_basename(parent_info.exe);
        const char *parent_comm = get_basename(parent_info.comm);

        bool is_shell = matches_list(parent_comm, SHELL_BINARIES) || matches_list(parent_exe, SHELL_BINARIES);
        bool is_terminal = matches_list(parent_comm, TERMINAL_BINARIES) || matches_list(parent_exe, TERMINAL_BINARIES);

        if (is_shell) {
            shell_found = true;
        }

        if (shell_found && is_terminal) {
            return true;
        }

        current_pid = parent_info.parent_pid;
    }

    return false;
}
