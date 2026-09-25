#include "notification.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

static void format_notification_body(const threat_info_t *threat, char *buf, size_t buf_size) {
    char files_summary[512] = {0};

    if (threat->affected_count == 0) {
        snprintf(files_summary, sizeof(files_summary), "Ninguno detectado");
    } else {
        size_t offset = 0;
        size_t limit = threat->affected_count > 5 ? 5 : threat->affected_count;

        for (size_t i = 0; i < limit; i++) {
            int n = snprintf(files_summary + offset, sizeof(files_summary) - offset,
                             "- %s\n", threat->affected_files[i]);
            if (n > 0 && offset + (size_t)n < sizeof(files_summary)) {
                offset += (size_t)n;
            } else {
                break;
            }
        }

        if (threat->affected_count > 5) {
            snprintf(files_summary + offset, sizeof(files_summary) - offset,
                     "... y %zu archivo(s) mas", threat->affected_count - 5);
        }
    }

    snprintf(buf, buf_size,
             "<b>Ejecutable:</b> %s\n"
             "<b>PID:</b> %u\n"
             "<b>Entropia de Shannon:</b> %.2f\n"
             "<b>Accion ejecutada:</b> %s\n"
             "<b>Restauracion CoW:</b> %s\n"
             "<b>Archivos afectados:</b>\n%s",
             threat->exe_path,
             threat->pid,
             threat->entropy,
             threat->action_taken,
             threat->cow_status[0] ? threat->cow_status : "N/A",
             files_summary);
}

static int dispatch_to_session(uid_t uid, const char *bus_path, const char *summary, const char *body) {
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        char bus_addr[512];
        char runtime_dir[128];
        snprintf(bus_addr, sizeof(bus_addr), "unix:path=%s", bus_path);
        snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%u", (unsigned int)uid);

        if (setgid((gid_t)uid) != 0 || setuid(uid) != 0) {
            _exit(1);
        }

        setenv("DBUS_SESSION_BUS_ADDRESS", bus_addr, 1);
        setenv("XDG_RUNTIME_DIR", runtime_dir, 1);
        setenv("DISPLAY", ":0", 1);

        char *const argv[] = {
            "notify-send",
            "--urgency=critical",
            "--icon=dialog-warning",
            "--app-name=sentinel",
            (char *)summary,
            (char *)body,
            NULL
        };

        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int send_critical_alert(const threat_info_t *threat) {
    if (threat == NULL) {
        return -1;
    }

    const char *summary = "Amenaza de Ransomware Detectada";
    char body[NOTIF_TEXT_LEN];
    format_notification_body(threat, body, sizeof(body));

    int delivered = 0;
    DIR *dir = opendir("/run/user");
    if (dir != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') {
                continue;
            }

            char *endptr = NULL;
            unsigned long uid_val = strtoul(entry->d_name, &endptr, 10);
            if (endptr != NULL && *endptr == '\0' && uid_val >= 1000) {
                char bus_path[256];
                snprintf(bus_path, sizeof(bus_path), "/run/user/%lu/bus", uid_val);

                struct stat st;
                if (stat(bus_path, &st) == 0) {
                    if (dispatch_to_session((uid_t)uid_val, bus_path, summary, body) == 0) {
                        delivered++;
                    }
                }
            }
        }
        closedir(dir);
    }

    if (delivered == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            char *const argv[] = {
                "notify-send",
                "--urgency=critical",
                "--icon=dialog-warning",
                "--app-name=sentinel",
                (char *)summary,
                body,
                NULL
            };
            execvp(argv[0], argv);
            _exit(127);
        } else if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
        }
    }

    return delivered;
}
