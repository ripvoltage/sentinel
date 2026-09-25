#include "sentinel.h"
#include "entropy.h"
#include "canaries.h"
#include "heuristics.h"
#include "proc_inspector.h"
#include "defense.h"
#include "cow_remediation.h"
#include "notification.h"
#include "logger.h"
#include "monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

static volatile sig_atomic_t g_running = 1;

typedef struct {
    heuristics_engine_t heuristics;
    pthread_mutex_t heuristics_lock;
    char ebpf_path[MAX_PATH_LEN];
} app_context_t;

static app_context_t g_app;
static monitor_context_t g_monitor;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void on_io_event(const io_event_t *event, void *user_data) {
    if (event == NULL || user_data == NULL) {
        return;
    }

    if (event->pid == get_daemon_pid() || event->pid <= 1) {
        return;
    }

    app_context_t *app = (app_context_t *)user_data;

    double entropy = 0.0;
    if (event->event_type == EVENT_VFS_WRITE && event->data_len > 0) {
        entropy = calculate_entropy_from_histogram(event->byte_counts, event->data_len);
    }

    bool canary_triggered = is_canary_path(event->path) || is_canary_path(event->new_path);

    pthread_mutex_lock(&app->heuristics_lock);
    verdict_t verdict = heuristics_evaluate(
        &app->heuristics,
        event->pid,
        event->path,
        event->event_type == EVENT_RENAME ? event->new_path : NULL,
        (event_type_t)event->event_type,
        entropy
    );
    pthread_mutex_unlock(&app->heuristics_lock);

    bool is_threat = verdict.score >= 40 || canary_triggered;
    if (!is_threat) {
        return;
    }

    process_info_t proc_info;
    if (proc_inspect(event->pid, &proc_info) == 0) {
        if (canary_triggered) {
            if (is_whitelisted_binary(&proc_info)) {
                log_msg(LOG_LVL_INFO, "False positive suppressed: PID %u (%s) is a trusted administrative binary",
                        event->pid, proc_info.exe);
                return;
            }
        } else if (is_trusted_process(&proc_info)) {
            log_msg(LOG_LVL_INFO, "False positive suppressed: PID %u (%s) is a trusted interactive process",
                    event->pid, proc_info.exe);
            return;
        }
    } else {
        safe_strncpy(proc_info.comm, event->comm, sizeof(proc_info.comm));
        safe_strncpy(proc_info.exe, event->comm, sizeof(proc_info.exe));
        safe_strncpy(proc_info.cmdline, event->comm, sizeof(proc_info.cmdline));
        proc_info.uid = event->uid;
        proc_info.gid = event->gid;
    }

    char rule_buf[256] = {0};
    if (canary_triggered) {
        snprintf(rule_buf, sizeof(rule_buf), "Canary File Modified");
    }
    for (size_t i = 0; i < verdict.reason_count; i++) {
        if (rule_buf[0] != '\0') {
            size_t cur = strlen(rule_buf);
            snprintf(rule_buf + cur, sizeof(rule_buf) - cur, " | %s", verdict.reasons[i]);
        } else {
            safe_strncpy(rule_buf, verdict.reasons[i], sizeof(rule_buf));
        }
    }

    char action_buf[128] = {0};
    if (neutralize_threat(event->pid) == 0) {
        safe_strncpy(action_buf, "Process neutralized: SIGSTOP + SIGKILL", sizeof(action_buf));
        log_msg(LOG_LVL_INFO, "Threat PID %u neutralized (SIGSTOP + SIGKILL)", event->pid);
    } else {
        safe_strncpy(action_buf, "Neutralization failed", sizeof(action_buf));
        log_msg(LOG_LVL_ERROR, "Failed to neutralize threat PID %u", event->pid);
    }

    char cow_status[128] = "N/A";
    cow_fs_type_t fs_type = detect_filesystem(event->path[0] ? event->path : "/home");
    if (fs_type != COW_FS_UNSUPPORTED) {
        restore_snapshot(event->path, fs_type, cow_status, sizeof(cow_status));
    }

    threat_event_t th_ev;
    memset(&th_ev, 0, sizeof(th_ev));
    th_ev.pid = event->pid;
    th_ev.uid = proc_info.uid;
    th_ev.gid = proc_info.gid;
    safe_strncpy(th_ev.exe_path, proc_info.exe, sizeof(th_ev.exe_path));
    safe_strncpy(th_ev.cmdline, proc_info.cmdline, sizeof(th_ev.cmdline));
    th_ev.entropy = entropy;
    safe_strncpy(th_ev.rule_triggered, rule_buf, sizeof(th_ev.rule_triggered));
    safe_strncpy(th_ev.action_taken, action_buf, sizeof(th_ev.action_taken));

    if (event->path[0] != '\0') {
        safe_strncpy(th_ev.affected_files[0], event->path, sizeof(th_ev.affected_files[0]));
        th_ev.affected_count = 1;
    }
    if (event->new_path[0] != '\0' && th_ev.affected_count < MAX_AFFECTED_FILES) {
        safe_strncpy(th_ev.affected_files[th_ev.affected_count], event->new_path, sizeof(th_ev.affected_files[0]));
        th_ev.affected_count++;
    }

    log_threat_event(&th_ev);

    threat_info_t notif_info;
    memset(&notif_info, 0, sizeof(notif_info));
    notif_info.pid = event->pid;
    safe_strncpy(notif_info.exe_path, proc_info.exe, sizeof(notif_info.exe_path));
    notif_info.entropy = entropy;
    safe_strncpy(notif_info.action_taken, action_buf, sizeof(notif_info.action_taken));
    safe_strncpy(notif_info.cow_status, cow_status, sizeof(notif_info.cow_status));
    notif_info.affected_count = th_ev.affected_count;
    for (size_t i = 0; i < th_ev.affected_count; i++) {
        safe_strncpy(notif_info.affected_files[i], th_ev.affected_files[i], sizeof(notif_info.affected_files[i]));
    }

    send_critical_alert(&notif_info);
}

static void *cleanup_thread_fn(void *arg) {
    app_context_t *app = (app_context_t *)arg;
    while (g_running) {
        sleep(30);
        if (!g_running) break;
        pthread_mutex_lock(&app->heuristics_lock);
        heuristics_cleanup_stale(&app->heuristics, STALE_MAX_AGE_SEC);
        pthread_mutex_unlock(&app->heuristics_lock);
    }
    return NULL;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n\n"
           "Options:\n"
           "  -b, --bpf-path <path>  Path to eBPF object file (default: %s)\n"
           "  -v, --version          Show version information\n"
           "  -h, --help             Show this help message\n",
           prog_name, DEFAULT_EBPF_PATH);
}

int main(int argc, char **argv) {
    const char *ebpf_path = DEFAULT_EBPF_PATH;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("Sentinel Anti-Ransomware v%s\n", SENTINEL_VERSION);
            return 0;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if ((strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--bpf-path") == 0) && i + 1 < argc) {
            ebpf_path = argv[++i];
        }
    }

    logger_init();

    log_msg(LOG_LVL_INFO, "Sentinel Anti-Ransomware Daemon v%s", SENTINEL_VERSION);
    log_msg(LOG_LVL_INFO, "PID: %u | EUID: %u", (unsigned int)getpid(), (unsigned int)geteuid());

    if (geteuid() != 0) {
        log_msg(LOG_LVL_WARN, "Daemon is not running as root. Some inspection and defense features may be limited.");
    }

    memset(&g_app, 0, sizeof(g_app));
    safe_strncpy(g_app.ebpf_path, ebpf_path, sizeof(g_app.ebpf_path));
    heuristics_init(&g_app.heuristics);
    pthread_mutex_init(&g_app.heuristics_lock, NULL);

    int deployed = deploy_canaries();
    log_msg(LOG_LVL_INFO, "Canary honeypot deployment completed: %d files verified", deployed);

    char snap_id[256];
    if (create_preventive_snapshot("/home", snap_id, sizeof(snap_id)) == 0) {
        log_msg(LOG_LVL_INFO, "Preventive CoW snapshot created for /home: %s", snap_id);
    }
    if (create_preventive_snapshot("/", snap_id, sizeof(snap_id)) == 0) {
        log_msg(LOG_LVL_INFO, "Preventive CoW snapshot created for /: %s", snap_id);
    }

    if (monitor_init(&g_monitor, g_app.ebpf_path, on_io_event, &g_app) != 0) {
        log_msg(LOG_LVL_ERROR, "Failed to initialize monitoring subsystem");
        return 1;
    }

    if (g_monitor.use_ebpf) {
        ebpf_register_daemon_pid(&g_monitor.bpf_ctx, get_daemon_pid());
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    pthread_t cleanup_thread;
    pthread_create(&cleanup_thread, NULL, cleanup_thread_fn, &g_app);

    log_msg(LOG_LVL_INFO, "Entering main event loop - monitoring filesystem activity...");

    while (g_running) {
        monitor_poll(&g_monitor, 500);
    }

    log_msg(LOG_LVL_INFO, "Shutting down Sentinel daemon...");

    pthread_join(cleanup_thread, NULL);
    monitor_cleanup(&g_monitor);
    pthread_mutex_destroy(&g_app.heuristics_lock);

    log_msg(LOG_LVL_INFO, "Shutdown complete");
    return 0;
}
