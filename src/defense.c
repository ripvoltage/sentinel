#include "defense.h"
#include <signal.h>
#include <unistd.h>

uint32_t get_daemon_pid(void) {
    return (uint32_t)getpid();
}

int freeze_process(uint32_t pid) {
    return kill((pid_t)pid, SIGSTOP);
}

int kill_process(uint32_t pid) {
    return kill((pid_t)pid, SIGKILL);
}

int neutralize_threat(uint32_t pid) {
    uint32_t self_pid = get_daemon_pid();
    if (pid == self_pid || pid <= 1) {
        return -1;
    }

    if (freeze_process(pid) != 0) {
        return -1;
    }

    usleep(100000);

    if (kill_process(pid) != 0) {
        return -1;
    }

    return 0;
}
