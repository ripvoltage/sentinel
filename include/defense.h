#ifndef DEFENSE_H
#define DEFENSE_H

#include <stdint.h>

uint32_t get_daemon_pid(void);
int freeze_process(uint32_t pid);
int kill_process(uint32_t pid);
int neutralize_threat(uint32_t pid);

#endif
