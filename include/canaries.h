#ifndef CANARIES_H
#define CANARIES_H

#include <stdbool.h>
#include <stddef.h>

#define CANARY_FILE_COUNT 6

typedef struct {
    const char *name;
    const char *content;
    size_t size;
} canary_file_t;

bool is_canary_path(const char *path);
int deploy_canaries(void);
int deploy_canaries_to_base(const char *base_path);

#endif
