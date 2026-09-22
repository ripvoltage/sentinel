#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CANARY_DIR_NAME ".canary_sentinel"
#define PAYLOAD_SIZE 1024

static void generate_encrypted_payload(uint8_t *buf, size_t len) {
    uint64_t state = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(state >> 33);
    }
}

static int find_canary_dir(char *out_path, size_t out_size) {
    const char *home = getenv("HOME");
    if (home != NULL) {
        snprintf(out_path, out_size, "%s/%s", home, CANARY_DIR_NAME);
        struct stat st;
        if (stat(out_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return 0;
        }
    }

    snprintf(out_path, out_size, "/root/%s", CANARY_DIR_NAME);
    struct stat root_st;
    if (stat(out_path, &root_st) == 0 && S_ISDIR(root_st.st_mode)) {
        return 0;
    }

    return -1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n"
           "Options:\n"
           "  -d, --dir <path>     Explicit path to canary directory\n"
           "  -b, --background     Detach and run in background (bypasses terminal check)\n"
           "  -h, --help           Show this help message\n",
           prog);
}

int main(int argc, char **argv) {
    char canary_dir[512] = {0};
    int run_background = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dir") == 0) && i + 1 < argc) {
            snprintf(canary_dir, sizeof(canary_dir), "%s", argv[++i]);
        }
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--background") == 0) {
            run_background = 1;
        }
    }

    if (canary_dir[0] == '\0') {
        if (find_canary_dir(canary_dir, sizeof(canary_dir)) != 0) {
            fprintf(stderr, "Canary directory not found. Ensure Sentinel has deployed canaries.\n");
            return 1;
        }
    }

    printf("Target canary directory: %s\n", canary_dir);

    if (run_background) {
        printf("Forking to background (PID detachment mode)...\n");
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid > 0) {
            printf("Background process spawned: PID %d\n", pid);
            return 0;
        }
        setsid();
    }

    DIR *dir = opendir(canary_dir);
    if (dir == NULL) {
        perror("opendir");
        return 1;
    }

    uint8_t payload[PAYLOAD_SIZE];
    generate_encrypted_payload(payload, sizeof(payload));

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/%s", canary_dir, entry->d_name);

        struct stat st;
        if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        printf("Targeting canary file: %s (PID: %d)\n", file_path, getpid());

        int fd = open(file_path, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            ssize_t written = write(fd, payload, sizeof(payload));
            close(fd);
            printf("Overwritten %zd bytes of high-entropy payload into: %s\n", written, file_path);
        }

        char enc_path[600];
        snprintf(enc_path, sizeof(enc_path), "%s.encrypted", file_path);
        if (rename(file_path, enc_path) == 0) {
            printf("Renamed canary to: %s\n", enc_path);
        }

        usleep(50000);
    }

    closedir(dir);
    printf("Canary targeting sequence completed.\n");
    return 0;
}
