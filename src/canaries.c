#include "canaries.h"
#include "sentinel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

static const canary_file_t CANARY_FILES[CANARY_FILE_COUNT] = {
    {
        .name = "important_document.docx",
        .content = "[SENTINEL_CANARY_DOCX_HEADER]\r\n"
                   "CONFIDENTIAL CORPORATE STRATEGY & MERGER TARGETS 2024-2026\r\n"
                   "DO NOT DISTRIBUTE - INTERNAL ONLY\r\n"
                   "Section 1: Executive Summary\r\n"
                   "Section 2: Valuation Models and Acquisition Roadmaps\r\n",
        .size = 197
    },
    {
        .name = "financial_report.xlsx",
        .content = "[SENTINEL_CANARY_XLSX_HEADER]\r\n"
                   "Q1-Q4 Audited Balance Sheets, Revenue Forecasting, EBITDA Projections\r\n"
                   "Account ID: 884-29104-92A\r\n"
                   "Net Income: $14,892,000\r\n",
        .size = 153
    },
    {
        .name = "family_photos.zip",
        .content = "PK\x03\x04\x14\x00\x00\x00\x08\x00"
                   "SENTINEL_CANARY_ARCHIVE_VACATION_PHOTOS_SUMMER_2023_FAMILY_MEMORIES"
                   "\x00\x00\x00\x00\x00\x00",
        .size = 83
    },
    {
        .name = "passwords.txt",
        .content = "# Sentinel Canary Vault - Personal & Infrastructure Credentials\r\n"
                   "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\r\n"
                   "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
                   "root_database_master_pass=S3cur3_C4n4ry_T0k3n_V4ult_99!\r\n",
        .size = 208
    },
    {
        .name = "bitcoin_wallet.dat",
        .content = "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                   "SENTINEL_BITCOIN_CORE_WALLET_DESCRIPTOR_CANARY_v0.21.0"
                   "\x00\x00\x00\x00\x00\x00",
        .size = 72
    },
    {
        .name = "tax_return_2024.pdf",
        .content = "%PDF-1.4\n"
                   "1 0 obj\n"
                   "<< /Title (Federal Form 1040 - U.S. Individual Income Tax Return 2024) /Author (Sentinel Canary) >>\n"
                   "endobj\n"
                   "trailer\n"
                   "<< /Root 1 0 R >>\n"
                   "%%EOF\n",
        .size = 151
    }
};

bool is_canary_path(const char *path) {
    if (path == NULL) {
        return false;
    }
    return strstr(path, CANARY_DIR_NAME) != NULL;
}

static int write_canary_file(const char *dir_path, const canary_file_t *file, uid_t uid, gid_t gid) {
    char file_path[MAX_PATH_LEN];
    int n = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, file->name);
    if (n < 0 || (size_t)n >= sizeof(file_path)) {
        return -1;
    }

    int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }

    size_t written = 0;
    while (written < file->size) {
        ssize_t ret = write(fd, file->content + written, file->size - written);
        if (ret <= 0) {
            close(fd);
            return -1;
        }
        written += (size_t)ret;
    }

    close(fd);

    if (uid != 0 || gid != 0) {
        if (chown(file_path, uid, gid) != 0) {
            /* non-fatal if running as non-root */
        }
    }

    return 0;
}

int deploy_canaries_to_base(const char *base_path) {
    if (base_path == NULL) {
        return -1;
    }

    char canary_dir[MAX_PATH_LEN];
    int n = snprintf(canary_dir, sizeof(canary_dir), "%s/%s", base_path, CANARY_DIR_NAME);
    if (n < 0 || (size_t)n >= sizeof(canary_dir)) {
        return -1;
    }

    struct stat st;
    uid_t uid = 0;
    gid_t gid = 0;
    if (stat(base_path, &st) == 0) {
        uid = st.st_uid;
        gid = st.st_gid;
    }

    if (mkdir(canary_dir, 0755) != 0 && stat(canary_dir, &st) != 0) {
        return -1;
    }

    if (uid != 0 || gid != 0) {
        if (chown(canary_dir, uid, gid) != 0) {
            /* non-fatal if running as non-root */
        }
    }

    int deployed = 0;
    for (size_t i = 0; i < CANARY_FILE_COUNT; i++) {
        if (write_canary_file(canary_dir, &CANARY_FILES[i], uid, gid) == 0) {
            deployed++;
        }
    }

    return deployed;
}

int deploy_canaries(void) {
    int total_deployed = 0;

    DIR *dir = opendir("/home");
    if (dir != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') {
                continue;
            }

            char user_home[MAX_PATH_LEN];
            int n = snprintf(user_home, sizeof(user_home), "/home/%s", entry->d_name);
            if (n < 0 || (size_t)n >= sizeof(user_home)) {
                continue;
            }

            struct stat st;
            if (stat(user_home, &st) == 0 && S_ISDIR(st.st_mode)) {
                int res = deploy_canaries_to_base(user_home);
                if (res > 0) {
                    total_deployed += res;
                }
            }
        }
        closedir(dir);
    }

    struct stat root_st;
    if (stat("/root", &root_st) == 0 && S_ISDIR(root_st.st_mode)) {
        int res = deploy_canaries_to_base("/root");
        if (res > 0) {
            total_deployed += res;
        }
    }

    return total_deployed;
}
