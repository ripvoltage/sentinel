#include "sentinel.h"
#include "entropy.h"
#include "canaries.h"
#include "heuristics.h"
#include "proc_inspector.h"
#include "defense.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_test_count = 0;
static int g_passed_count = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_test_count++; \
    if (cond) { \
        g_passed_count++; \
        printf("[PASS] %s\n", msg); \
    } else { \
        fprintf(stderr, "[FAIL] %s (Line %d)\n", msg, __LINE__); \
        assert(cond); \
    } \
} while (0)

static void test_entropy(void) {
    printf("--- Testing Shannon Entropy ---\n");

    uint8_t zero_data[1024];
    memset(zero_data, 0x55, sizeof(zero_data));
    double ent_zero = calculate_entropy(zero_data, sizeof(zero_data));
    TEST_ASSERT(fabs(ent_zero) < 1e-9, "Entropy of uniform bytes is 0.0");
    TEST_ASSERT(!is_high_entropy(ent_zero), "Uniform bytes not high entropy");

    uint8_t uniform_data[25600];
    for (size_t i = 0; i < sizeof(uniform_data); i++) {
        uniform_data[i] = (uint8_t)(i % 256);
    }
    double ent_uniform = calculate_entropy(uniform_data, sizeof(uniform_data));
    TEST_ASSERT(fabs(ent_uniform - 8.0) < 1e-9, "Entropy of perfectly distributed bytes is 8.0");
    TEST_ASSERT(is_high_entropy(ent_uniform), "8.0 entropy is high entropy");

    uint8_t prng_data[16384];
    uint64_t state = 0x853c49e6748fea9bULL;
    for (size_t i = 0; i < sizeof(prng_data); i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        prng_data[i] = (uint8_t)(state >> 33);
    }
    double ent_prng = calculate_entropy(prng_data, sizeof(prng_data));
    TEST_ASSERT(ent_prng >= 7.92, "PRNG byte stream entropy >= 7.92");
    TEST_ASSERT(is_high_entropy(ent_prng), "PRNG stream classified as high entropy");

    const char *text = "The quick brown fox jumps over the lazy dog. Natural language ASCII text with moderate entropy.";
    double ent_text = calculate_entropy((const uint8_t *)text, strlen(text));
    TEST_ASSERT(ent_text >= 3.0 && ent_text <= 6.0, "ASCII text entropy between 3.0 and 6.0");
    TEST_ASSERT(!is_high_entropy(ent_text), "ASCII text not classified as high entropy");

    TEST_ASSERT(calculate_entropy(NULL, 0) == 0.0, "Empty buffer entropy is 0.0");
}

static void test_canaries(void) {
    printf("--- Testing Canaries ---\n");

    TEST_ASSERT(is_canary_path("/home/user/.canary_sentinel/passwords.txt"), "Standard canary path matches");
    TEST_ASSERT(is_canary_path("/root/.canary_sentinel/bitcoin_wallet.dat"), "Root canary path matches");
    TEST_ASSERT(is_canary_path(".canary_sentinel/test"), "Relative canary path matches");
    TEST_ASSERT(!is_canary_path("/home/user/Documents/passwords.txt"), "Regular file path does not match");
    TEST_ASSERT(!is_canary_path(NULL), "NULL path does not match");

    char temp_dir[128];
    snprintf(temp_dir, sizeof(temp_dir), "/tmp/sentinel_test_canary_%d", getpid());
    mkdir(temp_dir, 0755);

    int deployed = deploy_canaries_to_base(temp_dir);
    TEST_ASSERT(deployed == CANARY_FILE_COUNT, "Deployed all 6 canary decoy files");

    char check_file[256];
    snprintf(check_file, sizeof(check_file), "%s/%s/passwords.txt", temp_dir, CANARY_DIR_NAME);
    struct stat st;
    TEST_ASSERT(stat(check_file, &st) == 0 && st.st_size > 0, "passwords.txt exists and non-empty");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", temp_dir);
    if (system(cmd) != 0) {
        /* cleanup */
    }
}

static void test_heuristics(void) {
    printf("--- Testing Heuristics Engine ---\n");

    heuristics_engine_t engine;
    heuristics_init(&engine);

    verdict_t v1 = heuristics_evaluate(&engine, 1234, "/home/user/test.txt", NULL, EVENT_VFS_WRITE, 4.5);
    TEST_ASSERT(!v1.is_suspicious && v1.score == 0, "Normal write payload is benign");

    verdict_t v2 = heuristics_evaluate(&engine, 1234, "/home/user/test.txt", NULL, EVENT_VFS_WRITE, 7.95);
    TEST_ASSERT(v2.is_suspicious && v2.score == 40, "High entropy write scores 40");

    heuristics_init(&engine);
    for (int i = 0; i < 50; i++) {
        heuristics_evaluate(&engine, 2345, "/home/user/file.txt", NULL, EVENT_VFS_WRITE, 4.0);
    }
    verdict_t v_burst = heuristics_evaluate(&engine, 2345, "/home/user/file.txt", NULL, EVENT_VFS_WRITE, 4.0);
    TEST_ASSERT(v_burst.is_suspicious && v_burst.score == 30, "Burst I/O >50 ops/100ms scores 30");

    heuristics_init(&engine);
    verdict_t v_rename = heuristics_evaluate(&engine, 3456, "/home/user/pic.jpg",
                                            "/home/user/pic.jpg.encrypted", EVENT_RENAME, 5.0);
    TEST_ASSERT(v_rename.is_suspicious && v_rename.score == 20, "Suspicious rename .encrypted scores 20");

    heuristics_init(&engine);
    heuristics_evaluate(&engine, 4567, "/home/user/data.bin", NULL, EVENT_VFS_WRITE, 7.95);
    verdict_t v_unlink = heuristics_evaluate(&engine, 4567, "/home/user/data.bin", NULL, EVENT_UNLINK, 0.0);
    TEST_ASSERT(v_unlink.is_suspicious && v_unlink.score == 10, "Unlink after high entropy scores 10");

    heuristics_init(&engine);
    heuristics_cleanup_stale(&engine, 0);
    TEST_ASSERT(engine.active_count == 0, "Stale records cleanup verified");
}

static void test_proc_inspector(void) {
    printf("--- Testing Process Inspector ---\n");

    process_info_t self_info;
    int res = proc_inspect((uint32_t)getpid(), &self_info);
    TEST_ASSERT(res == 0, "proc_inspect succeeds for self PID");
    TEST_ASSERT(self_info.pid == (uint32_t)getpid(), "self PID matches");
    TEST_ASSERT(strlen(self_info.comm) > 0, "comm is non-empty");

    process_info_t trusted_info;
    memset(&trusted_info, 0, sizeof(trusted_info));
    trusted_info.pid = 9999;
    trusted_info.parent_pid = 1;
    safe_strncpy(trusted_info.comm, "rsync", sizeof(trusted_info.comm));
    safe_strncpy(trusted_info.exe, "/usr/bin/rsync", sizeof(trusted_info.exe));
    TEST_ASSERT(is_trusted_process(&trusted_info), "rsync matches trusted binary whitelist");

    process_info_t untrusted_info;
    memset(&untrusted_info, 0, sizeof(untrusted_info));
    untrusted_info.pid = 9998;
    untrusted_info.parent_pid = 1;
    safe_strncpy(untrusted_info.comm, "evil_payload", sizeof(untrusted_info.comm));
    safe_strncpy(untrusted_info.exe, "/tmp/evil_payload", sizeof(untrusted_info.exe));
    TEST_ASSERT(!is_trusted_process(&untrusted_info), "unknown payload is not trusted");
}

static void test_defense(void) {
    printf("--- Testing Defense Subsystem ---\n");

    uint32_t self_pid = get_daemon_pid();
    TEST_ASSERT(neutralize_threat(self_pid) != 0, "Refuses to neutralize self PID");
    TEST_ASSERT(neutralize_threat(1) != 0, "Refuses to neutralize init PID (1)");
    TEST_ASSERT(neutralize_threat(0) != 0, "Refuses to neutralize PID 0");
}

int main(void) {
    printf("=========================================\n");
    printf("  Sentinel Anti-Ransomware Unit Tests\n");
    printf("=========================================\n");

    test_entropy();
    test_canaries();
    test_heuristics();
    test_proc_inspector();
    test_defense();

    printf("=========================================\n");
    printf("Summary: %d / %d tests passed\n", g_passed_count, g_test_count);
    printf("=========================================\n");

    return (g_passed_count == g_test_count) ? 0 : 1;
}
