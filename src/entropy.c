#include "entropy.h"
#include "sentinel.h"
#include <math.h>

double calculate_entropy_from_histogram(const uint32_t counts[256], size_t total) {
    if (total == 0) {
        return 0.0;
    }

    double total_f = (double)total;
    double entropy = 0.0;

    for (size_t i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / total_f;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

double calculate_entropy(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) {
        return 0.0;
    }

    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    return calculate_entropy_from_histogram(counts, len);
}

bool is_high_entropy(double entropy) {
    return entropy >= ENTROPY_THRESHOLD;
}
