#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

double calculate_entropy(const uint8_t *data, size_t len);
double calculate_entropy_from_histogram(const uint32_t counts[256], size_t total);
bool is_high_entropy(double entropy);

#endif
