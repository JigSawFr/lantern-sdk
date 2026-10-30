/* The unit tests' lists, one per file. */
#ifndef LANTERN_UNIT_TESTS_H
#define LANTERN_UNIT_TESTS_H

#include <stddef.h>

#include "harness.h"

extern const test_case basics_tests[];
extern const size_t basics_test_count;
extern const test_case documents_tests[];
extern const size_t documents_test_count;
extern const test_case client_tests[];
extern const size_t client_test_count;
extern const test_case crypto_tests[];
extern const size_t crypto_test_count;
extern const test_case homebrew_tests[];
extern const size_t homebrew_test_count;
extern const test_case discovery_tests[];
extern const size_t discovery_test_count;
extern const test_case v05_tests[];
extern const size_t v05_test_count;

#endif
