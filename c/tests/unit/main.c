/* The C API's unit tests: no network, the specification's files only. */
#include "tests.h"

int main(int argc, char** argv)
{
    const test_case* const lists[]
        = { basics_tests, documents_tests, client_tests, crypto_tests, homebrew_tests, discovery_tests };
    const size_t counts[] = { basics_test_count, documents_test_count, client_test_count, crypto_test_count,
        homebrew_test_count, discovery_test_count };
    return test_main(argc, argv, lists, counts, sizeof(lists) / sizeof(lists[0]));
}
