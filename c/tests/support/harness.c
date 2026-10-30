#include "harness.h"

#include <stdlib.h>

static bool current_failed;
static int failures;

void test_fail(const char* file, int line, const char* what)
{
    fprintf(stderr, "  %s:%d: failed: %s\n", file, line, what);
    current_failed = true;
    ++failures;
}

bool test_failed(void)
{
    return current_failed;
}

bool test_str_eq(lantern_str str, const char* literal)
{
    const size_t size = strlen(literal);
    /* Every lantern_str is NUL-terminated as well */
    return str.data != NULL && str.size == size && memcmp(str.data, literal, size) == 0
        && str.data[size] == '\0';
}

bool test_check_status(lantern_status got, lantern_status expected, const char* file, int line,
    const char* what, const lantern_error* error)
{
    if (got == expected)
        return true;
    fprintf(stderr, "  %s:%d: %s gave %s (%d), not %s (%d)", file, line, what, lantern_status_name(got),
        (int)got, lantern_status_name(expected), (int)expected);
    if (error != NULL)
        fprintf(stderr, ": %s [http %u, %s]", error->detail, (unsigned)error->http_status, error->code_text);
    fprintf(stderr, "\n");
    current_failed = true;
    ++failures;
    return false;
}

int test_main(int argc, char** argv, const test_case* const* lists, const size_t* counts, size_t list_count)
{
    const char* filter = argc > 1 ? argv[1] : NULL;
    int run            = 0;
    int failed         = 0;
    for (size_t l = 0; l < list_count; ++l)
    {
        for (size_t i = 0; i < counts[l]; ++i)
        {
            const test_case* test = &lists[l][i];
            if (filter != NULL && strstr(test->name, filter) == NULL)
                continue;
            current_failed = false;
            fprintf(stderr, "[ RUN  ] %s\n", test->name);
            test->run();
            ++run;
            if (current_failed)
                ++failed;
            fprintf(stderr, "[ %s ] %s\n", current_failed ? "FAIL" : " OK ", test->name);
        }
    }
    fprintf(stderr, "%d test cases, %d failed, %d checks failed\n", run, failed, failures);
    return failed == 0 && run > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
