/*
 * A small test harness in C11: CHECK records a failure and goes on, REQUIRE
 * ends the test case. Each test file lists its cases; main() runs them all,
 * or those whose name contains argv[1].
 */
#ifndef LANTERN_TEST_HARNESS_H
#define LANTERN_TEST_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <lantern/lantern.h>

typedef void (*test_function)(void);

typedef struct test_case
{
    const char* name;
    test_function run;
} test_case;

/* Records a failure of the running case. */
void test_fail(const char* file, int line, const char* what);
/* Whether the running case failed. */
bool test_failed(void);
/* Runs every case of every list; 0 when all passed. */
int test_main(int argc, char** argv, const test_case* const* lists, const size_t* counts, size_t list_count);

#define CHECK(condition)                                                                                     \
    do                                                                                                       \
    {                                                                                                        \
        if (!(condition))                                                                                    \
            test_fail(__FILE__, __LINE__, #condition);                                                       \
    } while (0)

#define REQUIRE(condition)                                                                                   \
    do                                                                                                       \
    {                                                                                                        \
        if (!(condition))                                                                                    \
        {                                                                                                    \
            test_fail(__FILE__, __LINE__, #condition);                                                       \
            return;                                                                                          \
        }                                                                                                    \
    } while (0)

/* A lantern_str and a literal. */
#define STR_EQ(str, literal) test_str_eq((str), (literal))
bool test_str_eq(lantern_str str, const char* literal);

/* A status, and the error's detail when it is not the one expected. */
#define CHECK_STATUS(expression, expected)                                                                   \
    test_check_status((expression), (expected), __FILE__, __LINE__, #expression, NULL)
#define REQUIRE_STATUS(expression, expected)                                                                 \
    do                                                                                                       \
    {                                                                                                        \
        if (!test_check_status((expression), (expected), __FILE__, __LINE__, #expression, NULL))             \
            return;                                                                                          \
    } while (0)
/* The same, printing `error` when it differs. */
#define CHECK_CALL(expression, expected, error)                                                              \
    test_check_status((expression), (expected), __FILE__, __LINE__, #expression, (error))
#define REQUIRE_CALL(expression, expected, error)                                                            \
    do                                                                                                       \
    {                                                                                                        \
        if (!test_check_status((expression), (expected), __FILE__, __LINE__, #expression, (error)))          \
            return;                                                                                          \
    } while (0)
bool test_check_status(lantern_status got, lantern_status expected, const char* file, int line,
    const char* what, const lantern_error* error);

#endif
