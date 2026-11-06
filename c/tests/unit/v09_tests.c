/* Draft 0.9 through the C API: an app's format, requires and includes,
 * the install decision, the update already inside an installed app, the
 * preferred variant, and what a static library says is missing when the
 * device gives its formats and tokens; spec/vectors' app-requires. Every
 * name is made up. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"
#include "vectors.h"

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define MAX_WORDS 16

/* Space-separated words, copied: `words` points into `buffer`. */
typedef struct word_list
{
    char buffer[512];
    const char* words[MAX_WORDS];
    size_t count;
} word_list;

static void split(word_list* list, const char* text)
{
    memset(list, 0, sizeof(*list));
    strncpy(list->buffer, text, sizeof(list->buffer) - 1);
    char* at = list->buffer;
    while (*at != '\0' && list->count < MAX_WORDS)
    {
        while (*at == ' ')
            *at++ = '\0';
        if (*at == '\0')
            break;
        list->words[list->count++] = at;
        while (*at != '\0' && *at != ' ')
            ++at;
    }
}

/* The apps of a page, as pointers. */
static size_t apps_of(const lantern_apps_page* page, const lantern_app** out, size_t room)
{
    size_t count = lantern_apps_page_get_items_count(page);
    if (count > room)
        count = room;
    for (size_t i = 0; i < count; ++i)
        out[i] = lantern_apps_page_get_items_at(page, i);
    return count;
}

static void install_decisions_of_the_vectors(void)
{
    for (size_t i = 0; i < COUNT(install_cases); ++i)
    {
        const install_case* c       = &install_cases[i];
        lantern_error error         = LANTERN_INIT(lantern_error);
        lantern_apps_page* app_page = NULL;
        lantern_apps_page* held     = NULL;
        REQUIRE_CALL(lantern_read_apps_page(c->app, strlen(c->app), NULL, NULL, &app_page, &error),
            LANTERN_OK, &error);
        REQUIRE_CALL(lantern_read_apps_page(c->installed, strlen(c->installed), NULL, NULL, &held, &error),
            LANTERN_OK, &error);
        const lantern_app* installed[MAX_WORDS];
        const size_t installed_count = apps_of(held, installed, MAX_WORDS);
        const lantern_app* app       = lantern_apps_page_get_items_at(app_page, 0);
        REQUIRE(app != NULL);
        word_list formats, satisfies;
        split(&formats, c->formats);
        split(&satisfies, c->satisfies);
        lantern_install_decision* decision = NULL;
        REQUIRE_CALL(lantern_app_install_decision(app, formats.words, formats.count, satisfies.words,
                         satisfies.count, installed, installed_count, NULL, &decision, &error),
            LANTERN_OK, &error);
        fprintf(stderr, "  vector: %s\n", c->name);
        CHECK((lantern_install_decision_get_verdict(decision) == LANTERN_INSTALL) == c->install);
        CHECK(lantern_install_decision_get_reason_count(decision) == c->reasons);
        /* The reasons say why: the format, a token, the update inside */
        for (size_t r = 0; r < lantern_install_decision_get_reason_count(decision); ++r)
        {
            const lantern_str why = lantern_install_decision_get_reason_at(decision, r);
            CHECK(why.size > 0
                && (strncmp(why.data, "format '", 8) == 0 || strncmp(why.data, "requires '", 10) == 0
                    || STR_EQ(why, "already included by an installed app")));
        }
        CHECK(lantern_app_included(app, installed, installed_count)
            == (!c->install && lantern_install_decision_get_reason_count(decision) == 1
                && STR_EQ(lantern_install_decision_get_reason_at(decision, 0),
                    "already included by an installed app")));
        lantern_install_decision_free(decision);
        lantern_apps_page_free(held);
        lantern_apps_page_free(app_page);
    }
}

static void decisions_of_nothing(void)
{
    CHECK(LANTERN_C_API_VERSION == 7);
    lantern_install_decision* decision = (lantern_install_decision*)&decision;
    lantern_error error                = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_app_install_decision(NULL, NULL, 0, NULL, 0, NULL, 0, NULL, &decision, &error),
        LANTERN_ERROR_USAGE);
    CHECK(decision == NULL);
    CHECK(lantern_install_decision_get_verdict(NULL) == LANTERN_UNAVAILABLE);
    CHECK(lantern_install_decision_get_reason_count(NULL) == 0);
    CHECK(lantern_install_decision_get_reason_at(NULL, 0).size == 0);
    CHECK(!lantern_app_included(NULL, NULL, 0));
    CHECK(lantern_prefer_variant(NULL, 0) == NULL);
    const lantern_app* none[1] = { NULL };
    CHECK(lantern_prefer_variant(none, 0) == NULL);
    lantern_install_decision_free(NULL);
}

static void the_preferred_variant(void)
{
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_apps_page* page = NULL;
    REQUIRE_CALL(lantern_read_apps_page(variants_page, strlen(variants_page), NULL, NULL, &page, &error),
        LANTERN_OK, &error);
    const lantern_app* variants[MAX_WORDS];
    const size_t count = apps_of(page, variants, MAX_WORDS);
    REQUIRE(count > 1);
    const lantern_app* best = lantern_prefer_variant(variants, count);
    REQUIRE(best != NULL);
    CHECK(STR_EQ(lantern_app_get_id(best), variants_preferred));
    /* The order of the list does not matter */
    for (size_t i = 0; i < count / 2; ++i)
    {
        const lantern_app* swap = variants[i];
        variants[i]             = variants[count - 1 - i];
        variants[count - 1 - i] = swap;
    }
    CHECK(lantern_prefer_variant(variants, count) == best);
    lantern_apps_page_free(page);
}

/* A static library of one page, in memory. */
typedef struct memory_library
{
    const char* handshake;
    const char* page;
} memory_library;

static lantern_status read_memory_file(
    void* user, lantern_str path, uint64_t offset, lantern_download_sink* sink, bool* found)
{
    const memory_library* library = user;
    const char* body              = NULL;
    if (STR_EQ(path, "lantern.json"))
        body = library->handshake;
    else if (STR_EQ(path, "v1/apps/switch/pages/1.json"))
        body = library->page;
    *found = body != NULL;
    if (body == NULL)
        return LANTERN_OK;
    const size_t size = strlen(body);
    if (offset > size)
        offset = size;
    lantern_error error = LANTERN_INIT(lantern_error);
    return lantern_download_sink_write(sink, (const uint8_t*)body + offset, size - (size_t)offset, &error);
}

static const char memory_handshake[]
    = "{\"schema\":1,\"uid\":\"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14\",\"name\":\"Lea's library\","
      "\"base\":\".\",\"versions\":[1],\"platforms\":[\"switch\"],\"language\":\"en\","
      "\"account\":{\"state\":\"anonymous\",\"scopes\":[\"library\"]},"
      "\"features\":{\"library\":1,\"titles\":0,\"homebrew\":0,\"cheats\":0,\"changes\":0,\"sections\":0,"
      "\"saves\":0,\"encrypted_saves\":0,\"requests\":0,\"pairing\":0,\"signatures\":0,\"admin\":0,"
      "\"events\":0,\"peers\":0,\"sync\":0},\"limits\":{\"page_size\":10},"
      "\"static\":{\"generated\":\"2026-10-30T18:00:00Z\",\"page_size\":10}}";

static int compare_words(const void* a, const void* b)
{
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

static void what_is_missing_in_the_vectors(void)
{
    memory_library memory                    = { memory_handshake, missing_library_page };
    lantern_static_files_callbacks callbacks = LANTERN_INIT(lantern_static_files_callbacks);
    callbacks.user                           = &memory;
    callbacks.read                           = read_memory_file;
    lantern_static_files* files              = NULL;
    REQUIRE_STATUS(lantern_static_files_create(&callbacks, NULL, &files, NULL), LANTERN_OK);
    lantern_static_library* library = NULL;
    lantern_error error             = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_static_library_open(files, NULL, NULL, &library, &error), LANTERN_OK, &error);
    for (size_t i = 0; i < COUNT(missing_vectors); ++i)
    {
        const missing_vector* v = &missing_vectors[i];
        word_list held, want, formats, satisfies, expected;
        split(&held, v->installed);
        split(&want, v->want);
        split(&formats, v->formats);
        split(&satisfies, v->satisfies);
        split(&expected, v->missing);
        lantern_installed_app installed[MAX_WORDS];
        for (size_t k = 0; k < held.count; ++k)
        {
            char* colon = strchr((char*)held.words[k], ':');
            REQUIRE(colon != NULL);
            *colon                    = '\0';
            installed[k].app_id       = held.words[k];
            installed[k].version_code = strtoull(colon + 1, NULL, 10);
        }
        lantern_missing_request request = LANTERN_INIT(lantern_missing_request);
        request.installed               = installed;
        request.installed_count         = held.count;
        request.want                    = want.words;
        request.want_count              = want.count;
        /* NULL: absent; the words' array, even with no word: present */
        request.formats         = v->has_formats ? formats.words : NULL;
        request.formats_count   = formats.count;
        request.satisfies       = v->has_satisfies ? satisfies.words : NULL;
        request.satisfies_count = satisfies.count;
        lantern_app_list* list  = NULL;
        REQUIRE_CALL(
            lantern_static_library_missing(library, "switch", &request, &list, &error), LANTERN_OK, &error);
        fprintf(stderr, "  vector: %s\n", v->name);
        CHECK(lantern_app_list_count(list) == expected.count);
        const char* got[MAX_WORDS];
        size_t got_count = 0;
        for (size_t k = 0; k < lantern_app_list_count(list) && got_count < MAX_WORDS; ++k)
            got[got_count++] = lantern_app_get_id(lantern_app_list_at(list, k)).data;
        qsort((void*)got, got_count, sizeof(got[0]), compare_words);
        qsort((void*)expected.words, expected.count, sizeof(expected.words[0]), compare_words);
        for (size_t k = 0; k < got_count && k < expected.count; ++k)
            CHECK(strcmp(got[k], expected.words[k]) == 0);
        lantern_app_list_free(list);
    }
    lantern_static_library_free(library);
    lantern_static_files_free(files);
}

static void the_library_lists_requires_and_includes(void)
{
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_apps_page* page = NULL;
    REQUIRE_CALL(
        lantern_read_apps_page(missing_library_page, strlen(missing_library_page), NULL, NULL, &page, &error),
        LANTERN_OK, &error);
    bool found = false;
    for (size_t i = 0; i < lantern_apps_page_get_items_count(page); ++i)
    {
        const lantern_app* app = lantern_apps_page_get_items_at(page, i);
        if (!STR_EQ(lantern_app_get_id(app), "b_lz4"))
            continue;
        found = true;
        CHECK(lantern_app_get_requires_count(app) == 2);
        CHECK(STR_EQ(lantern_app_get_requires_at(app, 0), "fs-compression"));
        CHECK(STR_EQ(lantern_app_get_requires_at(app, 1), "sigpatch"));
        REQUIRE(lantern_app_get_includes_count(app) == 1);
        const lantern_app_include* include = lantern_app_get_includes_at(app, 0);
        uint64_t version                   = 0;
        CHECK(STR_EQ(lantern_app_include_get_app_id(include), "0100ABCD00010800"));
        CHECK(lantern_app_include_get_version_code(include, &version) && version == 196608);
    }
    CHECK(found);
    lantern_apps_page_free(page);
}

const test_case v09_tests[] = {
    { "v09: the install decision of the vectors (app-requires.json)", install_decisions_of_the_vectors },
    { "v09: an install decision of nothing", decisions_of_nothing },
    { "v09: the preferred variant (Annex B.15)", the_preferred_variant },
    { "v09: what is missing for a device's formats and tokens, in a static library",
        what_is_missing_in_the_vectors },
    { "v09: requires and includes of a listed app", the_library_lists_requires_and_includes },
};
const size_t v09_test_count = sizeof(v09_tests) / sizeof(v09_tests[0]);
