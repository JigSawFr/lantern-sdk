/* The documents through their accessors, and the `schema` rule (SPEC.md
 * § 3.2) for every reader: absent, newer, and an unknown member. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"

#define READER(name)                                                                                         \
    static lantern_status try_##name(const char* text, size_t size, bool* present, lantern_error* error)     \
    {                                                                                                        \
        lantern_##name* document    = NULL;                                                                  \
        const lantern_status status = lantern_read_##name(text, size, NULL, NULL, &document, error);         \
        *present                    = document != NULL;                                                      \
        lantern_##name##_free(document);                                                                     \
        return status;                                                                                       \
    }

/* lantern_read_<x> gives a lantern_<x>, but for two names */
typedef lantern_cheat_sets lantern_cheat_sets_doc;
READER(handshake)
READER(discovery_reply)
READER(apps_page)
READER(changes)
READER(sections)
READER(title)
READER(titles)
READER(title_changes)
READER(homebrew)
READER(homebrew_page)
READER(saves)
READER(save)
READER(cheat_sets)
READER(cheat_set)
READER(problem)
READER(pairing_code)
READER(pairing_token)
READER(upload_session)
READER(title_requests)
READER(title_request)
READER(admin_users)
READER(admin_user)
READER(admin_devices)
READER(admin_pairings)
READER(invitations)
READER(invitation)
READER(peer_reply)
READER(grant)
READER(sync_state)
READER(sync_collection)

typedef lantern_status (*reader)(const char* text, size_t size, bool* present, lantern_error* error);

static const struct
{
    const char* file;
    reader read;
} documents[] = {
    { "handshake.json", try_handshake },
    { "discovery.json", try_discovery_reply },
    { "apps.json", try_apps_page },
    { "changes.json", try_changes },
    { "sections.json", try_sections },
    { "title.json", try_title },
    { "titles.json", try_titles },
    { "title-changes.json", try_title_changes },
    { "homebrew.json", try_homebrew },
    { "homebrew-page.json", try_homebrew_page },
    { "saves.json", try_saves },
    { "save.json", try_save },
    { "cheats.json", try_cheat_sets },
    { "cheat.json", try_cheat_set },
    { "problem.json", try_problem },
    { "pairing-code.json", try_pairing_code },
    { "pairing-token.json", try_pairing_token },
    { "upload.json", try_upload_session },
    { "requests.json", try_title_requests },
    { "request.json", try_title_request },
    { "admin-users.json", try_admin_users },
    { "admin-user.json", try_admin_user },
    { "admin-devices.json", try_admin_devices },
    { "admin-pairings.json", try_admin_pairings },
    { "invitations.json", try_invitations },
    { "invitation.json", try_invitation },
    { "discovery-peer.json", try_peer_reply },
    { "grant.json", try_grant },
    { "sync.json", try_sync_state },
    { "sync-collection.json", try_sync_collection },
};

static char* example(const char* file, size_t* size)
{
    char path[256];
    snprintf(path, sizeof(path), "examples/v1/%s", file);
    return spec_file(path, size);
}

/* `"schema": 1` in the text, or NULL. */
static char* schema_member(char* text)
{
    char* at = strstr(text, "\"schema\": 1");
    return at != NULL ? at : strstr(text, "\"schema\":1");
}

static void every_reader_and_the_schema_rule(void)
{
    for (size_t i = 0; i < sizeof(documents) / sizeof(documents[0]); ++i)
    {
        size_t size = 0;
        char* text  = example(documents[i].file, &size);
        REQUIRE(text != NULL);
        lantern_error error = LANTERN_INIT(lantern_error);
        bool present        = false;
        if (!CHECK_CALL(documents[i].read(text, size, &present, &error), LANTERN_OK, &error))
            fprintf(stderr, "    in %s\n", documents[i].file);
        CHECK(present);

        char* schema = schema_member(text);
        REQUIRE(schema != NULL);
        char* digit = strchr(schema, '1');

        /* Newer: absent, no error, nothing given */
        *digit  = '2';
        present = true;
        if (!CHECK_CALL(documents[i].read(text, size, &present, &error), LANTERN_ABSENT, &error))
            fprintf(stderr, "    in %s\n", documents[i].file);
        CHECK(!present);
        *digit = '1';

        /* Without `schema`: § 3.2 is broken, an error */
        schema[6] = 'X'; /* "schemX" */
        CHECK_STATUS(documents[i].read(text, size, &present, &error), LANTERN_ERROR_INVALID_RESPONSE);
        CHECK(!present);
        CHECK(error.status == LANTERN_ERROR_INVALID_RESPONSE);
        schema[6] = 'a';

        /* A member of a later version, at the top and nested: skipped */
        const char* later  = "\"a_later_member\":{\"nested\":[1,{\"deep\":true}],\"text\":\"Noor\"},";
        const size_t extra = strlen(later);
        char* longer       = malloc(size + extra + 1);
        REQUIRE(longer != NULL);
        const char* brace   = strchr(text, '{');
        const size_t before = (size_t)(brace - text) + 1;
        memcpy(longer, text, before);
        memcpy(longer + before, later, extra);
        memcpy(longer + before + extra, text + before, size - before + 1);
        if (!CHECK_CALL(documents[i].read(longer, size + extra, &present, &error), LANTERN_OK, &error))
            fprintf(stderr, "    in %s\n", documents[i].file);
        CHECK(present);
        free(longer);
        free(text);
    }
}

static void limits_and_bad_input(void)
{
    size_t size = 0;
    char* text  = example("titles.json", &size);
    REQUIRE(text != NULL);
    lantern_limits limits  = LANTERN_INIT(lantern_limits);
    limits.max_document    = 100;
    lantern_titles* titles = NULL;
    lantern_error error    = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_read_titles(text, size, &limits, NULL, &titles, &error), LANTERN_ERROR_LIMIT);
    CHECK(titles == NULL);
    limits.max_document = 0;
    limits.max_memory   = 64;
    CHECK_STATUS(lantern_read_titles(text, size, &limits, NULL, &titles, &error), LANTERN_ERROR_MEMORY);
    CHECK_STATUS(lantern_read_titles("{\"schema\":1,\"titles\":[", 23, NULL, NULL, &titles, &error),
        LANTERN_ERROR_INVALID_RESPONSE);
    CHECK_STATUS(lantern_read_titles(NULL, 4, NULL, NULL, &titles, &error), LANTERN_ERROR_USAGE);
    CHECK_STATUS(lantern_read_titles(text, size, NULL, NULL, NULL, &error), LANTERN_ERROR_USAGE);
    /* Not NUL-terminated: the size decides, here before the last brace */
    const size_t cut = (size_t)(strrchr(text, '}') - text);
    CHECK_STATUS(lantern_read_titles(text, cut, NULL, NULL, &titles, &error), LANTERN_ERROR_INVALID_RESPONSE);
    free(text);
}

static void handshake_accessors(void)
{
    size_t size = 0;
    char* text  = example("handshake.json", &size);
    REQUIRE(text != NULL);
    lantern_handshake* shake = NULL;
    REQUIRE_STATUS(lantern_read_handshake(text, size, NULL, NULL, &shake, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_handshake_get_uid(shake), "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14"));
    CHECK(STR_EQ(lantern_handshake_get_base(shake), "/api/lantern"));
    CHECK(STR_EQ(lantern_handshake_software_get_name(lantern_handshake_get_software(shake)), "ExampleShelf"));
    CHECK(lantern_handshake_get_versions_count(shake) == 1);
    uint64_t version = 0;
    CHECK(lantern_handshake_get_versions_at(shake, 0, &version) && version == 1);
    CHECK(!lantern_handshake_get_versions_at(shake, 1, &version));
    CHECK(lantern_handshake_get_platforms_count(shake) == 2);
    CHECK(STR_EQ(lantern_handshake_get_platforms_at(shake, 1), "android"));
    CHECK(STR_EQ(lantern_handshake_get_platforms_at(shake, 2), ""));
    const lantern_handshake_account* account = lantern_handshake_get_account(shake);
    REQUIRE(account != NULL);
    CHECK(STR_EQ(lantern_handshake_account_get_name(account), "lea"));
    CHECK(lantern_handshake_account_get_scopes_count(account) == 2);
    bool bound = false;
    CHECK(lantern_handshake_account_get_bound(account, &bound) && bound);
    uint64_t age = 0;
    CHECK(lantern_rating_cap_get_age(lantern_handshake_account_get_rating_cap(account), &age) && age == 12);
    /* A member the cap does not have: absent, and the pointer of an absent object is NULL */
    CHECK(STR_EQ(lantern_rating_cap_get_system(lantern_handshake_account_get_rating_cap(account)), ""));
    uint64_t schema = 0;
    CHECK(lantern_handshake_features_get_library(lantern_handshake_get_features(shake), &schema)
        && schema == 1);
    uint64_t page_size = 0;
    CHECK(lantern_handshake_limits_get_page_size(lantern_handshake_get_limits(shake), &page_size)
        && page_size == 500);
    uint64_t skew = 0;
    CHECK(lantern_handshake_auth_get_skew(lantern_handshake_get_auth(shake), &skew) && skew == 300);
    lantern_handshake_free(shake);
    free(text);
}

static void library_accessors(void)
{
    size_t size = 0;
    char* text  = example("apps.json", &size);
    REQUIRE(text != NULL);
    lantern_apps_page* page = NULL;
    REQUIRE_STATUS(lantern_read_apps_page(text, size, NULL, NULL, &page, NULL), LANTERN_OK);
    REQUIRE(lantern_apps_page_get_items_count(page) >= 2);
    const lantern_app* app = lantern_apps_page_get_items_at(page, 0);
    CHECK(STR_EQ(lantern_app_get_name(app), "Frostline Tales"));
    CHECK(STR_EQ(lantern_app_get_file(app), "/api/lantern/v1/files/f_Pq02Rt"));
    uint64_t value = 0;
    CHECK(lantern_app_get_size(app, &value) && value == 5368709120ULL);
    CHECK(lantern_app_get_installed_size(app, &value) && value == 10737418240ULL);
    uint8_t digest[32];
    char hex[65];
    CHECK(lantern_app_get_sha256(app, digest));
    lantern_digest_to_hex(digest, hex);
    CHECK(strcmp(hex, "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817") == 0);
    CHECK(lantern_apps_page_get_items_at(page, 1000) == NULL);
    lantern_apps_page_free(page);
    free(text);

    text = example("title.json", &size);
    REQUIRE(text != NULL);
    lantern_title* title = NULL;
    REQUIRE_STATUS(lantern_read_title(text, size, NULL, NULL, &title, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_title_get_name(title), "Frostline Tales"));
    const lantern_title_players* players = lantern_title_get_players(title);
    REQUIRE(players != NULL);
    CHECK(lantern_title_players_get_max(players, &value) && value == 4);
    CHECK(lantern_title_get_ratings_count(title) >= 1);
    CHECK(STR_EQ(lantern_rating_get_system(lantern_title_get_ratings_at(title, 0)), "PEGI"));
    lantern_title_free(title);
    free(text);

    text = example("problem.json", &size);
    REQUIRE(text != NULL);
    lantern_problem* problem = NULL;
    REQUIRE_STATUS(lantern_read_problem(text, size, NULL, NULL, &problem, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_problem_get_code(problem), "account_frozen"));
    CHECK(lantern_problem_get_status(problem, &value) && value == 403);
    lantern_problem_free(problem);
    free(text);
}

static void homebrew_accessors(void)
{
    size_t size = 0;
    char* text  = example("homebrew.json", &size);
    REQUIRE(text != NULL);
    lantern_homebrew* entry = NULL;
    REQUIRE_STATUS(lantern_read_homebrew(text, size, NULL, NULL, &entry, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_homebrew_get_id(entry), "org.example.frostline"));
    CHECK(STR_EQ(lantern_homebrew_get_author(entry), "Noor"));
    const lantern_requires* requires_ = lantern_homebrew_get_requires(entry);
    REQUIRE(requires_ != NULL);
    /* requires.min is kept raw: each member's key and JSON */
    const lantern_requires_min* min = lantern_requires_get_min(requires_);
    REQUIRE(min != NULL);
    REQUIRE(lantern_requires_min_get_members_count(min) == 1);
    lantern_str key;
    lantern_str json;
    CHECK(lantern_requires_min_get_members_at(min, 0, &key, &json));
    CHECK(STR_EQ(key, "atmosphere"));
    CHECK(STR_EQ(json, "\"1.7.0\""));
    CHECK(!lantern_requires_min_get_members_at(min, 1, &key, &json));
    const lantern_package* package = lantern_homebrew_get_package(entry);
    REQUIRE(package != NULL);
    CHECK(lantern_package_get_manifest_count(package) >= 1);
    CHECK(STR_EQ(lantern_image_get_url(lantern_homebrew_get_icon(entry)),
        "https://media.example.org/frostline/icon.jpg"));
    lantern_homebrew_free(entry);
    free(text);
}

const test_case documents_tests[] = {
    { "documents: every reader, newer, absent, unknown members", every_reader_and_the_schema_rule },
    { "documents: limits and bad input", limits_and_bad_input },
    { "documents: the handshake's accessors", handshake_accessors },
    { "documents: apps, a title, a problem", library_accessors },
    { "documents: a homebrew entry, requires.min raw", homebrew_accessors },
};
const size_t documents_test_count = sizeof(documents_tests) / sizeof(documents_tests[0]);
