/* Homebrew (SPEC.md § 8): packages, plans, signatures, pins, a port's data,
 * requirements, and paths against spec/vectors/paths.json. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"
#include "vectors.h"

static lantern_homebrew_page* read_page(char** text)
{
    size_t size = 0;
    *text       = spec_file("examples/v1/homebrew-page.json", &size);
    if (*text == NULL)
        return NULL;
    lantern_homebrew_page* page = NULL;
    if (lantern_read_homebrew_page(*text, size, NULL, NULL, &page, NULL) != LANTERN_OK)
        return NULL;
    return page;
}

static const lantern_homebrew* find(const lantern_homebrew_page* page, const char* id, const char* platform)
{
    for (size_t i = 0; i < lantern_homebrew_page_get_items_count(page); ++i)
    {
        const lantern_homebrew* entry = lantern_homebrew_page_get_items_at(page, i);
        if (STR_EQ(lantern_homebrew_get_id(entry), id)
            && STR_EQ(lantern_homebrew_get_platform(entry), platform))
            return entry;
    }
    return NULL;
}

static void a_package_planned_and_verified(void)
{
    size_t size = 0;
    char* text  = spec_file("examples/v1/homebrew.json", &size);
    REQUIRE(text != NULL);
    lantern_homebrew* entry = NULL;
    REQUIRE_STATUS(lantern_read_homebrew(text, size, NULL, NULL, &entry, NULL), LANTERN_OK);
    lantern_error error            = LANTERN_INIT(lantern_error);
    const lantern_package* package = NULL;
    REQUIRE_CALL(lantern_pick_package(entry, NULL, &package, &error), LANTERN_OK, &error);
    CHECK(package == lantern_homebrew_get_package(entry));

    lantern_install_plan* plan = NULL;
    REQUIRE_CALL(lantern_plan_install(entry, package, NULL, &plan, &error), LANTERN_OK, &error);
    CHECK(lantern_install_plan_get_placement(plan) == LANTERN_PLACEMENT_ARCHIVE);
    CHECK(lantern_install_plan_get_file_count(plan) == 2);
    CHECK(lantern_install_plan_get_consent_count(plan) == 0);
    CHECK(!lantern_install_plan_get_ask_before_installer(plan));
    lantern_planned_file file = LANTERN_INIT(lantern_planned_file);
    REQUIRE(lantern_install_plan_get_file(plan, 0, &file));
    CHECK(STR_EQ(file.path, "/config/org.example.frostline/settings.ini"));
    CHECK(file.size == 96);
    CHECK(!file.needs_consent);
    CHECK(!lantern_install_plan_get_file(plan, 2, &file));
    lantern_install_plan_free(plan);

    uint8_t digest[32];
    uint8_t expected[32];
    lantern_manifest_digest(package, digest);
    CHECK(lantern_package_get_manifest_sha256(package, expected));
    CHECK(memcmp(digest, expected, 32) == 0);

    lantern_package_signature signature = LANTERN_INIT(lantern_package_signature);
    REQUIRE_CALL(lantern_verify_package_signature(entry, package, &signature, &error), LANTERN_OK, &error);
    CHECK(signature.is_signed);

    lantern_strings* removed = NULL;
    REQUIRE_CALL(lantern_files_to_remove(package, package, NULL, &removed, &error), LANTERN_OK, &error);
    CHECK(lantern_strings_count(removed) == 0);
    lantern_strings_free(removed);

    const lantern_installed_system_id installed[] = { { "org.example.other", "com.example.other" } };
    CHECK_CALL(lantern_check_system_id(entry, installed, 1, &error), LANTERN_OK, &error);
    lantern_homebrew_free(entry);

    /* A signature over other bytes: refused */
    char* forged = strstr(text, "\"build\": 10400");
    REQUIRE(forged != NULL);
    forged[13] = '1';
    REQUIRE_STATUS(lantern_read_homebrew(text, size, NULL, NULL, &entry, NULL), LANTERN_OK);
    CHECK_STATUS(
        lantern_verify_package_signature(entry, lantern_homebrew_get_package(entry), &signature, &error),
        LANTERN_ERROR_SIGNATURE);
    lantern_homebrew_free(entry);
    free(text);
}

static void packages_per_architecture(void)
{
    char* text                  = NULL;
    lantern_homebrew_page* page = read_page(&text);
    REQUIRE(page != NULL);
    const lantern_homebrew* harbor = find(page, "org.example.harborlights", "linux");
    REQUIRE(harbor != NULL);
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_CALL(lantern_check_port(harbor, &error), LANTERN_OK, &error);
    const lantern_package* package = NULL;
    REQUIRE_CALL(lantern_pick_package(harbor, "aarch64", &package, &error), LANTERN_OK, &error);
    bool found = false;
    for (size_t i = 0; i < lantern_package_get_arch_count(package); ++i)
        found = found || STR_EQ(lantern_package_get_arch_at(package, i), "aarch64");
    CHECK(found);
    CHECK_STATUS(lantern_pick_package(harbor, "x86", &package, &error), LANTERN_ERROR_UNSUPPORTED);
    CHECK(package == NULL);
    lantern_homebrew_page_free(page);
    free(text);
}

/* A pin store in memory: one id. */
typedef struct pins
{
    bool has;
    lantern_pin pin;
} pins;

static lantern_status pin_load(
    void* user, lantern_str platform, lantern_str id, lantern_pin* out, bool* found)
{
    (void)platform;
    (void)id;
    pins* kept = user;
    *found     = kept->has;
    if (kept->has)
        *out = kept->pin;
    return LANTERN_OK;
}

static lantern_status pin_store(void* user, lantern_str platform, lantern_str id, const lantern_pin* pin)
{
    CHECK(STR_EQ(platform, "switch"));
    CHECK(STR_EQ(id, "org.example.frostline"));
    pins* kept = user;
    kept->has  = true;
    kept->pin  = *pin;
    return LANTERN_OK;
}

static void pins_of_homebrew_keys(void)
{
    pins kept                       = { 0 };
    lantern_pin_callbacks callbacks = LANTERN_INIT(lantern_pin_callbacks);
    callbacks.user                  = &kept;
    callbacks.load                  = pin_load;
    callbacks.store                 = pin_store;
    lantern_pin_store* store        = NULL;
    REQUIRE_STATUS(lantern_pin_store_create(&callbacks, NULL, &store, NULL), LANTERN_OK);
    lantern_package_signature offered = LANTERN_INIT(lantern_package_signature);
    offered.is_signed                 = true;
    memset(offered.public_key, 0x11, 32);
    lantern_pin_check check = LANTERN_INIT(lantern_pin_check);
    lantern_error error     = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_check_pin(store, "switch", "org.example.frostline", &offered, &check, &error),
        LANTERN_OK, &error);
    CHECK(check.verdict == LANTERN_PIN_FIRST_INSTALL);
    CHECK(!check.needs_consent);
    REQUIRE_CALL(lantern_commit_pin(store, "switch", "org.example.frostline", &check, false, &error),
        LANTERN_OK, &error);
    CHECK(kept.has && kept.pin.is_signed && kept.pin.public_key[0] == 0x11);
    REQUIRE_CALL(lantern_check_pin(store, "switch", "org.example.frostline", &offered, &check, &error),
        LANTERN_OK, &error);
    CHECK(check.verdict == LANTERN_PIN_SAME);

    /* Another key: refused unless the user accepts */
    memset(offered.public_key, 0x22, 32);
    REQUIRE_CALL(lantern_check_pin(store, "switch", "org.example.frostline", &offered, &check, &error),
        LANTERN_OK, &error);
    CHECK(check.verdict == LANTERN_PIN_KEY_CHANGED);
    CHECK(check.needs_consent);
    CHECK(check.has_pinned && check.pinned.public_key[0] == 0x11);
    CHECK_STATUS(lantern_commit_pin(store, "switch", "org.example.frostline", &check, false, &error),
        LANTERN_ERROR_SIGNATURE);
    CHECK(kept.pin.public_key[0] == 0x11);
    REQUIRE_CALL(lantern_commit_pin(store, "switch", "org.example.frostline", &check, true, &error),
        LANTERN_OK, &error);
    CHECK(kept.pin.public_key[0] == 0x22);

    /* Unsigned after signed */
    offered.is_signed = false;
    REQUIRE_CALL(lantern_check_pin(store, "switch", "org.example.frostline", &offered, &check, &error),
        LANTERN_OK, &error);
    CHECK(check.verdict == LANTERN_PIN_SIGNATURE_REMOVED);
    lantern_pin_store_free(store);
}

/* The device's storage, as a port's data probe sees it. */
typedef struct sd_card
{
    bool has_pak;
} sd_card;

static lantern_status probe_size(void* user, lantern_str path, uint64_t* size, bool* present)
{
    sd_card* sd = user;
    *present    = sd->has_pak && strcmp(path.data, "/switch/harborlights/data/HARBOR.PAK") == 0;
    *size       = *present ? 214748364U : 0;
    return LANTERN_OK;
}

static lantern_status probe_sha256(void* user, lantern_str path, uint8_t out[32])
{
    (void)user;
    (void)path;
    /* The 1.0 release's, as `accept` lists it */
    return hex_to_bytes("9fed1136876db26e1ad23fc7f670877229ef6175a0ebb578156745f8e775f95e", out, 32)
        ? LANTERN_OK
        : LANTERN_ERROR_STORAGE;
}

static void a_ports_data(void)
{
    char* text                  = NULL;
    lantern_homebrew_page* page = read_page(&text);
    REQUIRE(page != NULL);
    const lantern_homebrew* harbor = find(page, "org.example.harborlights", "switch");
    REQUIRE(harbor != NULL);
    lantern_error error = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_check_port(harbor, &error), LANTERN_OK, &error);
    const lantern_port* port = lantern_homebrew_get_port(harbor);
    REQUIRE(port != NULL);
    CHECK(STR_EQ(lantern_port_get_data_root(port), "/switch/harborlights/"));
    const lantern_required_data* optional = lantern_port_get_requires_data_at(port, 1);
    REQUIRE(optional != NULL);
    CHECK(lantern_required_data_get_one_of_count(optional) == 2);
    CHECK(lantern_required_data_get_one_of_size(optional, 0) == 1);
    CHECK(STR_EQ(lantern_required_file_get_path(lantern_required_data_get_one_of_at(optional, 1, 0)),
        "data/MUSIC.PAK"));
    CHECK(lantern_required_data_get_one_of_at(optional, 1, 1) == NULL);
    CHECK(lantern_required_data_get_one_of_at(optional, 2, 0) == NULL);

    sd_card sd                             = { false };
    lantern_data_probe_callbacks callbacks = LANTERN_INIT(lantern_data_probe_callbacks);
    callbacks.user                         = &sd;
    callbacks.size                         = probe_size;
    callbacks.sha256                       = probe_sha256;
    lantern_data_probe* probe              = NULL;
    REQUIRE_STATUS(lantern_data_probe_create(&callbacks, NULL, &probe, NULL), LANTERN_OK);
    lantern_launch_check* check = NULL;
    REQUIRE_CALL(lantern_launch_check_run(port, probe, NULL, &check, &error), LANTERN_OK, &error);
    CHECK(!lantern_launch_check_get_ready(check));
    REQUIRE(lantern_launch_check_get_issue_count(check) >= 1);
    lantern_launch_issue issue = LANTERN_INIT(lantern_launch_issue);
    REQUIRE(lantern_launch_check_get_issue(check, 0, &issue));
    CHECK(STR_EQ(issue.path, "data/HARBOR.PAK"));
    CHECK(issue.issue == LANTERN_DATA_MISSING);
    CHECK(issue.hint.size > 0);
    lantern_launch_check_free(check);
    sd.has_pak = true;
    REQUIRE_CALL(lantern_launch_check_run(port, probe, NULL, &check, &error), LANTERN_OK, &error);
    CHECK(lantern_launch_check_get_ready(check));
    CHECK(!lantern_launch_check_get_unverified(check));
    lantern_launch_check_free(check);
    lantern_data_probe_free(probe);
    lantern_homebrew_page_free(page);
    free(text);
}

static void requirements(void)
{
    char* text                  = NULL;
    lantern_homebrew_page* page = read_page(&text);
    REQUIRE(page != NULL);
    const lantern_homebrew* harbor = find(page, "org.example.harborlights", "linux");
    REQUIRE(harbor != NULL);
    const lantern_requires* requires_ = lantern_homebrew_get_requires(harbor);
    REQUIRE(requires_ != NULL);
    const lantern_version_fact versions[] = { { "glibc", "2.36" } };
    const char* const gpus[]              = { "gles2" };
    lantern_device_facts device           = LANTERN_INIT(lantern_device_facts);
    device.versions                       = versions;
    device.version_count                  = 1;
    device.has_ram_mb                     = true;
    device.ram_mb                         = 2048;
    device.has_screen                     = true;
    device.screen_width                   = 1280;
    device.screen_height                  = 720;
    device.has_gpus                       = true;
    device.gpus                           = gpus;
    device.gpu_count                      = 1;
    lantern_requires_check* check         = NULL;
    lantern_error error                   = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_check_requires(requires_, "linux", &device, NULL, &check, &error), LANTERN_OK, &error);
    CHECK(lantern_requires_check_get_offer(check) == LANTERN_OFFER);
    lantern_requires_check_free(check);

    device.ram_mb = 256;
    REQUIRE_CALL(
        lantern_check_requires(requires_, "linux", &device, NULL, &check, &error), LANTERN_OK, &error);
    CHECK(lantern_requires_check_get_offer(check) == LANTERN_REFUSE);
    bool named = false;
    for (size_t i = 0; i < lantern_requires_check_get_condition_count(check); ++i)
    {
        lantern_condition condition = LANTERN_INIT(lantern_condition);
        REQUIRE(lantern_requires_check_get_condition(check, i, &condition));
        if (condition.state == LANTERN_CONDITION_FAILED)
            named = named || strstr(condition.key.data, "ram_mb") != NULL;
    }
    CHECK(named);
    lantern_requires_check_free(check);

    /* What the app cannot tell: a warning */
    device.ram_mb   = 2048;
    device.has_gpus = false;
    REQUIRE_CALL(
        lantern_check_requires(requires_, "linux", &device, NULL, &check, &error), LANTERN_OK, &error);
    CHECK(lantern_requires_check_get_offer(check) == LANTERN_WARN);
    lantern_requires_check_free(check);

    CHECK_STATUS(lantern_check_requires(requires_, "a-console-of-later", &device, NULL, &check, &error),
        LANTERN_ERROR_UNSUPPORTED);
    lantern_homebrew_page_free(page);
    free(text);
}

static void paths_and_profiles(void)
{
    REQUIRE(sizeof(path_vectors) / sizeof(path_vectors[0]) > 10);
    for (size_t i = 0; i < sizeof(path_vectors) / sizeof(path_vectors[0]); ++i)
    {
        const path_vector* v               = &path_vectors[i];
        const lantern_path_problem problem = lantern_check_device_path(v->path, v->size);
        if ((problem == LANTERN_PATH_OK) != v->accepted)
            fprintf(stderr, "    %s: %s\n", v->why, lantern_path_problem_text(problem));
        CHECK((problem == LANTERN_PATH_OK) == v->accepted);
    }
    CHECK(lantern_check_data_path("data/HARBOR.PAK", 15) == LANTERN_PATH_OK);
    CHECK(lantern_check_data_path("/data/HARBOR.PAK", 16) == LANTERN_PATH_ABSOLUTE);
    CHECK(lantern_check_data_root("/switch/harborlights/", 21) == LANTERN_PATH_OK);
    CHECK(lantern_check_data_root("/switch/harborlights", 20) == LANTERN_PATH_NOT_A_FOLDER);
    CHECK(strlen(lantern_path_problem_text(LANTERN_PATH_DOT_PART)) > 0);
    CHECK(strcmp(lantern_path_problem_text(99), "") == 0);
    CHECK(
        lantern_match_roots("switch", "org.example.frostline", "/switch/org.example.frostline/frostline.nro")
        == LANTERN_ROOT_FREE);
    CHECK(lantern_match_roots("switch", "org.example.frostline", "/atmosphere/contents/x")
        != LANTERN_ROOT_FREE);
    CHECK(
        lantern_match_roots("a-console-of-later", "org.example.frostline", "/x") == LANTERN_ROOT_NO_PROFILE);
    CHECK(lantern_has_profile("switch"));
    CHECK(!lantern_has_profile("a-console-of-later"));
    CHECK(lantern_is_platform_name("switch"));
    CHECK(!lantern_is_platform_name("Switch"));
    CHECK(lantern_is_homebrew_id("org.example.frostline"));
    CHECK(!lantern_is_homebrew_id("../frostline"));
}

const test_case homebrew_tests[] = {
    { "homebrew: a package planned, signed, verified", a_package_planned_and_verified },
    { "homebrew: a package per architecture", packages_per_architecture },
    { "homebrew: pins of the authors' keys", pins_of_homebrew_keys },
    { "homebrew: a port's data before it launches", a_ports_data },
    { "homebrew: requirements offered, refused, warned", requirements },
    { "homebrew: paths.json, roots and profiles", paths_and_profiles },
};
const size_t homebrew_test_count = sizeof(homebrew_tests) / sizeof(homebrew_tests[0]);
