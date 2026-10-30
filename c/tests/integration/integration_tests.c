/*
 * The C API against the specification's reference server (spec/server), on
 * the fictional library of spec/tests/library.py (Frostline Tales, Lea, Noor
 * and Ines…), started by cpp/tests/integration/run_server.py, which sets
 * LANTERN_TEST_PUBLIC, LANTERN_TEST_PRIVATE, LANTERN_TEST_TOKEN,
 * LANTERN_TEST_KEY and LANTERN_TEST_DISCOVERY_PORT. Every name is made up.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "harness.h"
#include "loopback.h"
#include "support.h"

#define FROSTLINE "0100ABCD00010000"

static const char* env(const char* name)
{
    const char* value = getenv(name);
    if (value == NULL)
    {
        fprintf(stderr, "run through run_server.py: %s is not set\n", name);
        exit(EXIT_FAILURE);
    }
    return value;
}

/* The seed of the key pair_for_ci.py bound the CI token to, in base64. */
static bool test_seed(uint8_t out[32])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char* text             = env("LANTERN_TEST_KEY");
    uint32_t bits                = 0;
    int count                    = 0;
    size_t written               = 0;
    for (const char* c = text; *c != '\0' && *c != '='; ++c)
    {
        const char* at = strchr(alphabet, *c);
        if (at == NULL)
            return false;
        bits = (bits << 6U) | (uint32_t)(at - alphabet);
        count += 6;
        if (count >= 8)
        {
            count -= 8;
            if (written >= 32)
                return false;
            out[written++] = (uint8_t)(bits >> (unsigned)count);
        }
    }
    return written == 32;
}

static void pause_ms(long milliseconds)
{
    struct timespec wait = { milliseconds / 1000, (milliseconds % 1000) * 1000000L };
    nanosleep(&wait, NULL);
}

/* The device's clock, which a test may set wrong. */
static int64_t clock_skew;
static int64_t device_time(void* user)
{
    (void)user;
    return (int64_t)time(NULL) + clock_skew;
}

/* A device: a transport, a random source, a clock, and its client. */
typedef struct device
{
    lantern_transport* transport;
    lantern_random* random;
    lantern_clock* clock;
    lantern_client* client;
    lantern_handshake* handshake;
} device;

static bool device_open(
    device* d, const char* origin_variable, const char* platform, bool as_admin, size_t cut_after)
{
    memset(d, 0, sizeof(*d));
    d->transport                  = test_loopback_transport(cut_after);
    lantern_clock_callbacks clock = LANTERN_INIT(lantern_clock_callbacks);
    clock.unix_seconds            = device_time;
    if (d->transport == NULL || lantern_random_create_system(NULL, &d->random, NULL) != LANTERN_OK
        || lantern_clock_create(&clock, NULL, &d->clock, NULL) != LANTERN_OK)
        return false;
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = env(origin_variable);
    config.user_agent            = "LanternCTests/0.4";
    config.platform              = platform;
    config.transport             = d->transport;
    config.random                = d->random;
    config.clock                 = d->clock;
    lantern_error error          = LANTERN_INIT(lantern_error);
    if (!CHECK_CALL(lantern_client_create(&config, &d->client, &error), LANTERN_OK, &error))
        return false;
    if (as_admin)
    {
        uint8_t seed[32];
        lantern_device_key* key = NULL;
        if (!test_seed(seed) || lantern_device_key_from_seed(seed, NULL, &key, NULL) != LANTERN_OK)
            return false;
        const lantern_status set
            = lantern_client_set_credentials(d->client, env("LANTERN_TEST_TOKEN"), key, &error);
        lantern_device_key_free(key);
        if (!CHECK_CALL(set, LANTERN_OK, &error))
            return false;
    }
    return CHECK_CALL(lantern_client_handshake(d->client, &d->handshake, &error), LANTERN_OK, &error);
}

static void device_close(device* d)
{
    lantern_handshake_free(d->handshake);
    lantern_client_free(d->client);
    lantern_transport_free(d->transport);
    lantern_random_free(d->random);
    lantern_clock_free(d->clock);
}

#define OPEN(d, origin, platform, admin)                                                                     \
    do                                                                                                       \
    {                                                                                                        \
        if (!device_open(&(d), (origin), (platform), (admin), 0))                                            \
        {                                                                                                    \
            device_close(&(d));                                                                              \
            REQUIRE(false);                                                                                  \
        }                                                                                                    \
    } while (0)

static const lantern_handshake_account* account(const device* d)
{
    return lantern_handshake_get_account(lantern_client_server(d->client));
}

static void public_handshake(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    const lantern_handshake* server = lantern_client_server(d.client);
    CHECK(STR_EQ(lantern_handshake_get_base(server), "/api/lantern"));
    CHECK(STR_EQ(lantern_handshake_account_get_state(account(&d)), "anonymous"));
    CHECK(lantern_client_offers(d.client, LANTERN_FAMILY_LIBRARY) == 1);
    CHECK(lantern_client_offers(d.client, LANTERN_FAMILY_HOMEBREW) == 1);
    bool has_switch = false;
    bool has_linux  = false;
    for (size_t i = 0; i < lantern_handshake_get_platforms_count(server); ++i)
    {
        has_switch = has_switch || STR_EQ(lantern_handshake_get_platforms_at(server, i), "switch");
        has_linux  = has_linux || STR_EQ(lantern_handshake_get_platforms_at(server, i), "linux");
    }
    CHECK(has_switch && has_linux);
    device_close(&d);
}

static void apps_by_their_cursors(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    char cursor[256]    = "";
    int pages           = 0;
    size_t seen         = 0;
    uint64_t total      = 0;
    lantern_error error = LANTERN_INIT(lantern_error);
    do
    {
        lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
        query.page_size          = 3;
        query.cursor             = cursor;
        lantern_apps_page* page  = NULL;
        REQUIRE_CALL(lantern_client_apps(d.client, &query, &page, &error), LANTERN_OK, &error);
        lantern_apps_page_get_total(page, &total);
        for (size_t i = 0; i < lantern_apps_page_get_items_count(page); ++i)
        {
            const lantern_app* app = lantern_apps_page_get_items_at(page, i);
            CHECK(STR_EQ(lantern_app_get_platform(app), "switch"));
            ++seen;
        }
        snprintf(cursor, sizeof(cursor), "%s", lantern_apps_page_get_next(page).data);
        lantern_apps_page_free(page);
        ++pages;
    } while (cursor[0] != '\0' && pages < 20);
    CHECK(seen == 10);
    CHECK(total == 10);
    CHECK(pages == 4);

    lantern_apps_query bogus = LANTERN_INIT(lantern_apps_query);
    bogus.cursor             = "c_never-given";
    lantern_apps_page* page  = NULL;
    CHECK_STATUS(lantern_client_apps(d.client, &bogus, &page, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 400 || error.http_status == 410);
    CHECK(strlen(error.detail) > 0);
    device_close(&d);
}

static void missing_changes_titles(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    lantern_error error                     = LANTERN_INIT(lantern_error);
    const lantern_installed_app installed[] = { { FROSTLINE, 0 } };
    const char* const want[]                = { "update", "dlc" };
    lantern_missing_request request         = LANTERN_INIT(lantern_missing_request);
    request.installed                       = installed;
    request.installed_count                 = 1;
    request.want                            = want;
    request.want_count                      = 2;
    lantern_apps_page* page                 = NULL;
    REQUIRE_CALL(lantern_client_missing(d.client, &request, NULL, NULL, &page, &error), LANTERN_OK, &error);
    CHECK(lantern_apps_page_get_items_count(page) == 2);
    bool update = false;
    for (size_t i = 0; i < lantern_apps_page_get_items_count(page); ++i)
    {
        const lantern_app* app = lantern_apps_page_get_items_at(page, i);
        uint64_t version       = 0;
        if (STR_EQ(lantern_app_get_app_id(app), "0100ABCD00010800"))
            update = lantern_app_get_version_code(app, &version) && version == 196608;
    }
    CHECK(update);
    lantern_apps_page_free(page);

    lantern_changes* start = NULL;
    REQUIRE_CALL(lantern_client_changes(d.client, NULL, &start, &error), LANTERN_OK, &error);
    CHECK(lantern_changes_get_added_count(start) == 0);
    CHECK(lantern_changes_get_since(start).size > 0);
    lantern_changes* since = NULL;
    REQUIRE_CALL(lantern_client_changes(d.client, lantern_changes_get_since(start).data, &since, &error),
        LANTERN_OK, &error);
    lantern_changes_free(start);
    lantern_changes_free(since);

    lantern_title* title = NULL;
    REQUIRE_CALL(lantern_client_title(d.client, FROSTLINE, &title, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_title_get_name(title), "Frostline Tales"));
    CHECK(STR_EQ(lantern_title_get_publisher(title), "Fjord Works"));
    uint64_t players = 0;
    CHECK(lantern_title_players_get_max(lantern_title_get_players(title), &players) && players == 4);
    CHECK(lantern_title_get_genres_count(title) == 2);
    lantern_title_free(title);
    const char* const ids[] = { FROSTLINE, "0100FFFF00000000" };
    lantern_titles* bulk    = NULL;
    REQUIRE_CALL(lantern_client_titles(d.client, ids, 2, &bulk, &error), LANTERN_OK, &error);
    CHECK(lantern_titles_get_titles_count(bulk) == 1);
    CHECK(STR_EQ(lantern_titles_get_unknown_at(bulk, 0), "0100FFFF00000000"));
    lantern_titles_free(bulk);
    CHECK_STATUS(lantern_client_title(d.client, "0100FFFF00000000", &title, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.effective_code == LANTERN_CODE_NOT_FOUND);
    lantern_title_changes* changes = NULL;
    REQUIRE_CALL(lantern_client_title_changes(d.client, NULL, &changes, &error), LANTERN_OK, &error);
    lantern_title_changes_free(changes);
    device_close(&d);
}

static void target_of_app(const lantern_app* app, lantern_download_target* target)
{
    *target     = LANTERN_INIT(lantern_download_target);
    target->url = lantern_app_get_file(app).data;
    lantern_app_get_size(app, &target->size);
    lantern_app_get_sha256(app, target->sha256);
}

static void downloads_cut_and_resumed(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    lantern_error error      = LANTERN_INIT(lantern_error);
    lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
    query.title_id           = FROSTLINE;
    query.type               = "base";
    lantern_apps_page* page  = NULL;
    REQUIRE_CALL(lantern_client_apps(d.client, &query, &page, &error), LANTERN_OK, &error);
    REQUIRE(lantern_apps_page_get_items_count(page) == 1);
    lantern_download_target target;
    target_of_app(lantern_apps_page_get_items_at(page, 0), &target);
    REQUIRE(target.size == 6000);

    memory_sink whole;
    lantern_download_sink* sink   = memory_sink_make(&whole);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_client_download(d.client, &target, state, sink, &error), LANTERN_OK, &error);
    CHECK(whole.size == 6000);
    uint8_t digest[32];
    lantern_sha256(whole.bytes, whole.size, digest);
    CHECK(memcmp(digest, target.sha256, 32) == 0);

    /* Cut at 2500 bytes, then resumed with Range by another client */
    device flaky;
    if (!device_open(&flaky, "LANTERN_TEST_PUBLIC", "switch", false, 2500))
    {
        device_close(&flaky);
        REQUIRE(false);
    }
    memory_sink part;
    lantern_download_sink* part_sink = memory_sink_make(&part);
    lantern_download_state* partial  = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &partial, NULL), LANTERN_OK);
    CHECK_STATUS(
        lantern_client_download(flaky.client, &target, partial, part_sink, &error), LANTERN_ERROR_TRANSPORT);
    CHECK(lantern_download_state_received(partial) == 2500);
    const size_t before = test_loopback_requests();
    REQUIRE_CALL(lantern_client_download(d.client, &target, partial, part_sink, &error), LANTERN_OK, &error);
    CHECK(test_loopback_requests() == before + 1);
    CHECK(part.size == whole.size && memcmp(part.bytes, whole.bytes, whole.size) == 0);

    /* The listing's digest is not this file's: refused */
    target.sha256[0] ^= 1U;
    lantern_download_state_reset(state);
    memory_sink_clear(&whole);
    CHECK_STATUS(lantern_client_download(d.client, &target, state, sink, &error), LANTERN_ERROR_INTEGRITY);

    lantern_download_sink_free(sink);
    lantern_download_sink_free(part_sink);
    memory_sink_clear(&whole);
    memory_sink_clear(&part);
    lantern_download_state_free(state);
    lantern_download_state_free(partial);
    lantern_apps_page_free(page);
    device_close(&flaky);
    device_close(&d);
}

/* A port's data on the device: frost.pak 1.1 and the demo's music. */
static bool sd_ready;
static const char* sd_content(const char* path, size_t* size)
{
    static char frost[64 * 14 + 1];
    if (!sd_ready)
        return NULL;
    if (strcmp(path, "/switch/frostline/data/frost.pak") == 0)
    {
        frost[0] = '\0';
        for (int i = 0; i < 64; ++i)
            strcat(frost, "frost.pak 1.1 ");
        *size = strlen(frost);
        return frost;
    }
    if (strcmp(path, "/switch/frostline/music/demo.pak") == 0)
    {
        *size = 4;
        return "demo";
    }
    return NULL;
}

static lantern_status sd_size(void* user, lantern_str path, uint64_t* size, bool* present)
{
    (void)user;
    size_t length       = 0;
    const char* content = sd_content(path.data, &length);
    *present            = content != NULL;
    *size               = length;
    return LANTERN_OK;
}

static lantern_status sd_sha256(void* user, lantern_str path, uint8_t out[32])
{
    (void)user;
    size_t length       = 0;
    const char* content = sd_content(path.data, &length);
    if (content == NULL)
        return LANTERN_ERROR_STORAGE;
    lantern_sha256((const uint8_t*)content, length, out);
    return LANTERN_OK;
}

static void homebrew_planned_signed_and_ported(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    lantern_error error           = LANTERN_INIT(lantern_error);
    lantern_homebrew_query query  = LANTERN_INIT(lantern_homebrew_query);
    query.page_size               = 100;
    lantern_homebrew_page* listed = NULL;
    REQUIRE_CALL(lantern_client_homebrew(d.client, &query, &listed, &error), LANTERN_OK, &error);
    CHECK(lantern_homebrew_page_get_items_count(listed) >= 3);
    for (size_t i = 0; i < lantern_homebrew_page_get_items_count(listed); ++i)
    {
        /* A listing leaves the manifests out (SPEC.md 8.2): planning one is refused */
        const lantern_homebrew* entry = lantern_homebrew_page_get_items_at(listed, i);
        if (STR_EQ(lantern_homebrew_get_id(entry), "org.example.frostline"))
        {
            lantern_install_plan* plan = NULL;
            CHECK(lantern_plan_install(entry, lantern_homebrew_get_package(entry), NULL, &plan, &error) < 0);
            CHECK(plan == NULL);
        }
    }
    lantern_homebrew_page_free(listed);

    lantern_homebrew* frostline = NULL;
    REQUIRE_CALL(lantern_client_homebrew_entry(d.client, "org.example.frostline", &frostline, &error),
        LANTERN_OK, &error);
    const lantern_package* package = NULL;
    REQUIRE_CALL(lantern_pick_package(frostline, "aarch64", &package, &error), LANTERN_OK, &error);
    lantern_install_plan* plan = NULL;
    REQUIRE_CALL(lantern_plan_install(frostline, package, NULL, &plan, &error), LANTERN_OK, &error);
    CHECK(lantern_install_plan_get_file_count(plan) == 2);
    CHECK(lantern_install_plan_get_consent_count(plan) == 0);
    lantern_install_plan_free(plan);
    lantern_download_target target = LANTERN_INIT(lantern_download_target);
    target.url                     = lantern_package_get_file(package).data;
    lantern_package_get_size(package, &target.size);
    lantern_package_get_sha256(package, target.sha256);
    memory_sink zip;
    lantern_download_sink* sink   = memory_sink_make(&zip);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_client_download(d.client, &target, state, sink, &error), LANTERN_OK, &error);
    CHECK(zip.size > 2 && zip.bytes[0] == 'P' && zip.bytes[1] == 'K');
    lantern_homebrew_free(frostline);

    /* Ines's Paper Lamp, signed */
    lantern_homebrew* lamp = NULL;
    REQUIRE_CALL(
        lantern_client_homebrew_entry(d.client, "org.example.paperlamp", &lamp, &error), LANTERN_OK, &error);
    lantern_package_signature signature = LANTERN_INIT(lantern_package_signature);
    REQUIRE_CALL(
        lantern_verify_package_signature(lamp, lantern_homebrew_get_package(lamp), &signature, &error),
        LANTERN_OK, &error);
    CHECK(signature.is_signed);
    REQUIRE_CALL(lantern_plan_install(lamp, lantern_homebrew_get_package(lamp), NULL, &plan, &error),
        LANTERN_OK, &error);
    CHECK(lantern_install_plan_get_placement(plan) == LANTERN_PLACEMENT_SINGLE_FILE);
    lantern_install_plan_free(plan);
    lantern_homebrew_free(lamp);

    /* The port of Frostline Tales, and its data */
    lantern_homebrew* port = NULL;
    REQUIRE_CALL(lantern_client_homebrew_entry(d.client, "org.example.frostline-port", &port, &error),
        LANTERN_OK, &error);
    REQUIRE_CALL(lantern_check_port(port, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_port_get_data_root(lantern_homebrew_get_port(port)), "/switch/frostline/"));
    lantern_data_probe_callbacks callbacks = LANTERN_INIT(lantern_data_probe_callbacks);
    callbacks.size                         = sd_size;
    callbacks.sha256                       = sd_sha256;
    lantern_data_probe* probe              = NULL;
    REQUIRE_STATUS(lantern_data_probe_create(&callbacks, NULL, &probe, NULL), LANTERN_OK);
    lantern_launch_check* check = NULL;
    sd_ready                    = false;
    REQUIRE_CALL(lantern_launch_check_run(lantern_homebrew_get_port(port), probe, NULL, &check, &error),
        LANTERN_OK, &error);
    CHECK(!lantern_launch_check_get_ready(check));
    lantern_launch_check_free(check);
    sd_ready = true;
    REQUIRE_CALL(lantern_launch_check_run(lantern_homebrew_get_port(port), probe, NULL, &check, &error),
        LANTERN_OK, &error);
    CHECK(lantern_launch_check_get_ready(check));
    lantern_launch_check_free(check);
    lantern_data_probe_free(probe);
    lantern_homebrew_free(port);

    /* Updates of what is installed */
    const lantern_installed_homebrew installed[]
        = { { "org.example.frostline", 10300 }, { "org.example.paperlamp", 902 } };
    lantern_homebrew_updates_request updates = LANTERN_INIT(lantern_homebrew_updates_request);
    updates.installed                        = installed;
    updates.installed_count                  = 2;
    REQUIRE_CALL(
        lantern_client_homebrew_updates(d.client, &updates, NULL, NULL, &listed, &error), LANTERN_OK, &error);
    REQUIRE(lantern_homebrew_page_get_items_count(listed) == 1);
    uint64_t build = 0;
    CHECK(
        lantern_homebrew_get_build(lantern_homebrew_page_get_items_at(listed, 0), &build) && build == 10400);
    lantern_homebrew_page_free(listed);

    lantern_download_sink_free(sink);
    memory_sink_clear(&zip);
    lantern_download_state_free(state);
    device_close(&d);
}

static void harbor_lights_per_architecture(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "linux", false);
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_homebrew* entry = NULL;
    REQUIRE_CALL(lantern_client_homebrew_entry(d.client, "org.example.harborlights", &entry, &error),
        LANTERN_OK, &error);
    REQUIRE_CALL(lantern_check_port(entry, &error), LANTERN_OK, &error);
    const char* const arches[] = { "aarch64", "armhf", "x86_64", "riscv64" };
    for (size_t i = 0; i < 4; ++i)
    {
        const lantern_package* package = NULL;
        REQUIRE_CALL(lantern_pick_package(entry, arches[i], &package, &error), LANTERN_OK, &error);
        lantern_package_signature signature = LANTERN_INIT(lantern_package_signature);
        CHECK_CALL(lantern_verify_package_signature(entry, package, &signature, &error), LANTERN_OK, &error);
        lantern_install_plan* plan = NULL;
        REQUIRE_CALL(lantern_plan_install(entry, package, NULL, &plan, &error), LANTERN_OK, &error);
        CHECK(lantern_install_plan_get_consent_count(plan) == 1);
        lantern_install_plan_free(plan);
    }
    const lantern_package* none = NULL;
    CHECK(lantern_pick_package(entry, "x86", &none, &error) < 0);
    const lantern_version_fact glibc[] = { { "glibc", "2.36" } };
    lantern_device_facts facts         = LANTERN_INIT(lantern_device_facts);
    facts.versions                     = glibc;
    facts.version_count                = 1;
    facts.has_ram_mb                   = true;
    facts.ram_mb                       = 2048;
    lantern_requires_check* check      = NULL;
    REQUIRE_CALL(
        lantern_check_requires(lantern_homebrew_get_requires(entry), "linux", &facts, NULL, &check, &error),
        LANTERN_OK, &error);
    CHECK(lantern_requires_check_get_offer(check) == LANTERN_WARN);
    lantern_requires_check_free(check);
    lantern_homebrew_free(entry);
    device_close(&d);
}

static void a_private_server(void)
{
    device anonymous;
    OPEN(anonymous, "LANTERN_TEST_PRIVATE", "switch", false);
    CHECK(STR_EQ(lantern_handshake_account_get_state(account(&anonymous)), "anonymous"));
    CHECK(lantern_client_offers(anonymous.client, LANTERN_FAMILY_LIBRARY) == 0);
    CHECK(lantern_client_offers(anonymous.client, LANTERN_FAMILY_PAIRING) == 1);
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_apps_page* page = NULL;
    CHECK_STATUS(lantern_client_apps(anonymous.client, NULL, &page, &error), LANTERN_ERROR_UNSUPPORTED);

    /* A token the server never gave */
    REQUIRE_CALL(
        lantern_client_set_bearer_token(anonymous.client, "et_never-given", &error), LANTERN_OK, &error);
    lantern_handshake* shake = NULL;
    CHECK_STATUS(lantern_client_handshake(anonymous.client, &shake, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 401 && error.code == LANTERN_CODE_UNAUTHORIZED);
    /* The bound token without its key: pair again */
    REQUIRE_CALL(lantern_client_set_bearer_token(anonymous.client, env("LANTERN_TEST_TOKEN"), &error),
        LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_handshake(anonymous.client, &shake, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_SIGNATURE_REQUIRED);
    CHECK(strstr(error.detail, "pair again") != NULL);
    device_close(&anonymous);

    device paired;
    OPEN(paired, "LANTERN_TEST_PRIVATE", "switch", true);
    CHECK(STR_EQ(lantern_handshake_account_get_state(account(&paired)), "active"));
    bool bound = false;
    CHECK(lantern_handshake_account_get_bound(account(&paired), &bound) && bound);
    CHECK(lantern_client_offers(paired.client, LANTERN_FAMILY_CHEATS) == 1);
    lantern_cheats_query query = LANTERN_INIT(lantern_cheats_query);
    query.title_id             = FROSTLINE;
    lantern_cheat_sets* sets   = NULL;
    REQUIRE_CALL(lantern_client_cheats(paired.client, &query, &sets, &error), LANTERN_OK, &error);
    REQUIRE(lantern_cheat_sets_get_cheats_count(sets) == 2);
    for (size_t i = 0; i < 2; ++i)
    {
        const lantern_cheat_set* set = lantern_cheat_sets_get_cheats_at(sets, i);
        CHECK(STR_EQ(lantern_cheat_set_get_build_id(set), "4A1B2C3D4E5F6071"));
        lantern_string* text = NULL;
        REQUIRE_CALL(lantern_client_cheat_text(paired.client, set, &text, &error), LANTERN_OK, &error);
        CHECK(lantern_string_view(text).data[0] == '[');
        lantern_string_free(text);
    }
    lantern_cheat_sets_free(sets);
    device_close(&paired);
}

/* A credential store in memory. */
typedef struct kept
{
    int count;
    char uid[64];
    char token[256];
    bool has_key;
    uint8_t seed[32];
} kept;

static lantern_status kept_load(void* user, lantern_str uid, lantern_credentials_sink* sink)
{
    kept* store = user;
    if (store->count == 0 || strcmp(uid.data, store->uid) != 0)
        return LANTERN_OK;
    lantern_credentials credentials = LANTERN_INIT(lantern_credentials);
    credentials.token.data          = store->token;
    credentials.token.size          = strlen(store->token);
    credentials.has_key             = store->has_key;
    memcpy(credentials.key_seed, store->seed, 32);
    return lantern_credentials_sink_set(sink, &credentials);
}

static lantern_status kept_store(void* user, lantern_str uid, const lantern_credentials* credentials)
{
    kept* store = user;
    snprintf(store->uid, sizeof(store->uid), "%s", uid.data);
    snprintf(store->token, sizeof(store->token), "%s", credentials->token.data);
    store->has_key = credentials->has_key;
    memcpy(store->seed, credentials->key_seed, 32);
    ++store->count;
    return LANTERN_OK;
}

static lantern_status kept_erase(void* user, lantern_str uid)
{
    (void)uid;
    ((kept*)user)->count = 0;
    return LANTERN_OK;
}

static const lantern_admin_pairing* waiting_with(const lantern_admin_pairings* pairings, lantern_str code)
{
    for (size_t i = 0; i < lantern_admin_pairings_get_items_count(pairings); ++i)
    {
        const lantern_admin_pairing* item = lantern_admin_pairings_get_items_at(pairings, i);
        if (lantern_admin_pairing_get_code(item).size == code.size
            && memcmp(lantern_admin_pairing_get_code(item).data, code.data, code.size) == 0)
            return item;
    }
    return NULL;
}

static void pairing_approved_by_an_admin(void)
{
    device console;
    OPEN(console, "LANTERN_TEST_PRIVATE", "switch", false);
    lantern_error error             = LANTERN_INIT(lantern_error);
    const char* const scopes[]      = { "library", "saves" };
    lantern_pairing_options options = LANTERN_INIT(lantern_pairing_options);
    options.device                  = "Lea's Switch";
    options.scopes                  = scopes;
    options.scope_count             = 2;
    lantern_pairing* pairing        = NULL;
    REQUIRE_CALL(
        lantern_client_start_pairing(console.client, &options, &pairing, &error), LANTERN_OK, &error);
    REQUIRE(lantern_pairing_get_key(pairing) != NULL);
    const lantern_pairing_code* code = lantern_pairing_get_code(pairing);
    CHECK(lantern_is_pairing_code(lantern_pairing_code_get_code(code).data));
    CHECK(
        strstr(lantern_pairing_code_get_verify_complete(code).data, lantern_pairing_code_get_code(code).data)
        != NULL);
    lantern_poll_state state = LANTERN_POLL_PAIRED;
    REQUIRE_CALL(
        lantern_client_poll_pairing(console.client, pairing, NULL, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_WAITING);
    REQUIRE_CALL(
        lantern_client_poll_pairing(console.client, pairing, NULL, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_WAITING);
    CHECK(lantern_pairing_get_wait(pairing) >= 10);

    /* The admin sees the code and the key's fingerprint, and approves less than asked */
    device admin;
    OPEN(admin, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_admin_pairings* waiting = NULL;
    REQUIRE_CALL(lantern_client_admin_pairings(admin.client, NULL, &waiting, &error), LANTERN_OK, &error);
    const lantern_admin_pairing* found = waiting_with(waiting, lantern_pairing_code_get_code(code));
    REQUIRE(found != NULL);
    char fingerprint[20];
    lantern_device_key_fingerprint(lantern_pairing_get_key(pairing), fingerprint);
    CHECK(STR_EQ(lantern_admin_pairing_get_key(found), fingerprint));
    CHECK(STR_EQ(lantern_admin_pairing_get_device(found), "Lea's Switch"));
    const char* const library[]             = { "library" };
    lantern_admin_pairing_decision decision = LANTERN_INIT(lantern_admin_pairing_decision);
    decision.decision                       = "approve";
    decision.scopes                         = library;
    decision.scope_count                    = 1;
    REQUIRE_CALL(lantern_client_admin_decide_pairing(
                     admin.client, lantern_admin_pairing_get_id(found).data, &decision, &error),
        LANTERN_OK, &error);
    lantern_admin_pairings_free(waiting);

    /* The poll waits out the interval it was asked to keep */
    pause_ms(4200);
    kept memory                            = { 0 };
    lantern_credential_callbacks callbacks = LANTERN_INIT(lantern_credential_callbacks);
    callbacks.user                         = &memory;
    callbacks.load                         = kept_load;
    callbacks.store                        = kept_store;
    callbacks.erase                        = kept_erase;
    lantern_credential_store* store        = NULL;
    REQUIRE_STATUS(lantern_credential_store_create(&callbacks, NULL, &store, NULL), LANTERN_OK);
    REQUIRE_CALL(
        lantern_client_poll_pairing(console.client, pairing, store, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_PAIRED);
    CHECK(memory.count == 1 && memory.has_key);
    lantern_handshake* shake = NULL;
    REQUIRE_CALL(lantern_client_handshake(console.client, &shake, &error), LANTERN_OK, &error);
    bool bound = false;
    CHECK(lantern_handshake_account_get_bound(lantern_handshake_get_account(shake), &bound) && bound);
    CHECK(lantern_client_offers(console.client, LANTERN_FAMILY_SAVES) == 0);
    lantern_handshake_free(shake);
    lantern_apps_page* page = NULL;
    REQUIRE_CALL(lantern_client_apps(console.client, NULL, &page, &error), LANTERN_OK, &error);
    lantern_apps_page_free(page);
    CHECK_STATUS(
        lantern_client_poll_pairing(console.client, pairing, NULL, &state, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.effective_code == LANTERN_CODE_GONE);

    /* Another client of the same device signs in from the store */
    device later;
    OPEN(later, "LANTERN_TEST_PRIVATE", "switch", false);
    bool signed_in = false;
    REQUIRE_CALL(lantern_client_sign_in(later.client, store, &signed_in, &error), LANTERN_OK, &error);
    CHECK(signed_in);
    REQUIRE_CALL(lantern_client_handshake(later.client, &shake, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_handshake_account_get_state(lantern_handshake_get_account(shake)), "active"));
    lantern_handshake_free(shake);

    /* The admin revokes the device: it loses its access at once */
    lantern_admin_devices* devices = NULL;
    REQUIRE_CALL(
        lantern_client_admin_devices(admin.client, NULL, NULL, &devices, &error), LANTERN_OK, &error);
    const lantern_admin_device* mine = NULL;
    for (size_t i = 0; i < lantern_admin_devices_get_items_count(devices); ++i)
    {
        const lantern_admin_device* item = lantern_admin_devices_get_items_at(devices, i);
        if (STR_EQ(lantern_admin_device_get_device(item), "Lea's Switch")
            && STR_EQ(lantern_admin_device_get_key(item), fingerprint))
            mine = item;
    }
    REQUIRE(mine != NULL);
    REQUIRE_CALL(
        lantern_client_admin_revoke_device(admin.client, lantern_admin_device_get_id(mine).data, &error),
        LANTERN_OK, &error);
    lantern_admin_devices_free(devices);
    CHECK_STATUS(lantern_client_apps(console.client, NULL, &page, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 401);

    lantern_credential_store_free(store);
    lantern_pairing_free(pairing);
    device_close(&later);
    device_close(&admin);
    device_close(&console);
}

static void in_days(int days, char* out, size_t size)
{
    const time_t when = time(NULL) + (time_t)days * 86400;
    struct tm utc;
    gmtime_r(&when, &utc);
    strftime(out, size, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

static void invitations(void)
{
    device admin;
    OPEN(admin, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error        = LANTERN_INIT(lantern_error);
    lantern_admin_users* users = NULL;
    REQUIRE_CALL(lantern_client_admin_users(admin.client, NULL, &users, &error), LANTERN_OK, &error);
    bool mila = false;
    for (size_t i = 0; i < lantern_admin_users_get_items_count(users); ++i)
        mila
            = mila || STR_EQ(lantern_admin_user_get_name(lantern_admin_users_get_items_at(users, i)), "mila");
    CHECK(mila);
    lantern_admin_users_free(users);

    const char* const scopes[]       = { "library", "requests" };
    lantern_admin_user_create create = LANTERN_INIT(lantern_admin_user_create);
    create.name                      = "noor";
    create.scopes                    = scopes;
    create.scope_count               = 2;
    lantern_admin_user* user         = NULL;
    REQUIRE_CALL(lantern_client_admin_create_user(admin.client, &create, &user, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_admin_user_get_state(user), "active"));
    lantern_admin_user_free(user);
    CHECK_STATUS(
        lantern_client_admin_create_user(admin.client, &create, &user, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_CONFLICT);

    char expires[32];
    in_days(1, expires, sizeof(expires));
    lantern_invitation_create invite = LANTERN_INIT(lantern_invitation_create);
    invite.user                      = "noor";
    invite.scopes                    = scopes;
    invite.scope_count               = 1;
    invite.expires                   = expires;
    invite.devices                   = 1;
    invite.note                      = "Noor's consoles";
    lantern_invitation* invitation   = NULL;
    REQUIRE_CALL(lantern_client_admin_create_invitation(admin.client, &invite, &invitation, &error),
        LANTERN_OK, &error);
    lantern_invitation_link link = LANTERN_INIT(lantern_invitation_link);
    REQUIRE_CALL(lantern_parse_invitation_link(lantern_invitation_get_link(invitation).data, &link, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_invitation_get_code(invitation), link.code));
    CHECK(!link.has_spki); /* plain HTTP on loopback: no key to pin */
    lantern_invitation_free(invitation);

    /* Redeemed: the first poll gives the token */
    device console;
    OPEN(console, "LANTERN_TEST_PRIVATE", "switch", false);
    const char* const asked[]       = { "library", "saves" };
    lantern_pairing_options options = LANTERN_INIT(lantern_pairing_options);
    options.device                  = "Noor's Switch";
    options.scopes                  = asked;
    options.scope_count             = 2;
    options.invitation              = link.code;
    lantern_pairing* pairing        = NULL;
    REQUIRE_CALL(
        lantern_client_start_pairing(console.client, &options, &pairing, &error), LANTERN_OK, &error);
    lantern_poll_state state = LANTERN_POLL_WAITING;
    REQUIRE_CALL(
        lantern_client_poll_pairing(console.client, pairing, NULL, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_PAIRED);
    lantern_handshake* shake = NULL;
    REQUIRE_CALL(lantern_client_handshake(console.client, &shake, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_handshake_account_get_name(lantern_handshake_get_account(shake)), "noor"));
    lantern_handshake_free(shake);
    lantern_pairing_free(pairing);

    /* Frozen: the device sees it on its next call */
    lantern_admin_user_update freeze = LANTERN_INIT(lantern_admin_user_update);
    freeze.state                     = "frozen";
    REQUIRE_CALL(
        lantern_client_admin_update_user(admin.client, "noor", &freeze, &user, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_admin_user_get_state(user), "frozen"));
    lantern_admin_user_free(user);
    REQUIRE_CALL(lantern_client_handshake(console.client, &shake, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_handshake_account_get_state(lantern_handshake_get_account(shake)), "frozen"));
    lantern_handshake_free(shake);
    CHECK(lantern_client_offers(console.client, LANTERN_FAMILY_LIBRARY) == 0);

    /* Listed, then one revoked */
    lantern_invitations* listed = NULL;
    REQUIRE_CALL(lantern_client_admin_invitations(admin.client, NULL, &listed, &error), LANTERN_OK, &error);
    lantern_invitations_free(listed);
    invite.devices = 2;
    REQUIRE_CALL(lantern_client_admin_create_invitation(admin.client, &invite, &invitation, &error),
        LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_admin_revoke_invitation(
                     admin.client, lantern_invitation_get_id(invitation).data, &error),
        LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_admin_revoke_invitation(
                     admin.client, lantern_invitation_get_id(invitation).data, &error),
        LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 404);
    lantern_invitation_free(invitation);
    device_close(&console);
    device_close(&admin);
}

static void a_clock_an_hour_off(void)
{
    device d;
    clock_skew = 0;
    OPEN(d, "LANTERN_TEST_PRIVATE", "switch", true);
    CHECK(lantern_client_clock_offset(d.client) > -5 && lantern_client_clock_offset(d.client) < 5);
    clock_skew              = -3600;
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_apps_page* page = NULL;
    REQUIRE_CALL(lantern_client_apps(d.client, NULL, &page, &error), LANTERN_OK, &error);
    lantern_apps_page_free(page);
    CHECK(lantern_client_clock_offset(d.client) > 3590 && lantern_client_clock_offset(d.client) < 3610);
    clock_skew = 0;
    device_close(&d);
}

/* A zip with nothing but a comment of `size` bytes: a save of any size. */
static uint8_t* empty_zip(size_t size, size_t* length)
{
    *length      = 22 + size;
    uint8_t* zip = calloc(*length, 1);
    if (zip == NULL)
        return NULL;
    memcpy(zip, "PK\x05\x06", 4);
    zip[20] = (uint8_t)(size & 0xFFU);
    zip[21] = (uint8_t)((size >> 8U) & 0xFFU);
    memset(zip + 22, 'L', size);
    return zip;
}

typedef struct archive
{
    const uint8_t* bytes;
    size_t size;
    int reads;
} archive;

static lantern_status archive_read(void* user, uint64_t offset, uint8_t* out, size_t size)
{
    archive* source = user;
    if (offset + size > source->size)
        return LANTERN_ERROR_STORAGE;
    memcpy(out, source->bytes + offset, size);
    ++source->reads;
    return LANTERN_OK;
}

static lantern_upload_source* source_of(archive* source)
{
    lantern_upload_callbacks callbacks = LANTERN_INIT(lantern_upload_callbacks);
    callbacks.user                     = source;
    callbacks.read                     = archive_read;
    lantern_upload_source* out         = NULL;
    lantern_upload_source_create(&callbacks, NULL, &out, NULL);
    return out;
}

static bool has_save(const lantern_saves* saves, lantern_str id)
{
    for (size_t i = 0; i < lantern_saves_get_saves_count(saves); ++i)
    {
        const lantern_str other = lantern_save_get_save_id(lantern_saves_get_saves_at(saves, i));
        if (other.size == id.size && memcmp(other.data, id.data, id.size) == 0)
            return true;
    }
    return false;
}

static void saves(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PRIVATE", "switch", true);
    REQUIRE(lantern_client_offers(d.client, LANTERN_FAMILY_SAVES) == 1);
    lantern_error error = LANTERN_INIT(lantern_error);

    /* § 9.2: in one request */
    size_t small_size          = 0;
    uint8_t* small             = empty_zip(300, &small_size);
    lantern_save_info info     = LANTERN_INIT(lantern_save_info);
    info.kind                  = "account";
    info.has_game_version_code = true;
    info.game_version_code     = 196608;
    info.profile               = "L\xC3\xA9"
                                 "a";
    info.note                  = "Chapter 4, by the lake";
    lantern_save* save         = NULL;
    REQUIRE_CALL(lantern_client_upload_save(d.client, FROSTLINE, small, small_size, &info, &save, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_save_get_platform(save), "switch"));
    CHECK(STR_EQ(lantern_save_get_profile(save),
        "L\xC3\xA9"
        "a"));
    CHECK(STR_EQ(lantern_save_get_note(save), "Chapter 4, by the lake"));
    uint64_t version = 0;
    CHECK(lantern_save_get_game_version_code(save, &version) && version == 196608);
    memory_sink downloaded;
    lantern_download_sink* sink   = memory_sink_make(&downloaded);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_client_download_save(d.client, save, state, sink, &error), LANTERN_OK, &error);
    CHECK(downloaded.size == small_size && memcmp(downloaded.bytes, small, small_size) == 0);

    /* § 9.3: in chunks of 16 KiB */
    size_t large_size              = 0;
    uint8_t* large                 = empty_zip(40000, &large_size);
    lantern_upload_request request = LANTERN_INIT(lantern_upload_request);
    request.size                   = large_size;
    lantern_sha256(large, large_size, request.sha256);
    request.kind                      = "account";
    request.profile                   = "Ines";
    archive whole                     = { large, large_size, 0 };
    lantern_upload_source* source     = source_of(&whole);
    lantern_upload_progress* progress = NULL;
    REQUIRE_STATUS(lantern_upload_progress_create(NULL, &progress, NULL), LANTERN_OK);
    lantern_save* uploaded = NULL;
    REQUIRE_CALL(lantern_client_upload_resumable(
                     d.client, FROSTLINE, &request, source, progress, 16384, NULL, &uploaded, &error),
        LANTERN_OK, &error);
    uint64_t size = 0;
    CHECK(lantern_save_get_size(uploaded, &size) && size == large_size);
    CHECK(whole.reads == 3);
    CHECK(STR_EQ(lantern_upload_progress_url(progress), ""));
    lantern_save_free(uploaded);

    /* A cut: one chunk went, the app kept an older offset; HEAD says where to go on */
    lantern_upload_session* session = NULL;
    REQUIRE_CALL(lantern_client_open_upload(d.client, FROSTLINE, &request, NULL, &session, &error),
        LANTERN_OK, &error);
    const char* upload = lantern_upload_session_get_upload(session).data;
    uint64_t offset    = 0;
    lantern_save* done = NULL;
    REQUIRE_CALL(lantern_client_upload_chunk(d.client, upload, 0, large, 10000, &offset, &done, &error),
        LANTERN_OK, &error);
    CHECK(offset == 10000);
    CHECK(done == NULL);
    CHECK_STATUS(lantern_client_upload_chunk(d.client, upload, 0, large, 10000, &offset, &done, &error),
        LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_CONFLICT);
    REQUIRE_CALL(lantern_client_upload_offset(d.client, upload, &offset, &error), LANTERN_OK, &error);
    CHECK(offset == 10000);
    /* Resumed from what the app saved: its progress document */
    uint64_t chunk_size = 0;
    lantern_upload_session_get_chunk_size(session, &chunk_size);
    char saved[1024];
    snprintf(saved, sizeof(saved), "{\"schema\":1,\"url\":\"%s\",\"offset\":0,\"chunk_size\":%llu}", upload,
        (unsigned long long)chunk_size);
    lantern_upload_progress* resumed = NULL;
    REQUIRE_STATUS(lantern_upload_progress_create(NULL, &resumed, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_upload_progress_load(resumed, saved, strlen(saved), &error), LANTERN_OK, &error);
    archive rest                       = { large, large_size, 0 };
    lantern_upload_source* rest_source = source_of(&rest);
    REQUIRE_CALL(lantern_client_upload_resumable(
                     d.client, FROSTLINE, &request, rest_source, resumed, 16384, NULL, &uploaded, &error),
        LANTERN_OK, &error);
    CHECK(rest.reads == 2);
    lantern_save_free(uploaded);
    lantern_upload_session_free(session);

    /* A wrong digest: the server checks the whole archive */
    lantern_upload_request wrong = request;
    lantern_sha256(small, small_size, wrong.sha256);
    archive again                       = { large, large_size, 0 };
    lantern_upload_source* again_source = source_of(&again);
    lantern_upload_progress_reset(progress);
    CHECK_STATUS(lantern_client_upload_resumable(
                     d.client, FROSTLINE, &wrong, again_source, progress, 65536, NULL, &uploaded, &error),
        LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_DIGEST_MISMATCH);

    /* Abandoned: gone */
    REQUIRE_CALL(lantern_client_open_upload(d.client, FROSTLINE, &request, NULL, &session, &error),
        LANTERN_OK, &error);
    REQUIRE_CALL(
        lantern_client_abandon_upload(d.client, lantern_upload_session_get_upload(session).data, &error),
        LANTERN_OK, &error);
    CHECK(lantern_client_upload_offset(
              d.client, lantern_upload_session_get_upload(session).data, &offset, &error)
        < 0);
    lantern_upload_session_free(session);

    /* Listed, then removed */
    lantern_saves* listed = NULL;
    REQUIRE_CALL(lantern_client_saves(d.client, FROSTLINE, NULL, &listed, &error), LANTERN_OK, &error);
    CHECK(has_save(listed, lantern_save_get_save_id(save)));
    lantern_saves_free(listed);
    REQUIRE_CALL(lantern_client_delete_save(d.client, save, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_saves(d.client, FROSTLINE, NULL, &listed, &error), LANTERN_OK, &error);
    CHECK(!has_save(listed, lantern_save_get_save_id(save)));
    lantern_saves_free(listed);

    lantern_save_free(save);
    lantern_upload_source_free(source);
    lantern_upload_source_free(rest_source);
    lantern_upload_source_free(again_source);
    lantern_upload_progress_free(progress);
    lantern_upload_progress_free(resumed);
    lantern_download_sink_free(sink);
    memory_sink_clear(&downloaded);
    lantern_download_state_free(state);
    free(small);
    free(large);
    device_close(&d);
}

static void cheats_written(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error       = LANTERN_INIT(lantern_error);
    lantern_cheat_write write = LANTERN_INIT(lantern_cheat_write);
    write.platform            = "switch";
    write.title_id            = FROSTLINE;
    write.build_id            = "4A1B2C3D4E5F6071";
    write.source              = "Lantern C tests";
    write.note                = "Lamp oil";
    write.text                = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    lantern_cheat_set* made   = NULL;
    REQUIRE_CALL(lantern_client_create_cheat_set(d.client, &write, &made, &error), LANTERN_OK, &error);
    lantern_string* text = NULL;
    REQUIRE_CALL(lantern_client_cheat_text(d.client, made, &text, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(text), write.text));
    lantern_string_free(text);
    lantern_cheat_set* twice = NULL;
    CHECK_STATUS(lantern_client_create_cheat_set(d.client, &write, &twice, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_CONFLICT);
    write.text     = "[Endless lamp oil]\n04000000 00ABCDEF 000003E7\n";
    const char* id = lantern_cheat_set_get_id(made).data;
    REQUIRE_CALL(lantern_client_replace_cheat_set(d.client, id, &write, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_delete_cheat_set(d.client, id, &error), LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_delete_cheat_set(d.client, id, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 404);
    lantern_cheat_set_free(made);
    device_close(&d);
}

static void requests(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error           = LANTERN_INIT(lantern_error);
    lantern_request_create wish   = LANTERN_INIT(lantern_request_create);
    wish.title_id                 = "0100FFFF00010000";
    lantern_title_request* first  = NULL;
    lantern_title_request* second = NULL;
    REQUIRE_CALL(lantern_client_request_title(d.client, &wish, &first, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_title_request_get_status(first), "open"));
    CHECK(STR_EQ(lantern_title_request_get_platform(first), "switch"));
    REQUIRE_CALL(lantern_client_request_title(d.client, &wish, &second, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_title_request_get_id(second), lantern_title_request_get_id(first).data));
    lantern_title_requests* listed = NULL;
    REQUIRE_CALL(lantern_client_requests(d.client, NULL, &listed, &error), LANTERN_OK, &error);
    CHECK(lantern_title_requests_get_requests_count(listed) >= 1);
    lantern_title_requests_free(listed);
    const char* id = lantern_title_request_get_id(first).data;
    REQUIRE_CALL(lantern_client_withdraw_request(d.client, id, &error), LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_withdraw_request(d.client, id, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 404);
    lantern_title_request_free(first);
    lantern_title_request_free(second);
    device_close(&d);
}

static int found_servers;
static char found_origin[128];
static bool on_server(void* user, const lantern_discovered_server* server)
{
    (void)user;
    ++found_servers;
    snprintf(found_origin, sizeof(found_origin), "%s", server->origin.data);
    return true;
}

static void discovery_on_loopback(void)
{
    lantern_udp_socket* socket = test_udp_socket();
    REQUIRE(socket != NULL);
    lantern_discovery_options options = LANTERN_INIT(lantern_discovery_options);
    options.address                   = "127.0.0.1";
    options.port                      = (uint16_t)atoi(env("LANTERN_TEST_DISCOVERY_PORT"));
    options.wait_ms                   = 1200;
    options.attempts                  = 3;
    found_servers                     = 0;
    lantern_error error               = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_discover(socket, &options, on_server, NULL, &error), LANTERN_OK, &error);
    CHECK(found_servers == 1);
    const char* public_origin = env("LANTERN_TEST_PUBLIC");
    char expected[128];
    snprintf(expected, sizeof(expected), "https://127.0.0.1%s", strrchr(public_origin, ':'));
    CHECK(strcmp(found_origin, expected) == 0);
    lantern_udp_socket_free(socket);
}

/* ------------------------------------------------------------ Draft 0.5 */

static void v05_families(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    CHECK(lantern_client_offers(d.client, LANTERN_FAMILY_EVENTS) == 1);
    CHECK(lantern_client_offers(d.client, LANTERN_FAMILY_PEERS) == 1);
    uint64_t heartbeat = 0;
    CHECK(lantern_handshake_limits_get_heartbeat(
              lantern_handshake_get_limits(lantern_client_server(d.client)), &heartbeat)
        && heartbeat >= 5);
    CHECK(lantern_client_event_silence_limit(d.client) == 2 * heartbeat);
    uint8_t key[32];
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_CALL(lantern_grant_key_of(lantern_client_server(d.client), key, &error), LANTERN_OK, &error);
    device_close(&d);
    device admin;
    OPEN(admin, "LANTERN_TEST_PRIVATE", "switch", true);
    CHECK(lantern_client_offers(admin.client, LANTERN_FAMILY_SYNC) == 1);
    CHECK(lantern_client_offers(admin.client, LANTERN_FAMILY_ENCRYPTED_SAVES) == 1);
    device_close(&admin);
}

/* The events a stream gives, until the kind waited for. */
typedef struct waiter
{
    lantern_event_kind until;
    int count;
    lantern_event_kind last;
    char data[512];
} waiter;

static bool wait_event(void* user, const lantern_stream_event* event)
{
    waiter* w = user;
    ++w->count;
    w->last = event->kind;
    snprintf(w->data, sizeof(w->data), "%s", event->data.data);
    return event->kind != w->until;
}

static void v05_events(void)
{
    device lea;
    OPEN(lea, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error               = LANTERN_INIT(lantern_error);
    lantern_event_stream_state* state = NULL;
    REQUIRE_STATUS(lantern_event_stream_state_create(NULL, &state, NULL), LANTERN_OK);
    waiter ready                      = { LANTERN_EVENT_READY, 0, LANTERN_EVENT_SHUTDOWN, "" };
    lantern_event_callbacks callbacks = LANTERN_INIT(lantern_event_callbacks);
    callbacks.user                    = &ready;
    callbacks.on_event                = wait_event;
    REQUIRE_CALL(lantern_client_events(lea.client, state, &callbacks, NULL, &error), LANTERN_OK, &error);
    CHECK(ready.count == 1 && ready.last == LANTERN_EVENT_READY);
    char since[512];
    snprintf(since, sizeof(since), "%s", lantern_event_stream_state_last_id(state).data);
    REQUIRE(since[0] != '\0');

    /* A request made: it comes after `ready` on the stream resumed */
    lantern_request_create wish = LANTERN_INIT(lantern_request_create);
    wish.platform               = "switch";
    wish.title_id               = FROSTLINE;
    lantern_title_request* made = NULL;
    REQUIRE_CALL(lantern_client_request_title(lea.client, &wish, &made, &error), LANTERN_OK, &error);
    waiter request = { LANTERN_EVENT_REQUEST, 0, LANTERN_EVENT_SHUTDOWN, "" };
    callbacks.user = &request;
    REQUIRE_CALL(lantern_client_events(lea.client, state, &callbacks, NULL, &error), LANTERN_OK, &error);
    CHECK(request.last == LANTERN_EVENT_REQUEST);
    lantern_request_event* read = NULL;
    REQUIRE_CALL(lantern_read_request_event(request.data, strlen(request.data), NULL, &read, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_request_event_get_id(read), lantern_title_request_get_id(made).data));
    CHECK(STR_EQ(lantern_request_event_get_status(read), "open"));
    lantern_request_event_free(read);

    /* Long polling: the same event after the same token */
    lantern_changes* polled = NULL;
    REQUIRE_CALL(
        lantern_client_wait_changes(lea.client, since, 5, NULL, &polled, &error), LANTERN_OK, &error);
    bool seen = false;
    for (size_t i = 0; i < lantern_changes_get_events_count(polled); ++i)
        seen = seen || STR_EQ(lantern_event_get_event(lantern_changes_get_events_at(polled, i)), "request");
    CHECK(seen);
    CHECK(lantern_changes_get_since(polled).size > 0);
    lantern_changes_free(polled);
    REQUIRE_CALL(lantern_client_withdraw_request(lea.client, lantern_title_request_get_id(made).data, &error),
        LANTERN_OK, &error);
    lantern_title_request_free(made);

    /* A token the server never gave: the position forgotten */
    REQUIRE(lantern_event_stream_state_set_last_id(state, "s_00000000_1"));
    waiter none    = { LANTERN_EVENT_READY, 0, LANTERN_EVENT_SHUTDOWN, "" };
    callbacks.user = &none;
    CHECK_STATUS(lantern_client_events(lea.client, state, &callbacks, NULL, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 400 || error.http_status == 410);
    CHECK(STR_EQ(lantern_event_stream_state_last_id(state), ""));
    lantern_event_stream_state_free(state);
    device_close(&lea);
}

/* The peer of run_server.py, from LANTERN_TEST_PEER ("http://127.0.0.1:<port>"). */
static lantern_peer_endpoint test_peer(char* host, size_t size)
{
    const char* origin = env("LANTERN_TEST_PEER");
    const char* start  = strstr(origin, "//") + 2;
    const char* colon  = strrchr(origin, ':');
    snprintf(host, size, "%.*s", (int)(colon - start), start);
    lantern_peer_endpoint peer = LANTERN_INIT(lantern_peer_endpoint);
    peer.host                  = host;
    peer.port                  = (uint16_t)atoi(colon + 1);
    peer.base                  = "/lantern";
    return peer;
}

static void v05_grants_peers_mirrors(void)
{
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    lantern_error error     = LANTERN_INIT(lantern_error);
    lantern_apps_page* page = NULL;
    REQUIRE_CALL(lantern_client_apps(d.client, NULL, &page, &error), LANTERN_OK, &error);
    REQUIRE(lantern_apps_page_get_items_count(page) > 1);
    const lantern_app* app = lantern_apps_page_get_items_at(page, 0);
    lantern_download_target target;
    target_of_app(app, &target);
    lantern_grant* grant = NULL;
    REQUIRE_CALL(lantern_client_grant(d.client, target.sha256, &grant, &error), LANTERN_OK, &error);
    uint64_t size = 0;
    CHECK(lantern_grant_get_size(grant, &size) && size == target.size);

    char host[64];
    const lantern_peer_endpoint peer = test_peer(host, sizeof(host));
    bool holds                       = false;
    REQUIRE_CALL(lantern_client_peer_holds(d.client, &peer, grant, &holds, &error), LANTERN_OK, &error);
    CHECK(holds);
    memory_sink sink;
    lantern_download_sink* out    = memory_sink_make(&sink);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_client_download_from_peer(d.client, &peer, grant, &target, state, out, &error),
        LANTERN_OK, &error);
    CHECK(sink.size == target.size);

    /* The grant of one file, for another: the peer says 403 */
    const lantern_app* other = lantern_apps_page_get_items_at(page, 1);
    uint8_t other_sha[32];
    uint64_t other_size = 0;
    char hex[65];
    lantern_app_get_sha256(other, other_sha);
    lantern_app_get_size(other, &other_size);
    lantern_digest_to_hex(other_sha, hex);
    char forged_text[2048];
    snprintf(forged_text, sizeof(forged_text),
        "{\"schema\":1,\"sha256\":\"%s\",\"size\":%llu,\"grant\":\"%s\",\"expires\":\"%s\"}", hex,
        (unsigned long long)other_size, lantern_grant_get_grant(grant).data,
        lantern_grant_get_expires(grant).data);
    lantern_grant* forged = NULL;
    REQUIRE_CALL(lantern_read_grant(forged_text, strlen(forged_text), NULL, NULL, &forged, &error),
        LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_peer_holds(d.client, &peer, forged, &holds, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 403);
    lantern_grant_free(forged);

    /* A mirror: the server's own file at another address, read untrusted */
    char mirror[512];
    snprintf(mirror, sizeof(mirror), "%s%s", env("LANTERN_TEST_PUBLIC"), target.url);
    memory_sink mirrored;
    lantern_download_sink* mirror_out    = memory_sink_make(&mirrored);
    lantern_download_state* mirror_state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &mirror_state, NULL), LANTERN_OK);
    REQUIRE_CALL(
        lantern_client_download_from_mirror(d.client, mirror, &target, mirror_state, mirror_out, &error),
        LANTERN_OK, &error);
    CHECK(mirrored.size == sink.size && memcmp(mirrored.bytes, sink.bytes, sink.size) == 0);
    /* With mirrors and then the server: none here, the server serves */
    memory_sink served;
    lantern_download_sink* served_out = memory_sink_make(&served);
    lantern_download_state_reset(mirror_state);
    REQUIRE_CALL(
        lantern_client_download_with_mirrors(d.client, NULL, 0, &target, mirror_state, served_out, &error),
        LANTERN_OK, &error);
    CHECK(served.size == sink.size);

    lantern_download_sink_free(served_out);
    memory_sink_clear(&served);
    lantern_download_sink_free(mirror_out);
    memory_sink_clear(&mirrored);
    lantern_download_state_free(mirror_state);
    lantern_download_sink_free(out);
    memory_sink_clear(&sink);
    lantern_download_state_free(state);
    lantern_grant_free(grant);
    lantern_apps_page_free(page);
    device_close(&d);
}

typedef struct peers_found
{
    int count;
    char name[64];
    char server[64];
    uint16_t port;
} peers_found;

static bool on_any_server(void* user, const lantern_discovered_server* server)
{
    (void)user;
    (void)server;
    return true;
}

static bool on_peer_found(void* user, const lantern_discovered_peer* peer)
{
    peers_found* found = user;
    ++found->count;
    snprintf(found->name, sizeof(found->name), "%s", lantern_peer_reply_get_name(peer->reply).data);
    snprintf(
        found->server, sizeof(found->server), "%s", lantern_peer_reply_get_servers_at(peer->reply, 0).data);
    found->port = peer->endpoint.port;
    CHECK(strcmp(peer->endpoint.base, "/lantern") == 0);
    return true;
}

static void v05_peer_discovery(void)
{
    lantern_udp_socket* socket = test_udp_socket();
    REQUIRE(socket != NULL);
    peers_found found                 = { 0, "", "", 0 };
    lantern_discovery_options options = LANTERN_INIT(lantern_discovery_options);
    options.address                   = "127.0.0.1";
    options.port                      = (uint16_t)atoi(env("LANTERN_TEST_PEER_DISCOVERY_PORT"));
    options.wait_ms                   = 1200;
    options.attempts                  = 2;
    options.peers                     = true;
    options.on_peer                   = on_peer_found;
    lantern_error error               = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_discover(socket, &options, on_any_server, &found, &error), LANTERN_OK, &error);
    REQUIRE(found.count == 1);
    CHECK(strcmp(found.name, "Lea's Switch") == 0);
    device d;
    OPEN(d, "LANTERN_TEST_PUBLIC", "switch", false);
    CHECK(STR_EQ(lantern_handshake_get_uid(lantern_client_server(d.client)), found.server));
    char host[64];
    CHECK(test_peer(host, sizeof(host)).port == found.port);
    device_close(&d);
    lantern_udp_socket_free(socket);
}

static void v05_sync(void)
{
    device lea;
    OPEN(lea, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error       = LANTERN_INIT(lantern_error);
    lantern_sync_state* state = NULL;
    CHECK_STATUS(lantern_client_sync_state(lea.client, &state, &error), LANTERN_ERROR_REFUSED);
    lantern_sync_consent consent = LANTERN_INIT(lantern_sync_consent);
    consent.sync                 = true;
    REQUIRE_CALL(lantern_client_set_sync_consent(lea.client, &consent, NULL, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_sync_state(lea.client, &state, &error), LANTERN_OK, &error);
    char generation[64];
    char device_id[64];
    snprintf(generation, sizeof(generation), "%s", lantern_sync_state_get_generation(state).data);
    snprintf(device_id, sizeof(device_id), "%s", lantern_sync_state_get_device(state).data);
    CHECK(strncmp(device_id, "d_", 2) == 0);
    lantern_sync_state_free(state);

    lantern_wish_input wish = LANTERN_INIT(lantern_wish_input);
    wish.platform           = "switch";
    wish.title_id           = FROSTLINE;
    wish.note               = "For the holidays";
    lantern_string* value   = NULL;
    lantern_string* key     = NULL;
    REQUIRE_STATUS(lantern_write_wish(&wish, NULL, &value, NULL), LANTERN_OK);
    REQUIRE_STATUS(lantern_wish_key("switch", FROSTLINE, NULL, &key, NULL), LANTERN_OK);
    char now[32];
    lantern_format_sync_time((int64_t)time(NULL) * 1000, now);
    const lantern_sync_item_input item
        = { lantern_string_view(key).data, lantern_string_view(value).data, false, now };
    lantern_sync_collection* written = NULL;
    REQUIRE_CALL(lantern_client_sync_write(lea.client, "wishes", &item, 1, false, 0, &written, &error),
        LANTERN_OK, &error);
    REQUIRE(lantern_sync_collection_get_items_count(written) == 1);
    uint64_t rev = 0;
    CHECK(lantern_sync_item_get_rev(lantern_sync_collection_get_items_at(written, 0), &rev) && rev > 0);
    uint64_t collection_rev = 0;
    lantern_sync_collection_get_rev(written, &collection_rev);
    lantern_wish* back       = NULL;
    const lantern_str stored = lantern_sync_item_get_value(lantern_sync_collection_get_items_at(written, 0));
    REQUIRE_CALL(lantern_read_wish(stored.data, stored.size, NULL, &back, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_wish_get_note(back), "For the holidays"));
    lantern_wish_free(back);
    lantern_sync_collection_free(written);

    lantern_sync_collection* changed = NULL;
    REQUIRE_CALL(lantern_client_sync_items(lea.client, "wishes", true, rev - 1, NULL, &changed, &error),
        LANTERN_OK, &error);
    bool found = false;
    for (size_t i = 0; i < lantern_sync_collection_get_items_count(changed); ++i)
        found = found
            || STR_EQ(lantern_sync_item_get_key(lantern_sync_collection_get_items_at(changed, i)),
                lantern_string_view(key).data);
    CHECK(found);
    lantern_sync_collection_free(changed);

    /* All or nothing: a stale If-Match changes nothing */
    CHECK_STATUS(lantern_client_sync_write(lea.client, "wishes", &item, 1, true, rev - 1, &written, &error),
        LANTERN_ERROR_PROTOCOL);
    CHECK(error.effective_code == LANTERN_CODE_PRECONDITION_FAILED);
    REQUIRE_CALL(
        lantern_client_sync_write(lea.client, "wishes", &item, 1, true, collection_rev, &written, &error),
        LANTERN_OK, &error);
    lantern_sync_collection_free(written);

    /* What is installed: only by name */
    lantern_installed_input installed = LANTERN_INIT(lantern_installed_input);
    installed.device                  = "Lea's Switch";
    installed.platform                = "switch";
    lantern_string* mine_value        = NULL;
    REQUIRE_STATUS(lantern_write_installed(&installed, NULL, &mine_value, NULL), LANTERN_OK);
    const lantern_sync_item_input mine = { device_id, lantern_string_view(mine_value).data, false, now };
    CHECK(lantern_client_sync_write(lea.client, "installed", &mine, 1, false, 0, &written, &error) < 0);
    consent.installed = true;
    REQUIRE_CALL(lantern_client_set_sync_consent(
                     lea.client, &consent, lantern_client_sync_generation(lea.client).data, &error),
        LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_sync_write(lea.client, "installed", &mine, 1, false, 0, &written, &error),
        LANTERN_OK, &error);
    lantern_sync_collection_free(written);

    /* Another console keeps the generation it read; Lea deletes everything */
    device other;
    OPEN(other, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_sync_consent only_sync = LANTERN_INIT(lantern_sync_consent);
    only_sync.sync                 = true;
    REQUIRE_CALL(
        lantern_client_set_sync_consent(other.client, &only_sync, generation, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_sync_delete(lea.client, NULL, &error), LANTERN_OK, &error);
    CHECK_STATUS(lantern_client_sync_items(other.client, "wishes", false, 0, NULL, &changed, &error),
        LANTERN_ERROR_REFUSED);
    lantern_sync_consent after = LANTERN_INIT(lantern_sync_consent);
    lantern_client_get_sync_consent(other.client, &after);
    CHECK(!after.sync);
    REQUIRE_CALL(lantern_client_sync_state(lea.client, &state, &error), LANTERN_OK, &error);
    CHECK(!STR_EQ(lantern_sync_state_get_generation(state), generation));
    lantern_sync_state_free(state);

    lantern_string_free(mine_value);
    lantern_string_free(value);
    lantern_string_free(key);
    device_close(&other);
    device_close(&lea);
}

static void v05_encrypted_backups(void)
{
    device lea;
    OPEN(lea, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error   = LANTERN_INIT(lantern_error);
    lantern_save_key* key = NULL;
    REQUIRE_CALL(lantern_save_key_generate(lea.random, NULL, &key, &error), LANTERN_OK, &error);
    const size_t archive_size = 2 * LANTERN_SAVE_CHUNK_SIZE + 1234;
    uint8_t* archive_bytes    = malloc(archive_size);
    REQUIRE(archive_bytes != NULL);
    for (size_t i = 0; i < archive_size; ++i)
        archive_bytes[i] = (uint8_t)((i * 31 + 7) % 253);
    uint8_t header[LANTERN_SAVE_HEADER_SIZE];
    REQUIRE_CALL(lantern_make_save_header(key, lea.random, header, &error), LANTERN_OK, &error);
    archive plain                     = { archive_bytes, archive_size, 0 };
    lantern_upload_source* clear      = source_of(&plain);
    lantern_upload_source* encrypting = NULL;
    REQUIRE_CALL(
        lantern_encrypting_source_create(key, header, clear, archive_size, NULL, &encrypting, &error),
        LANTERN_OK, &error);
    lantern_upload_request request = LANTERN_INIT(lantern_upload_request);
    request.kind                   = "account";
    REQUIRE_CALL(lantern_encrypting_source_describe(encrypting, &request, &error), LANTERN_OK, &error);
    lantern_upload_progress* progress = NULL;
    REQUIRE_STATUS(lantern_upload_progress_create(NULL, &progress, NULL), LANTERN_OK);
    lantern_save* save = NULL;
    REQUIRE_CALL(lantern_client_upload_resumable(
                     lea.client, FROSTLINE, &request, encrypting, progress, 50000, NULL, &save, &error),
        LANTERN_OK, &error);
    char id[17];
    lantern_save_key_id_text(key, id);
    const lantern_save_encryption* encryption = lantern_save_get_encryption(save);
    REQUIRE(encryption != NULL);
    CHECK(STR_EQ(lantern_save_encryption_get_key_id(encryption), id));
    uint64_t size = 0;
    CHECK(lantern_save_get_size(save, &size) && size == lantern_encrypted_save_size(archive_size));

    /* Opened as it downloads: the archive, whole */
    memory_sink restored;
    lantern_download_sink* out     = memory_sink_make(&restored);
    lantern_download_sink* opening = NULL;
    REQUIRE_STATUS(lantern_decrypting_sink_create(key, out, NULL, &opening, NULL), LANTERN_OK);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_client_download_save(lea.client, save, state, opening, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_decrypting_sink_finish(opening, &error), LANTERN_OK, &error);
    CHECK(restored.size == archive_size && memcmp(restored.bytes, archive_bytes, archive_size) == 0);

    /* Another key opens nothing */
    lantern_save_key* other = NULL;
    REQUIRE_STATUS(lantern_save_key_generate(lea.random, NULL, &other, NULL), LANTERN_OK);
    memory_sink nothing;
    lantern_download_sink* nothing_out = memory_sink_make(&nothing);
    lantern_download_sink* wrong       = NULL;
    REQUIRE_STATUS(lantern_decrypting_sink_create(other, nothing_out, NULL, &wrong, NULL), LANTERN_OK);
    lantern_download_state* again = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &again, NULL), LANTERN_OK);
    CHECK(lantern_client_download_save(lea.client, save, again, wrong, &error) < 0);
    CHECK(nothing.size == 0);

    /* A small one in one request, with Lantern-Save-Encryption */
    const char* small = "Frostline Tales, chapter 3";
    uint8_t small_header[LANTERN_SAVE_HEADER_SIZE];
    REQUIRE_STATUS(lantern_make_save_header(key, lea.random, small_header, NULL), LANTERN_OK);
    lantern_string* sealed = NULL;
    REQUIRE_STATUS(
        lantern_encrypt_save(key, small_header, (const uint8_t*)small, strlen(small), NULL, &sealed, NULL),
        LANTERN_OK);
    lantern_save_info info = LANTERN_INIT(lantern_save_info);
    info.kind              = "account";
    info.encryption_key_id = id;
    lantern_save* one      = NULL;
    REQUIRE_CALL(
        lantern_client_upload_save(lea.client, FROSTLINE, (const uint8_t*)lantern_string_view(sealed).data,
            lantern_string_view(sealed).size, &info, &one, &error),
        LANTERN_OK, &error);
    CHECK(lantern_save_get_encryption(one) != NULL);
    REQUIRE_CALL(lantern_client_delete_save(lea.client, one, &error), LANTERN_OK, &error);
    REQUIRE_CALL(lantern_client_delete_save(lea.client, save, &error), LANTERN_OK, &error);

    lantern_save_free(one);
    lantern_string_free(sealed);
    lantern_download_state_free(again);
    lantern_download_sink_free(wrong);
    lantern_download_sink_free(nothing_out);
    memory_sink_clear(&nothing);
    lantern_save_key_free(other);
    lantern_download_state_free(state);
    lantern_download_sink_free(opening);
    lantern_download_sink_free(out);
    memory_sink_clear(&restored);
    lantern_save_free(save);
    lantern_upload_progress_free(progress);
    lantern_upload_source_free(encrypting);
    lantern_upload_source_free(clear);
    free(archive_bytes);
    lantern_save_key_free(key);
    device_close(&lea);
}

static void v05_account_deletion(void)
{
    device lea;
    OPEN(lea, "LANTERN_TEST_PRIVATE", "switch", true);
    lantern_error error              = LANTERN_INIT(lantern_error);
    const char* const scopes[]       = { "library" };
    lantern_admin_user_create create = LANTERN_INIT(lantern_admin_user_create);
    create.name                      = "ines";
    create.scopes                    = scopes;
    create.scope_count               = 1;
    lantern_admin_user* user         = NULL;
    REQUIRE_CALL(lantern_client_admin_create_user(lea.client, &create, &user, &error), LANTERN_OK, &error);
    lantern_admin_user_free(user);
    CHECK(lantern_client_admin_delete_user(lea.client, "ines", "ine", &error) < 0);
    REQUIRE_CALL(lantern_client_admin_delete_user(lea.client, "ines", "ines", &error), LANTERN_OK, &error);
    lantern_admin_users* users = NULL;
    REQUIRE_CALL(lantern_client_admin_users(lea.client, NULL, &users, &error), LANTERN_OK, &error);
    for (size_t i = 0; i < lantern_admin_users_get_items_count(users); ++i)
        CHECK(!STR_EQ(lantern_admin_user_get_name(lantern_admin_users_get_items_at(users, i)), "ines"));
    lantern_admin_users_free(users);
    CHECK_STATUS(
        lantern_client_admin_delete_user(lea.client, "ines", "ines", &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 404);
    CHECK_STATUS(
        lantern_client_admin_delete_user(lea.client, "mila", "mila", &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 409);
    device_close(&lea);
}

/* A static library's folder, read through the device's own files. */
static int folder_reads;
static lantern_status folder_read(
    void* user, lantern_str path, uint64_t offset, lantern_download_sink* sink, bool* found)
{
    const char* root = user;
    ++folder_reads;
    if (!lantern_is_static_path(path.data))
        return LANTERN_ERROR_INVALID_RESPONSE;
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", root, path.data);
    FILE* file = fopen(full, "rb");
    if (file == NULL)
    {
        *found = false;
        return LANTERN_OK;
    }
    if (offset != 0 && fseek(file, (long)offset, SEEK_SET) != 0)
    {
        fclose(file);
        return LANTERN_ERROR_STORAGE;
    }
    uint8_t buffer[4096];
    size_t got = 0;
    while ((got = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        if (lantern_download_sink_write(sink, buffer, got, NULL) != LANTERN_OK)
        {
            fclose(file);
            return LANTERN_ERROR_STORAGE;
        }
    }
    fclose(file);
    return LANTERN_OK;
}

static int compare_ids(const void* a, const void* b)
{
    return strcmp((const char*)a, (const char*)b);
}

static void v05_static_library(void)
{
    lantern_transport* transport = test_loopback_transport(0);
    REQUIRE(transport != NULL);
    lantern_error error        = LANTERN_INIT(lantern_error);
    lantern_static_files* http = NULL;
    REQUIRE_CALL(lantern_static_files_create_http(
                     transport, env("LANTERN_TEST_STATIC"), "LanternCTests/0.5", NULL, &http, &error),
        LANTERN_OK, &error);
    lantern_static_files_callbacks callbacks = LANTERN_INIT(lantern_static_files_callbacks);
    char root[512];
    snprintf(root, sizeof(root), "%s", env("LANTERN_TEST_STATIC_DIR"));
    callbacks.user               = root;
    callbacks.read               = folder_read;
    lantern_static_files* folder = NULL;
    REQUIRE_STATUS(lantern_static_files_create(&callbacks, NULL, &folder, NULL), LANTERN_OK);
    device server;
    OPEN(server, "LANTERN_TEST_PUBLIC", "switch", false);
    lantern_static_files* sources[] = { http, folder };
    folder_reads                    = 0;
    for (size_t s = 0; s < 2; ++s)
    {
        lantern_static_library* library = NULL;
        REQUIRE_CALL(
            lantern_static_library_open(sources[s], NULL, NULL, &library, &error), LANTERN_OK, &error);
        const lantern_handshake* shake = lantern_static_library_handshake(library);
        CHECK(STR_EQ(lantern_handshake_get_base(shake), "."));
        uint64_t page_size = 0;
        CHECK(lantern_handshake_static_get_page_size(lantern_handshake_get_static(shake), &page_size)
            && page_size == 2);

        /* Every page of the Switch's apps, chained by their cursors */
        char cursor[256]         = "";
        lantern_apps_page* first = NULL;
        size_t apps              = 0;
        for (int pages = 0; pages < 1000; ++pages)
        {
            lantern_apps_page* page = NULL;
            REQUIRE_CALL(
                lantern_static_library_apps(library, "switch", cursor, &page, &error), LANTERN_OK, &error);
            apps += lantern_apps_page_get_items_count(page);
            snprintf(cursor, sizeof(cursor), "%s", lantern_apps_page_get_next(page).data);
            if (first == NULL)
                first = page;
            else
                lantern_apps_page_free(page);
            if (cursor[0] == '\0')
                break;
        }
        REQUIRE(apps > 0);

        /* What a Switch with Frostline Tales 1.0 is missing: as the server says */
        const lantern_installed_app installed[] = { { FROSTLINE, 0 } };
        const char* const want[]                = { "update", "dlc", "base" };
        lantern_missing_request request         = LANTERN_INIT(lantern_missing_request);
        request.installed                       = installed;
        request.installed_count                 = 1;
        request.want                            = want;
        request.want_count                      = 3;
        lantern_app_list* computed              = NULL;
        REQUIRE_CALL(lantern_static_library_missing(library, "switch", &request, &computed, &error),
            LANTERN_OK, &error);
        lantern_apps_page* answered = NULL;
        REQUIRE_CALL(lantern_client_missing(server.client, &request, NULL, NULL, &answered, &error),
            LANTERN_OK, &error);
        REQUIRE(lantern_app_list_count(computed) == lantern_apps_page_get_items_count(answered));
        char ours[16][64];
        char theirs[16][64];
        memset(ours, 0, sizeof(ours));
        memset(theirs, 0, sizeof(theirs));
        const size_t count = lantern_app_list_count(computed);
        REQUIRE(count <= 16);
        for (size_t i = 0; i < count; ++i)
        {
            snprintf(ours[i], 64, "%s", lantern_app_get_app_id(lantern_app_list_at(computed, i)).data);
            snprintf(theirs[i], 64, "%s",
                lantern_app_get_app_id(lantern_apps_page_get_items_at(answered, i)).data);
        }
        qsort(ours, count, 64, compare_ids);
        qsort(theirs, count, 64, compare_ids);
        CHECK(memcmp(ours, theirs, count * 64) == 0);
        lantern_app_list_free(computed);
        lantern_apps_page_free(answered);

        /* A file, checked; a title and a homebrew entry where § 21.1 puts them */
        const lantern_app* app = lantern_apps_page_get_items_at(first, 0);
        lantern_download_target target;
        target_of_app(app, &target);
        memory_sink sink;
        lantern_download_sink* out    = memory_sink_make(&sink);
        lantern_download_state* state = NULL;
        REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
        REQUIRE_CALL(
            lantern_static_library_download(library, &target, state, out, &error), LANTERN_OK, &error);
        CHECK(sink.size == target.size);
        lantern_title* title = NULL;
        REQUIRE_CALL(lantern_static_library_title(
                         library, "switch", lantern_app_get_title_id(app).data, &title, &error),
            LANTERN_OK, &error);
        lantern_title_free(title);
        lantern_homebrew_page* homebrew = NULL;
        REQUIRE_CALL(
            lantern_static_library_homebrew(library, "switch", NULL, &homebrew, &error), LANTERN_OK, &error);
        REQUIRE(lantern_homebrew_page_get_items_count(homebrew) > 0);
        lantern_homebrew* entry = NULL;
        REQUIRE_CALL(lantern_static_library_homebrew_entry(library, "switch",
                         lantern_homebrew_get_id(lantern_homebrew_page_get_items_at(homebrew, 0)).data,
                         &entry, &error),
            LANTERN_OK, &error);
        lantern_install_plan* plan = NULL;
        CHECK_CALL(lantern_plan_install(entry, lantern_homebrew_get_package(entry), NULL, &plan, &error),
            LANTERN_OK, &error);
        lantern_install_plan_free(plan);
        const lantern_installed_homebrew old[]   = { { lantern_homebrew_get_id(entry).data, 0 } };
        lantern_homebrew_updates_request updates = LANTERN_INIT(lantern_homebrew_updates_request);
        updates.installed                        = old;
        updates.installed_count                  = 1;
        lantern_homebrew_list* newer             = NULL;
        REQUIRE_CALL(lantern_static_library_homebrew_updates(library, "switch", &updates, &newer, &error),
            LANTERN_OK, &error);
        CHECK(lantern_homebrew_list_count(newer) == 1);
        lantern_homebrew_list_free(newer);
        lantern_homebrew_free(entry);
        lantern_homebrew_page_free(homebrew);
        lantern_cheat_sets* cheats = NULL;
        CHECK(lantern_static_library_cheats(library, "switch", FROSTLINE, &cheats, &error) >= 0);
        lantern_cheat_sets_free(cheats);
        lantern_download_state_free(state);
        lantern_download_sink_free(out);
        memory_sink_clear(&sink);
        lantern_apps_page_free(first);
        lantern_static_library_free(library);
    }
    CHECK(folder_reads > 0);
    device_close(&server);
    lantern_static_files_free(folder);
    lantern_static_files_free(http);
    lantern_transport_free(transport);
}

int main(int argc, char** argv)
{
    static const test_case tests[] = {
        { "integration: a public server's handshake", public_handshake },
        { "integration: apps by their cursors", apps_by_their_cursors },
        { "integration: missing, changes, titles", missing_changes_titles },
        { "integration: a download, cut and resumed", downloads_cut_and_resumed },
        { "integration: homebrew planned, signed, ported, updated", homebrew_planned_signed_and_ported },
        { "integration: Harbor Lights per architecture", harbor_lights_per_architecture },
        { "integration: a private server, its token and key", a_private_server },
        { "integration: pairing approved by an admin, signed in, revoked", pairing_approved_by_an_admin },
        { "integration: invitations, frozen accounts", invitations },
        { "integration: a clock an hour off", a_clock_an_hour_off },
        { "integration: saves, whole and resumable", saves },
        { "integration: cheat sets written", cheats_written },
        { "integration: requests", requests },
        { "integration: discovery on loopback", discovery_on_loopback },
        { "integration v05: the handshake's new families and limits", v05_families },
        { "integration v05: the event stream, resumed, and long polling", v05_events },
        { "integration v05: a grant, the peer's file with it, a mirror", v05_grants_peers_mirrors },
        { "integration v05: the peer answers discovery", v05_peer_discovery },
        { "integration v05: sync with consent, If-Match, deletion, the generation", v05_sync },
        { "integration v05: an encrypted backup, resumable and whole, opened back", v05_encrypted_backups },
        { "integration v05: an account deleted, its name typed again", v05_account_deletion },
        { "integration v05: the static library, over HTTP and from its folder", v05_static_library },
    };
    const test_case* const lists[] = { tests };
    const size_t counts[]          = { sizeof(tests) / sizeof(tests[0]) };
    return test_main(argc, argv, lists, counts, 1);
}
