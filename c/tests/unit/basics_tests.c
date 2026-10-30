/* Versions, errors, strings and digests, memory, and the struct_size rule. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"

static void versions(void)
{
    CHECK(lantern_version() == LANTERN_C_API_VERSION);
    CHECK(strcmp(lantern_version_string(), LANTERN_VERSION_STRING) == 0);
    CHECK(strcmp(lantern_spec_draft(), "0.5") == 0);
    CHECK(LANTERN_KNOWN_SCHEMA == 1);
}

static void statuses_and_codes(void)
{
    CHECK(strcmp(lantern_status_name(LANTERN_OK), "ok") == 0);
    CHECK(strcmp(lantern_status_name(LANTERN_ABSENT), "absent") == 0);
    CHECK(strcmp(lantern_status_name(LANTERN_ERROR_PROTOCOL), "protocol") == 0);
    CHECK(strcmp(lantern_status_name(LANTERN_ERROR_MEMORY), "memory") == 0);
    CHECK(strcmp(lantern_status_name(-99), "") == 0);
    for (lantern_code code = LANTERN_CODE_BAD_REQUEST; code < LANTERN_CODE_UNKNOWN; ++code)
        CHECK(lantern_code_from_name(lantern_code_name(code)) == code);
    CHECK(strcmp(lantern_code_name(LANTERN_CODE_ACCOUNT_FROZEN), "account_frozen") == 0);
    CHECK(strcmp(lantern_code_name(LANTERN_CODE_NONE), "") == 0);
    CHECK(strcmp(lantern_code_name(1000), "") == 0);
    CHECK(lantern_code_from_name("a_code_of_draft_9") == LANTERN_CODE_UNKNOWN);
    CHECK(lantern_code_from_name(NULL) == LANTERN_CODE_UNKNOWN);
    CHECK(lantern_code_for_status(404) == LANTERN_CODE_NOT_FOUND);
    CHECK(lantern_code_for_status(429) == LANTERN_CODE_SLOW_DOWN);
}

static void errors(void)
{
    lantern_error error;
    memset(&error, 0x55, sizeof(error));
    lantern_error_init(&error);
    CHECK(error.struct_size == sizeof(lantern_error));
    CHECK(error.status == LANTERN_OK);
    CHECK(error.detail[0] == '\0');

    /* A local error: its category and detail, nothing of a server */
    uint8_t digest[32];
    CHECK_STATUS(lantern_spki_sha256_pem("not a certificate", digest, &error), LANTERN_ERROR_USAGE);
    CHECK(error.status != LANTERN_OK);
    CHECK(error.http_status == 0);
    CHECK(error.code == LANTERN_CODE_NONE);
    CHECK(strlen(error.detail) > 0);
    /* Success clears it */
    lantern_trust* trust = NULL;
    CHECK_STATUS(lantern_trust_create(NULL, &trust, &error), LANTERN_OK);
    CHECK(error.status == LANTERN_OK && error.detail[0] == '\0');
    lantern_trust_free(trust);

    /* An error of an older header, shorter: nothing written past its end */
    union
    {
        lantern_error error;
        unsigned char bytes[sizeof(lantern_error) + 8];
    } shorter;
    unsigned char* buffer = shorter.bytes;
    memset(buffer, 0xAB, sizeof(shorter.bytes));
    lantern_error* old = &shorter.error;
    old->struct_size   = offsetof(lantern_error, title);
    CHECK_STATUS(lantern_spki_sha256_pem("still not one", digest, old), LANTERN_ERROR_USAGE);
    CHECK(old->status == LANTERN_ERROR_USAGE);
    CHECK(old->struct_size == offsetof(lantern_error, title));
    for (size_t i = offsetof(lantern_error, title); i < sizeof(shorter.bytes); ++i)
        CHECK(buffer[i] == 0xAB);

    /* An app's callback sets one; a detail too long is cut at a character */
    lantern_error_init(&error);
    char long_detail[400];
    memset(long_detail, 'a', sizeof(long_detail));
    long_detail[199]                     = '\xC3'; /* é across the cut, after 200 bytes */
    long_detail[200]                     = '\xA9';
    long_detail[sizeof(long_detail) - 1] = '\0';
    lantern_error_set(&error, LANTERN_ERROR_STORAGE, long_detail);
    CHECK(error.status == LANTERN_ERROR_STORAGE);
    CHECK(strlen(error.detail) == 199);
    lantern_error_set(NULL, LANTERN_ERROR_STORAGE, "nothing");
}

static void digests(void)
{
    uint8_t digest[32];
    lantern_sha256((const uint8_t*)"abc", 3, digest);
    char hex[65];
    lantern_digest_to_hex(digest, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    uint8_t back[32];
    CHECK(lantern_digest_from_hex(hex, back));
    CHECK(memcmp(back, digest, 32) == 0);
    CHECK(!lantern_digest_from_hex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", back));
    CHECK(!lantern_digest_from_hex("ba78", back));
    CHECK(!lantern_digest_from_hex(NULL, back));

    char field[55];
    lantern_format_digest_field(digest, field);
    CHECK(strcmp(field, "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:") == 0);
    uint8_t parsed[32];
    CHECK(lantern_parse_digest_field(field, parsed) == LANTERN_DIGEST_FIELD_SHA256);
    CHECK(memcmp(parsed, digest, 32) == 0);
    CHECK(lantern_parse_digest_field("sha-512=:AAAA:", parsed) == LANTERN_DIGEST_FIELD_ABSENT);
    CHECK(lantern_parse_digest_field("sha-256=:AAAA:", parsed) == LANTERN_DIGEST_FIELD_MALFORMED);

    char short_form[20];
    lantern_short_form(digest, short_form);
    CHECK(strcmp(short_form, "BA78 16BF 8F01 CFEA") == 0);
}

static void strings_owned(void)
{
    lantern_string* origin = NULL;
    lantern_error error    = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_discovered_origin("fe80::1", 8443, NULL, &origin, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(origin), "https://[fe80::1]:8443"));
    lantern_string_free(origin);
    lantern_string_free(NULL);
    CHECK(STR_EQ(lantern_string_view(NULL), ""));
    CHECK(lantern_strings_count(NULL) == 0);
    CHECK(STR_EQ(lantern_strings_at(NULL, 3), ""));
    lantern_strings_free(NULL);
}

/* Every object made with the app's allocator goes back to it. */
static void allocator_counts_everything(void)
{
    counting_allocator counter        = { 0 };
    const lantern_allocator allocator = counting_allocator_make(&counter);
    size_t size                       = 0;
    char* text                        = spec_file("examples/v1/homebrew-page.json", &size);
    REQUIRE(text != NULL);
    lantern_homebrew_page* page = NULL;
    lantern_error error         = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_read_homebrew_page(text, size, NULL, &allocator, &page, &error), LANTERN_OK, &error);
    CHECK(counter.live > 0);
    lantern_trust* trust = NULL;
    CHECK_STATUS(lantern_trust_create(&allocator, &trust, NULL), LANTERN_OK);
    lantern_string* uri = NULL;
    CHECK_STATUS(
        lantern_target_uri("https://shelf.example.org:443/api/lantern/v1/apps?x=1", &allocator, &uri, NULL),
        LANTERN_OK);
    CHECK(STR_EQ(lantern_string_view(uri), "https://shelf.example.org/api/lantern/v1/apps?x=1"));
    lantern_homebrew_page_free(page);
    lantern_trust_free(trust);
    lantern_string_free(uri);
    CHECK(counter.live == 0);
    CHECK(counter.bytes == 0);
    CHECK(counter.total > 3);
    free(text);

    /* An allocator without its functions is refused */
    lantern_allocator broken = LANTERN_INIT(lantern_allocator);
    CHECK_STATUS(lantern_trust_create(&broken, &trust, NULL), LANTERN_ERROR_USAGE);
    CHECK(trust == NULL);
}

/* A document lives on after the client it came from. */
static void documents_outlive_their_client(void)
{
    counting_allocator counter        = { 0 };
    const lantern_allocator allocator = counting_allocator_make(&counter);
    fake_server server;
    fake_init(&server, "https://shelf.example.org");
    char* handshake = spec_file("examples/v1/handshake.json", NULL);
    REQUIRE(handshake != NULL);
    fake_add(&server, "GET", "/.well-known/lantern", 200, handshake);
    lantern_transport* transport = fake_transport(&server, &allocator);
    REQUIRE(transport != NULL);
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = "https://shelf.example.org";
    config.user_agent            = "LanternCTests/0.4";
    config.transport             = transport;
    config.allocator             = &allocator;
    lantern_client* client       = NULL;
    lantern_error error          = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_create(&config, &client, &error), LANTERN_OK, &error);
    lantern_handshake* shake = NULL;
    REQUIRE_CALL(lantern_client_handshake(client, &shake, &error), LANTERN_OK, &error);
    lantern_client_free(client);
    lantern_transport_free(transport);
    CHECK(server.released);
    CHECK(counter.live > 0);
    CHECK(STR_EQ(lantern_handshake_get_name(shake), "Living room shelf"));
    lantern_handshake_free(shake);
    CHECK(counter.live == 0);
    free(handshake);
}

/* A struct of an older header, shorter, is read as far as it goes: what it
 * does not have keeps its default. */
static void struct_size_rule(void)
{
    fake_server server;
    fake_init(&server, "https://shelf.example.org");
    char* handshake = spec_file("examples/v1/handshake.json", NULL);
    char* apps      = spec_file("examples/v1/apps.json", NULL);
    REQUIRE(handshake != NULL && apps != NULL);
    fake_add(&server, "GET", "/.well-known/lantern", 200, handshake);
    fake_add(&server, "GET", "/api/lantern/v1/apps*", 200, apps);
    lantern_transport* transport      = fake_transport(&server, NULL);
    counting_allocator counter        = { 0 };
    const lantern_allocator allocator = counting_allocator_make(&counter);
    lantern_client_config config      = LANTERN_INIT(lantern_client_config);
    config.origin                     = "https://shelf.example.org";
    config.user_agent                 = "LanternCTests/0.4";
    config.platform                   = "switch";
    config.transport                  = transport;
    config.allocator                  = &allocator;
    /* As an older header's: it stops after the transport, and the
     * allocator past its end is not looked at */
    config.struct_size     = offsetof(lantern_client_config, transport) + sizeof(config.transport);
    lantern_client* client = NULL;
    REQUIRE_STATUS(lantern_client_create(&config, &client, NULL), LANTERN_OK);
    lantern_handshake* shake = NULL;
    REQUIRE_STATUS(lantern_client_handshake(client, &shake, NULL), LANTERN_OK);
    char value[64];
    CHECK(fake_last_header(&server, "Lantern-Platform", value, sizeof(value)) != NULL);
    CHECK(counter.total == 0);

    lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
    query.title_id           = "0100ABCD00010000";
    query.cursor             = "c_never-sent";
    query.struct_size        = offsetof(lantern_apps_query, page_size);
    lantern_apps_page* page  = NULL;
    REQUIRE_STATUS(lantern_client_apps(client, &query, &page, NULL), LANTERN_OK);
    CHECK(strstr(server.last_url, "title_id=0100ABCD00010000") != NULL);
    CHECK(strstr(server.last_url, "cursor") == NULL);
    lantern_apps_page_free(page);
    lantern_handshake_free(shake);
    lantern_client_free(client);
    lantern_transport_free(transport);
    free(handshake);
    free(apps);
}

static int releases;
static void count_release(void* user)
{
    (void)user;
    ++releases;
}
static lantern_status fill_zero(void* user, uint8_t* out, size_t size)
{
    (void)user;
    memset(out, 7, size);
    return LANTERN_OK;
}
static int64_t fixed_time(void* user)
{
    (void)user;
    return 1793345400;
}

/* Callbacks objects: the functions they need, and release when freed. */
static void callbacks_objects(void)
{
    lantern_random_callbacks random = LANTERN_INIT(lantern_random_callbacks);
    lantern_random* made            = NULL;
    CHECK_STATUS(lantern_random_create(&random, NULL, &made, NULL), LANTERN_ERROR_USAGE);
    CHECK(made == NULL);
    CHECK_STATUS(lantern_random_create(NULL, NULL, &made, NULL), LANTERN_ERROR_USAGE);
    random.fill    = fill_zero;
    random.release = count_release;
    releases       = 0;
    REQUIRE_STATUS(lantern_random_create(&random, NULL, &made, NULL), LANTERN_OK);
    lantern_random_free(made);
    CHECK(releases == 1);

    lantern_clock_callbacks clock = LANTERN_INIT(lantern_clock_callbacks);
    clock.unix_seconds            = fixed_time;
    clock.release                 = count_release;
    lantern_clock* made_clock     = NULL;
    REQUIRE_STATUS(lantern_clock_create(&clock, NULL, &made_clock, NULL), LANTERN_OK);
    lantern_clock_free(made_clock);
    CHECK(releases == 2);

    lantern_credential_callbacks store = LANTERN_INIT(lantern_credential_callbacks);
    lantern_credential_store* kept     = NULL;
    CHECK_STATUS(lantern_credential_store_create(&store, NULL, &kept, NULL), LANTERN_ERROR_USAGE);
    lantern_pin_callbacks pins = LANTERN_INIT(lantern_pin_callbacks);
    lantern_pin_store* pinned  = NULL;
    CHECK_STATUS(lantern_pin_store_create(&pins, NULL, &pinned, NULL), LANTERN_ERROR_USAGE);
    lantern_upload_callbacks upload = LANTERN_INIT(lantern_upload_callbacks);
    lantern_upload_source* source   = NULL;
    CHECK_STATUS(lantern_upload_source_create(&upload, NULL, &source, NULL), LANTERN_ERROR_USAGE);
    lantern_deprecation_callbacks log = LANTERN_INIT(lantern_deprecation_callbacks);
    lantern_deprecation_log* logged   = NULL;
    CHECK_STATUS(lantern_deprecation_log_create(&log, NULL, &logged, NULL), LANTERN_ERROR_USAGE);
    lantern_data_probe_callbacks probe = LANTERN_INIT(lantern_data_probe_callbacks);
    lantern_data_probe* probed         = NULL;
    CHECK_STATUS(lantern_data_probe_create(&probe, NULL, &probed, NULL), LANTERN_ERROR_USAGE);
    lantern_udp_callbacks udp = LANTERN_INIT(lantern_udp_callbacks);
    lantern_udp_socket* sock  = NULL;
    CHECK_STATUS(lantern_udp_socket_create(&udp, NULL, &sock, NULL), LANTERN_ERROR_USAGE);
    lantern_transport_callbacks transport = LANTERN_INIT(lantern_transport_callbacks);
    lantern_transport* sent               = NULL;
    CHECK_STATUS(lantern_transport_create(&transport, NULL, &sent, NULL), LANTERN_ERROR_USAGE);
    CHECK(sent == NULL);

    /* Every free takes NULL */
    lantern_random_free(NULL);
    lantern_clock_free(NULL);
    lantern_credential_store_free(NULL);
    lantern_pin_store_free(NULL);
    lantern_deprecation_log_free(NULL);
    lantern_download_sink_free(NULL);
    lantern_upload_source_free(NULL);
    lantern_data_probe_free(NULL);
    lantern_udp_socket_free(NULL);
    lantern_transport_free(NULL);
    lantern_trust_free(NULL);
    lantern_client_free(NULL);
    lantern_pairing_free(NULL);
    lantern_device_key_free(NULL);
    lantern_download_state_free(NULL);
    lantern_upload_progress_free(NULL);
    lantern_install_plan_free(NULL);
    lantern_launch_check_free(NULL);
    lantern_requires_check_free(NULL);
    lantern_handshake_free(NULL);
}

/* A NULL where an object is needed is a usage error, never a crash. */
static void null_arguments(void)
{
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_client_create(NULL, NULL, &error), LANTERN_ERROR_USAGE);
    lantern_client* client       = NULL;
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = "https://shelf.example.org";
    config.user_agent            = "LanternCTests/0.4";
    CHECK_STATUS(lantern_client_create(&config, &client, &error), LANTERN_ERROR_USAGE);
    CHECK(client == NULL);
    CHECK_STATUS(lantern_client_handshake(NULL, NULL, &error), LANTERN_ERROR_USAGE);
    lantern_apps_page* page = NULL;
    CHECK_STATUS(lantern_client_apps(NULL, NULL, &page, &error), LANTERN_ERROR_USAGE);
    CHECK(lantern_client_server(NULL) == NULL);
    CHECK(lantern_client_offers(NULL, LANTERN_FAMILY_LIBRARY) == 0);
    CHECK(!lantern_client_has_token(NULL));
    CHECK(STR_EQ(lantern_app_get_name(NULL), ""));
    uint64_t number = 0;
    CHECK(!lantern_app_get_size(NULL, &number));
    CHECK(lantern_apps_page_get_items_count(NULL) == 0);
    CHECK(lantern_apps_page_get_items_at(NULL, 0) == NULL);
}

const test_case basics_tests[] = {
    { "basics: versions", versions },
    { "basics: statuses and codes", statuses_and_codes },
    { "basics: errors, struct_size included", errors },
    { "basics: digests and fingerprints", digests },
    { "basics: strings the library makes", strings_owned },
    { "basics: the app's allocator, counted", allocator_counts_everything },
    { "basics: documents outlive their client", documents_outlive_their_client },
    { "basics: a struct of an older header", struct_size_rule },
    { "basics: callbacks objects", callbacks_objects },
    { "basics: NULL arguments", null_arguments },
};
const size_t basics_test_count = sizeof(basics_tests) / sizeof(basics_tests[0]);
