/* Discovery (SPEC.md § 4.1), the library's transports, and the files an
 * app keeps to resume (their `schema` rule). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"

static void datagrams(void)
{
    CHECK(STR_EQ(lantern_discovery_request(), "{\"schema\":1,\"lantern\":\"discover\"}"));
    size_t size = 0;
    char* text  = spec_file("examples/v1/discovery.json", &size);
    REQUIRE(text != NULL);
    lantern_discovery_reply* reply = NULL;
    lantern_error error            = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_read_discovery_datagram((const uint8_t*)text, size, NULL, &reply, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_discovery_reply_get_name(reply), "Living room shelf"));
    uint64_t port = 0;
    CHECK(lantern_discovery_reply_get_port(reply, &port) && port == 443);
    lantern_discovery_reply_free(reply);

    const char* newer = "{\"schema\":2,\"lantern\":\"server\",\"what\":\"of later\"}";
    CHECK_STATUS(lantern_read_discovery_datagram((const uint8_t*)newer, strlen(newer), NULL, &reply, &error),
        LANTERN_ABSENT);
    CHECK(reply == NULL);
    const char* other = "{\"schema\":1,\"lantern\":\"discover\"}";
    CHECK(lantern_read_discovery_datagram((const uint8_t*)other, strlen(other), NULL, &reply, &error) < 0);
    free(text);

    lantern_string* origin = NULL;
    REQUIRE_CALL(lantern_discovered_origin("192.168.1.20", 8443, NULL, &origin, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(origin), "https://192.168.1.20:8443"));
    lantern_string_free(origin);
}

/* A LAN of one server, as a UDP socket sees it. */
typedef struct lan
{
    int sent;
    int received;
    char reply[256];
} lan;

static lantern_status lan_send(
    void* user, const char* address, uint16_t port, const uint8_t* bytes, size_t size)
{
    lan* net = user;
    CHECK(strcmp(address, "192.168.1.255") == 0);
    CHECK(port == 47115);
    CHECK(size == strlen("{\"schema\":1,\"lantern\":\"discover\"}"));
    CHECK(memcmp(bytes, "{\"schema\":1", 11) == 0);
    ++net->sent;
    return LANTERN_OK;
}

static lantern_status lan_receive(
    void* user, uint8_t* buffer, size_t capacity, uint32_t timeout_ms, lantern_datagram* out, bool* received)
{
    (void)timeout_ms;
    lan* net = user;
    /* The server answers each request: the client keeps one */
    if (net->received >= net->sent)
    {
        *received = false;
        return LANTERN_OK;
    }
    ++net->received;
    const size_t size = strlen(net->reply);
    if (size > capacity)
        return LANTERN_ERROR_TRANSPORT;
    memcpy(buffer, net->reply, size);
    out->size = size;
    snprintf(out->address, sizeof(out->address), "192.168.1.20");
    out->port = 47115;
    *received = true;
    return LANTERN_OK;
}

static int servers;
static bool on_server(void* user, const lantern_discovered_server* server)
{
    (void)user;
    ++servers;
    CHECK(STR_EQ(server->address, "192.168.1.20"));
    CHECK(STR_EQ(server->origin, "https://192.168.1.20:8443"));
    CHECK(STR_EQ(lantern_discovery_reply_get_name(server->reply), "Ines's shelf"));
    return true;
}

static void discovery_over_the_apps_socket(void)
{
    lan net = { 0, 0, "" };
    snprintf(net.reply, sizeof(net.reply),
        "{\"schema\":1,\"lantern\":\"server\",\"uid\":\"6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14\","
        "\"name\":\"Ines's shelf\",\"port\":8443,\"base\":\"/api/lantern\",\"versions\":[1]}");
    lantern_udp_callbacks callbacks = LANTERN_INIT(lantern_udp_callbacks);
    callbacks.user                  = &net;
    callbacks.send_to               = lan_send;
    callbacks.receive               = lan_receive;
    lantern_udp_socket* socket      = NULL;
    REQUIRE_STATUS(lantern_udp_socket_create(&callbacks, NULL, &socket, NULL), LANTERN_OK);
    lantern_discovery_options options = LANTERN_INIT(lantern_discovery_options);
    options.address                   = "192.168.1.255";
    options.wait_ms                   = 300;
    options.attempts                  = 3;
    servers                           = 0;
    lantern_error error               = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_discover(socket, &options, on_server, NULL, &error), LANTERN_OK, &error);
    CHECK(net.sent >= 1);
    CHECK(servers == 1); /* each server once */
    lantern_udp_socket_free(socket);
}

static void the_librarys_transports(void)
{
    lantern_transport* transport = NULL;
    lantern_error error          = LANTERN_INIT(lantern_error);
    if (lantern_has_transport(LANTERN_TRANSPORT_CURL))
    {
        REQUIRE_CALL(lantern_curl_global_init(&error), LANTERN_OK, &error);
        lantern_trust* trust = NULL;
        REQUIRE_STATUS(lantern_trust_create(NULL, &trust, NULL), LANTERN_OK);
        lantern_curl_options options = LANTERN_INIT(lantern_curl_options);
        options.trust                = trust;
        options.connect_timeout_ms   = 3000;
        REQUIRE_CALL(lantern_transport_create_curl(&options, NULL, &transport, &error), LANTERN_OK, &error);
        CHECK(transport != NULL);
        lantern_transport_free(transport);
        lantern_trust_free(trust);
    }
    else
    {
        CHECK_STATUS(
            lantern_transport_create_curl(NULL, NULL, &transport, &error), LANTERN_ERROR_UNSUPPORTED);
        CHECK(transport == NULL);
    }
    if (lantern_has_transport(LANTERN_TRANSPORT_MBEDTLS))
    {
        lantern_mbedtls_options options = LANTERN_INIT(lantern_mbedtls_options);
        CHECK_STATUS(
            lantern_transport_create_mbedtls(&options, NULL, &transport, &error), LANTERN_ERROR_USAGE);
        lantern_random* random = NULL;
        if (lantern_random_create_system(NULL, &random, NULL) == LANTERN_OK)
        {
            options.random = random;
            REQUIRE_CALL(
                lantern_transport_create_mbedtls(&options, NULL, &transport, &error), LANTERN_OK, &error);
            lantern_transport_free(transport);
            lantern_random_free(random);
        }
    }
    else
        CHECK_STATUS(
            lantern_transport_create_mbedtls(NULL, NULL, &transport, &error), LANTERN_ERROR_UNSUPPORTED);
    CHECK(!lantern_has_transport(0));
}

/* The state of a download, saved as JSON: the `schema` rule. */
static void download_state_files(void)
{
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    lantern_error error   = LANTERN_INIT(lantern_error);
    lantern_string* saved = NULL;
    REQUIRE_CALL(lantern_download_state_save(state, &saved, &error), LANTERN_OK, &error);
    const lantern_str fresh = lantern_string_view(saved);
    const char* begins      = "{\"schema\":1,\"received\":0,\"hash\":{\"h\":[";
    CHECK(strncmp(fresh.data, begins, strlen(begins)) == 0);

    /* A member of a later version: read, and kept when written again */
    char later[2048];
    snprintf(later, sizeof(later), "{\"later\":{\"kept\":[1,2]},%s", fresh.data + 1);
    REQUIRE_CALL(lantern_download_state_load(state, later, strlen(later), &error), LANTERN_OK, &error);
    lantern_string* again = NULL;
    REQUIRE_CALL(lantern_download_state_save(state, &again, &error), LANTERN_OK, &error);
    CHECK(strstr(lantern_string_view(again).data, "\"later\":{\"kept\":[1,2]}") != NULL);
    CHECK(strstr(lantern_string_view(again).data, "\"received\":0") != NULL);
    lantern_string_free(again);

    /* Absent schema: an error, the state as it was */
    const char* absent = "{\"received\":0,\"hash\":{}}";
    CHECK_STATUS(
        lantern_download_state_load(state, absent, strlen(absent), &error), LANTERN_ERROR_INVALID_RESPONSE);
    /* Of another form */
    const char* other = "{\"schema\":1,\"received\":\"zero\"}";
    CHECK_STATUS(
        lantern_download_state_load(state, other, strlen(other), &error), LANTERN_ERROR_INVALID_RESPONSE);

    /* Newer: absent, and never written over */
    char newer[2048];
    snprintf(newer, sizeof(newer), "%s", fresh.data);
    newer[10] = '2';
    CHECK_STATUS(lantern_download_state_load(state, newer, strlen(newer), &error), LANTERN_ABSENT);
    CHECK(lantern_download_state_received(state) == 0);
    CHECK_STATUS(lantern_download_state_save(state, &again, &error), LANTERN_ABSENT);
    CHECK(again == NULL);
    lantern_string_free(saved);
    lantern_download_state_free(state);
}

static void upload_progress_files(void)
{
    lantern_upload_progress* progress = NULL;
    REQUIRE_STATUS(lantern_upload_progress_create(NULL, &progress, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_upload_progress_url(progress), ""));
    lantern_error error = LANTERN_INIT(lantern_error);
    const char* kept
        = "{\"schema\":1,\"url\":\"https://shelf.example.org/api/lantern/v1/saves/0100ABCD00010000/"
          "uploads/u_1\",\"offset\":16384,\"chunk_size\":16384,\"from_later\":true}";
    REQUIRE_CALL(lantern_upload_progress_load(progress, kept, strlen(kept), &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_upload_progress_url(progress),
        "https://shelf.example.org/api/lantern/v1/saves/0100ABCD00010000/uploads/u_1"));
    CHECK(lantern_upload_progress_offset(progress) == 16384);
    lantern_string* saved = NULL;
    REQUIRE_CALL(lantern_upload_progress_save(progress, &saved, &error), LANTERN_OK, &error);
    CHECK(strstr(lantern_string_view(saved).data, "\"from_later\":true") != NULL);
    lantern_string_free(saved);
    lantern_upload_progress_reset(progress);
    CHECK(lantern_upload_progress_offset(progress) == 0);

    const char* absent = "{\"url\":\"\",\"offset\":0,\"chunk_size\":0}";
    CHECK_STATUS(lantern_upload_progress_load(progress, absent, strlen(absent), &error),
        LANTERN_ERROR_INVALID_RESPONSE);
    const char* newer = "{\"schema\":3,\"url\":\"elsewhere\"}";
    CHECK_STATUS(lantern_upload_progress_load(progress, newer, strlen(newer), &error), LANTERN_ABSENT);
    CHECK_STATUS(lantern_upload_progress_save(progress, &saved, &error), LANTERN_ABSENT);
    lantern_upload_progress_free(progress);
}

const test_case discovery_tests[] = {
    { "discovery: datagrams and origins", datagrams },
    { "discovery: over the app's socket, each server once", discovery_over_the_apps_socket },
    { "transports: the library's own", the_librarys_transports },
    { "state: a download's, saved and loaded with its schema", download_state_files },
    { "state: an upload's, saved and loaded with its schema", upload_progress_files },
};
const size_t discovery_test_count = sizeof(discovery_tests) / sizeof(discovery_tests[0]);
