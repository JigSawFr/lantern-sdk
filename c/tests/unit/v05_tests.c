/* Draft 0.5 through the C API: events, grants and peers, sync, encrypted
 * saves, static libraries, deleting an account; spec/vectors' grants,
 * sync-merge, static-layout and encrypted-saves. Every name is made up. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"
#include "vectors.h"

#define ORIGIN "https://shelf.example.org"
#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

/* Hex of any length into a new buffer. */
static size_t from_hex(const char* hex, uint8_t** out)
{
    const size_t size = strlen(hex) / 2;
    *out              = malloc(size == 0 ? 1 : size);
    if (*out == NULL || !hex_to_bytes(hex, *out, size))
        abort();
    return size;
}

static bool equals_hex(const uint8_t* bytes, size_t size, const char* hex)
{
    if (strlen(hex) != size * 2)
        return false;
    for (size_t i = 0; i < size; ++i)
    {
        char two[3];
        snprintf(two, sizeof(two), "%02x", bytes[i]);
        if (memcmp(two, hex + 2 * i, 2) != 0)
            return false;
    }
    return true;
}

/* A client of a scripted server whose handshake offers what draft 0.5 adds. */
typedef struct setup
{
    fake_server server;
    char* handshake;
    lantern_transport* transport;
    lantern_random* random;
    lantern_clock* clock;
    lantern_client* client;
    lantern_handshake* shake;
} setup;

/* The vectors' time: a grant of theirs is not expired at it. */
static int64_t vector_time(void* user)
{
    (void)user;
    return 1793345400;
}

static void offer_family(char* text, const char* family)
{
    char key[64];
    snprintf(key, sizeof(key), "\"%s\": ", family);
    char* at = strstr(text, key);
    if (at != NULL)
        at[strlen(key)] = '1';
}

static bool setup_open(setup* s)
{
    memset(s, 0, sizeof(*s));
    fake_init(&s->server, ORIGIN);
    s->handshake = spec_file("examples/v1/handshake.json", NULL);
    if (s->handshake == NULL)
        return false;
    offer_family(s->handshake, "sync");
    offer_family(s->handshake, "admin");
    fake_add(&s->server, "GET", "/.well-known/lantern", 200, s->handshake);
    s->transport                  = fake_transport(&s->server, NULL);
    lantern_clock_callbacks clock = LANTERN_INIT(lantern_clock_callbacks);
    clock.unix_seconds            = vector_time;
    if (s->transport == NULL || lantern_random_create_system(NULL, &s->random, NULL) != LANTERN_OK
        || lantern_clock_create(&clock, NULL, &s->clock, NULL) != LANTERN_OK)
        return false;
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = ORIGIN;
    config.user_agent            = "LanternCTests/0.5";
    config.platform              = "switch";
    config.transport             = s->transport;
    config.random                = s->random;
    config.clock                 = s->clock;
    return lantern_client_create(&config, &s->client, NULL) == LANTERN_OK
        && lantern_client_handshake(s->client, &s->shake, NULL) == LANTERN_OK;
}

static void setup_close(setup* s)
{
    lantern_handshake_free(s->shake);
    lantern_client_free(s->client);
    lantern_transport_free(s->transport);
    lantern_random_free(s->random);
    lantern_clock_free(s->clock);
    free(s->handshake);
}

#define OPEN(s)                                                                                              \
    do                                                                                                       \
    {                                                                                                        \
        if (!setup_open(&(s)))                                                                               \
        {                                                                                                    \
            setup_close(&(s));                                                                               \
            REQUIRE(false);                                                                                  \
        }                                                                                                    \
    } while (0)

static void codes_and_families(void)
{
    /* The values of API 1 never move; precondition_failed is appended */
    CHECK(LANTERN_CODE_GONE == 12);
    CHECK(lantern_code_from_name("too_large") == LANTERN_CODE_TOO_LARGE);
    CHECK(lantern_code_from_name("unavailable") == LANTERN_CODE_UNAVAILABLE);
    CHECK(lantern_code_from_name("precondition_failed") == LANTERN_CODE_PRECONDITION_FAILED);
    CHECK(strcmp(lantern_code_name(LANTERN_CODE_PRECONDITION_FAILED), "precondition_failed") == 0);
    CHECK(strcmp(lantern_code_name(LANTERN_CODE_UNKNOWN), "unknown") == 0);
    CHECK(strcmp(lantern_code_name(21), "") == 0);
    CHECK(lantern_code_for_status(412) == LANTERN_CODE_PRECONDITION_FAILED);
    CHECK(lantern_code_for_status(410) == LANTERN_CODE_GONE);

    setup s;
    OPEN(s);
    CHECK(lantern_client_offers(s.client, LANTERN_FAMILY_EVENTS) == 1);
    CHECK(lantern_client_offers(s.client, LANTERN_FAMILY_PEERS) == 1);
    CHECK(lantern_client_offers(s.client, LANTERN_FAMILY_SYNC) == 1);
    CHECK(lantern_client_offers(s.client, LANTERN_FAMILY_ENCRYPTED_SAVES) == 1);
    CHECK(lantern_client_offers(s.client, 15) == 0);
    uint64_t heartbeat = 0;
    CHECK(lantern_handshake_limits_get_heartbeat(lantern_handshake_get_limits(s.shake), &heartbeat)
        && heartbeat == 15);
    CHECK(lantern_client_event_silence_limit(s.client) == 30);
    uint8_t key[32];
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_CALL(lantern_grant_key_of(s.shake, key, &error), LANTERN_OK, &error);
    setup_close(&s);
}

static void event_documents(void)
{
    const char* library      = "{\"schema\":1,\"families\":[\"apps\",\"titles\"],\"platforms\":[\"switch\"]}";
    lantern_library_event* l = NULL;
    REQUIRE_STATUS(lantern_read_library_event(library, strlen(library), NULL, &l, NULL), LANTERN_OK);
    CHECK(lantern_library_event_get_families_count(l) == 2);
    CHECK(STR_EQ(lantern_library_event_get_families_at(l, 1), "titles"));
    CHECK(STR_EQ(lantern_library_event_get_platforms_at(l, 0), "switch"));
    CHECK(STR_EQ(lantern_library_event_get_platforms_at(l, 1), ""));
    lantern_library_event_free(l);
    const char* newer = "{\"schema\":2,\"whatever\":true}";
    CHECK_STATUS(lantern_read_library_event(newer, strlen(newer), NULL, &l, NULL), LANTERN_ABSENT);
    CHECK(l == NULL);
    const char* broken = "{\"schema\":1,\"families\":[]}";
    CHECK(lantern_read_library_event(broken, strlen(broken), NULL, &l, NULL) < 0);
    const char* missing = "{\"families\":[\"apps\"],\"platforms\":[]}";
    CHECK_STATUS(
        lantern_read_library_event(missing, strlen(missing), NULL, &l, NULL), LANTERN_ERROR_INVALID_RESPONSE);

    const char* request      = "{\"schema\":1,\"id\":\"r_7Qm2\",\"platform\":\"switch\",\"deleted\":true}";
    lantern_request_event* r = NULL;
    REQUIRE_STATUS(lantern_read_request_event(request, strlen(request), NULL, &r, NULL), LANTERN_OK);
    CHECK(lantern_request_event_get_deleted(r));
    CHECK(STR_EQ(lantern_request_event_get_id(r), "r_7Qm2"));
    CHECK(STR_EQ(lantern_request_event_get_status(r), ""));
    lantern_request_event_free(r);
    const char* pairing = "{\"schema\":1,\"id\":\"pr_1\",\"code\":\"KQ4M-7TXD\",\"device\":\"Lea's Switch\","
                          "\"key\":\"3F9A 1C07 B2E4 55D0\",\"expires\":\"2026-10-30T09:40:00Z\"}";
    lantern_pairing_event* p = NULL;
    REQUIRE_STATUS(lantern_read_pairing_event(pairing, strlen(pairing), NULL, &p, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_pairing_event_get_code(p), "KQ4M-7TXD"));
    CHECK(STR_EQ(lantern_pairing_event_get_device(p), "Lea's Switch"));
    CHECK(STR_EQ(lantern_pairing_event_get_key(p), "3F9A 1C07 B2E4 55D0"));
    CHECK(STR_EQ(lantern_pairing_event_get_expires(p), "2026-10-30T09:40:00Z"));
    CHECK(STR_EQ(lantern_pairing_event_get_id(p), "pr_1"));
    lantern_pairing_event_free(p);
    const char* save
        = "{\"schema\":1,\"platform\":\"switch\",\"title_id\":\"0100ABCD00010000\",\"save_id\":\"sv_1\"}";
    lantern_save_event* v = NULL;
    REQUIRE_STATUS(lantern_read_save_event(save, strlen(save), NULL, &v, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_save_event_get_save_id(v), "sv_1"));
    CHECK(STR_EQ(lantern_save_event_get_title_id(v), "0100ABCD00010000"));
    CHECK(STR_EQ(lantern_save_event_get_platform(v), "switch"));
    CHECK(STR_EQ(lantern_save_event_get_device(v), ""));
    CHECK(STR_EQ(lantern_save_event_get_created(v), ""));
    lantern_save_event_free(v);
    const char* sync      = "{\"schema\":1,\"collection\":\"wishes\",\"rev\":42}";
    lantern_sync_event* y = NULL;
    REQUIRE_STATUS(lantern_read_sync_event(sync, strlen(sync), NULL, &y, NULL), LANTERN_OK);
    CHECK(lantern_sync_event_get_rev(y) == 42);
    CHECK(STR_EQ(lantern_sync_event_get_collection(y), "wishes"));
    lantern_sync_event_free(y);
    const char* shutdown      = "{\"schema\":1,\"retry\":30}";
    lantern_shutdown_event* d = NULL;
    REQUIRE_STATUS(lantern_read_shutdown_event(shutdown, strlen(shutdown), NULL, &d, NULL), LANTERN_OK);
    uint64_t retry = 0;
    CHECK(lantern_shutdown_event_get_retry(d, &retry) && retry == 30);
    lantern_shutdown_event_free(d);
    CHECK(strcmp(lantern_event_kind_name(LANTERN_EVENT_SHUTDOWN), "shutdown") == 0);
    CHECK(strcmp(lantern_event_kind_name(99), "") == 0);
}

typedef struct seen_events
{
    int kinds[8];
    int count;
    int heartbeats;
    char last_data[256];
} seen_events;

static bool on_event(void* user, const lantern_stream_event* event)
{
    seen_events* seen = user;
    if (seen->count < 8)
        seen->kinds[seen->count] = event->kind;
    ++seen->count;
    snprintf(seen->last_data, sizeof(seen->last_data), "%s", event->data.data);
    return true;
}

static bool on_heartbeat(void* user)
{
    ++((seen_events*)user)->heartbeats;
    return true;
}

static void the_event_stream_and_long_polling(void)
{
    setup s;
    OPEN(s);
    const char* body
        = "retry: 3000\n\nid: s_9f2c01aa_1042\nevent: ready\ndata: {\"schema\":1}\n\n: heartbeat\n\n"
          "id: s_9f2c01aa_1043\nevent: library\ndata: "
          "{\"schema\":1,\"families\":[\"apps\"],\"platforms\":[\"switch\"]}\n\n"
          "id: s_9f2c01aa_1044\nevent: comet\ndata: {\"schema\":1}\n\n"
          "id: s_9f2c01aa_1045\nevent: request\ndata: {\"schema\":2,\"id\":\"r_1\"}\n\n"
          "id: s_9f2c01aa_1046\nevent: shutdown\ndata: {\"schema\":1,\"retry\":30}\n\n";
    fake_route* stream = fake_add(&s.server, "GET", "/api/lantern/v1/events*", 200, body);
    stream->times      = 1;
    fake_header(stream, "Content-Type", "text/event-stream");
    fake_problem(&s.server, "GET", "/api/lantern/v1/events*", 410,
        "{\"schema\":1,\"type\":\"about:blank\",\"title\":\"Gone\",\"status\":410,\"code\":\"gone\"}");
    lantern_event_stream_state* state = NULL;
    REQUIRE_STATUS(lantern_event_stream_state_create(NULL, &state, NULL), LANTERN_OK);
    CHECK(STR_EQ(lantern_event_stream_state_last_id(state), ""));
    CHECK(lantern_event_stream_state_set_last_id(state, "s_9f2c01aa_1041"));
    lantern_event_callbacks callbacks = LANTERN_INIT(lantern_event_callbacks);
    seen_events seen;
    memset(&seen, 0, sizeof(seen));
    callbacks.user         = &seen;
    callbacks.on_event     = on_event;
    callbacks.on_heartbeat = on_heartbeat;
    lantern_error error    = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_events(s.client, state, &callbacks, NULL, &error), LANTERN_OK, &error);
    char value[128];
    CHECK(fake_last_header(&s.server, "Last-Event-ID", value, sizeof(value)) != NULL
        && strcmp(value, "s_9f2c01aa_1041") == 0);
    CHECK(fake_last_header(&s.server, "Accept", value, sizeof(value)) != NULL
        && strcmp(value, "text/event-stream") == 0);
    /* Unknown events and newer schemas ignored */
    REQUIRE(seen.count == 3);
    CHECK(seen.kinds[0] == LANTERN_EVENT_READY);
    CHECK(seen.kinds[1] == LANTERN_EVENT_LIBRARY);
    CHECK(seen.kinds[2] == LANTERN_EVENT_SHUTDOWN);
    CHECK(strcmp(seen.last_data, "{\"schema\":1,\"retry\":30}") == 0);
    CHECK(seen.heartbeats == 1);
    CHECK(STR_EQ(lantern_event_stream_state_last_id(state), "s_9f2c01aa_1046"));
    CHECK(lantern_event_stream_state_failures(state) == 0);
    CHECK(lantern_event_stream_state_retry_ms(state) == 30000);
    CHECK(lantern_event_stream_state_reconnect_delay_ms(state, 0.0) == 30000);

    /* 410: the position forgotten */
    CHECK_STATUS(lantern_client_events(s.client, state, &callbacks, NULL, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.effective_code == LANTERN_CODE_GONE);
    CHECK(STR_EQ(lantern_event_stream_state_last_id(state), ""));
    CHECK(lantern_event_stream_state_failures(state) == 1);
    CHECK(lantern_event_stream_state_reconnect_delay_ms(state, 0.0) >= 60000);
    lantern_event_stream_state_forget_position(state);
    callbacks.on_event = NULL;
    CHECK_STATUS(lantern_client_events(s.client, state, &callbacks, NULL, &error), LANTERN_ERROR_USAGE);
    char long_id[600];
    memset(long_id, 'x', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = '\0';
    CHECK(!lantern_event_stream_state_set_last_id(state, long_id));
    lantern_event_stream_state_free(state);

    /* Long polling */
    char* changes = spec_file("examples/v1/changes.json", NULL);
    REQUIRE(changes != NULL);
    fake_add(&s.server, "GET", "/api/lantern/v1/changes*", 200, changes);
    lantern_changes* polled = NULL;
    REQUIRE_CALL(lantern_client_wait_changes(s.client, "s_9f2c01aa_1041", 30, NULL, &polled, &error),
        LANTERN_OK, &error);
    CHECK(strstr(s.server.last_url, "since=s_9f2c01aa_1041") != NULL);
    CHECK(strstr(s.server.last_url, "wait=") != NULL);
    for (size_t i = 0; i < lantern_changes_get_events_count(polled); ++i)
        CHECK(lantern_event_get_event(lantern_changes_get_events_at(polled, i)).size > 0);
    lantern_changes_free(polled);
    free(changes);
    setup_close(&s);
}

static void grants_of_the_vectors(void)
{
    REQUIRE(COUNT(grant_cases) == 7);
    for (size_t i = 0; i < COUNT(grant_cases); ++i)
    {
        const grant_case* v = &grant_cases[i];
        lantern_grant_key server;
        server.uid = v->server_uid;
        REQUIRE(hex_to_bytes(v->server_key, server.key, 32));
        uint8_t sha[32];
        REQUIRE(hex_to_bytes(v->path_sha256, sha, 32));
        lantern_grant_claims claims = LANTERN_INIT(lantern_grant_claims);
        lantern_error error         = LANTERN_INIT(lantern_error);
        const lantern_status status
            = lantern_verify_grant(v->grant, sha, v->peer_time, &server, 1, &claims, &error);
        if ((status == LANTERN_OK) != v->serves)
            fprintf(stderr, "    \"%s\": %s\n", v->name, lantern_status_name(status));
        CHECK((status == LANTERN_OK) == v->serves);
        if (v->serves)
        {
            CHECK(strcmp(claims.uid, v->server_uid) == 0);
            CHECK(memcmp(claims.sha256, sha, 32) == 0);
            CHECK(claims.exp > v->peer_time);
        }
        else
            CHECK(status == LANTERN_ERROR_REFUSED);
    }
}

static void a_grant_asked_and_admin_deletion(void)
{
    setup s;
    OPEN(s);
    char* grant = spec_file("examples/v1/grant.json", NULL);
    REQUIRE(grant != NULL);
    fake_add(&s.server, "GET", "/api/lantern/v1/grants/sha256/*", 200, grant);
    fake_add(&s.server, "DELETE", "/api/lantern/v1/admin/users/noor?confirm=noor", 204, NULL);
    uint8_t sha[32];
    REQUIRE(hex_to_bytes("3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817", sha, 32));
    lantern_grant* got  = NULL;
    lantern_error error = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_grant(s.client, sha, &got, &error), LANTERN_OK, &error);
    CHECK(strstr(s.server.last_url, "/grants/sha256/3a7bd3e2") != NULL);
    uint64_t size = 0;
    CHECK(lantern_grant_get_size(got, &size) && size == 734003200U);
    CHECK(lantern_grant_get_grant(got).size > 0);
    lantern_grant_free(got);
    free(grant);

    CHECK_STATUS(lantern_client_admin_delete_user(s.client, "noor", "noo", &error), LANTERN_ERROR_USAGE);
    REQUIRE_CALL(lantern_client_admin_delete_user(s.client, "noor", "noor", &error), LANTERN_OK, &error);
    CHECK(strcmp(s.server.last_method, "DELETE") == 0);
    setup_close(&s);
}

static void peers_and_their_datagrams(void)
{
    CHECK(lantern_is_private_host("192.168.1.20"));
    CHECK(lantern_is_private_host("fe80::1"));
    CHECK(!lantern_is_private_host("203.0.113.5"));
    CHECK(!lantern_is_private_host("shelf.example.org"));
    CHECK(strstr(lantern_discovery_request_peers().data, "\"peers\":true") != NULL);
    size_t size = 0;
    char* text  = spec_file("examples/v1/discovery-peer.json", &size);
    REQUIRE(text != NULL);
    lantern_peer_reply* reply = NULL;
    lantern_error error       = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_read_peer_datagram((const uint8_t*)text, size, NULL, &reply, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_peer_reply_get_name(reply), "Lea's Switch"));
    CHECK(lantern_peer_serves(reply, "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14"));
    CHECK(!lantern_peer_serves(reply, "00000000-0000-4000-8000-000000000000"));
    lantern_peer_reply_free(reply);
    free(text);
    const char* server = "{\"schema\":1,\"lantern\":\"server\"}";
    CHECK(lantern_read_peer_datagram((const uint8_t*)server, strlen(server), NULL, &reply, &error) < 0);

    lantern_peer_endpoint peer = LANTERN_INIT(lantern_peer_endpoint);
    peer.host                  = "192.168.1.20";
    peer.port                  = 47116;
    peer.base                  = "/lantern";
    uint8_t sha[32];
    REQUIRE(hex_to_bytes("3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817", sha, 32));
    lantern_string* url = NULL;
    REQUIRE_CALL(lantern_peer_blob_url(&peer, sha, NULL, &url, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(url),
        "http://192.168.1.20:47116/lantern/v1/blobs/sha256/"
        "3a7bd3e2b4c1f0a9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a392817"));
    lantern_string_free(url);
    peer.host = "203.0.113.5";
    CHECK(lantern_peer_blob_url(&peer, sha, NULL, &url, &error) < 0);
}

/* A console that shares one file. */
typedef struct shelf
{
    uint8_t sha[32];
    uint64_t size;
} shelf;

static bool held_size(void* user, const uint8_t sha256[32], uint64_t* size)
{
    const shelf* held = user;
    if (memcmp(held->sha, sha256, 32) != 0)
        return false;
    *size = held->size;
    return true;
}

static int64_t gate_time(void* user)
{
    (void)user;
    return grant_cases[0].peer_time;
}

static void the_gate_of_a_console_that_shares(void)
{
    const grant_case* valid = &grant_cases[0];
    lantern_grant_key server;
    server.uid = valid->server_uid;
    REQUIRE(hex_to_bytes(valid->server_key, server.key, 32));
    shelf held;
    REQUIRE(hex_to_bytes(valid->path_sha256, held.sha, 32));
    lantern_grant_claims claims = LANTERN_INIT(lantern_grant_claims);
    REQUIRE_STATUS(lantern_verify_grant(valid->grant, held.sha, valid->peer_time, &server, 1, &claims, NULL),
        LANTERN_OK);
    held.size = claims.size;

    lantern_held_files_callbacks files = LANTERN_INIT(lantern_held_files_callbacks);
    files.user                         = &held;
    files.size_of                      = held_size;
    lantern_clock_callbacks clock      = LANTERN_INIT(lantern_clock_callbacks);
    clock.unix_seconds                 = gate_time;
    lantern_clock* time_source         = NULL;
    REQUIRE_STATUS(lantern_clock_create(&clock, NULL, &time_source, NULL), LANTERN_OK);
    counting_allocator counter        = { 0 };
    const lantern_allocator allocator = counting_allocator_make(&counter);
    lantern_peer_gate* gate           = NULL;
    lantern_error error               = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_peer_gate_create(&server, 1, &files, time_source, NULL, &allocator, &gate, &error),
        LANTERN_OK, &error);

    char target[160];
    snprintf(target, sizeof(target), "/lantern/v1/blobs/sha256/%s", valid->path_sha256);
    lantern_peer_request request = LANTERN_INIT(lantern_peer_request);
    request.method               = "GET";
    request.target               = target;
    request.grant                = valid->grant;
    request.remote_address       = "192.168.1.30";
    lantern_peer_answer* answer  = NULL;
    REQUIRE_CALL(lantern_peer_gate_handle(gate, &request, &answer, &error), LANTERN_OK, &error);
    CHECK(lantern_peer_answer_status(answer) == 200);
    CHECK(lantern_peer_answer_serve(answer));
    CHECK(lantern_peer_answer_slot(answer));
    CHECK(lantern_peer_answer_length(answer) == held.size);
    CHECK(lantern_peer_answer_size(answer) == held.size);
    uint8_t served[32];
    lantern_peer_answer_sha256(answer, served);
    CHECK(memcmp(served, held.sha, 32) == 0);
    bool digest = false;
    for (size_t i = 0; i < lantern_peer_answer_header_count(answer); ++i)
    {
        lantern_header header;
        REQUIRE(lantern_peer_answer_header_at(answer, i, &header));
        CHECK(header.name.data[header.name.size] == '\0');
        digest = digest || STR_EQ(header.name, "Repr-Digest");
    }
    CHECK(digest);
    CHECK(lantern_peer_gate_active(gate) == 1);
    lantern_peer_gate_release(gate);
    CHECK(lantern_peer_gate_active(gate) == 0);
    lantern_peer_answer_free(answer);

    /* No grant, then sharing off: 403 */
    request.grant = NULL;
    REQUIRE_STATUS(lantern_peer_gate_handle(gate, &request, &answer, NULL), LANTERN_OK);
    CHECK(lantern_peer_answer_status(answer) == 403);
    CHECK(!lantern_peer_answer_serve(answer));
    CHECK(lantern_peer_answer_body(answer).size > 0);
    lantern_peer_answer_free(answer);
    request.grant = valid->grant;
    lantern_peer_gate_set_enabled(gate, false);
    REQUIRE_STATUS(lantern_peer_gate_handle(gate, &request, &answer, NULL), LANTERN_OK);
    CHECK(lantern_peer_answer_status(answer) == 403);
    lantern_peer_answer_free(answer);
    lantern_peer_gate_set_enabled(gate, true);
    request.method = "HEAD";
    REQUIRE_STATUS(lantern_peer_gate_handle(gate, &request, &answer, NULL), LANTERN_OK);
    CHECK(lantern_peer_answer_status(answer) == 200);
    CHECK(!lantern_peer_answer_serve(answer));
    lantern_peer_answer_free(answer);

    lantern_peer_limits limits = LANTERN_INIT(lantern_peer_limits);
    limits.slots               = 9;
    lantern_peer_gate* refused = NULL;
    CHECK_STATUS(lantern_peer_gate_create(&server, 1, &files, NULL, &limits, NULL, &refused, NULL),
        LANTERN_ERROR_USAGE);
    lantern_peer_gate_free(gate);
    CHECK(counter.live == 0);
    lantern_clock_free(time_source);
}

static void sync_merge_of_the_vectors(void)
{
    int64_t now = 0;
    REQUIRE(lantern_parse_sync_time(merge_server_time, &now));
    REQUIRE(COUNT(merge_cases) == 10);
    for (size_t i = 0; i < COUNT(merge_cases); ++i)
    {
        const merge_case* v = &merge_cases[i];
        lantern_sync_item_input have
            = { "switch/0100ABCD00010000", v->have.value, v->have.deleted, v->have.updated };
        lantern_sync_item_input sent
            = { "switch/0100ABCD00010000", v->sent.value, v->sent.deleted, v->sent.updated };
        lantern_sync_merge merge = LANTERN_INIT(lantern_sync_merge);
        lantern_error error      = LANTERN_INIT(lantern_error);
        REQUIRE_CALL(
            lantern_sync_merge_items(v->have.present ? &have : NULL, &sent, now, merge_skew, &merge, &error),
            LANTERN_OK, &error);
        if (merge.replaced != v->replaced)
            fprintf(stderr, "    \"%s\"\n", v->name);
        CHECK(merge.replaced == v->replaced);
        int64_t kept = 0;
        if (merge.replaced)
            kept = merge.updated;
        else
            REQUIRE(lantern_parse_sync_time(have.updated, &kept));
        char written[32];
        lantern_format_sync_time(kept, written);
        CHECK(strcmp(written, v->kept_updated) == 0);
        if (v->canonical_have[0] != '\0')
        {
            lantern_string* ours   = NULL;
            lantern_string* theirs = NULL;
            REQUIRE_STATUS(
                lantern_canonical_json(have.value, strlen(have.value), NULL, &ours, NULL), LANTERN_OK);
            REQUIRE_STATUS(
                lantern_canonical_json(sent.value, strlen(sent.value), NULL, &theirs, NULL), LANTERN_OK);
            CHECK(STR_EQ(lantern_string_view(ours), v->canonical_have));
            CHECK(STR_EQ(lantern_string_view(theirs), v->canonical_sent));
            lantern_string_free(ours);
            lantern_string_free(theirs);
        }
    }
    CHECK(!lantern_parse_sync_time("2026-02-30T09:00:00Z", &now));
    lantern_sync_item_input bad = { "k", "{}", false, "yesterday" };
    lantern_sync_merge merge    = LANTERN_INIT(lantern_sync_merge);
    CHECK(lantern_sync_merge_items(NULL, &bad, now, 300, &merge, NULL) < 0);
}

static void wishes_and_what_is_installed(void)
{
    CHECK(lantern_is_sync_collection("wishes"));
    CHECK(lantern_is_sync_collection("installed"));
    CHECK(!lantern_is_sync_collection("Wishes"));
    lantern_wish_input wish = LANTERN_INIT(lantern_wish_input);
    wish.platform           = "switch";
    wish.title_id           = "0100ABCD00010000";
    wish.note               = "For the holidays";
    lantern_string* value   = NULL;
    lantern_error error     = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_write_wish(&wish, NULL, &value, &error), LANTERN_OK, &error);
    lantern_wish* back = NULL;
    REQUIRE_CALL(lantern_read_wish(
                     lantern_string_view(value).data, lantern_string_view(value).size, NULL, &back, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_wish_get_note(back), "For the holidays"));
    CHECK(STR_EQ(lantern_wish_get_title_id(back), "0100ABCD00010000"));
    lantern_wish_free(back);
    lantern_string_free(value);
    CHECK(lantern_read_wish("{\"platform\":1}", 14, NULL, &back, &error) < 0);
    lantern_string* key = NULL;
    REQUIRE_CALL(lantern_wish_key("switch", "0100ABCD00010000", NULL, &key, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(key), "switch/0100ABCD00010000"));
    lantern_string_free(key);

    const lantern_installed_app apps[]          = { { "0100ABCD00010000", 196608 } };
    const lantern_installed_homebrew homebrew[] = { { "org.example.frostline", 10400 } };
    lantern_installed_input installed           = LANTERN_INIT(lantern_installed_input);
    installed.device                            = "Lea's Switch";
    installed.platform                          = "switch";
    installed.apps                              = apps;
    installed.app_count                         = 1;
    installed.homebrew                          = homebrew;
    installed.homebrew_count                    = 1;
    REQUIRE_CALL(lantern_write_installed(&installed, NULL, &value, &error), LANTERN_OK, &error);
    lantern_installed_value* read = NULL;
    REQUIRE_CALL(lantern_read_installed(
                     lantern_string_view(value).data, lantern_string_view(value).size, NULL, &read, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_installed_value_get_device(read), "Lea's Switch"));
    CHECK(STR_EQ(lantern_installed_value_get_platform(read), "switch"));
    REQUIRE(lantern_installed_value_get_app_count(read) == 1);
    lantern_installed_app app = { NULL, 0 };
    REQUIRE(lantern_installed_value_get_app(read, 0, &app));
    CHECK(strcmp(app.app_id, "0100ABCD00010000") == 0 && app.version_code == 196608);
    CHECK(!lantern_installed_value_get_app(read, 1, &app));
    REQUIRE(lantern_installed_value_get_homebrew_count(read) == 1);
    lantern_installed_homebrew entry = { NULL, 0 };
    REQUIRE(lantern_installed_value_get_homebrew(read, 0, &entry));
    CHECK(strcmp(entry.id, "org.example.frostline") == 0 && entry.build == 10400);
    lantern_installed_value_free(read);
    lantern_string_free(value);
}

static void sync_only_with_consent(void)
{
    setup s;
    OPEN(s);
    char* state      = spec_file("examples/v1/sync.json", NULL);
    char* collection = spec_file("examples/v1/sync-collection.json", NULL);
    REQUIRE(state != NULL && collection != NULL);
    fake_add(&s.server, "GET", "/api/lantern/v1/sync", 200, state);
    fake_add(&s.server, "GET", "/api/lantern/v1/sync/wishes*", 200, collection);
    fake_add(&s.server, "PATCH", "/api/lantern/v1/sync/wishes*", 200, collection);
    fake_add(&s.server, "DELETE", "/api/lantern/v1/sync", 204, NULL);
    lantern_error error       = LANTERN_INIT(lantern_error);
    lantern_sync_state* found = NULL;
    const int before          = s.server.requests;
    CHECK_STATUS(lantern_client_sync_state(s.client, &found, &error), LANTERN_ERROR_REFUSED);
    CHECK(s.server.requests == before); /* nothing sent */
    lantern_sync_consent consent = LANTERN_INIT(lantern_sync_consent);
    consent.sync                 = true;
    REQUIRE_CALL(lantern_client_set_sync_consent(s.client, &consent, NULL, &error), LANTERN_OK, &error);
    lantern_sync_consent kept = LANTERN_INIT(lantern_sync_consent);
    lantern_client_get_sync_consent(s.client, &kept);
    CHECK(kept.sync && !kept.installed);
    REQUIRE_CALL(lantern_client_sync_state(s.client, &found, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_sync_state_get_generation(found), "g_4Rz1"));
    CHECK(STR_EQ(lantern_client_sync_generation(s.client), "g_4Rz1"));
    const lantern_sync_state_collections* collections = lantern_sync_state_get_collections(found);
    CHECK(lantern_sync_state_collections_get_extra_count(collections) == 2);
    lantern_sync_state_free(found);

    lantern_sync_collection* items = NULL;
    REQUIRE_CALL(
        lantern_client_sync_items(s.client, "wishes", true, 40, NULL, &items, &error), LANTERN_OK, &error);
    CHECK(strstr(s.server.last_url, "since=40") != NULL);
    REQUIRE(lantern_sync_collection_get_items_count(items) > 0);
    const lantern_sync_item* first = lantern_sync_collection_get_items_at(items, 0);
    lantern_wish* wish             = NULL;
    REQUIRE_CALL(lantern_read_wish(lantern_sync_item_get_value(first).data,
                     lantern_sync_item_get_value(first).size, NULL, &wish, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_wish_get_name(wish), "Frostline Tales"));
    lantern_wish_free(wish);
    lantern_sync_collection_free(items);

    char now[32];
    lantern_format_sync_time(1793352723250, now);
    const lantern_sync_item_input write[] = { { "switch/0100ABCD00010000",
        "{\"platform\":\"switch\",\"title_id\":\"0100ABCD00010000\"}", false, now } };
    REQUIRE_CALL(lantern_client_sync_write(s.client, "wishes", write, 1, true, 42, &items, &error),
        LANTERN_OK, &error);
    char value[64];
    CHECK(
        fake_last_header(&s.server, "If-Match", value, sizeof(value)) != NULL && strstr(value, "42") != NULL);
    CHECK(strstr(s.server.last_body, "\"generation\":\"g_4Rz1\"") != NULL);
    lantern_sync_collection_free(items);
    /* What is installed only by name */
    CHECK_STATUS(lantern_client_sync_write(s.client, "installed", write, 1, false, 0, &items, &error),
        LANTERN_ERROR_REFUSED);
    REQUIRE_CALL(lantern_client_sync_delete(s.client, NULL, &error), LANTERN_OK, &error);
    free(state);
    free(collection);
    setup_close(&s);
}

/* The archive of a vector: its hex, or of its size, byte i = i % 251. */
static uint8_t* archive_of(const backup_case* v, size_t* size)
{
    if (v->archive != NULL)
    {
        uint8_t* bytes = NULL;
        *size          = from_hex(v->archive, &bytes);
        return bytes;
    }
    uint8_t* bytes = malloc(v->archive_size);
    if (bytes == NULL)
        abort();
    for (size_t i = 0; i < v->archive_size; ++i)
        bytes[i] = (uint8_t)(i % 251);
    *size = v->archive_size;
    return bytes;
}

static lantern_save_key* key_of(const char* hex)
{
    uint8_t bytes[32];
    lantern_save_key* key = NULL;
    if (!hex_to_bytes(hex, bytes, 32) || lantern_save_key_from_bytes(bytes, NULL, &key, NULL) != LANTERN_OK)
        return NULL;
    return key;
}

static void encrypted_saves_primitives_and_keys(void)
{
    uint8_t* ikm          = NULL;
    uint8_t* okm          = NULL;
    const size_t ikm_size = from_hex(hkdf_ikm, &ikm);
    const size_t okm_size = from_hex(hkdf_okm, &okm);
    uint8_t out[64];
    REQUIRE(okm_size <= sizeof(out));
    CHECK(lantern_hkdf_sha256(NULL, strlen(hkdf_salt) / 2, ikm, ikm_size, (const uint8_t*)hkdf_info,
        strlen(hkdf_info), out, okm_size));
    CHECK(memcmp(out, okm, okm_size) == 0);
    free(ikm);
    free(okm);

    uint8_t key[32];
    uint8_t nonce16[16];
    uint8_t subkey[32];
    REQUIRE(hex_to_bytes(hchacha_key, key, 32));
    REQUIRE(hex_to_bytes(hchacha_nonce, nonce16, 16));
    lantern_hchacha20(key, nonce16, subkey);
    CHECK(equals_hex(subkey, 32, hchacha_subkey));

    for (size_t i = 0; i < COUNT(xchacha_cases); ++i)
    {
        const xchacha_case* v = &xchacha_cases[i];
        uint8_t nonce[24];
        REQUIRE(hex_to_bytes(v->key, key, 32));
        REQUIRE(hex_to_bytes(v->nonce, nonce, 24));
        uint8_t* aad            = NULL;
        uint8_t* plain          = NULL;
        const size_t aad_size   = from_hex(v->aad, &aad);
        const size_t plain_size = from_hex(v->plaintext, &plain);
        uint8_t* sealed         = malloc(plain_size + 16);
        uint8_t* opened         = malloc(plain_size + 1);
        REQUIRE(sealed != NULL && opened != NULL);
        lantern_error error = LANTERN_INIT(lantern_error);
        REQUIRE_CALL(
            lantern_xchacha20poly1305_seal(key, nonce, aad, aad_size, plain, plain_size, sealed, &error),
            LANTERN_OK, &error);
        CHECK(equals_hex(sealed, plain_size + 16, v->sealed));
        REQUIRE_CALL(lantern_xchacha20poly1305_open(
                         key, nonce, aad, aad_size, sealed, plain_size + 16, opened, &error),
            LANTERN_OK, &error);
        CHECK(memcmp(opened, plain, plain_size) == 0);
        sealed[0] ^= 1U;
        CHECK_STATUS(lantern_xchacha20poly1305_open(
                         key, nonce, aad, aad_size, sealed, plain_size + 16, opened, &error),
            LANTERN_ERROR_INTEGRITY);
        free(aad);
        free(plain);
        free(sealed);
        free(opened);
    }

    for (size_t i = 0; i < COUNT(save_key_cases); ++i)
    {
        const save_key_case* v = &save_key_cases[i];
        lantern_save_key* made = key_of(v->save_key);
        REQUIRE(made != NULL);
        char id[17];
        char phrase[70];
        char qr[76];
        lantern_save_key_id_text(made, id);
        lantern_save_key_phrase(made, phrase);
        lantern_save_key_qr_text(made, qr);
        CHECK(strcmp(id, v->key_id) == 0);
        CHECK(strcmp(phrase, v->phrase) == 0);
        CHECK(strcmp(qr, v->qr) == 0);
        lantern_save_key* from_phrase = NULL;
        lantern_save_key* from_qr     = NULL;
        REQUIRE_STATUS(lantern_save_key_from_phrase(v->phrase, NULL, &from_phrase, NULL), LANTERN_OK);
        REQUIRE_STATUS(lantern_save_key_from_qr(v->qr, NULL, &from_qr, NULL), LANTERN_OK);
        uint8_t a[32];
        uint8_t b[32];
        uint8_t c[32];
        lantern_save_key_bytes(made, a);
        lantern_save_key_bytes(from_phrase, b);
        lantern_save_key_bytes(from_qr, c);
        CHECK(memcmp(a, b, 32) == 0 && memcmp(a, c, 32) == 0);
        lantern_save_key_free(made);
        lantern_save_key_free(from_phrase);
        lantern_save_key_free(from_qr);
    }
    for (size_t i = 0; i < COUNT(phrase_cases); ++i)
    {
        lantern_save_key* made      = NULL;
        const lantern_status status = lantern_save_key_from_phrase(phrase_cases[i].phrase, NULL, &made, NULL);
        CHECK((status == LANTERN_OK) == phrase_cases[i].accepted);
        if (!phrase_cases[i].accepted)
            CHECK(status == LANTERN_ERROR_REFUSED);
        lantern_save_key_free(made);
    }
    CHECK(lantern_save_chunk_count(0) == 1);
    CHECK(lantern_save_chunk_count(65537) == 2);
    CHECK(lantern_encrypted_save_size(22) == 126);
}

/* A sink into memory, its bytes reached through a decrypting sink. */
static void encrypted_saves_backups(void)
{
    for (size_t i = 0; i < COUNT(backup_cases); ++i)
    {
        const backup_case* v  = &backup_cases[i];
        lantern_save_key* key = key_of(v->save_key);
        REQUIRE(key != NULL);
        uint8_t file_key[32];
        uint8_t wrap_nonce[24];
        REQUIRE(hex_to_bytes(v->file_key, file_key, 32));
        REQUIRE(hex_to_bytes(v->wrap_nonce, wrap_nonce, 24));
        uint8_t header[LANTERN_SAVE_HEADER_SIZE];
        lantern_make_save_header_with(key, file_key, wrap_nonce, header);
        CHECK(equals_hex(header, sizeof(header), v->header));
        size_t size            = 0;
        uint8_t* archive       = archive_of(v, &size);
        lantern_string* sealed = NULL;
        lantern_error error    = LANTERN_INIT(lantern_error);
        REQUIRE_CALL(
            lantern_encrypt_save(key, header, archive, size, NULL, &sealed, &error), LANTERN_OK, &error);
        const lantern_str bytes = lantern_string_view(sealed);
        CHECK(bytes.size == v->size);
        uint8_t digest[32];
        lantern_sha256((const uint8_t*)bytes.data, bytes.size, digest);
        CHECK(equals_hex(digest, 32, v->sha256));
        if (v->encrypted[0] != '\0')
            CHECK(equals_hex((const uint8_t*)bytes.data, bytes.size, v->encrypted));
        char id[17];
        REQUIRE_CALL(lantern_save_backup_key_id((const uint8_t*)bytes.data, bytes.size, id, &error),
            LANTERN_OK, &error);
        char own[17];
        lantern_save_key_id_text(key, own);
        CHECK(strcmp(id, own) == 0);

        /* Opened as it downloads: in cuts of 1000 bytes */
        memory_sink restored;
        lantern_download_sink* out     = memory_sink_make(&restored);
        lantern_download_sink* opening = NULL;
        REQUIRE_CALL(lantern_decrypting_sink_create(key, out, NULL, &opening, &error), LANTERN_OK, &error);
        for (size_t at = 0; at < bytes.size; at += 1000)
        {
            const size_t cut = bytes.size - at < 1000 ? bytes.size - at : 1000;
            REQUIRE_CALL(lantern_download_sink_write(opening, (const uint8_t*)bytes.data + at, cut, &error),
                LANTERN_OK, &error);
        }
        REQUIRE_CALL(lantern_decrypting_sink_finish(opening, &error), LANTERN_OK, &error);
        CHECK(lantern_decrypting_sink_archive_bytes(opening) == size);
        CHECK(restored.size == size && (size == 0 || memcmp(restored.bytes, archive, size) == 0));
        CHECK_STATUS(lantern_decrypting_sink_finish(out, &error), LANTERN_ERROR_USAGE);
        lantern_download_sink_free(opening);
        memory_sink_clear(&restored);
        lantern_download_sink_free(out);

        memory_sink whole;
        out = memory_sink_make(&whole);
        REQUIRE_CALL(lantern_decrypt_save(key, (const uint8_t*)bytes.data, bytes.size, out, &error),
            LANTERN_OK, &error);
        CHECK(whole.size == size);
        memory_sink_clear(&whole);
        lantern_download_sink_free(out);
        lantern_string_free(sealed);
        free(archive);
        lantern_save_key_free(key);
    }
}

static const backup_case* backup_named(const char* name)
{
    for (size_t i = 0; i < COUNT(backup_cases); ++i)
    {
        if (strcmp(backup_cases[i].name, name) == 0)
            return &backup_cases[i];
    }
    return NULL;
}

static void encrypted_saves_refused(void)
{
    for (size_t i = 0; i < COUNT(refused_backups); ++i)
    {
        const refused_backup* v = &refused_backups[i];
        const backup_case* from = backup_named(v->backup[0] != '\0' ? v->backup : "An empty zip: one chunk");
        REQUIRE(from != NULL);
        lantern_save_key* made = key_of(from->save_key);
        uint8_t file_key[32];
        uint8_t wrap_nonce[24];
        uint8_t header[LANTERN_SAVE_HEADER_SIZE];
        REQUIRE(made != NULL && hex_to_bytes(from->file_key, file_key, 32)
            && hex_to_bytes(from->wrap_nonce, wrap_nonce, 24));
        lantern_make_save_header_with(made, file_key, wrap_nonce, header);
        size_t size            = 0;
        uint8_t* archive       = archive_of(from, &size);
        lantern_string* sealed = NULL;
        REQUIRE_STATUS(lantern_encrypt_save(made, header, archive, size, NULL, &sealed, NULL), LANTERN_OK);
        lantern_save_key_free(made);
        const lantern_str encrypted = lantern_string_view(sealed);
        size_t length               = encrypted.size;
        uint8_t* bytes              = malloc(length + 16);
        REQUIRE(bytes != NULL);
        memcpy(bytes, encrypted.data, length);
        const char* operation = v->operation;
        if (strncmp(operation, "flip bit 0 of byte ", 19) == 0)
            bytes[strtoul(operation + 19, NULL, 10)] ^= 1U;
        else if (strcmp(operation, "flip bit 0 of the last byte") == 0)
            bytes[length - 1] ^= 1U;
        else if (strcmp(operation, "drop the last byte") == 0)
            --length;
        else if (strcmp(operation, "keep the first 88 + 65552 bytes") == 0)
            length = 88 + 65552;
        else if (strcmp(operation, "append 16 zero bytes") == 0)
        {
            memset(bytes + length, 0, 16);
            length += 16;
        }
        else if (strcmp(operation, "swap the two chunks") == 0)
        {
            uint8_t* swapped = malloc(length);
            REQUIRE(swapped != NULL);
            memcpy(swapped, bytes, 88);
            memcpy(swapped + 88, bytes + 88 + 65552, length - 88 - 65552);
            memcpy(swapped + length - 65552, bytes + 88, 65552);
            memcpy(bytes, swapped, length);
            free(swapped);
        }
        else if (strcmp(operation, "a zip in clear") == 0)
        {
            memcpy(bytes, archive, size);
            length = size;
        }
        else
            CHECK(strcmp(operation, "read with the second key") == 0);
        uint8_t digest[32];
        lantern_sha256(bytes, length, digest);
        if (!equals_hex(digest, 32, v->sha256))
            fprintf(stderr, "    \"%s\": not the vector's bytes\n", v->name);
        CHECK(equals_hex(digest, 32, v->sha256));
        lantern_save_key* key = key_of(v->save_key);
        REQUIRE(key != NULL);
        memory_sink restored;
        lantern_download_sink* out     = memory_sink_make(&restored);
        lantern_download_sink* opening = NULL;
        REQUIRE_STATUS(lantern_decrypting_sink_create(key, out, NULL, &opening, NULL), LANTERN_OK);
        lantern_status status = lantern_download_sink_write(opening, bytes, length, NULL);
        if (status == LANTERN_OK)
            status = lantern_decrypting_sink_finish(opening, NULL);
        CHECK(status < 0);
        CHECK(restored.size <= 65536);
        lantern_download_sink_free(opening);
        lantern_download_sink_free(out);
        memory_sink_clear(&restored);
        lantern_save_key_free(key);
        lantern_string_free(sealed);
        free(bytes);
        free(archive);
    }
}

typedef struct plain_archive
{
    const uint8_t* bytes;
    size_t size;
} plain_archive;

static lantern_status read_plain(void* user, uint64_t offset, uint8_t* out, size_t size)
{
    const plain_archive* archive = user;
    if (offset + size > archive->size)
        return LANTERN_ERROR_STORAGE;
    memcpy(out, archive->bytes + offset, size);
    return LANTERN_OK;
}

static lantern_status fill_seven(void* user, uint8_t* out, size_t size)
{
    unsigned* next = user;
    for (size_t i = 0; i < size; ++i)
        out[i] = (uint8_t)(*next)++;
    return LANTERN_OK;
}

static void encrypted_saves_uploads(void)
{
    setup s;
    OPEN(s);
    unsigned next                   = 7;
    lantern_random_callbacks random = LANTERN_INIT(lantern_random_callbacks);
    random.user                     = &next;
    random.fill                     = fill_seven;
    lantern_random* source_of_bytes = NULL;
    REQUIRE_STATUS(lantern_random_create(&random, NULL, &source_of_bytes, NULL), LANTERN_OK);
    lantern_save_key* key = NULL;
    REQUIRE_STATUS(lantern_save_key_generate(source_of_bytes, NULL, &key, NULL), LANTERN_OK);
    uint8_t first[LANTERN_SAVE_HEADER_SIZE];
    uint8_t second[LANTERN_SAVE_HEADER_SIZE];
    REQUIRE_STATUS(lantern_make_save_header(key, source_of_bytes, first, NULL), LANTERN_OK);
    REQUIRE_STATUS(lantern_make_save_header(key, source_of_bytes, second, NULL), LANTERN_OK);
    CHECK(memcmp(first, second, sizeof(first)) != 0);

    static uint8_t archive[70000];
    for (size_t i = 0; i < sizeof(archive); ++i)
        archive[i] = (uint8_t)((i * 31 + 7) % 253);
    plain_archive plain                = { archive, sizeof(archive) };
    lantern_upload_callbacks callbacks = LANTERN_INIT(lantern_upload_callbacks);
    callbacks.user                     = &plain;
    callbacks.read                     = read_plain;
    lantern_upload_source* clear       = NULL;
    REQUIRE_STATUS(lantern_upload_source_create(&callbacks, NULL, &clear, NULL), LANTERN_OK);
    lantern_upload_source* encrypting = NULL;
    lantern_error error               = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_encrypting_source_create(key, first, clear, sizeof(archive), NULL, &encrypting, &error),
        LANTERN_OK, &error);
    lantern_upload_request request = LANTERN_INIT(lantern_upload_request);
    request.kind                   = "account";
    REQUIRE_CALL(lantern_encrypting_source_describe(encrypting, &request, &error), LANTERN_OK, &error);
    CHECK(request.size == lantern_encrypted_save_size(sizeof(archive)));
    CHECK(strcmp(request.encryption_scheme, LANTERN_SAVE_SCHEME) == 0);
    char id[17];
    lantern_save_key_id_text(key, id);
    CHECK(strcmp(request.encryption_key_id, id) == 0);
    /* The same bytes as the whole backup in memory */
    lantern_string* whole = NULL;
    REQUIRE_STATUS(
        lantern_encrypt_save(key, first, archive, sizeof(archive), NULL, &whole, NULL), LANTERN_OK);
    uint8_t digest[32];
    lantern_sha256((const uint8_t*)lantern_string_view(whole).data, lantern_string_view(whole).size, digest);
    CHECK(memcmp(digest, request.sha256, 32) == 0);
    CHECK_STATUS(lantern_encrypting_source_describe(clear, &request, &error), LANTERN_ERROR_USAGE);

    /* The upload's document says it; one request sends its key id */
    char* upload = spec_file("examples/v1/upload.json", NULL);
    char* save   = spec_file("examples/v1/save.json", NULL);
    REQUIRE(upload != NULL && save != NULL);
    fake_add(&s.server, "POST", "/api/lantern/v1/saves/0100ABCD00010000/uploads*", 201, upload);
    fake_add(&s.server, "POST", "/api/lantern/v1/saves/*", 201, save);
    lantern_upload_session* session = NULL;
    REQUIRE_CALL(lantern_client_open_upload(s.client, "0100ABCD00010000", &request, NULL, &session, &error),
        LANTERN_OK, &error);
    CHECK(strstr(s.server.last_body, "\"encryption\":{\"scheme\":\"lantern-save-e2e-1\"") != NULL);
    lantern_upload_session_free(session);
    lantern_save_info info = LANTERN_INIT(lantern_save_info);
    info.kind              = "account";
    info.encryption_key_id = id;
    lantern_save* sent     = NULL;
    REQUIRE_CALL(lantern_client_upload_save(s.client, "0100ABCD00010000",
                     (const uint8_t*)lantern_string_view(whole).data, lantern_string_view(whole).size, &info,
                     &sent, &error),
        LANTERN_OK, &error);
    char value[128];
    CHECK(fake_last_header(&s.server, "Lantern-Save-Encryption", value, sizeof(value)) != NULL
        && strstr(value, id) != NULL);
    lantern_save_free(sent);
    free(upload);
    free(save);
    lantern_string_free(whole);
    lantern_upload_source_free(encrypting);
    lantern_upload_source_free(clear);
    lantern_save_key_free(key);
    lantern_random_free(source_of_bytes);
    setup_close(&s);
}

/* A static library of no file at all. */
static lantern_status no_file(
    void* user, lantern_str path, uint64_t offset, lantern_download_sink* sink, bool* found)
{
    (void)offset;
    (void)sink;
    int* reads = user;
    ++*reads;
    CHECK(STR_EQ(path, "lantern.json"));
    *found = false;
    return LANTERN_OK;
}

static void static_libraries(void)
{
    for (size_t i = 0; i < COUNT(static_paths); ++i)
        CHECK(lantern_is_static_path(static_paths[i].path) == static_paths[i].accepted);
    for (size_t i = 0; i < COUNT(static_route_files); ++i)
        CHECK(lantern_is_static_path(static_route_files[i]));
    CHECK(!lantern_is_static_path(""));
    CHECK(!lantern_is_static_path(".."));

    int reads                                = 0;
    lantern_static_files_callbacks callbacks = LANTERN_INIT(lantern_static_files_callbacks);
    callbacks.user                           = &reads;
    callbacks.read                           = no_file;
    lantern_static_files* files              = NULL;
    REQUIRE_STATUS(lantern_static_files_create(&callbacks, NULL, &files, NULL), LANTERN_OK);
    lantern_static_library* library = NULL;
    lantern_error error             = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_static_library_open(files, NULL, NULL, &library, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 404);
    CHECK(library == NULL);
    CHECK(reads == 1);
    lantern_static_files_free(files);
    callbacks.read = NULL;
    CHECK_STATUS(lantern_static_files_create(&callbacks, NULL, &files, NULL), LANTERN_ERROR_USAGE);
    CHECK(lantern_app_list_count(NULL) == 0);
    CHECK(lantern_homebrew_list_at(NULL, 0) == NULL);
}

const test_case v05_tests[] = {
    { "v05: codes kept, families added", codes_and_families },
    { "v05: events' documents and their schema rule", event_documents },
    { "v05: the event stream, resumed, and long polling", the_event_stream_and_long_polling },
    { "v05: grants of the vectors (grants.json)", grants_of_the_vectors },
    { "v05: a grant asked, an account deleted", a_grant_asked_and_admin_deletion },
    { "v05: peers, their datagrams, their URLs", peers_and_their_datagrams },
    { "v05: the gate of a console that shares", the_gate_of_a_console_that_shares },
    { "v05: sync's merge of the vectors (sync-merge.json)", sync_merge_of_the_vectors },
    { "v05: wishes and what is installed", wishes_and_what_is_installed },
    { "v05: sync only with consent", sync_only_with_consent },
    { "v05: encrypted saves, the primitives and keys (encrypted-saves.json)",
        encrypted_saves_primitives_and_keys },
    { "v05: encrypted saves, the backups of the vectors", encrypted_saves_backups },
    { "v05: encrypted saves, the refused backups of the vectors", encrypted_saves_refused },
    { "v05: encrypted saves, an upload's source and document", encrypted_saves_uploads },
    { "v05: static libraries' paths (static-layout.json) and files", static_libraries },
};
const size_t v05_test_count = sizeof(v05_tests) / sizeof(v05_tests[0]);
