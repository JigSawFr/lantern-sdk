/* Draft 0.7 through the C API: canonical JSON (RFC 8785), chunk indexes,
 * a file put together from seeds and ranges (hostile answers included), the
 * upload's HEAD, and finding a library at an address; spec/vectors'
 * canonical-json and chunks. Every name is made up. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"
#include "vectors.h"

#define ORIGIN "https://shelf.example.org"
#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static bool equals_hex(const uint8_t* bytes, const char* hex)
{
    if (strlen(hex) != 64)
        return false;
    for (size_t i = 0; i < 32; ++i)
    {
        char two[3];
        snprintf(two, sizeof(two), "%02x", bytes[i]);
        if (memcmp(two, hex + 2 * i, 2) != 0)
            return false;
    }
    return true;
}

/* The vectors' files: SHA-256(seed, i on 8 bytes big-endian), cut to size. */
static uint8_t* stream(const char* seed, size_t size)
{
    uint8_t* out = malloc(size + 32);
    if (out == NULL)
        abort();
    const size_t seed_size = strlen(seed);
    uint8_t* input         = malloc(seed_size + 8);
    if (input == NULL)
        abort();
    memcpy(input, seed, seed_size);
    for (uint64_t i = 0; i * 32 < size; ++i)
    {
        for (int k = 0; k < 8; ++k)
            input[seed_size + (size_t)k] = (uint8_t)(i >> (56 - 8 * k));
        lantern_sha256(input, seed_size + 8, out + i * 32);
    }
    free(input);
    return out;
}

/* The newer version: 777 bytes inserted at 300,000, 10,000 removed at 700,000. */
static uint8_t* edited(const uint8_t* base, size_t* size)
{
    uint8_t* insertion = stream("an insertion", 777);
    uint8_t* out       = malloc(1000000 + 777);
    if (out == NULL)
        abort();
    size_t at = 0;
    memcpy(out + at, base, 300000);
    at += 300000;
    memcpy(out + at, insertion, 777);
    at += 777;
    memcpy(out + at, base + 300000, 400000);
    at += 400000;
    memcpy(out + at, base + 710000, 290000);
    at += 290000;
    free(insertion);
    *size = at;
    return out;
}

static void canonical_vectors(void)
{
    REQUIRE(COUNT(canonical_cases) == 7);
    for (size_t i = 0; i < COUNT(canonical_cases); ++i)
    {
        const canonical_case* v = &canonical_cases[i];
        lantern_string* out     = NULL;
        lantern_error error     = LANTERN_INIT(lantern_error);
        REQUIRE_CALL(
            lantern_canonical_json(v->json, strlen(v->json), NULL, &out, &error), LANTERN_OK, &error);
        const lantern_str got = lantern_string_view(out);
        CHECK(got.size == strlen(v->canonical) && memcmp(got.data, v->canonical, got.size) == 0);
        uint8_t digest[32];
        lantern_sha256((const uint8_t*)got.data, got.size, digest);
        CHECK(equals_hex(digest, v->sha256));
        lantern_string_free(out);
    }
    /* Numbers as ECMAScript writes them */
    static const char* const numbers[][2] = { { "1.0", "1" }, { "-0", "0" }, { "0.5", "0.5" },
        { "1e21", "1e+21" }, { "1E20", "100000000000000000000" }, { "1e-7", "1e-7" },
        { "0.000001", "0.000001" }, { "5e-324", "5e-324" }, { "333333333.33333329", "333333333.3333333" } };
    for (size_t i = 0; i < COUNT(numbers); ++i)
    {
        lantern_string* out = NULL;
        REQUIRE_STATUS(lantern_canonical_number(numbers[i][0], NULL, &out, NULL), LANTERN_OK);
        CHECK(STR_EQ(lantern_string_view(out), numbers[i][1]));
        lantern_string_free(out);
    }
    lantern_string* out = NULL;
    CHECK_STATUS(lantern_canonical_number("1e999", NULL, &out, NULL), LANTERN_ERROR_INVALID_RESPONSE);
    CHECK_STATUS(lantern_canonical_number("01", NULL, &out, NULL), LANTERN_ERROR_INVALID_RESPONSE);
    CHECK(out == NULL);
    /* A key twice has no canonical form */
    CHECK(lantern_canonical_json("{\"a\":1,\"a\":2}", 13, NULL, &out, NULL) < 0);
}

static void chunk_indexes_of_the_vectors(void)
{
    REQUIRE(COUNT(chunk_cases) == 6);
    for (size_t i = 0; i < COUNT(chunk_cases); ++i)
    {
        const chunk_case* v = &chunk_cases[i];
        uint8_t sha[32];
        REQUIRE(hex_to_bytes(v->file_sha256, sha, 32));
        lantern_chunk_index* index = NULL;
        lantern_error error        = LANTERN_INIT(lantern_error);
        /* Asked by the file's SHA-256 alone: no `chunks` to compare with */
        REQUIRE_CALL(lantern_read_chunk_index(
                         v->index, strlen(v->index), NULL, sha, v->file_size, NULL, &index, &error),
            LANTERN_OK, &error);
        CHECK(lantern_chunk_index_size(index) == v->file_size);
        CHECK(lantern_chunk_index_chunker_size(index) == v->chunker_size);
        CHECK(lantern_chunk_index_count(index) == v->chunk_count);
        uint8_t got[32];
        lantern_chunk_index_sha256(index, got);
        CHECK(memcmp(got, sha, 32) == 0);
        uint64_t total = 0;
        for (size_t k = 0; k < lantern_chunk_index_count(index); ++k)
        {
            uint32_t size = 0;
            CHECK(lantern_chunk_index_at(index, k, &size, got));
            total += size;
        }
        CHECK(total == v->file_size);
        CHECK(!lantern_chunk_index_at(index, lantern_chunk_index_count(index), NULL, NULL));
        lantern_chunk_index_free(index);
    }
    /* Another file's index, or other sizes: refused, and the file read whole */
    for (size_t i = 0; i < COUNT(refused_indexes); ++i)
    {
        const refused_index* v = &refused_indexes[i];
        uint8_t sha[32];
        REQUIRE(hex_to_bytes(v->file_sha256, sha, 32));
        lantern_chunk_index* index  = NULL;
        const lantern_status status = lantern_read_chunk_index(
            v->index, strlen(v->index), NULL, sha, v->file_size, NULL, &index, NULL);
        if (status == LANTERN_OK)
        {
            /* Only the bytes `chunks` gives, not a reading, can refuse the first of them */
            CHECK(strcmp(v->name, "Its bytes are not those whose SHA-256 the document gives") == 0);
            lantern_chunk_index_free(index);
        }
        else
            CHECK(index == NULL);
    }
}

/* A client of a scripted server whose handshake offers draft 0.7's family. */
typedef struct setup
{
    fake_server server;
    char* handshake;
    lantern_transport* transport;
    lantern_random* random;
    lantern_client* client;
    lantern_handshake* shake;
} setup;

static bool setup_open(setup* s)
{
    memset(s, 0, sizeof(*s));
    fake_init(&s->server, ORIGIN);
    s->handshake = spec_file("examples/v1/handshake.json", NULL);
    if (s->handshake == NULL)
        return false;
    fake_add(&s->server, "GET", "/.well-known/lantern", 200, s->handshake);
    s->transport = fake_transport(&s->server, NULL);
    if (s->transport == NULL || lantern_random_create_system(NULL, &s->random, NULL) != LANTERN_OK)
        return false;
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = ORIGIN;
    config.user_agent            = "LanternCTests/0.7";
    config.platform              = "switch";
    config.transport             = s->transport;
    config.random                = s->random;
    return lantern_client_create(&config, &s->client, NULL) == LANTERN_OK
        && lantern_client_handshake(s->client, &s->shake, NULL) == LANTERN_OK;
}

static void setup_close(setup* s)
{
    lantern_handshake_free(s->shake);
    lantern_client_free(s->client);
    lantern_transport_free(s->transport);
    lantern_random_free(s->random);
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

static void deltas_are_a_family(void)
{
    CHECK(LANTERN_C_API_VERSION == 6);
    CHECK(LANTERN_FAMILY_DELTAS == 15);
    setup s;
    OPEN(s);
    CHECK(lantern_client_offers(s.client, LANTERN_FAMILY_DELTAS) == 1);
    CHECK(lantern_client_offers(s.client, 16) == 0);
    uint64_t deltas = 0;
    CHECK(lantern_handshake_features_get_deltas(lantern_handshake_get_features(s.shake), &deltas)
        && deltas == 1);
    setup_close(&s);
}

/* The update of the vectors, on a scripted server. */
typedef struct update
{
    uint8_t* older;
    size_t older_size;
    uint8_t* newer;
    size_t newer_size;
    const chunk_case* index;
    char app_json[2048];
    char index_path[160];
    char file_path[160];
    lantern_apps_page* page;
    const lantern_app_chunks* chunks;
    lantern_download_target target;
} update;

static bool update_open(update* u)
{
    memset(u, 0, sizeof(*u));
    u->older      = stream("lantern-cdc-1 vector", 1000000);
    u->older_size = 1000000;
    u->newer      = edited(u->older, &u->newer_size);
    u->index      = &chunk_cases[4];
    uint8_t sha[32];
    lantern_sha256(u->newer, u->newer_size, sha);
    if (u->newer_size != u->index->file_size || !equals_hex(sha, u->index->file_sha256))
        return false;
    snprintf(u->index_path, sizeof(u->index_path), "/api/lantern/v1/chunks/sha256/%s", u->index->file_sha256);
    snprintf(u->file_path, sizeof(u->file_path), "/api/lantern/v1/blobs/sha256/%s", u->index->file_sha256);
    snprintf(u->app_json, sizeof(u->app_json),
        "{\"schema\":1,\"items\":[{\"id\":\"a_1\",\"platform\":\"switch\",\"title_id\":\"0100ABCD00010000\","
        "\"app_id\":\"0100ABCD00010800\",\"type\":\"update\",\"version_code\":196608,\"name\":\"Frostline "
        "Tales\","
        "\"size\":%llu,\"format\":\"nsz\",\"sha256\":\"%s\",\"file\":\"%s\","
        "\"chunks\":{\"url\":\"%s\",\"size\":%llu,\"sha256\":\"%s\"}}],\"total\":1,\"next\":null}",
        (unsigned long long)u->newer_size, u->index->file_sha256, u->file_path, u->index_path,
        (unsigned long long)u->index->index_size, u->index->index_sha256);
    if (lantern_read_apps_page(u->app_json, strlen(u->app_json), NULL, NULL, &u->page, NULL) != LANTERN_OK)
        return false;
    const lantern_app* app = lantern_apps_page_get_items_at(u->page, 0);
    u->chunks              = app == NULL ? NULL : lantern_app_get_chunks(app);
    u->target.struct_size  = sizeof(u->target);
    u->target.url          = u->file_path;
    u->target.size         = u->newer_size;
    return u->chunks != NULL && hex_to_bytes(u->index->file_sha256, u->target.sha256, 32);
}

static void update_close(update* u)
{
    lantern_apps_page_free(u->page);
    free(u->older);
    free(u->newer);
}

#define OPEN_UPDATE(u)                                                                                       \
    do                                                                                                       \
    {                                                                                                        \
        if (!update_open(&(u)))                                                                              \
        {                                                                                                    \
            update_close(&(u));                                                                              \
            REQUIRE(false);                                                                                  \
        }                                                                                                    \
    } while (0)

/* The ranges the vectors name, as routes answered in order. */
static const size_t range_first[2] = { 223418, 528735 };
static const size_t range_last[2]  = { 364436, 757525 };

static void route_ranges(
    setup* s, update* u, char ranges[2][64], int count, int flip, size_t cut, size_t short_by)
{
    for (int i = 0; i < count; ++i)
    {
        fake_route* route = fake_add(&s->server, "GET", u->file_path, 206, NULL);
        snprintf(ranges[i], 64, "bytes %zu-%zu/%zu", range_first[i], range_last[i], u->newer_size);
        route->headers[0][0] = "Content-Type";
        route->headers[0][1] = "application/octet-stream";
        route->headers[1][0] = "Content-Range";
        route->headers[1][1] = ranges[i];
        route->body          = (const char*)u->newer + range_first[i];
        route->body_size     = range_last[i] - range_first[i] + 1;
        route->times         = 1;
        if (i == 0)
        {
            if (flip)
                u->newer[range_first[0] + 70000] ^= 1U;
            route->cut_after = cut;
            route->body_size -= short_by;
        }
    }
}

static void route_whole(setup* s, update* u, uint8_t* whole)
{
    fake_route* route    = fake_add(&s->server, "GET", u->file_path, 200, NULL);
    route->headers[0][0] = "Content-Type";
    route->headers[0][1] = "application/octet-stream";
    route->body          = (const char*)whole;
    route->body_size     = u->newer_size;
}

static void update_from_a_seed(void)
{
    setup s;
    update u;
    OPEN(s);
    OPEN_UPDATE(u);
    fake_add(&s.server, "GET", u.index_path, 200, u.index->index);
    char ranges[2][64];
    route_ranges(&s, &u, ranges, 2, 0, 0, 0);
    memory_sink sink;
    memset(&sink, 0, sizeof(sink));
    lantern_download_sink* out = memory_sink_make(&sink);
    REQUIRE(out != NULL);
    const lantern_seed seeds[1] = { { u.older, u.older_size } };
    lantern_delta_options o     = LANTERN_INIT(lantern_delta_options);
    o.has_gap                   = true;
    o.gap                       = 0;
    lantern_delta_report report = LANTERN_INIT(lantern_delta_report);
    lantern_error error         = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_client_download_with_seeds(s.client, &u.target, u.chunks, seeds, 1, out, &o, &report, &error),
        LANTERN_OK, &error);
    CHECK(!report.whole_file);
    CHECK(report.requests == 2);
    CHECK(report.from_ranges == update_read);
    CHECK(report.from_seeds + report.from_ranges == u.newer_size);
    CHECK(sink.size == u.newer_size && memcmp(sink.bytes, u.newer, u.newer_size) == 0);
    CHECK(sink.restarts == 0);
    for (size_t i = 0; i < COUNT(update_ranges); ++i)
    {
        char expected[64];
        snprintf(expected, sizeof(expected), "bytes=%zu-%zu", range_first[i], range_last[i]);
        CHECK(strcmp(update_ranges[i], expected) == 0);
    }
    CHECK(s.server.requests == 4); /* the handshake, the index, two ranges */
    memory_sink_clear(&sink);
    lantern_download_sink_free(out);
    update_close(&u);
    setup_close(&s);
}

static void update_with_an_index_in_hand(void)
{
    setup s;
    update u;
    OPEN(s);
    OPEN_UPDATE(u);
    fake_add(&s.server, "GET", u.index_path, 200, u.index->index);
    lantern_chunk_index* index = NULL;
    lantern_error error        = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_client_chunk_index(s.client, u.chunks, &u.target, &index, &error), LANTERN_OK, &error);
    CHECK(lantern_chunk_index_count(index) == u.index->chunk_count);
    /* The newer file as its own seed: nothing to ask for */
    char ranges[2][64];
    route_ranges(&s, &u, ranges, 2, 0, 0, 0);
    memory_sink sink;
    memset(&sink, 0, sizeof(sink));
    lantern_download_sink* out  = memory_sink_make(&sink);
    const lantern_seed seeds[1] = { { u.newer, u.newer_size } };
    lantern_delta_report report = LANTERN_INIT(lantern_delta_report);
    const int before            = s.server.requests;
    REQUIRE_CALL(
        lantern_client_download_with_index(s.client, &u.target, index, seeds, 1, out, NULL, &report, &error),
        LANTERN_OK, &error);
    CHECK(report.from_ranges == 0);
    CHECK(report.from_seeds == u.newer_size);
    CHECK(s.server.requests == before);
    CHECK(sink.size == u.newer_size);
    /* By the file's SHA-256 alone */
    fake_add(&s.server, "GET", u.index_path, 200, u.index->index);
    lantern_chunk_index* by_hash = NULL;
    REQUIRE_CALL(lantern_client_chunk_index_of(s.client, u.target.sha256, u.newer_size, &by_hash, &error),
        LANTERN_OK, &error);
    CHECK(lantern_chunk_index_count(by_hash) == u.index->chunk_count);
    lantern_chunk_index_free(by_hash);
    lantern_chunk_index_free(index);
    memory_sink_clear(&sink);
    lantern_download_sink_free(out);
    update_close(&u);
    setup_close(&s);
}

typedef enum lie
{
    LIE_CHUNK,
    LIE_CUT,
    LIE_SHORT,
    LIE_INDEX,
    LIE_NO_SEED
} lie;

static void update_that_goes_wrong(lie what)
{
    setup s;
    update u;
    OPEN(s);
    OPEN_UPDATE(u);
    /* The good bytes, for the whole file read after the lie */
    uint8_t* good = malloc(u.newer_size);
    REQUIRE(good != NULL);
    memcpy(good, u.newer, u.newer_size);
    char* index = malloc(strlen(u.index->index) + 1);
    REQUIRE(index != NULL);
    strcpy(index, u.index->index);
    if (what == LIE_INDEX)
        index[40] = index[40] == 'a' ? 'b' : 'a';
    fake_add(&s.server, "GET", u.index_path, 200, index);
    char ranges[2][64];
    /* The first range lies; the second route would answer the whole file asked for after it */
    route_ranges(&s, &u, ranges, what == LIE_INDEX || what == LIE_NO_SEED ? 0 : 1, what == LIE_CHUNK,
        what == LIE_CUT ? 20000 : 0, what == LIE_SHORT ? 100 : 0);
    route_whole(&s, &u, good);
    memory_sink sink;
    memset(&sink, 0, sizeof(sink));
    lantern_download_sink* out = memory_sink_make(&sink);
    lantern_seed seeds[1]      = { { u.older, u.older_size } };
    if (what == LIE_NO_SEED)
        seeds[0].size = 0;
    lantern_delta_options o     = LANTERN_INIT(lantern_delta_options);
    o.has_gap                   = true;
    lantern_delta_report report = LANTERN_INIT(lantern_delta_report);
    lantern_error error         = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_client_download_with_seeds(s.client, &u.target, u.chunks, seeds, 1, out, &o, &report, &error),
        LANTERN_OK, &error);
    /* L-22.3-4: the file whole, and right */
    CHECK(report.whole_file);
    CHECK(sink.restarts >= 1);
    CHECK(sink.size == u.newer_size && memcmp(sink.bytes, good, u.newer_size) == 0);
    memory_sink_clear(&sink);
    lantern_download_sink_free(out);
    free(index);
    free(good);
    update_close(&u);
    setup_close(&s);
}

static void update_with_a_chunk_changed(void)
{
    update_that_goes_wrong(LIE_CHUNK);
}
static void update_with_a_range_cut(void)
{
    update_that_goes_wrong(LIE_CUT);
}
static void update_with_a_short_range(void)
{
    update_that_goes_wrong(LIE_SHORT);
}
static void update_with_a_bad_index(void)
{
    update_that_goes_wrong(LIE_INDEX);
}
static void update_with_a_seed_of_nothing(void)
{
    update_that_goes_wrong(LIE_NO_SEED);
}

static void upload_head_gives_the_chunk_size(void)
{
    setup s;
    OPEN(s);
    fake_route* route = fake_add(&s.server, "HEAD", "/api/lantern/v1/uploads/u_1", 204, NULL);
    fake_header(route, "Upload-Offset", "512");
    fake_header(route, "Upload-Length", "4096");
    fake_header(route, "Lantern-Chunk-Size", "1024");
    lantern_upload_head head = LANTERN_INIT(lantern_upload_head);
    lantern_error error      = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_upload_head(s.client, "/api/lantern/v1/uploads/u_1", &head, &error),
        LANTERN_OK, &error);
    CHECK(head.offset == 512);
    CHECK(head.has_length && head.length == 4096);
    CHECK(head.has_chunk_size && head.chunk_size == 1024);
    /* A server of an earlier draft sends neither */
    s.server.route_count = 1;
    route                = fake_add(&s.server, "HEAD", "/api/lantern/v1/uploads/u_2", 204, NULL);
    fake_header(route, "Upload-Offset", "7");
    lantern_upload_head bare = LANTERN_INIT(lantern_upload_head);
    REQUIRE_CALL(lantern_client_upload_head(s.client, "/api/lantern/v1/uploads/u_2", &bare, &error),
        LANTERN_OK, &error);
    CHECK(bare.offset == 7);
    CHECK(!bare.has_length && !bare.has_chunk_size);
    setup_close(&s);
}

static void find_a_library_at_an_address(void)
{
    fake_server server;
    fake_init(&server, ORIGIN);
    char* handshake = spec_file("examples/v1/handshake.json", NULL);
    REQUIRE(handshake != NULL);
    fake_add(&server, "GET", "/.well-known/lantern", 200, handshake);
    lantern_transport* transport = fake_transport(&server, NULL);
    REQUIRE(transport != NULL);
    lantern_found_library* found = NULL;
    lantern_error error          = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(
        lantern_find_library(transport, ORIGIN "/some/path", "LanternCTests/0.7", NULL, NULL, &found, &error),
        LANTERN_OK, &error);
    CHECK(lantern_found_library_kind(found) == LANTERN_LIBRARY_SERVER);
    CHECK(STR_EQ(lantern_found_library_root(found), ORIGIN));
    CHECK(lantern_found_library_handshake(found) != NULL);
    lantern_found_library_free(found);
    /* Nothing there */
    server.route_count = 0;
    found              = NULL;
    CHECK_STATUS(lantern_find_library(transport, ORIGIN "/", "LanternCTests/0.7", NULL, NULL, &found, NULL),
        LANTERN_ABSENT);
    CHECK(found == NULL);
    CHECK(lantern_find_library(
              transport, "ftp://shelf.example.org/", "LanternCTests/0.7", NULL, NULL, &found, NULL)
        < 0);
    lantern_transport_free(transport);
    free(handshake);
}

const test_case v07_tests[] = {
    { "v07: canonical JSON, the vectors and numbers", canonical_vectors },
    { "v07: chunk indexes, the vectors", chunk_indexes_of_the_vectors },
    { "v07: deltas is a family", deltas_are_a_family },
    { "v07: a file from a seed and two ranges", update_from_a_seed },
    { "v07: an index in hand, and by the file's SHA-256", update_with_an_index_in_hand },
    { "v07: a chunk that does not match reads the whole file", update_with_a_chunk_changed },
    { "v07: a range cut reads the whole file", update_with_a_range_cut },
    { "v07: a short range reads the whole file", update_with_a_short_range },
    { "v07: a bad index reads the whole file", update_with_a_bad_index },
    { "v07: a seed that holds nothing reads the whole file", update_with_a_seed_of_nothing },
    { "v07: an upload's HEAD gives the chunk size", upload_head_gives_the_chunk_size },
    { "v07: a library at an address", find_a_library_at_an_address },
};
const size_t v07_test_count = sizeof(v07_tests) / sizeof(v07_tests[0]);
