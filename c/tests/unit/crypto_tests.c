/* Signed requests against spec/vectors/signatures.json, byte for byte; the
 * device key; the server's key against spki.json; invitations. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"
#include "vectors.h"

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static lantern_device_key* vector_key(void)
{
    uint8_t seed[32];
    if (!hex_to_bytes(vector_seed, seed, 32))
        return NULL;
    lantern_device_key* key = NULL;
    if (lantern_device_key_from_seed(seed, NULL, &key, NULL) != LANTERN_OK)
        return NULL;
    return key;
}

/* The nonce a vector chose, from its Signature-Input. */
static void nonce_of(const char* input, char* out, size_t size)
{
    const char* at = strstr(input, "nonce=\"");
    out[0]         = '\0';
    if (at == NULL)
        return;
    at += 7;
    const char* end = strchr(at, '"');
    size_t length   = (size_t)(end - at);
    if (length >= size)
        length = size - 1;
    memcpy(out, at, length);
    out[length] = '\0';
}

static void the_vectors_key(void)
{
    lantern_device_key* key = vector_key();
    REQUIRE(key != NULL);
    char keyid[44];
    lantern_device_key_keyid(key, keyid);
    CHECK(strcmp(keyid, vector_keyid) == 0);
    char fingerprint[20];
    lantern_device_key_fingerprint(key, fingerprint);
    CHECK(strcmp(fingerprint, vector_fingerprint) == 0);
    uint8_t seed[32];
    uint8_t expected[32];
    lantern_device_key_seed(key, seed);
    REQUIRE(hex_to_bytes(vector_seed, expected, 32));
    CHECK(memcmp(seed, expected, 32) == 0);
    /* RFC 8032 § 7.1, test 1: the empty message */
    uint8_t signature[64];
    uint8_t public_key[32];
    lantern_device_key_sign(key, NULL, 0, signature);
    lantern_device_key_public_key(key, public_key);
    uint8_t rfc[64];
    REQUIRE(hex_to_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        rfc, 64));
    CHECK(memcmp(signature, rfc, 64) == 0);
    CHECK(lantern_ed25519_verify(signature, public_key, NULL, 0));
    signature[0] ^= 1U;
    CHECK(!lantern_ed25519_verify(signature, public_key, NULL, 0));
    lantern_device_key_free(key);
}

static void every_accepted_request(void)
{
    lantern_device_key* key = vector_key();
    REQUIRE(key != NULL);
    REQUIRE(COUNT(accepted_requests) == 5);
    lantern_error error = LANTERN_INIT(lantern_error);
    for (size_t i = 0; i < COUNT(accepted_requests); ++i)
    {
        const signed_request* v = &accepted_requests[i];
        char nonce[80];
        nonce_of(v->signature_input, nonce, sizeof(nonce));
        lantern_string* uri = NULL;
        REQUIRE_CALL(lantern_target_uri(v->uri, NULL, &uri, &error), LANTERN_OK, &error);
        CHECK(STR_EQ(lantern_string_view(uri), v->uri));
        if (v->body[0] != '\0')
        {
            uint8_t digest[32];
            char field[55];
            lantern_sha256((const uint8_t*)v->body, strlen(v->body), digest);
            lantern_format_digest_field(digest, field);
            CHECK(strcmp(field, v->content_digest) == 0);
        }
        lantern_signed_components components = LANTERN_INIT(lantern_signed_components);
        components.method                    = v->method;
        components.target_uri                = lantern_string_view(uri).data;
        components.authorization             = v->authorization;
        components.content_digest            = v->content_digest;
        lantern_string* base                 = NULL;
        REQUIRE_CALL(
            lantern_signature_base(&components, vector_server_time, nonce, vector_keyid, NULL, &base, &error),
            LANTERN_OK, &error);
        if (!STR_EQ(lantern_string_view(base), v->signature_base))
            fprintf(stderr, "    base of \"%s\"\n", v->name);
        CHECK(STR_EQ(lantern_string_view(base), v->signature_base));
        lantern_string* input     = NULL;
        lantern_string* signature = NULL;
        REQUIRE_CALL(lantern_sign_components(
                         key, &components, vector_server_time, nonce, NULL, &input, &signature, &error),
            LANTERN_OK, &error);
        CHECK(STR_EQ(lantern_string_view(input), v->signature_input));
        CHECK(STR_EQ(lantern_string_view(signature), v->signature));

        /* And a server takes it */
        lantern_signature_check check = LANTERN_INIT(lantern_signature_check);
        check.method                  = v->method;
        check.target_uri              = lantern_string_view(uri).data;
        check.authorization           = v->authorization;
        check.content_digest          = v->content_digest;
        check.has_body                = v->body[0] != '\0';
        check.signature_input         = v->signature_input;
        check.signature               = v->signature;
        lantern_device_key_public_key(key, check.public_key);
        check.now             = vector_server_time;
        check.has_body_sha256 = true;
        lantern_sha256((const uint8_t*)v->body, strlen(v->body), check.body_sha256);
        lantern_signature_verdict verdict = LANTERN_INIT(lantern_signature_verdict);
        REQUIRE_CALL(lantern_check_signature(&check, &verdict, &error), LANTERN_OK, &error);
        CHECK(verdict.code == LANTERN_CODE_NONE);
        CHECK(strcmp(verdict.nonce, nonce) == 0);
        CHECK(strcmp(verdict.keyid, vector_keyid) == 0);
        lantern_string_free(uri);
        lantern_string_free(base);
        lantern_string_free(input);
        lantern_string_free(signature);
    }
    lantern_device_key_free(key);
}

/* A server's check of one request, with the nonces it saw, for replays. */
static lantern_code check_one(
    const lantern_device_key* key, const signed_request* v, char seen[][160], size_t* seen_count)
{
    lantern_string* uri = NULL;
    if (lantern_target_uri(v->uri, NULL, &uri, NULL) != LANTERN_OK)
        return LANTERN_CODE_UNKNOWN;
    lantern_signature_check check = LANTERN_INIT(lantern_signature_check);
    check.method                  = v->method;
    check.target_uri              = lantern_string_view(uri).data;
    check.authorization           = v->authorization;
    check.content_digest          = v->content_digest;
    check.has_body                = v->body[0] != '\0';
    check.signature_input         = v->signature_input;
    check.signature               = v->signature;
    lantern_device_key_public_key(key, check.public_key);
    check.now                         = vector_server_time;
    check.skew                        = vector_skew;
    lantern_signature_verdict verdict = LANTERN_INIT(lantern_signature_verdict);
    const lantern_status status       = lantern_check_signature(&check, &verdict, NULL);
    lantern_string_free(uri);
    if (status != LANTERN_OK)
        return LANTERN_CODE_UNKNOWN;
    if (verdict.code != LANTERN_CODE_NONE)
        return verdict.code;
    char nonce[160];
    snprintf(nonce, sizeof(nonce), "%s/%s", verdict.keyid, verdict.nonce);
    for (size_t i = 0; i < *seen_count; ++i)
    {
        if (strcmp(seen[i], nonce) == 0)
            return LANTERN_CODE_SIGNATURE_REPLAYED;
    }
    snprintf(seen[(*seen_count)++], 160, "%s", nonce);
    return LANTERN_CODE_NONE;
}

static void every_refused_request(void)
{
    lantern_device_key* key = vector_key();
    REQUIRE(key != NULL);
    char seen[16][160];
    size_t seen_count = 0;
    REQUIRE(COUNT(refused_requests) >= 6);
    for (size_t i = 0; i < COUNT(refused_requests); ++i)
    {
        const refused_request* v = &refused_requests[i];
        if (v->after[0] != '\0')
        {
            for (size_t a = 0; a < COUNT(accepted_requests); ++a)
            {
                if (strcmp(accepted_requests[a].name, v->after) == 0)
                    CHECK(check_one(key, &accepted_requests[a], seen, &seen_count) == LANTERN_CODE_NONE);
            }
        }
        const lantern_code code = check_one(key, &v->request, seen, &seen_count);
        if (strcmp(lantern_code_name(code), v->code) != 0)
            fprintf(stderr, "    \"%s\": %s, not %s\n", v->name, lantern_code_name(code), v->code);
        CHECK(strcmp(lantern_code_name(code), v->code) == 0);
    }
    lantern_device_key_free(key);
}

static lantern_status scripted(void* user, uint8_t* out, size_t size)
{
    int* calls = user;
    ++*calls;
    for (size_t i = 0; i < size; ++i)
        out[i] = (uint8_t)(i * 37U + (size_t)*calls);
    return LANTERN_OK;
}

static lantern_status broken(void* user, uint8_t* out, size_t size)
{
    (void)user;
    (void)out;
    (void)size;
    return LANTERN_ERROR_STORAGE;
}

static void device_keys_from_a_random_source(void)
{
    int calls                          = 0;
    lantern_random_callbacks callbacks = LANTERN_INIT(lantern_random_callbacks);
    callbacks.user                     = &calls;
    callbacks.fill                     = scripted;
    lantern_random* random             = NULL;
    REQUIRE_STATUS(lantern_random_create(&callbacks, NULL, &random, NULL), LANTERN_OK);
    lantern_device_key* key = NULL;
    REQUIRE_STATUS(lantern_device_key_generate(random, NULL, &key, NULL), LANTERN_OK);
    CHECK(calls == 1);
    char keyid[44];
    lantern_device_key_keyid(key, keyid);
    CHECK(strlen(keyid) == 43);
    lantern_device_key_free(key);
    lantern_random_free(random);

    callbacks.fill = broken;
    REQUIRE_STATUS(lantern_random_create(&callbacks, NULL, &random, NULL), LANTERN_OK);
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_device_key_generate(random, NULL, &key, &error), LANTERN_ERROR_STORAGE);
    CHECK(key == NULL);
    lantern_random_free(random);

    /* The system's */
    lantern_random* system      = NULL;
    const lantern_status status = lantern_random_create_system(NULL, &system, &error);
    CHECK(status == LANTERN_OK || status == LANTERN_ERROR_UNSUPPORTED);
    if (status == LANTERN_OK)
    {
        lantern_device_key* first  = NULL;
        lantern_device_key* second = NULL;
        REQUIRE_STATUS(lantern_device_key_generate(system, NULL, &first, NULL), LANTERN_OK);
        REQUIRE_STATUS(lantern_device_key_generate(system, NULL, &second, NULL), LANTERN_OK);
        uint8_t a[32];
        uint8_t b[32];
        lantern_device_key_public_key(first, a);
        lantern_device_key_public_key(second, b);
        CHECK(memcmp(a, b, 32) != 0);
        lantern_device_key_free(first);
        lantern_device_key_free(second);
    }
    lantern_random_free(system);
}

static void http_dates(void)
{
    int64_t seconds = 0;
    CHECK(lantern_parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT", &seconds));
    CHECK(seconds == 784111777);
    CHECK(!lantern_parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT", &seconds));
    CHECK(!lantern_parse_http_date(NULL, &seconds));
}

static void the_server_key(void)
{
    lantern_error error = LANTERN_INIT(lantern_error);
    REQUIRE(COUNT(spki_vectors) == 3);
    for (size_t i = 0; i < COUNT(spki_vectors); ++i)
    {
        uint8_t digest[32];
        REQUIRE_CALL(lantern_spki_sha256_pem(spki_vectors[i].pem, digest, &error), LANTERN_OK, &error);
        char hex[65];
        lantern_digest_to_hex(digest, hex);
        CHECK(strcmp(hex, spki_vectors[i].spki_sha256) == 0);
        char short_form[20];
        lantern_short_form(digest, short_form);
        CHECK(strcmp(short_form, spki_vectors[i].short_form) == 0);
    }

    /* The trust: a pin decides, whatever the CA store says */
    lantern_trust* trust = NULL;
    REQUIRE_STATUS(lantern_trust_create(NULL, &trust, NULL), LANTERN_OK);
    CHECK(lantern_trust_get_mode(trust) == LANTERN_TRUST_CA);
    const uint8_t spki_a[] = { 0x30, 0x03, 0x01, 0x02, 0x03 };
    const uint8_t spki_b[] = { 0x30, 0x03, 0x04, 0x05, 0x06 };
    CHECK(lantern_trust_accept(trust, spki_a, sizeof(spki_a), true));
    CHECK(!lantern_trust_accept(trust, spki_a, sizeof(spki_a), false));
    uint8_t seen[32];
    CHECK(lantern_trust_get_seen(trust, seen));
    const uint32_t generation = lantern_trust_get_generation(trust);
    lantern_trust_allow_unverified(trust);
    CHECK(lantern_trust_get_mode(trust) == LANTERN_TRUST_UNVERIFIED);
    CHECK(lantern_trust_get_generation(trust) != generation);
    CHECK(lantern_trust_accept(trust, spki_b, sizeof(spki_b), false));
    uint8_t pin[32];
    lantern_sha256(spki_a, sizeof(spki_a), pin);
    lantern_trust_pin(trust, pin);
    CHECK(lantern_trust_get_mode(trust) == LANTERN_TRUST_PINNED);
    uint8_t pinned[32];
    CHECK(lantern_trust_get_pin(trust, pinned) && memcmp(pinned, pin, 32) == 0);
    CHECK(lantern_trust_accept(trust, spki_a, sizeof(spki_a), false));
    CHECK(!lantern_trust_accept(trust, spki_b, sizeof(spki_b), true));
    CHECK(!lantern_trust_accept_certificate(trust, spki_a, sizeof(spki_a), true));
    lantern_trust_require_ca(trust);
    CHECK(lantern_trust_get_mode(trust) == LANTERN_TRUST_CA);
    CHECK(!lantern_trust_get_pin(trust, pinned));
    lantern_trust_free(trust);
}

static void invitations_and_codes(void)
{
    lantern_invitation_link link = LANTERN_INIT(lantern_invitation_link);
    lantern_error error          = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_parse_invitation_link(
                     "https://shelf.example.org/invite?invitation=MZ7Q-4KHP-XW2N-8TRD"
                     "&spki=79315e024cf7f6e0f2553884fd098ac59df2e2a7e5f1e1e7b46d1e6c1a5b9f7c",
                     &link, &error),
        LANTERN_OK, &error);
    CHECK(strcmp(link.code, "MZ7Q-4KHP-XW2N-8TRD") == 0);
    CHECK(link.has_spki);
    CHECK(link.spki[0] == 0x79 && link.spki[1] == 0x31);
    CHECK_STATUS(lantern_parse_invitation_link("https://shelf.example.org/invite", &link, &error),
        LANTERN_ERROR_USAGE);
    CHECK(lantern_is_pairing_code("KQ4M-7TXD"));
    CHECK(!lantern_is_pairing_code("kq4m-7txd"));
    CHECK(lantern_is_invitation_code("MZ7Q-4KHP-XW2N-8TRD"));
    CHECK(!lantern_is_invitation_code("KQ4M-7TXD"));
    CHECK(!lantern_is_pairing_code(NULL));
}

const test_case crypto_tests[] = {
    { "crypto: the vectors' key", the_vectors_key },
    { "crypto: every accepted request of the vectors, byte for byte", every_accepted_request },
    { "crypto: every refused request of the vectors, with its code", every_refused_request },
    { "crypto: device keys from a random source", device_keys_from_a_random_source },
    { "crypto: HTTP dates", http_dates },
    { "crypto: the server's key, spki.json, the trust", the_server_key },
    { "crypto: invitation links and codes", invitations_and_codes },
};
const size_t crypto_test_count = sizeof(crypto_tests) / sizeof(crypto_tests[0]);
