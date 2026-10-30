/*
 * Lantern's C API: a thin, stable C ABI over the C++23 client library
 * (cpp/), for Swift, Kotlin (through JNI) and any language with a C FFI.
 * It follows the specification's draft 0.4 (SPEC.md).
 *
 * C11 or later, and C++ (extern "C"). The rules every function keeps, which
 * c/README.md explains at length:
 *
 * - Errors: a function that can fail returns a lantern_status, LANTERN_OK
 *   (0) or a negative LANTERN_ERROR_*; its last argument, a lantern_error*
 *   the caller may leave NULL, then says what went wrong (the problem+json
 *   of SPEC.md § 12 when the server sent one). LANTERN_ABSENT (1) is not an
 *   error: a document of a newer `schema` than this library reads (§ 3.2),
 *   for which *out is NULL.
 * - Strings given to the library are UTF-8 and NUL-terminated (`const
 *   char*`; NULL is the empty string), unless a size goes with them. Strings
 *   the library gives are lantern_str, UTF-8 with their size, and always
 *   NUL-terminated at data[size] too (data is never NULL); they are
 *   borrowed from the object they come from and live as long as it does.
 * - Ownership: a function that gives an object through an `**out`
 *   argument gives it to the caller, who frees it with the matching
 *   lantern_*_free() (each accepts NULL). Every other pointer the library
 *   gives (a `const T*` result, a lantern_str) is borrowed from the object
 *   it was asked of. Objects the caller passes in (a transport, a store, a
 *   trust…) are borrowed by the library and must outlive what holds them.
 * - Memory: every allocation goes through the lantern_allocator the caller
 *   gives, or the C++ default resource (operator new) when it gives none.
 * - Structs passed by pointer begin with `size_t struct_size`, which the
 *   caller sets to sizeof the struct it was compiled with (LANTERN_INIT
 *   does): a later version only appends members, and reads or writes no
 *   further than struct_size. Structs passed in arrays (lantern_header,
 *   lantern_installed_app…) are frozen: a change makes a new one.
 * - Threads: a lantern_client is used by one thread at a time; see
 *   c/README.md.
 */
#ifndef LANTERN_LANTERN_H
#define LANTERN_LANTERN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* x-release-please-start-version: release-please writes the SDK's version below (RELEASING.md) */

/* Versions. LANTERN_C_API_VERSION goes up by one with each release that
 * adds to the API (functions, members appended to a struct, constants);
 * nothing is ever removed or changed while LANTERN_C_ABI_VERSION, the
 * shared library's SONAME version, stays the same. */
#define LANTERN_C_API_VERSION 1
#define LANTERN_C_ABI_VERSION 1
#define LANTERN_VERSION_STRING "0.4.0"
#define LANTERN_SPEC_DRAFT "0.4"

/* x-release-please-end */

/* LANTERN_API marks what the library exports, and nothing else is. A
 * program that links the static library on Windows defines
 * LANTERN_C_STATIC (CMake's Lantern::c_static does). */
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(LANTERN_C_BUILD)
#define LANTERN_API __declspec(dllexport)
#elif defined(LANTERN_C_STATIC)
#define LANTERN_API
#else
#define LANTERN_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define LANTERN_API __attribute__((visibility("default")))
#else
#define LANTERN_API
#endif

/* A struct of this API with its struct_size set and everything else zero
 * (the defaults): `lantern_client_config config = LANTERN_INIT(lantern_client_config);` */
// clang-format off
#if defined(__cplusplus)
#define LANTERN_INIT(type) ([] { type value_ {}; value_.struct_size = sizeof(type); return value_; }())
#else
#define LANTERN_INIT(type) ((type) { .struct_size = sizeof(type) })
#endif
// clang-format on

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- Basics */

/* The API version the library was built with: an app compiled against a
 * header of version N checks lantern_version() >= N before it calls what
 * version N added. */
LANTERN_API uint32_t lantern_version(void);
/* "0.4.0", and "0.4", the specification's draft it follows. */
LANTERN_API const char* lantern_version_string(void);
LANTERN_API const char* lantern_spec_draft(void);

/* A string the library gives: UTF-8, `size` bytes, NUL-terminated at
 * data[size], borrowed. */
typedef struct lantern_str
{
    const char* data;
    size_t size;
} lantern_str;

/* What a function returns. */
typedef int32_t lantern_status;
enum
{
    LANTERN_OK = 0,
    /* A document of a newer `schema` (SPEC.md § 3.2): *out is NULL, not an error. */
    LANTERN_ABSENT = 1,
    /* The server answered with an error status (problem+json, § 12). */
    LANTERN_ERROR_PROTOCOL = -1,
    /* The request did not reach the server, or its answer was cut. */
    LANTERN_ERROR_TRANSPORT = -2,
    /* A document or header the protocol does not allow. */
    LANTERN_ERROR_INVALID_RESPONSE = -3,
    /* Beyond § 13's limits, or the app's lower ones. */
    LANTERN_ERROR_LIMIT = -4,
    /* A size or SHA-256 that does not match: the download is refused. */
    LANTERN_ERROR_INTEGRITY = -5,
    /* A homebrew signature that does not verify, or a changed key. */
    LANTERN_ERROR_SIGNATURE = -6,
    /* A manifest, path or package the client must refuse (§ 8.3, § 8.6),
     * or a server key that is not the one pinned (§ 5.3). */
    LANTERN_ERROR_REFUSED = -7,
    /* A family the server does not offer, a platform with no profile, a
     * transport this build does not have. */
    LANTERN_ERROR_UNSUPPORTED = -8,
    /* An argument the protocol, or this API, does not allow. */
    LANTERN_ERROR_USAGE = -9,
    /* The app's sink, key store or credential store failed. */
    LANTERN_ERROR_STORAGE = -10,
    /* The memory budget (lantern_limits.max_memory) is spent. */
    LANTERN_ERROR_MEMORY = -11
};
/* "ok", "absent", "protocol", "transport"…; "" for another value. */
LANTERN_API const char* lantern_status_name(lantern_status status);

/* The error codes of SPEC.md § 12. */
typedef int32_t lantern_code;
enum
{
    LANTERN_CODE_NONE               = 0,
    LANTERN_CODE_BAD_REQUEST        = 1,
    LANTERN_CODE_KEY_REQUIRED       = 2,
    LANTERN_CODE_UNAUTHORIZED       = 3,
    LANTERN_CODE_SIGNATURE_REQUIRED = 4,
    LANTERN_CODE_SIGNATURE_INVALID  = 5,
    LANTERN_CODE_SIGNATURE_EXPIRED  = 6,
    LANTERN_CODE_SIGNATURE_REPLAYED = 7,
    LANTERN_CODE_FORBIDDEN          = 8,
    LANTERN_CODE_ACCOUNT_FROZEN     = 9,
    LANTERN_CODE_NOT_FOUND          = 10,
    LANTERN_CODE_CONFLICT           = 11,
    LANTERN_CODE_GONE               = 12,
    LANTERN_CODE_TOO_LARGE          = 13,
    LANTERN_CODE_UNSUPPORTED_SCHEMA = 14,
    LANTERN_CODE_DIGEST_MISMATCH    = 15,
    LANTERN_CODE_SLOW_DOWN          = 16,
    LANTERN_CODE_INTERNAL           = 17,
    LANTERN_CODE_UNAVAILABLE        = 18,
    /* A code of a later version: act on effective_code. */
    LANTERN_CODE_UNKNOWN = 19
};
/* The code's name as § 12 writes it ("account_frozen"); "" for none. */
LANTERN_API const char* lantern_code_name(lantern_code code);
/* A code from its name; LANTERN_CODE_UNKNOWN for a name § 12 does not have. */
LANTERN_API lantern_code lantern_code_from_name(const char* name);
/* The code an HTTP status implies (§ 12's table). */
LANTERN_API lantern_code lantern_code_for_status(uint16_t status);

/* What went wrong. Fixed-size, nothing to free; the texts are bounded,
 * NUL-terminated and free of control characters, ready to show. */
typedef struct lantern_error
{
    size_t struct_size;
    /* The category: one of LANTERN_ERROR_*. */
    lantern_status status;
    /* The code as the server wrote it (LANTERN_CODE_UNKNOWN for one of a
     * later version, NONE for none or for a local error)… */
    lantern_code code;
    /* …and the one to act on: the server's, or what its status implies. */
    lantern_code effective_code;
    /* The HTTP status, 0 for a local error. */
    uint16_t http_status;
    /* Retry-After in seconds, on a 429 or a 503; 0: none given. */
    uint32_t retry_after;
    /* The code exactly as the server wrote it, unknown ones included. */
    char code_text[33];
    char title[97];
    char detail[201];
} lantern_error;
/* Sets struct_size and clears the rest. */
LANTERN_API void lantern_error_init(lantern_error* error);
/* For a callback of the app (a transport's send, a store's load): sets
 * `status` and `detail` (cut to fit), which the library takes as the
 * error it returns. */
LANTERN_API void lantern_error_set(lantern_error* error, lantern_status status, const char* detail);

/* Where the library's memory comes from. `allocate` returns `size` bytes
 * aligned on `alignment` (a power of two); it must not fail: return NULL
 * and the program ends, as a C++ allocation without exceptions does. The
 * library stays within lantern_limits.max_memory per document read, so an
 * allocator sized for it never runs out first. Both are called from
 * whichever thread uses the objects, so they must be thread-safe when
 * objects live on several threads. The allocator must outlive every object
 * made with it; the library copies the struct. */
typedef struct lantern_allocator
{
    size_t struct_size;
    void* user;
    void* (*allocate)(void* user, size_t size, size_t alignment);
    void (*deallocate)(void* user, void* pointer, size_t size, size_t alignment);
} lantern_allocator;

/* SPEC.md § 13's limits on each document read; zero members keep § 13's
 * (32 MiB, depth 16, 4 KiB strings, 64 MiB of memory). */
typedef struct lantern_limits
{
    size_t struct_size;
    size_t max_document;
    size_t max_depth;
    size_t max_string;
    size_t max_memory;
} lantern_limits;

/* A string the library made, owned by the caller. */
typedef struct lantern_string lantern_string;
LANTERN_API lantern_str lantern_string_view(const lantern_string* string);
LANTERN_API void lantern_string_free(lantern_string* string);

/* A list of strings the library made, owned by the caller. */
typedef struct lantern_strings lantern_strings;
LANTERN_API size_t lantern_strings_count(const lantern_strings* strings);
LANTERN_API lantern_str lantern_strings_at(const lantern_strings* strings, size_t index);
LANTERN_API void lantern_strings_free(lantern_strings* strings);

#ifdef __cplusplus
}
#endif

/* The documents of the protocol (generated from spec/schemas). */
#include "lantern_documents.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------ Digests */

/* SHA-256 of `size` bytes. */
LANTERN_API void lantern_sha256(const uint8_t* bytes, size_t size, uint8_t out[32]);
/* 64 lower-case hex digits and a NUL. */
LANTERN_API void lantern_digest_to_hex(const uint8_t digest[32], char out[65]);
/* Exactly 64 lower-case hex digits (SPEC.md's form); false for anything else. */
LANTERN_API bool lantern_digest_from_hex(const char* hex, uint8_t out[32]);
/* RFC 9530's field (Repr-Digest, Content-Digest): "sha-256=:<base64>:", and a NUL. */
LANTERN_API void lantern_format_digest_field(const uint8_t digest[32], char out[55]);
typedef int32_t lantern_digest_field;
enum
{
    LANTERN_DIGEST_FIELD_SHA256    = 0, /* a well-formed sha-256 member, in *out */
    LANTERN_DIGEST_FIELD_ABSENT    = 1, /* no sha-256 member */
    LANTERN_DIGEST_FIELD_MALFORMED = 2
};
LANTERN_API lantern_digest_field lantern_parse_digest_field(const char* value, uint8_t out[32]);
/* The short fingerprint of § 5.3 and § 8.4, for people: the first 16 hex
 * digits of `digest`, upper case, in groups of 4 ("3F9A 1C07 B2E4 55D0"),
 * and a NUL. Show it for a server's SPKI next to a pairing code. */
LANTERN_API void lantern_short_form(const uint8_t digest[32], char out[20]);

/* ------------------------------------------------- The server's key (§ 5.3) */

/* The SHA-256 of a certificate's SubjectPublicKeyInfo, from its DER or the
 * first CERTIFICATE of a PEM text. */
LANTERN_API lantern_status lantern_spki_sha256(
    const uint8_t* certificate_der, size_t size, uint8_t out[32], lantern_error* error);
LANTERN_API lantern_status lantern_spki_sha256_pem(const char* pem, uint8_t out[32], lantern_error* error);

/* What a TLS transport checks of the certificate a server shows: the CA
 * store, a pin, or, before pairing only, any key, recorded. A transport
 * of the library asks it by itself; an app's own (URLSession, OkHttp)
 * calls lantern_trust_accept_certificate() once per connection. */
typedef struct lantern_trust lantern_trust;
typedef int32_t lantern_trust_mode;
enum
{
    LANTERN_TRUST_CA         = 0,
    LANTERN_TRUST_PINNED     = 1,
    LANTERN_TRUST_UNVERIFIED = 2
};
LANTERN_API lantern_status lantern_trust_create(
    const lantern_allocator* allocator, lantern_trust** out, lantern_error* error);
LANTERN_API void lantern_trust_free(lantern_trust* trust);
LANTERN_API void lantern_trust_require_ca(lantern_trust* trust);
LANTERN_API void lantern_trust_pin(lantern_trust* trust, const uint8_t spki_sha256[32]);
LANTERN_API void lantern_trust_allow_unverified(lantern_trust* trust);
LANTERN_API lantern_trust_mode lantern_trust_get_mode(const lantern_trust* trust);
/* False when there is none. */
LANTERN_API bool lantern_trust_get_pin(const lantern_trust* trust, uint8_t out[32]);
/* The SHA-256 of the SPKI the last connection showed. */
LANTERN_API bool lantern_trust_get_seen(const lantern_trust* trust, uint8_t out[32]);
/* Goes up each time the mode or the pin changes. */
LANTERN_API uint32_t lantern_trust_get_generation(const lantern_trust* trust);
/* True to go on with the connection. */
LANTERN_API bool lantern_trust_accept(
    lantern_trust* trust, const uint8_t* spki_der, size_t size, bool ca_verified);
LANTERN_API bool lantern_trust_accept_certificate(
    lantern_trust* trust, const uint8_t* certificate_der, size_t size, bool ca_verified);

/* What an invitation's link carries (§ 5.5). */
typedef struct lantern_invitation_link
{
    size_t struct_size;
    char code[33];
    /* The whole fingerprint of the server's key, to pin without asking. */
    bool has_spki;
    uint8_t spki[32];
} lantern_invitation_link;
LANTERN_API lantern_status lantern_parse_invitation_link(
    const char* link, lantern_invitation_link* out, lantern_error* error);
LANTERN_API bool lantern_is_pairing_code(const char* code);
LANTERN_API bool lantern_is_invitation_code(const char* code);

/* ---------------------------------------------------- The app's callbacks */

/* Each callback object is made from a struct of function pointers and a
 * `user` context the library passes back; `release`, when set, is called
 * with `user` when the object is freed. Callbacks are called on the thread
 * that called the library, during that call, never later. A callback that
 * fails returns an error status (LANTERN_ERROR_STORAGE, …) and may say why
 * with lantern_error_set() where it is given a lantern_error. */

/* Cryptographic random bytes: SecRandomCopyBytes, SecureRandom,
 * getrandom(), BCryptGenRandom, a console's own generator. */
typedef struct lantern_random_callbacks
{
    size_t struct_size;
    void* user;
    lantern_status (*fill)(void* user, uint8_t* out, size_t size);
    void (*release)(void* user);
} lantern_random_callbacks;
typedef struct lantern_random lantern_random;
LANTERN_API lantern_status lantern_random_create(const lantern_random_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_random** out, lantern_error* error);
/* The operating system's generator (getrandom/getentropy, arc4random_buf
 * on Apple's systems, BCryptGenRandom on Windows); UNSUPPORTED elsewhere. */
LANTERN_API lantern_status lantern_random_create_system(
    const lantern_allocator* allocator, lantern_random** out, lantern_error* error);
LANTERN_API void lantern_random_free(lantern_random* random);

/* The time a signature is made at, in Unix seconds. */
typedef struct lantern_clock_callbacks
{
    size_t struct_size;
    void* user;
    int64_t (*unix_seconds)(void* user);
    void (*release)(void* user);
} lantern_clock_callbacks;
typedef struct lantern_clock lantern_clock;
LANTERN_API lantern_status lantern_clock_create(const lantern_clock_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_clock** out, lantern_error* error);
LANTERN_API void lantern_clock_free(lantern_clock* clock);

/* What a paired device keeps for a server, by its uid (§ 5): its token, the
 * device key's seed when the token is bound (§ 5.4), the server key pinned
 * (§ 5.3). The token and the seed are secrets: keep them in the keychain
 * or the keystore, never in a log. */
typedef struct lantern_credentials
{
    size_t struct_size;
    lantern_str token;
    bool has_key;
    uint8_t key_seed[32];
    bool has_spki;
    uint8_t spki[32];
} lantern_credentials;
/* Where a store's load() puts what it kept (copied at once). */
typedef struct lantern_credentials_sink lantern_credentials_sink;
LANTERN_API lantern_status lantern_credentials_sink_set(
    lantern_credentials_sink* sink, const lantern_credentials* credentials);
typedef struct lantern_credential_callbacks
{
    size_t struct_size;
    void* user;
    /* Calls lantern_credentials_sink_set() when something is kept for
     * `uid`; returns LANTERN_OK either way. */
    lantern_status (*load)(void* user, lantern_str uid, lantern_credentials_sink* sink);
    lantern_status (*store)(void* user, lantern_str uid, const lantern_credentials* credentials);
    lantern_status (*erase)(void* user, lantern_str uid);
    void (*release)(void* user);
} lantern_credential_callbacks;
typedef struct lantern_credential_store lantern_credential_store;
LANTERN_API lantern_status lantern_credential_store_create(const lantern_credential_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_credential_store** out, lantern_error* error);
LANTERN_API void lantern_credential_store_free(lantern_credential_store* store);

/* Homebrew key pins (§ 8.4), kept by the app per platform and id. */
typedef struct lantern_pin
{
    bool is_signed; /* false: first installed unsigned */
    uint8_t public_key[32];
} lantern_pin;
typedef struct lantern_pin_callbacks
{
    size_t struct_size;
    void* user;
    /* *found false before the id's first install. */
    lantern_status (*load)(void* user, lantern_str platform, lantern_str id, lantern_pin* out, bool* found);
    lantern_status (*store)(void* user, lantern_str platform, lantern_str id, const lantern_pin* pin);
    void (*release)(void* user);
} lantern_pin_callbacks;
typedef struct lantern_pin_store lantern_pin_store;
LANTERN_API lantern_status lantern_pin_store_create(const lantern_pin_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_pin_store** out, lantern_error* error);
LANTERN_API void lantern_pin_store_free(lantern_pin_store* store);

/* § 3.4: told of each Deprecation a server announces, for the app's log.
 * `deprecation` as sent ("@1793318400"), `sunset` an HTTP date or empty. */
typedef struct lantern_deprecation_callbacks
{
    size_t struct_size;
    void* user;
    void (*deprecated)(void* user, lantern_str url, lantern_str deprecation, lantern_str sunset);
    void (*release)(void* user);
} lantern_deprecation_callbacks;
typedef struct lantern_deprecation_log lantern_deprecation_log;
LANTERN_API lantern_status lantern_deprecation_log_create(const lantern_deprecation_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_deprecation_log** out, lantern_error* error);
LANTERN_API void lantern_deprecation_log_free(lantern_deprecation_log* log);

/* Where a download's bytes go: the app's file, or memory. */
typedef struct lantern_download_callbacks
{
    size_t struct_size;
    void* user;
    /* Appends the next bytes. */
    lantern_status (*write)(void* user, const uint8_t* bytes, size_t size);
    /* The server sends the file from its start again: drop what was written. */
    lantern_status (*restart)(void* user);
    void (*release)(void* user);
} lantern_download_callbacks;
typedef struct lantern_download_sink lantern_download_sink;
LANTERN_API lantern_status lantern_download_sink_create(const lantern_download_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_download_sink** out, lantern_error* error);
LANTERN_API void lantern_download_sink_free(lantern_download_sink* sink);

/* Where a resumable upload reads the archive from (§ 9.3). */
typedef struct lantern_upload_callbacks
{
    size_t struct_size;
    void* user;
    /* Fills out[0..size) with the bytes from `offset` on (never past the end). */
    lantern_status (*read)(void* user, uint64_t offset, uint8_t* out, size_t size);
    void (*release)(void* user);
} lantern_upload_callbacks;
typedef struct lantern_upload_source lantern_upload_source;
LANTERN_API lantern_status lantern_upload_source_create(const lantern_upload_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_upload_source** out, lantern_error* error);
LANTERN_API void lantern_upload_source_free(lantern_upload_source* source);

/* ------------------------------------------------------------ Transport */

/* The library speaks HTTP through a transport: the app's own (URLSession,
 * OkHttp or HttpURLConnection, a console's sockets), or one of the
 * library's, libcurl's or mbedTLS's, when the build has them. */
typedef int32_t lantern_method;
enum
{
    LANTERN_METHOD_GET    = 0,
    LANTERN_METHOD_HEAD   = 1,
    LANTERN_METHOD_POST   = 2,
    LANTERN_METHOD_PUT    = 3,
    LANTERN_METHOD_PATCH  = 4,
    LANTERN_METHOD_DELETE = 5
};

typedef struct lantern_header
{
    lantern_str name;
    lantern_str value;
} lantern_header;

/* One request, borrowed for the call to send(). */
typedef struct lantern_request
{
    size_t struct_size;
    lantern_method method;
    lantern_str method_name; /* "GET" */
    lantern_str url; /* absolute: scheme, host, port, path and query */
    const lantern_header* headers;
    size_t header_count;
    const uint8_t* body;
    size_t body_size;
} lantern_request;

/* Where a transport hands the answer as it comes: the status, each header
 * line, then the body (decoded from chunked) in order. Each returns false
 * when the library wants the transfer stopped: the transport then stops
 * and returns. */
typedef struct lantern_response lantern_response;
LANTERN_API bool lantern_response_status(lantern_response* response, uint16_t status);
LANTERN_API bool lantern_response_header(
    lantern_response* response, const char* name, size_t name_size, const char* value, size_t value_size);
LANTERN_API bool lantern_response_body(lantern_response* response, const uint8_t* bytes, size_t size);

typedef struct lantern_transport_callbacks
{
    size_t struct_size;
    void* user;
    /* Sends the request and delivers the answer, synchronously: does TLS
     * (asking the lantern_trust, when the app has one), follows no
     * redirect, adds no header but Host and the body's framing. A
     * connection that failed or was cut: LANTERN_ERROR_TRANSPORT (what was
     * delivered stays valid: a download resumes from it); a server key
     * refused: LANTERN_ERROR_REFUSED. */
    lantern_status (*send)(
        void* user, const lantern_request* request, lantern_response* response, lantern_error* error);
    void (*release)(void* user);
} lantern_transport_callbacks;
typedef struct lantern_transport lantern_transport;
LANTERN_API lantern_status lantern_transport_create(const lantern_transport_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error);
LANTERN_API void lantern_transport_free(lantern_transport* transport);

typedef int32_t lantern_transport_kind;
enum
{
    LANTERN_TRANSPORT_CURL    = 1,
    LANTERN_TRANSPORT_MBEDTLS = 2
};
/* Whether this build has the library's transport of that kind. Their
 * functions are always there; without the transport they give
 * LANTERN_ERROR_UNSUPPORTED. */
LANTERN_API bool lantern_has_transport(lantern_transport_kind kind);

/* libcurl and its TLS (desktops, phones). One transport, one connection
 * kept, one request at a time. */
typedef struct lantern_curl_options
{
    size_t struct_size;
    lantern_trust* trust; /* the server's key; NULL: the CA store alone */
    const char* ca_file; /* a PEM bundle instead of the system's; NULL: the system's */
    uint32_t connect_timeout_ms; /* 0: 10 s (Annex B.1) */
    uint32_t stall_timeout_s; /* 0: 60 s */
} lantern_curl_options;
/* curl_global_init(), once per process, before the first curl transport. */
LANTERN_API lantern_status lantern_curl_global_init(lantern_error* error);
LANTERN_API lantern_status lantern_transport_create_curl(const lantern_curl_options* options,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error);

/* mbedTLS over POSIX sockets (consoles), its randomness from `random`. */
typedef struct lantern_mbedtls_options
{
    size_t struct_size;
    lantern_random* random; /* required */
    lantern_trust* trust;
    const char* ca_pem; /* the CAs trusted, PEM; NULL: pinned keys only */
    uint32_t timeout_ms; /* 0: 10 s */
} lantern_mbedtls_options;
LANTERN_API lantern_status lantern_transport_create_mbedtls(const lantern_mbedtls_options* options,
    const lantern_allocator* allocator, lantern_transport** out, lantern_error* error);

/* -------------------------------------------------------- The device's key */

/* An Ed25519 key a device makes for one server when it pairs (§ 5.4). */
typedef struct lantern_device_key lantern_device_key;
LANTERN_API lantern_status lantern_device_key_generate(lantern_random* random,
    const lantern_allocator* allocator, lantern_device_key** out, lantern_error* error);
LANTERN_API lantern_status lantern_device_key_from_seed(const uint8_t seed[32],
    const lantern_allocator* allocator, lantern_device_key** out, lantern_error* error);
/* Wipes the private key. */
LANTERN_API void lantern_device_key_free(lantern_device_key* key);
/* The 32 bytes the app keeps: the whole key derives from them. A secret. */
LANTERN_API void lantern_device_key_seed(const lantern_device_key* key, uint8_t out[32]);
LANTERN_API void lantern_device_key_public_key(const lantern_device_key* key, uint8_t out[32]);
/* keyid: base64url of the public key's SHA-256, 43 characters, and a NUL. */
LANTERN_API void lantern_device_key_keyid(const lantern_device_key* key, char out[44]);
/* The short fingerprint the server's admin compares (§ 5.7). */
LANTERN_API void lantern_device_key_fingerprint(const lantern_device_key* key, char out[20]);
LANTERN_API void lantern_device_key_sign(
    const lantern_device_key* key, const uint8_t* message, size_t size, uint8_t out[64]);
LANTERN_API bool lantern_ed25519_verify(
    const uint8_t signature[64], const uint8_t public_key[32], const uint8_t* message, size_t size);

/* ------------------------------------------------ Signed requests (§ 5.4) */

/* The client signs by itself; these are the same steps one at a time, for
 * a server or a test. */
typedef struct lantern_signed_components
{
    size_t struct_size;
    const char* method; /* "GET" */
    const char* target_uri; /* as lantern_target_uri() gives it */
    const char* authorization; /* NULL or "" for a poll */
    const char* content_digest; /* NULL or "" without a body */
} lantern_signed_components;
/* "@target-uri" of an absolute URL (RFC 9421 § 2.2.2). */
LANTERN_API lantern_status lantern_target_uri(
    const char* url, const lantern_allocator* allocator, lantern_string** out, lantern_error* error);
/* The signature base (RFC 9421 § 2.5), "@signature-params" last. */
LANTERN_API lantern_status lantern_signature_base(const lantern_signed_components* components,
    int64_t created, const char* nonce, const char* keyid, const lantern_allocator* allocator,
    lantern_string** out, lantern_error* error);
/* Signature-Input and Signature, with `created` and a nonce of 22 to 64
 * base64url characters. */
LANTERN_API lantern_status lantern_sign_components(const lantern_device_key* key,
    const lantern_signed_components* components, int64_t created, const char* nonce,
    const lantern_allocator* allocator, lantern_string** signature_input, lantern_string** signature,
    lantern_error* error);

/* What a server checks of a signed request; absent headers are NULL. */
typedef struct lantern_signature_check
{
    size_t struct_size;
    const char* method;
    const char* target_uri;
    const char* authorization;
    const char* content_digest;
    bool has_body;
    const char* signature_input;
    const char* signature;
    uint8_t public_key[32]; /* the token's, or the pairing's */
    int64_t now; /* the server's clock */
    uint32_t skew; /* 0: 300 s */
    bool has_body_sha256;
    uint8_t body_sha256[32];
} lantern_signature_check;
typedef struct lantern_signature_verdict
{
    size_t struct_size;
    /* NONE when it holds; otherwise the code § 5.4 answers. */
    lantern_code code;
    /* For the caller's check of replays. */
    char nonce[65];
    char keyid[65];
} lantern_signature_verdict;
LANTERN_API lantern_status lantern_check_signature(
    const lantern_signature_check* check, lantern_signature_verdict* out, lantern_error* error);
/* An IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") in Unix seconds. */
LANTERN_API bool lantern_parse_http_date(const char* text, int64_t* out);

/* -------------------------------------------------------------- Downloads */

/* A download in progress, kept between attempts so that the next asks for
 * the rest only (Range, If-Range), its SHA-256 state included. */
typedef struct lantern_download_state lantern_download_state;
LANTERN_API lantern_status lantern_download_state_create(
    const lantern_allocator* allocator, lantern_download_state** out, lantern_error* error);
LANTERN_API void lantern_download_state_free(lantern_download_state* state);
LANTERN_API void lantern_download_state_reset(lantern_download_state* state);
LANTERN_API uint64_t lantern_download_state_received(const lantern_download_state* state);
/* Saved next to the partial file, as a JSON document with `schema` 1.
 * load(): LANTERN_ABSENT for a newer schema (the state starts over, and
 * save() then refuses with LANTERN_ABSENT: never write over it). save()
 * keeps the members a later version added to what was loaded. */
LANTERN_API lantern_status lantern_download_state_save(
    const lantern_download_state* state, lantern_string** out, lantern_error* error);
LANTERN_API lantern_status lantern_download_state_load(
    lantern_download_state* state, const char* json, size_t size, lantern_error* error);

/* What the app knows of the file: its entry's `file`, size and SHA-256. */
typedef struct lantern_download_target
{
    size_t struct_size;
    const char* url;
    uint64_t size;
    uint8_t sha256[32];
} lantern_download_target;

/* -------------------------------------------------------------- The client */

typedef struct lantern_client lantern_client;

typedef struct lantern_client_config
{
    size_t struct_size;
    /* "https://shelf.example.org" or "https://192.0.2.10:8443"; plain HTTP
     * on loopback only (§ 2). Required. */
    const char* origin;
    /* "Name/version" (§ 2). Required. */
    const char* user_agent;
    /* Lantern-Platform on every call (§ 4.3); NULL: none. */
    const char* platform;
    /* Accept-Language, as the app builds it; NULL: none. */
    const char* accept_language;
    /* Required; borrowed, and must outlive the client. */
    lantern_transport* transport;
    /* For a device key and a nonce per signed request; without it, the
     * client takes bearer-only tokens alone. */
    lantern_random* random;
    /* NULL: the system's clock, corrected by the server's Date. */
    lantern_clock* clock;
    /* The transport's lantern_trust, when it has one: the client pins the
     * key it pairs over and sends no token over a connection unverified. */
    lantern_trust* trust;
    lantern_deprecation_log* deprecations;
    /* NULL: the default resource. Copied. */
    const lantern_allocator* allocator;
    /* NULL: § 13's. Copied. */
    const lantern_limits* limits;
    /* The most of a problem+json read for an error; 0: 64 KiB. */
    size_t max_error_body;
} lantern_client_config;

LANTERN_API lantern_status lantern_client_create(
    const lantern_client_config* config, lantern_client** out, lantern_error* error);
LANTERN_API void lantern_client_free(lantern_client* client);

/* GET /.well-known/lantern (§ 4.2): every other call needs it first. The
 * client keeps a copy, lantern_client_server(), until the next one. */
LANTERN_API lantern_status lantern_client_handshake(
    lantern_client* client, lantern_handshake** out, lantern_error* error);
/* Borrowed; NULL before a handshake. */
LANTERN_API const lantern_handshake* lantern_client_server(const lantern_client* client);

typedef int32_t lantern_family;
enum
{
    LANTERN_FAMILY_LIBRARY    = 0,
    LANTERN_FAMILY_TITLES     = 1,
    LANTERN_FAMILY_CHANGES    = 2,
    LANTERN_FAMILY_SECTIONS   = 3,
    LANTERN_FAMILY_HOMEBREW   = 4,
    LANTERN_FAMILY_SAVES      = 5,
    LANTERN_FAMILY_CHEATS     = 6,
    LANTERN_FAMILY_REQUESTS   = 7,
    LANTERN_FAMILY_PAIRING    = 8,
    LANTERN_FAMILY_SIGNATURES = 9,
    LANTERN_FAMILY_ADMIN      = 10
};
/* The schema the server writes for a family, 0 when it does not offer it
 * to this caller. */
LANTERN_API uint64_t lantern_client_offers(const lantern_client* client, lantern_family family);

/* Authorization on every call to the server's origin, and to no other. */
LANTERN_API lantern_status lantern_client_set_bearer_token(
    lantern_client* client, const char* token, lantern_error* error);
/* A token bound to `key` (copied): every request carrying it is signed. */
LANTERN_API lantern_status lantern_client_set_credentials(
    lantern_client* client, const char* token, const lantern_device_key* key, lantern_error* error);
LANTERN_API void lantern_client_clear_token(lantern_client* client);
LANTERN_API bool lantern_client_has_token(const lantern_client* client);
/* Borrowed; NULL without a bound token. */
LANTERN_API const lantern_device_key* lantern_client_device_key(const lantern_client* client);
/* Seconds added to the clock for `created` (Annex B.9). */
LANTERN_API int64_t lantern_client_clock_offset(const lantern_client* client);

/* What the store kept for this server (after the handshake): *signed_in
 * false when nothing: the device pairs. */
LANTERN_API lantern_status lantern_client_sign_in(
    lantern_client* client, lantern_credential_store* store, bool* signed_in, lantern_error* error);
LANTERN_API lantern_status lantern_client_forget(
    lantern_client* client, lantern_credential_store* store, lantern_error* error);

/* ---------------------------------------------------------- Pairing (§ 5.2) */

typedef struct lantern_pairing_options
{
    size_t struct_size;
    const char* device; /* the name the user sees ("Lea's Switch") */
    const char* const* scopes; /* "library", "saves", … */
    size_t scope_count;
    const char* invitation; /* an invitation's code (§ 5.5): approved at once */
    /* A token without a device key, for a server that still takes them;
     * false (the default): a key is made and the token bound to it. */
    bool bearer_only;
} lantern_pairing_options;

typedef struct lantern_pairing lantern_pairing;
LANTERN_API lantern_status lantern_client_start_pairing(lantern_client* client,
    const lantern_pairing_options* options, lantern_pairing** out, lantern_error* error);
LANTERN_API void lantern_pairing_free(lantern_pairing* pairing);
/* code, verify, verify_complete (a QR code), interval, expires. */
LANTERN_API const lantern_pairing_code* lantern_pairing_get_code(const lantern_pairing* pairing);
/* Seconds to wait before the next poll. */
LANTERN_API uint32_t lantern_pairing_get_wait(const lantern_pairing* pairing);
/* The server key's short fingerprint, to show next to the code; empty when
 * the client had no lantern_trust. */
LANTERN_API lantern_str lantern_pairing_get_fingerprint(const lantern_pairing* pairing);
LANTERN_API bool lantern_pairing_get_spki(const lantern_pairing* pairing, uint8_t out[32]);
/* Borrowed; NULL for a bearer-only pairing. */
LANTERN_API const lantern_device_key* lantern_pairing_get_key(const lantern_pairing* pairing);

typedef int32_t lantern_poll_state;
enum
{
    LANTERN_POLL_WAITING = 0, /* poll again after lantern_pairing_get_wait() seconds */
    LANTERN_POLL_PAIRED  = 1 /* the client holds its token, kept in `store` when given */
};
/* GET poll, signed by the pairing's key. 410 (gone): refused, expired or
 * collected. `store` may be NULL. */
LANTERN_API lantern_status lantern_client_poll_pairing(lantern_client* client, lantern_pairing* pairing,
    lantern_credential_store* store, lantern_poll_state* state, lantern_error* error);

/* ------------------------------------------------------------- The library */

typedef struct lantern_apps_query
{
    size_t struct_size;
    const char* platform; /* overrides Lantern-Platform */
    const char* type;
    const char* title_id;
    const char* q;
    const char* sort; /* "name", "added" or "release" */
    uint32_t page_size; /* 0: the server's */
    const char* cursor; /* a page's `next` */
} lantern_apps_query;
/* § 6.2: a page; pass its `next` as the next query's cursor. A 410
 * (LANTERN_CODE_GONE): the cursor expired, read from the start. */
LANTERN_API lantern_status lantern_client_apps(
    lantern_client* client, const lantern_apps_query* query, lantern_apps_page** out, lantern_error* error);

typedef struct lantern_installed_app
{
    const char* app_id;
    uint64_t version_code;
} lantern_installed_app;
typedef struct lantern_missing_request
{
    size_t struct_size;
    const lantern_installed_app* installed;
    size_t installed_count;
    const char* const* want; /* "update", "dlc" */
    size_t want_count;
} lantern_missing_request;
/* § 6.3: needs a platform (the configuration's, or `platform`). */
LANTERN_API lantern_status lantern_client_missing(lantern_client* client,
    const lantern_missing_request* request, const char* cursor, const char* platform, lantern_apps_page** out,
    lantern_error* error);
/* § 6.4: without `since`, no apps and the current token. */
LANTERN_API lantern_status lantern_client_changes(
    lantern_client* client, const char* since, lantern_changes** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_sections(
    lantern_client* client, lantern_sections** out, lantern_error* error);
/* § 7.1, § 7.2 (100 ids at most), § 7.3. */
LANTERN_API lantern_status lantern_client_title(
    lantern_client* client, const char* title_id, lantern_title** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_titles(
    lantern_client* client, const char* const* ids, size_t count, lantern_titles** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_title_changes(
    lantern_client* client, const char* since, lantern_title_changes** out, lantern_error* error);

/* § 6.6: downloads `target` into `sink` from what `state` received (a
 * Range request), hashing as it goes: LANTERN_OK only when the whole file
 * is there and its SHA-256 is the target's. A transport error leaves
 * `state` where it was cut: call again to resume. A digest or size that
 * does not match is LANTERN_ERROR_INTEGRITY, and `state` starts over. */
LANTERN_API lantern_status lantern_client_download(lantern_client* client,
    const lantern_download_target* target, lantern_download_state* state, lantern_download_sink* sink,
    lantern_error* error);

/* ---------------------------------------------------------- Homebrew (§ 8) */

typedef struct lantern_homebrew_query
{
    size_t struct_size;
    const char* platform;
    const char* q;
    const char* kind;
    const char* genre;
    uint32_t page_size;
    const char* cursor;
} lantern_homebrew_query;
LANTERN_API lantern_status lantern_client_homebrew(lantern_client* client,
    const lantern_homebrew_query* query, lantern_homebrew_page** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_homebrew_entry(
    lantern_client* client, const char* id, lantern_homebrew** out, lantern_error* error);
typedef struct lantern_installed_homebrew
{
    const char* id;
    uint64_t build;
} lantern_installed_homebrew;
typedef struct lantern_homebrew_updates_request
{
    size_t struct_size;
    const lantern_installed_homebrew* installed;
    size_t installed_count;
} lantern_homebrew_updates_request;
LANTERN_API lantern_status lantern_client_homebrew_updates(lantern_client* client,
    const lantern_homebrew_updates_request* request, const char* cursor, const char* platform,
    lantern_homebrew_page** out, lantern_error* error);

/* § 8.2: the package for a device of architecture `device_arch` (NULL for
 * a platform of one architecture); borrowed from `entry`. */
LANTERN_API lantern_status lantern_pick_package(const lantern_homebrew* entry, const char* device_arch,
    const lantern_package** out, lantern_error* error);

typedef int32_t lantern_placement;
enum
{
    LANTERN_PLACEMENT_SINGLE_FILE      = 0,
    LANTERN_PLACEMENT_ARCHIVE          = 1,
    LANTERN_PLACEMENT_SYSTEM_INSTALLER = 2
};
/* What installing a package writes (§ 8.3), checked before anything is
 * downloaded: formats, paths in the profile's roots, the manifest's digest.
 * Anything else is LANTERN_ERROR_REFUSED: install nothing. */
typedef struct lantern_install_plan lantern_install_plan;
LANTERN_API lantern_status lantern_plan_install(const lantern_homebrew* entry, const lantern_package* package,
    const lantern_allocator* allocator, lantern_install_plan** out, lantern_error* error);
LANTERN_API void lantern_install_plan_free(lantern_install_plan* plan);
LANTERN_API lantern_placement lantern_install_plan_get_placement(const lantern_install_plan* plan);
/* A system installer: ask the user before handing the package over. */
LANTERN_API bool lantern_install_plan_get_ask_before_installer(const lantern_install_plan* plan);
/* How many files need the user's consent: show each, install only on yes. */
LANTERN_API size_t lantern_install_plan_get_consent_count(const lantern_install_plan* plan);
LANTERN_API size_t lantern_install_plan_get_file_count(const lantern_install_plan* plan);
typedef struct lantern_planned_file
{
    size_t struct_size;
    lantern_str path;
    uint64_t size;
    uint8_t sha256[32];
    bool needs_consent;
} lantern_planned_file;
/* False past the end. */
LANTERN_API bool lantern_install_plan_get_file(
    const lantern_install_plan* plan, size_t index, lantern_planned_file* out);

/* § 8.3: the files of the old package's manifest the new one has not,
 * which an update removes. */
LANTERN_API lantern_status lantern_files_to_remove(const lantern_package* old_package,
    const lantern_package* new_package, const lantern_allocator* allocator, lantern_strings** out,
    lantern_error* error);
typedef struct lantern_installed_system_id
{
    const char* id;
    const char* system_id;
} lantern_installed_system_id;
/* § 8.3: refused when the entry's system_id is another id's on the device. */
LANTERN_API lantern_status lantern_check_system_id(const lantern_homebrew* entry,
    const lantern_installed_system_id* installed, size_t count, lantern_error* error);
/* § 8.6: a port's data_root and data paths. */
LANTERN_API lantern_status lantern_check_port(const lantern_homebrew* entry, lantern_error* error);
/* § 8.2's canonical manifest's SHA-256. */
LANTERN_API void lantern_manifest_digest(const lantern_package* package, uint8_t out[32]);

/* § 8.4: the signature covering `package`. */
typedef struct lantern_package_signature
{
    size_t struct_size;
    bool is_signed;
    uint8_t public_key[32];
} lantern_package_signature;
/* An unsigned package is not an error; one that does not verify is
 * LANTERN_ERROR_SIGNATURE: install nothing. */
LANTERN_API lantern_status lantern_verify_package_signature(const lantern_homebrew* entry,
    const lantern_package* package, lantern_package_signature* out, lantern_error* error);

typedef int32_t lantern_pin_verdict;
enum
{
    LANTERN_PIN_FIRST_INSTALL     = 0,
    LANTERN_PIN_SAME              = 1,
    LANTERN_PIN_NEWLY_SIGNED      = 2,
    LANTERN_PIN_KEY_CHANGED       = 3, /* refused unless the user accepts */
    LANTERN_PIN_SIGNATURE_REMOVED = 4 /* refused unless the user accepts */
};
typedef struct lantern_pin_check
{
    size_t struct_size;
    lantern_pin_verdict verdict;
    bool has_pinned;
    lantern_pin pinned;
    lantern_pin offered;
    /* Show both short fingerprints; install only when the user accepts. */
    bool needs_consent;
} lantern_pin_check;
LANTERN_API lantern_status lantern_check_pin(lantern_pin_store* store, const char* platform, const char* id,
    const lantern_package_signature* signature, lantern_pin_check* out, lantern_error* error);
/* After the install: pins what the package carried. */
LANTERN_API lantern_status lantern_commit_pin(lantern_pin_store* store, const char* platform, const char* id,
    const lantern_pin_check* check, bool user_accepted_change, lantern_error* error);

/* § 8.6: whether a port has its data before it launches. */
typedef struct lantern_data_probe_callbacks
{
    size_t struct_size;
    void* user;
    /* The size of the file at `path`, *present false when it is not there. */
    lantern_status (*size)(void* user, lantern_str path, uint64_t* size, bool* present);
    lantern_status (*sha256)(void* user, lantern_str path, uint8_t out[32]);
    void (*release)(void* user);
} lantern_data_probe_callbacks;
typedef struct lantern_data_probe lantern_data_probe;
LANTERN_API lantern_status lantern_data_probe_create(const lantern_data_probe_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_data_probe** out, lantern_error* error);
LANTERN_API void lantern_data_probe_free(lantern_data_probe* probe);

typedef struct lantern_launch_check lantern_launch_check;
typedef int32_t lantern_data_issue;
enum
{
    LANTERN_DATA_MISSING         = 0,
    LANTERN_DATA_UNKNOWN_VERSION = 1,
    LANTERN_DATA_WRONG_SIZE      = 2
};
typedef struct lantern_launch_issue
{
    size_t struct_size;
    lantern_str path; /* relative to data_root */
    lantern_str hint;
    lantern_data_issue issue;
    bool in_group;
} lantern_launch_issue;
/* The port must have passed lantern_check_port(). */
LANTERN_API lantern_status lantern_launch_check_run(const lantern_port* port, lantern_data_probe* probe,
    const lantern_allocator* allocator, lantern_launch_check** out, lantern_error* error);
LANTERN_API void lantern_launch_check_free(lantern_launch_check* check);
LANTERN_API bool lantern_launch_check_get_ready(const lantern_launch_check* check);
/* A file taken on its presence alone (SHA-1 or MD5 only). */
LANTERN_API bool lantern_launch_check_get_unverified(const lantern_launch_check* check);
LANTERN_API size_t lantern_launch_check_get_issue_count(const lantern_launch_check* check);
LANTERN_API bool lantern_launch_check_get_issue(
    const lantern_launch_check* check, size_t index, lantern_launch_issue* out);

/* § 8.7: offer, warn or refuse, from `requires` and what the app knows. */
typedef struct lantern_version_fact
{
    const char* key; /* "firmware", "atmosphere", "glibc"… */
    const char* value; /* dotted, "18.0.0" */
} lantern_version_fact;
typedef struct lantern_device_facts
{
    size_t struct_size;
    const lantern_version_fact* versions;
    size_t version_count;
    bool has_ram_mb;
    uint64_t ram_mb;
    bool has_screen;
    uint32_t screen_width;
    uint32_t screen_height;
    bool has_gpus;
    const char* const* gpus; /* "gles2", "vulkan"… */
    size_t gpu_count;
} lantern_device_facts;
typedef int32_t lantern_offer;
enum
{
    LANTERN_OFFER  = 0,
    LANTERN_WARN   = 1,
    LANTERN_REFUSE = 2
};
typedef int32_t lantern_condition_state;
enum
{
    LANTERN_CONDITION_MET        = 0,
    LANTERN_CONDITION_FAILED     = 1,
    LANTERN_CONDITION_UNREADABLE = 2
};
typedef struct lantern_condition
{
    size_t struct_size;
    lantern_str key; /* "min.glibc", "gpu", or an unknown member's key */
    lantern_str detail; /* for people */
    lantern_condition_state state;
} lantern_condition;
typedef struct lantern_requires_check lantern_requires_check;
/* `platform` names the profile (Annex A); UNSUPPORTED without one. */
LANTERN_API lantern_status lantern_check_requires(const lantern_requires* requires_, const char* platform,
    const lantern_device_facts* device, const lantern_allocator* allocator, lantern_requires_check** out,
    lantern_error* error);
LANTERN_API void lantern_requires_check_free(lantern_requires_check* check);
LANTERN_API lantern_offer lantern_requires_check_get_offer(const lantern_requires_check* check);
LANTERN_API size_t lantern_requires_check_get_condition_count(const lantern_requires_check* check);
LANTERN_API bool lantern_requires_check_get_condition(
    const lantern_requires_check* check, size_t index, lantern_condition* out);

/* Paths on the device (§ 8.2, § 8.6). */
typedef int32_t lantern_path_problem;
enum
{
    LANTERN_PATH_OK            = 0,
    LANTERN_PATH_EMPTY         = 1,
    LANTERN_PATH_NOT_ABSOLUTE  = 2,
    LANTERN_PATH_ABSOLUTE      = 3,
    LANTERN_PATH_DRIVE_LETTER  = 4,
    LANTERN_PATH_EMPTY_PART    = 5,
    LANTERN_PATH_DOT_PART      = 6,
    LANTERN_PATH_BACKSLASH     = 7,
    LANTERN_PATH_COLON         = 8,
    LANTERN_PATH_QUOTE         = 9,
    LANTERN_PATH_CONTROL       = 10,
    LANTERN_PATH_PART_TOO_LONG = 11,
    LANTERN_PATH_TOO_LONG      = 12,
    LANTERN_PATH_NOT_A_FOLDER  = 13
};
LANTERN_API lantern_path_problem lantern_check_device_path(const char* path, size_t size);
LANTERN_API lantern_path_problem lantern_check_data_path(const char* path, size_t size);
LANTERN_API lantern_path_problem lantern_check_data_root(const char* path, size_t size);
/* For people ("a part is . or .."). */
LANTERN_API const char* lantern_path_problem_text(lantern_path_problem problem);
typedef int32_t lantern_root_match;
enum
{
    LANTERN_ROOT_OUTSIDE    = 0,
    LANTERN_ROOT_FREE       = 1,
    LANTERN_ROOT_CONSENT    = 2,
    LANTERN_ROOT_NO_PROFILE = 3
};
LANTERN_API lantern_root_match lantern_match_roots(
    const char* platform, const char* homebrew_id, const char* path);
/* The core's forms (§ 4.3, § 8.1). */
LANTERN_API bool lantern_is_platform_name(const char* name);
LANTERN_API bool lantern_is_homebrew_id(const char* id);
/* Whether Annex A has a profile for the platform. */
LANTERN_API bool lantern_has_profile(const char* platform);

/* ------------------------------------------------------------ Cheats (§ 10) */

typedef struct lantern_cheats_query
{
    size_t struct_size;
    const char* platform;
    const char* title_id;
    const char* build_id;
} lantern_cheats_query;
LANTERN_API lantern_status lantern_client_cheats(lantern_client* client, const lantern_cheats_query* query,
    lantern_cheat_sets** out, lantern_error* error);
/* A set's text (1 MiB at most), checked against its size and SHA-256. */
LANTERN_API lantern_status lantern_client_cheat_text(
    lantern_client* client, const lantern_cheat_set* set, lantern_string** out, lantern_error* error);
typedef struct lantern_cheat_write
{
    size_t struct_size;
    const char* platform;
    const char* title_id;
    const char* build_id;
    const char* source;
    const char* note;
    const char* text;
} lantern_cheat_write;
/* Scope cheats.write: POST (409 conflict when it exists), PUT, DELETE. */
LANTERN_API lantern_status lantern_client_create_cheat_set(
    lantern_client* client, const lantern_cheat_write* set, lantern_cheat_set** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_replace_cheat_set(
    lantern_client* client, const char* id, const lantern_cheat_write* set, lantern_error* error);
LANTERN_API lantern_status lantern_client_delete_cheat_set(
    lantern_client* client, const char* id, lantern_error* error);

/* ------------------------------------------------------------- Saves (§ 9) */

/* The account's backups, newest first per title. */
LANTERN_API lantern_status lantern_client_saves(lantern_client* client, const char* title_id,
    const char* platform, lantern_saves** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_download_save(lantern_client* client, const lantern_save* save,
    lantern_download_state* state, lantern_download_sink* sink, lantern_error* error);
LANTERN_API lantern_status lantern_client_delete_save(
    lantern_client* client, const lantern_save* save, lantern_error* error);

typedef struct lantern_save_info
{
    size_t struct_size;
    const char* platform; /* overrides the configuration's */
    const char* kind; /* account, device, bcat, cache, other */
    const char* slot;
    bool has_game_version_code;
    uint64_t game_version_code;
    const char* profile; /* 64 bytes at most */
    const char* note; /* 120 bytes at most */
} lantern_save_info;
/* § 9.2: at most limits.save_body bytes, in one request. */
LANTERN_API lantern_status lantern_client_upload_save(lantern_client* client, const char* title_id,
    const uint8_t* archive, size_t size, const lantern_save_info* info, lantern_save** out,
    lantern_error* error);

typedef struct lantern_upload_request
{
    size_t struct_size;
    uint64_t size;
    uint8_t sha256[32];
    const char* kind;
    const char* slot;
    bool has_game_version_code;
    uint64_t game_version_code;
    const char* profile;
    const char* note;
} lantern_upload_request;
/* § 9.3, a step at a time: open, HEAD, PATCH a chunk, DELETE. */
LANTERN_API lantern_status lantern_client_open_upload(lantern_client* client, const char* title_id,
    const lantern_upload_request* request, const char* platform, lantern_upload_session** out,
    lantern_error* error);
LANTERN_API lantern_status lantern_client_upload_offset(
    lantern_client* client, const char* upload, uint64_t* offset, lantern_error* error);
/* *save is set (owned) once the last chunk is in, NULL before; a 409
 * (conflict) says the offset is not the server's: ask upload_offset(). */
LANTERN_API lantern_status lantern_client_upload_chunk(lantern_client* client, const char* upload,
    uint64_t offset, const uint8_t* chunk, size_t size, uint64_t* new_offset, lantern_save** save,
    lantern_error* error);
LANTERN_API lantern_status lantern_client_abandon_upload(
    lantern_client* client, const char* upload, lantern_error* error);

/* An upload in progress, kept to resume after a cut or a restart. */
typedef struct lantern_upload_progress lantern_upload_progress;
LANTERN_API lantern_status lantern_upload_progress_create(
    const lantern_allocator* allocator, lantern_upload_progress** out, lantern_error* error);
LANTERN_API void lantern_upload_progress_free(lantern_upload_progress* progress);
LANTERN_API void lantern_upload_progress_reset(lantern_upload_progress* progress);
/* The upload's address (empty before it is opened), and what the server has. */
LANTERN_API lantern_str lantern_upload_progress_url(const lantern_upload_progress* progress);
LANTERN_API uint64_t lantern_upload_progress_offset(const lantern_upload_progress* progress);
/* As lantern_download_state_save() and _load(): JSON with `schema` 1. */
LANTERN_API lantern_status lantern_upload_progress_save(
    const lantern_upload_progress* progress, lantern_string** out, lantern_error* error);
LANTERN_API lantern_status lantern_upload_progress_load(
    lantern_upload_progress* progress, const char* json, size_t size, lantern_error* error);
/* § 9.3 whole: opens the upload, or asks where it is, then sends the rest
 * in chunks of at most `max_chunk` bytes (0: 1 MiB). A lost connection
 * leaves `progress` where the server is: call again to resume. */
LANTERN_API lantern_status lantern_client_upload_resumable(lantern_client* client, const char* title_id,
    const lantern_upload_request* request, lantern_upload_source* source, lantern_upload_progress* progress,
    size_t max_chunk, const char* platform, lantern_save** out, lantern_error* error);

/* ---------------------------------------------------------- Requests (§ 11) */

LANTERN_API lantern_status lantern_client_requests(
    lantern_client* client, const char* platform, lantern_title_requests** out, lantern_error* error);
typedef struct lantern_request_create
{
    size_t struct_size;
    const char* platform;
    const char* title_id;
} lantern_request_create;
/* 201 for a new request, 200 for the open one of the same title. */
LANTERN_API lantern_status lantern_client_request_title(lantern_client* client,
    const lantern_request_create* request, lantern_title_request** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_withdraw_request(
    lantern_client* client, const char* id, lantern_error* error);

/* ---------------------------------------------------- Administration (§ 5.7) */

typedef struct lantern_page_query
{
    size_t struct_size;
    uint32_t page_size; /* 0: the server's */
    const char* cursor;
} lantern_page_query;
typedef struct lantern_admin_user_create
{
    size_t struct_size;
    const char* name;
    const char* const* scopes;
    size_t scope_count;
    const char* state;
} lantern_admin_user_create;
typedef struct lantern_admin_user_update
{
    size_t struct_size;
    const char* state; /* NULL: unchanged */
    const char* const* scopes; /* none: unchanged */
    size_t scope_count;
} lantern_admin_user_update;
typedef struct lantern_rating_cap_input
{
    size_t struct_size;
    bool has_age;
    uint64_t age;
    const char* system;
    const char* rating;
    const char* unrated;
} lantern_rating_cap_input;
typedef struct lantern_admin_pairing_decision
{
    size_t struct_size;
    const char* decision; /* "approve" or "refuse" */
    const char* user;
    const char* const* scopes;
    size_t scope_count;
    const lantern_rating_cap_input* rating_cap; /* NULL: none */
} lantern_admin_pairing_decision;
typedef struct lantern_invitation_create
{
    size_t struct_size;
    const char* user;
    const char* const* scopes;
    size_t scope_count;
    const char* expires; /* RFC 3339 */
    uint64_t devices;
    const lantern_rating_cap_input* rating_cap;
    const char* note;
} lantern_invitation_create;

LANTERN_API lantern_status lantern_client_admin_users(
    lantern_client* client, const lantern_page_query* page, lantern_admin_users** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_create_user(lantern_client* client,
    const lantern_admin_user_create* user, lantern_admin_user** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_update_user(lantern_client* client, const char* name,
    const lantern_admin_user_update* change, lantern_admin_user** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_devices(lantern_client* client, const char* user,
    const lantern_page_query* page, lantern_admin_devices** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_revoke_device(
    lantern_client* client, const char* id, lantern_error* error);
/* Each waiting pairing's code and key, to compare with the console's screen. */
LANTERN_API lantern_status lantern_client_admin_pairings(lantern_client* client,
    const lantern_page_query* page, lantern_admin_pairings** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_decide_pairing(lantern_client* client, const char* id,
    const lantern_admin_pairing_decision* decision, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_invitations(
    lantern_client* client, const lantern_page_query* page, lantern_invitations** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_create_invitation(lantern_client* client,
    const lantern_invitation_create* invitation, lantern_invitation** out, lantern_error* error);
LANTERN_API lantern_status lantern_client_admin_revoke_invitation(
    lantern_client* client, const char* id, lantern_error* error);

/* ----------------------------------------------------- Discovery (§ 4.1) */

/* {"schema":1,"lantern":"discover"}, to send to UDP 47115. */
LANTERN_API lantern_str lantern_discovery_request(void);
/* A datagram read as a reply: LANTERN_ABSENT for a newer schema; an error
 * for one that is not a reply (drop it). */
LANTERN_API lantern_status lantern_read_discovery_datagram(const uint8_t* bytes, size_t size,
    const lantern_allocator* allocator, lantern_discovery_reply** out, lantern_error* error);
/* "https://<address>:<port>" (IPv6 in brackets): the origin a client takes. */
LANTERN_API lantern_status lantern_discovered_origin(const char* address, uint16_t port,
    const lantern_allocator* allocator, lantern_string** out, lantern_error* error);

typedef struct lantern_datagram
{
    size_t size; /* bytes received into the buffer */
    char address[64]; /* the source, as text, NUL-terminated */
    uint16_t port;
} lantern_datagram;
typedef struct lantern_udp_callbacks
{
    size_t struct_size;
    void* user;
    lantern_status (*send_to)(
        void* user, const char* address, uint16_t port, const uint8_t* bytes, size_t size);
    /* The next datagram into buffer[0..capacity), *received false when none
     * came within `timeout_ms`. */
    lantern_status (*receive)(void* user, uint8_t* buffer, size_t capacity, uint32_t timeout_ms,
        lantern_datagram* out, bool* received);
    void (*release)(void* user);
} lantern_udp_callbacks;
typedef struct lantern_udp_socket lantern_udp_socket;
LANTERN_API lantern_status lantern_udp_socket_create(const lantern_udp_callbacks* callbacks,
    const lantern_allocator* allocator, lantern_udp_socket** out, lantern_error* error);
LANTERN_API void lantern_udp_socket_free(lantern_udp_socket* socket);

typedef struct lantern_discovered_server
{
    size_t struct_size;
    lantern_str address; /* the reply's source */
    lantern_str origin; /* "https://<address>:<port>" */
    const lantern_discovery_reply* reply;
} lantern_discovered_server;
/* Once per server (by uid); false to stop. Everything is borrowed for the call. */
typedef bool (*lantern_discovery_handler)(void* user, const lantern_discovered_server* server);
typedef struct lantern_discovery_options
{
    size_t struct_size;
    const char* address; /* the subnet's broadcast ("192.168.1.255"), or one server's */
    uint16_t port; /* 0: 47115 */
    uint32_t wait_ms; /* how long to listen; 0: 1500 */
    uint32_t attempts; /* requests sent over the wait; 0: 2 */
    const lantern_limits* limits;
} lantern_discovery_options;
LANTERN_API lantern_status lantern_discover(lantern_udp_socket* socket,
    const lantern_discovery_options* options, lantern_discovery_handler handler, void* user,
    lantern_error* error);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_LANTERN_H */
