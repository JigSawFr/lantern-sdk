/*
 * What the C tests share: the specification's files, an allocator that
 * counts, and a scripted server behind a transport of callbacks. Every name
 * and game here is made up (Lea, Noor, Ines, Frostline Tales).
 */
#ifndef LANTERN_TEST_SUPPORT_H
#define LANTERN_TEST_SUPPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lantern/lantern.h>

/* A file of spec/ (LANTERN_SPEC_DIR), NUL-terminated, malloc'd; NULL when missing. */
char* spec_file(const char* relative, size_t* size);

/* An allocator that counts what is live, and refuses nothing. */
typedef struct counting_allocator
{
    size_t live; /* blocks */
    size_t bytes; /* bytes */
    size_t total; /* blocks ever */
} counting_allocator;
lantern_allocator counting_allocator_make(counting_allocator* counter);

/* A scripted server: answers by method and path (after the origin), a
 * route whose path ends with '*' matching any path it begins. */
#define FAKE_MAX_ROUTES 48
#define FAKE_MAX_HEADERS 6
typedef struct fake_route
{
    const char* method;
    const char* path;
    uint16_t status;
    const char* headers[FAKE_MAX_HEADERS][2];
    const char* body;
    size_t body_size; /* 0: strlen(body) */
    /* Answered this many times, then the route is skipped (0: always). */
    int times;
    int used;
    /* Cut the body after this many bytes and fail as a lost connection (0: never). */
    size_t cut_after;
} fake_route;

typedef struct fake_server
{
    const char* origin;
    fake_route routes[FAKE_MAX_ROUTES];
    size_t route_count;
    /* The last request */
    int requests;
    char last_method[8];
    char last_url[1024];
    char last_headers[4096]; /* "name: value\n"… */
    char last_body[8192];
    size_t last_body_size;
    bool released;
} fake_server;

void fake_init(fake_server* server, const char* origin);
fake_route* fake_add(
    fake_server* server, const char* method, const char* path, uint16_t status, const char* body);
void fake_header(fake_route* route, const char* name, const char* value);
/* A route answering with a problem+json document (SPEC.md § 12). */
fake_route* fake_problem(
    fake_server* server, const char* method, const char* path, uint16_t status, const char* body);
/* The transport over the server (made with `allocator`, which may be NULL). */
lantern_transport* fake_transport(fake_server* server, const lantern_allocator* allocator);
/* The value of a header of the last request, or NULL. */
const char* fake_last_header(fake_server* server, const char* name, char* out, size_t size);

/* A sink that keeps the bytes in memory. */
typedef struct memory_sink
{
    uint8_t* bytes;
    size_t size;
    size_t capacity;
    int restarts;
} memory_sink;
lantern_download_sink* memory_sink_make(memory_sink* sink);
void memory_sink_clear(memory_sink* sink);

/* A key from a hex seed. */
bool hex_to_bytes(const char* hex, uint8_t* out, size_t size);

#endif
