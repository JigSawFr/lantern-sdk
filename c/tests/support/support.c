#include "support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* spec_file(const char* relative, size_t* size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", LANTERN_SPEC_DIR, relative);
    FILE* file = fopen(path, "rb");
    if (file == NULL)
        return NULL;
    fseek(file, 0, SEEK_END);
    const long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (length < 0)
    {
        fclose(file);
        return NULL;
    }
    char* text       = malloc((size_t)length + 1);
    const size_t got = text == NULL ? 0 : fread(text, 1, (size_t)length, file);
    fclose(file);
    if (text == NULL)
        return NULL;
    text[got] = '\0';
    if (size != NULL)
        *size = got;
    return text;
}

/* Blocks of any alignment over malloc: the pointer malloc gave is kept
 * just before the aligned block. */
static void* counting_allocate(void* user, size_t size, size_t alignment)
{
    counting_allocator* counter = user;
    if (alignment < sizeof(void*))
        alignment = sizeof(void*);
    unsigned char* raw = malloc(size + alignment + sizeof(void*));
    if (raw == NULL)
        return NULL;
    uintptr_t start = (uintptr_t)(raw + sizeof(void*));
    start           = (start + alignment - 1) & ~(uintptr_t)(alignment - 1);
    void** before   = (void**)start - 1;
    *before         = raw;
    ++counter->live;
    ++counter->total;
    counter->bytes += size;
    return (void*)start;
}

static void counting_deallocate(void* user, void* pointer, size_t size, size_t alignment)
{
    (void)alignment;
    counting_allocator* counter = user;
    if (pointer == NULL)
        return;
    --counter->live;
    counter->bytes -= size;
    free(((void**)pointer)[-1]);
}

lantern_allocator counting_allocator_make(counting_allocator* counter)
{
    lantern_allocator allocator = LANTERN_INIT(lantern_allocator);
    allocator.user              = counter;
    allocator.allocate          = counting_allocate;
    allocator.deallocate        = counting_deallocate;
    return allocator;
}

void fake_init(fake_server* server, const char* origin)
{
    memset(server, 0, sizeof(*server));
    server->origin = origin;
}

fake_route* fake_add(
    fake_server* server, const char* method, const char* path, uint16_t status, const char* body)
{
    if (server->route_count >= FAKE_MAX_ROUTES)
        abort();
    fake_route* route = &server->routes[server->route_count++];
    memset(route, 0, sizeof(*route));
    route->method = method;
    route->path   = path;
    route->status = status;
    route->body   = body;
    /* A JSON document says so */
    if (body != NULL && body[0] == '{')
        fake_header(route, "Content-Type", "application/json");
    return route;
}

fake_route* fake_problem(
    fake_server* server, const char* method, const char* path, uint16_t status, const char* body)
{
    fake_route* route = fake_add(server, method, path, status, NULL);
    route->body       = body;
    fake_header(route, "Content-Type", "application/problem+json");
    return route;
}

void fake_header(fake_route* route, const char* name, const char* value)
{
    for (size_t i = 0; i < FAKE_MAX_HEADERS; ++i)
    {
        if (route->headers[i][0] == NULL)
        {
            route->headers[i][0] = name;
            route->headers[i][1] = value;
            return;
        }
    }
    abort();
}

static bool matches(const fake_route* route, const char* method, const char* path)
{
    if (strcmp(route->method, method) != 0)
        return false;
    if (route->times != 0 && route->used >= route->times)
        return false;
    const size_t size = strlen(route->path);
    if (size > 0 && route->path[size - 1] == '*')
        return strncmp(route->path, path, size - 1) == 0;
    return strcmp(route->path, path) == 0;
}

static void copy_into(char* out, size_t capacity, const char* text, size_t size)
{
    if (size >= capacity)
        size = capacity - 1;
    memcpy(out, text, size);
    out[size] = '\0';
}

static lantern_status fake_send(
    void* user, const lantern_request* request, lantern_response* response, lantern_error* error)
{
    fake_server* server = user;
    ++server->requests;
    copy_into(server->last_method, sizeof(server->last_method), request->method_name.data,
        request->method_name.size);
    copy_into(server->last_url, sizeof(server->last_url), request->url.data, request->url.size);
    size_t at               = 0;
    server->last_headers[0] = '\0';
    for (size_t i = 0; i < request->header_count; ++i)
    {
        const lantern_header* h = &request->headers[i];
        const int written = snprintf(server->last_headers + at, sizeof(server->last_headers) - at, "%s: %s\n",
            h->name.data, h->value.data);
        if (written > 0 && (size_t)written < sizeof(server->last_headers) - at)
            at += (size_t)written;
    }
    server->last_body_size = request->body_size < sizeof(server->last_body) ? request->body_size : 0;
    if (server->last_body_size > 0)
        memcpy(server->last_body, request->body, server->last_body_size);
    const size_t origin = strlen(server->origin);
    if (strncmp(request->url.data, server->origin, origin) != 0)
    {
        lantern_error_set(error, LANTERN_ERROR_TRANSPORT, "not the fake server's origin");
        return LANTERN_ERROR_TRANSPORT;
    }
    const char* path = request->url.data + origin;
    for (size_t r = 0; r < server->route_count; ++r)
    {
        fake_route* route = &server->routes[r];
        if (!matches(route, request->method_name.data, path))
            continue;
        ++route->used;
        if (!lantern_response_status(response, route->status))
            return LANTERN_OK;
        for (size_t i = 0; i < FAKE_MAX_HEADERS && route->headers[i][0] != NULL; ++i)
        {
            const char* name  = route->headers[i][0];
            const char* value = route->headers[i][1];
            if (!lantern_response_header(response, name, strlen(name), value, strlen(value)))
                return LANTERN_OK;
        }
        const char* body = route->body == NULL ? "" : route->body;
        size_t size      = route->body_size != 0 ? route->body_size : strlen(body);
        if (route->cut_after != 0 && route->cut_after < size)
        {
            lantern_response_body(response, (const uint8_t*)body, route->cut_after);
            lantern_error_set(error, LANTERN_ERROR_TRANSPORT, "connection reset (by the test)");
            return LANTERN_ERROR_TRANSPORT;
        }
        /* In two chunks, as a network gives them */
        const size_t half = size / 2;
        if (half > 0 && !lantern_response_body(response, (const uint8_t*)body, half))
            return LANTERN_OK;
        lantern_response_body(response, (const uint8_t*)body + half, size - half);
        return LANTERN_OK;
    }
    lantern_response_status(response, 404);
    const char* problem = "{\"schema\":1,\"type\":\"about:blank\",\"title\":\"Not found\",\"status\":404,"
                          "\"code\":\"not_found\",\"detail\":\"No route in the fake server.\"}";
    lantern_response_header(response, "Content-Type", 12, "application/problem+json", 24);
    lantern_response_body(response, (const uint8_t*)problem, strlen(problem));
    return LANTERN_OK;
}

static void fake_release(void* user)
{
    ((fake_server*)user)->released = true;
}

lantern_transport* fake_transport(fake_server* server, const lantern_allocator* allocator)
{
    lantern_transport_callbacks callbacks = LANTERN_INIT(lantern_transport_callbacks);
    callbacks.user                        = server;
    callbacks.send                        = fake_send;
    callbacks.release                     = fake_release;
    lantern_transport* transport          = NULL;
    if (lantern_transport_create(&callbacks, allocator, &transport, NULL) != LANTERN_OK)
        return NULL;
    return transport;
}

const char* fake_last_header(fake_server* server, const char* name, char* out, size_t size)
{
    const size_t length = strlen(name);
    for (const char* line = server->last_headers; *line != '\0';)
    {
        const char* end = strchr(line, '\n');
        if (end == NULL)
            break;
        if (strncmp(line, name, length) == 0 && line[length] == ':')
        {
            copy_into(out, size, line + length + 2, (size_t)(end - line) - length - 2);
            return out;
        }
        line = end + 1;
    }
    return NULL;
}

static lantern_status sink_write(void* user, const uint8_t* bytes, size_t size)
{
    memory_sink* sink = user;
    if (sink->size + size > sink->capacity)
    {
        size_t capacity = sink->capacity == 0 ? 4096 : sink->capacity;
        while (capacity < sink->size + size)
            capacity *= 2;
        uint8_t* grown = realloc(sink->bytes, capacity);
        if (grown == NULL)
            return LANTERN_ERROR_STORAGE;
        sink->bytes    = grown;
        sink->capacity = capacity;
    }
    memcpy(sink->bytes + sink->size, bytes, size);
    sink->size += size;
    return LANTERN_OK;
}

static lantern_status sink_restart(void* user)
{
    memory_sink* sink = user;
    sink->size        = 0;
    ++sink->restarts;
    return LANTERN_OK;
}

lantern_download_sink* memory_sink_make(memory_sink* sink)
{
    memset(sink, 0, sizeof(*sink));
    lantern_download_callbacks callbacks = LANTERN_INIT(lantern_download_callbacks);
    callbacks.user                       = sink;
    callbacks.write                      = sink_write;
    callbacks.restart                    = sink_restart;
    lantern_download_sink* out           = NULL;
    if (lantern_download_sink_create(&callbacks, NULL, &out, NULL) != LANTERN_OK)
        return NULL;
    return out;
}

void memory_sink_clear(memory_sink* sink)
{
    free(sink->bytes);
    memset(sink, 0, sizeof(*sink));
}

bool hex_to_bytes(const char* hex, uint8_t* out, size_t size)
{
    if (strlen(hex) != size * 2)
        return false;
    for (size_t i = 0; i < size; ++i)
    {
        unsigned value = 0;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return false;
        out[i] = (uint8_t)value;
    }
    return true;
}
