/* Reads a Lantern server's library, page by page, and downloads its first
 * app, checked, over libcurl: c/README.md's example.
 *   read_library https://shelf.example.org [TOKEN SEED_HEX] */
#include <lantern/lantern.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lantern_status write_file(void* user, const uint8_t* bytes, size_t size)
{
    return fwrite(bytes, 1, size, (FILE*)user) == size ? LANTERN_OK : LANTERN_ERROR_STORAGE;
}

/* The server sends the file from its start again */
static lantern_status restart_file(void* user)
{
    return fseek((FILE*)user, 0, SEEK_SET) == 0 ? LANTERN_OK : LANTERN_ERROR_STORAGE;
}

static int report(const char* what, const lantern_error* error)
{
    fprintf(stderr, "%s: %s (%s, HTTP %u, %s)\n", what, error->detail, lantern_status_name(error->status),
        (unsigned)error->http_status, error->code_text);
    return EXIT_FAILURE;
}

static bool seed_of(const char* hex, uint8_t seed[32])
{
    return lantern_digest_from_hex(hex, seed); /* 64 lower-case hex digits, as a digest */
}

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 4)
    {
        fprintf(stderr, "usage: %s ORIGIN [TOKEN SEED_HEX]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (lantern_version() < LANTERN_C_API_VERSION)
    {
        fprintf(stderr, "liblantern_c is older than its header\n");
        return EXIT_FAILURE;
    }
    lantern_error error          = LANTERN_INIT(lantern_error);
    lantern_trust* trust         = NULL;
    lantern_transport* transport = NULL;
    lantern_random* random       = NULL;
    lantern_client* client       = NULL;
    lantern_handshake* server    = NULL;
    lantern_apps_page* first     = NULL;
    int status                   = EXIT_FAILURE;

    /* libcurl's TLS, the server's key checked by the trust (SPEC.md 5.3) */
    lantern_curl_options options = LANTERN_INIT(lantern_curl_options);
    if (lantern_trust_create(NULL, &trust, &error) != LANTERN_OK
        || lantern_curl_global_init(&error) != LANTERN_OK)
        goto done;
    options.trust = trust;
    if (lantern_transport_create_curl(&options, NULL, &transport, &error) != LANTERN_OK
        || lantern_random_create_system(NULL, &random, &error) != LANTERN_OK)
        goto done;

    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = argv[1];
    config.user_agent            = "ReadLibrary/1.0";
    config.platform              = "switch";
    config.transport             = transport;
    config.random                = random;
    config.trust                 = trust;
    if (lantern_client_create(&config, &client, &error) != LANTERN_OK)
        goto done;
    if (argc == 4)
    {
        /* A token bound to a device key (SPEC.md 5.4): every request is signed */
        uint8_t seed[32];
        lantern_device_key* key = NULL;
        if (!seed_of(argv[3], seed) || lantern_device_key_from_seed(seed, NULL, &key, &error) != LANTERN_OK)
            goto done;
        const lantern_status set = lantern_client_set_credentials(client, argv[2], key, &error);
        lantern_device_key_free(key); /* the client keeps a copy */
        if (set != LANTERN_OK)
            goto done;
    }

    const lantern_status shake = lantern_client_handshake(client, &server, &error);
    if (shake == LANTERN_ABSENT)
    {
        fprintf(stderr, "a server of a newer protocol: update the app\n");
        goto done;
    }
    if (shake != LANTERN_OK)
        goto done;
    printf("%s\n", lantern_handshake_get_name(server).data);

    /* Every page, by its cursor; the first page is kept for its first app */
    char cursor[512] = "";
    do
    {
        lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
        query.cursor             = cursor;
        lantern_apps_page* page  = NULL;
        if (lantern_client_apps(client, &query, &page, &error) != LANTERN_OK)
            goto done;
        for (size_t i = 0; i < lantern_apps_page_get_items_count(page); ++i)
        {
            const lantern_app* app = lantern_apps_page_get_items_at(page, i);
            printf("  %s (%s)\n", lantern_app_get_name(app).data, lantern_app_get_app_id(app).data);
        }
        snprintf(cursor, sizeof(cursor), "%s", lantern_apps_page_get_next(page).data);
        if (first == NULL)
            first = page;
        else
            lantern_apps_page_free(page);
    } while (cursor[0] != '\0');

    const lantern_app* app = lantern_apps_page_get_items_at(first, 0);
    if (app == NULL)
    {
        status = EXIT_SUCCESS;
        goto done;
    }
    /* The file, its size and SHA-256 as the listing gave them */
    lantern_download_target target = LANTERN_INIT(lantern_download_target);
    target.url                     = lantern_app_get_file(app).data;
    lantern_app_get_size(app, &target.size);
    lantern_app_get_sha256(app, target.sha256);
    FILE* file = fopen("first-app.part", "wb");
    if (file == NULL)
        goto done;
    lantern_download_callbacks callbacks = LANTERN_INIT(lantern_download_callbacks);
    callbacks.user                       = file;
    callbacks.write                      = write_file;
    callbacks.restart                    = restart_file;
    lantern_download_sink* sink          = NULL;
    lantern_download_state* state        = NULL;
    lantern_status got                   = lantern_download_sink_create(&callbacks, NULL, &sink, &error);
    if (got == LANTERN_OK)
        got = lantern_download_state_create(NULL, &state, &error);
    if (got == LANTERN_OK)
        got = lantern_client_download(client, &target, state, sink, &error);
    lantern_download_sink_free(sink);
    lantern_download_state_free(state);
    fclose(file);
    /* Only now, with the SHA-256 checked, is the file the app's */
    if (got == LANTERN_OK && rename("first-app.part", "first-app.bin") == 0)
        status = EXIT_SUCCESS;

done:
    if (status != EXIT_SUCCESS && error.status != LANTERN_OK)
        report("lantern", &error);
    lantern_apps_page_free(first);
    lantern_handshake_free(server);
    lantern_client_free(client);
    lantern_transport_free(transport);
    lantern_random_free(random);
    lantern_trust_free(trust);
    return status;
}
