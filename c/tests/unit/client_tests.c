/* The client against a scripted server: every call of the API, its
 * requests and its errors. The server's documents are the specification's
 * examples (Frostline Tales, Lea and Noor). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness.h"
#include "support.h"
#include "tests.h"

#define ORIGIN "https://shelf.example.org"

typedef struct fixture
{
    fake_server server;
    char* documents[24];
    size_t document_count;
    lantern_transport* transport;
    lantern_random* random;
    lantern_client* client;
    lantern_handshake* handshake;
} fixture;

static const char* example(fixture* f, const char* file)
{
    char path[256];
    snprintf(path, sizeof(path), "examples/v1/%s", file);
    char* text = spec_file(path, NULL);
    if (text == NULL || f->document_count >= sizeof(f->documents) / sizeof(f->documents[0]))
        abort();
    f->documents[f->document_count++] = text;
    return text;
}

/* `"family": 0` made `"family": 1` in a document of the fixture's. */
static void offer(char* text, const char* family)
{
    char key[64];
    snprintf(key, sizeof(key), "\"%s\": ", family);
    char* at = strstr(text, key);
    if (at != NULL)
        at[strlen(key)] = '1';
}

static lantern_status fill_counting(void* user, uint8_t* out, size_t size)
{
    unsigned* counter = user;
    for (size_t i = 0; i < size; ++i)
        out[i] = (uint8_t)(++*counter * 131U + 7U);
    return LANTERN_OK;
}

static unsigned random_counter;

/* A client of the scripted server; routes may be added before or after. */
static bool fixture_open(fixture* f)
{
    memset(f, 0, sizeof(*f));
    fake_init(&f->server, ORIGIN);
    char* shake = (char*)example(f, "handshake.json");
    offer(shake, "requests");
    offer(shake, "admin");
    fake_add(&f->server, "GET", "/.well-known/lantern", 200, shake);
    f->transport                    = fake_transport(&f->server, NULL);
    lantern_random_callbacks random = LANTERN_INIT(lantern_random_callbacks);
    random.user                     = &random_counter;
    random.fill                     = fill_counting;
    if (f->transport == NULL || lantern_random_create(&random, NULL, &f->random, NULL) != LANTERN_OK)
        return false;
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = ORIGIN;
    config.user_agent            = "LanternCTests/0.4";
    config.platform              = "switch";
    config.accept_language       = "fr, en;q=0.5";
    config.transport             = f->transport;
    config.random                = f->random;
    lantern_error error          = LANTERN_INIT(lantern_error);
    if (!CHECK_CALL(lantern_client_create(&config, &f->client, &error), LANTERN_OK, &error))
        return false;
    return CHECK_CALL(lantern_client_handshake(f->client, &f->handshake, &error), LANTERN_OK, &error);
}

static void fixture_close(fixture* f)
{
    lantern_handshake_free(f->handshake);
    lantern_client_free(f->client);
    lantern_transport_free(f->transport);
    lantern_random_free(f->random);
    for (size_t i = 0; i < f->document_count; ++i)
        free(f->documents[i]);
}

static void handshake_and_families(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    CHECK(lantern_client_server(f.client) != NULL);
    CHECK(STR_EQ(lantern_handshake_get_name(lantern_client_server(f.client)), "Living room shelf"));
    CHECK(lantern_client_offers(f.client, LANTERN_FAMILY_LIBRARY) == 1);
    CHECK(lantern_client_offers(f.client, LANTERN_FAMILY_ADMIN) == 1);
    CHECK(lantern_client_offers(f.client, 99) == 0);
    CHECK(!lantern_client_has_token(f.client));
    CHECK(lantern_client_device_key(f.client) == NULL);
    CHECK(strcmp(f.server.last_url, ORIGIN "/.well-known/lantern") == 0);
    char value[128];
    CHECK(fake_last_header(&f.server, "User-Agent", value, sizeof(value)) != NULL
        && strcmp(value, "LanternCTests/0.4") == 0);
    CHECK(fake_last_header(&f.server, "Lantern-Platform", value, sizeof(value)) != NULL
        && strcmp(value, "switch") == 0);
    CHECK(fake_last_header(&f.server, "Accept-Language", value, sizeof(value)) != NULL);
    fixture_close(&f);
}

static void library_calls(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_server* s = &f.server;
    fake_add(s, "GET", "/api/lantern/v1/apps?*", 200, example(&f, "apps.json"));
    fake_add(s, "GET", "/api/lantern/v1/apps", 200, example(&f, "apps.json"));
    fake_add(s, "POST", "/api/lantern/v1/apps/missing*", 200, example(&f, "apps.json"));
    fake_add(s, "GET", "/api/lantern/v1/changes*", 200, example(&f, "changes.json"));
    fake_add(s, "GET", "/api/lantern/v1/sections", 200, example(&f, "sections.json"));
    fake_add(s, "GET", "/api/lantern/v1/titles/changes*", 200, example(&f, "title-changes.json"));
    fake_add(s, "GET", "/api/lantern/v1/titles?ids=*", 200, example(&f, "titles.json"));
    fake_add(s, "GET", "/api/lantern/v1/titles/*", 200, example(&f, "title.json"));
    lantern_error error = LANTERN_INIT(lantern_error);

    lantern_apps_query query = LANTERN_INIT(lantern_apps_query);
    query.page_size          = 3;
    query.cursor             = "c_2";
    query.q                  = "Moss & Ember";
    lantern_apps_page* page  = NULL;
    REQUIRE_CALL(lantern_client_apps(f.client, &query, &page, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "page_size=3") != NULL);
    CHECK(strstr(s->last_url, "cursor=c_2") != NULL);
    CHECK(strstr(s->last_url, "q=Moss%20%26%20Ember") != NULL);
    CHECK(lantern_apps_page_get_items_count(page) >= 2);
    CHECK(STR_EQ(lantern_apps_page_get_next(page), "c_Kp9w"));
    lantern_apps_page_free(page);
    /* A NULL query: the defaults */
    REQUIRE_CALL(lantern_client_apps(f.client, NULL, &page, &error), LANTERN_OK, &error);
    lantern_apps_page_free(page);

    const lantern_installed_app installed[] = { { "0100ABCD00010000", 0 } };
    const char* const want[]                = { "update", "dlc" };
    lantern_missing_request missing         = LANTERN_INIT(lantern_missing_request);
    missing.installed                       = installed;
    missing.installed_count                 = 1;
    missing.want                            = want;
    missing.want_count                      = 2;
    REQUIRE_CALL(lantern_client_missing(f.client, &missing, NULL, NULL, &page, &error), LANTERN_OK, &error);
    CHECK(strcmp(s->last_method, "POST") == 0);
    CHECK(
        strstr(s->last_body, "\"installed\":[{\"app_id\":\"0100ABCD00010000\",\"version_code\":0}]") != NULL);
    CHECK(strstr(s->last_body, "\"want\":[\"update\",\"dlc\"]") != NULL);
    lantern_apps_page_free(page);

    lantern_changes* changes = NULL;
    REQUIRE_CALL(lantern_client_changes(f.client, "s_20261030T1015", &changes, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "since=s_20261030T1015") != NULL);
    CHECK(lantern_changes_get_removed_count(changes) == 1);
    lantern_changes_free(changes);

    lantern_sections* sections = NULL;
    REQUIRE_CALL(lantern_client_sections(f.client, &sections, &error), LANTERN_OK, &error);
    CHECK(lantern_sections_get_sections_count(sections) > 0);
    lantern_sections_free(sections);

    lantern_title* title = NULL;
    REQUIRE_CALL(lantern_client_title(f.client, "0100ABCD00010000", &title, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "/titles/0100ABCD00010000") != NULL);
    lantern_title_free(title);

    const char* const ids[] = { "0100ABCD00010000", "0100FFFF00000000" };
    lantern_titles* titles  = NULL;
    REQUIRE_CALL(lantern_client_titles(f.client, ids, 2, &titles, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "ids=0100ABCD00010000,0100FFFF00000000") != NULL);
    CHECK(lantern_titles_get_titles_count(titles) >= 1);
    lantern_titles_free(titles);

    lantern_title_changes* title_changes = NULL;
    REQUIRE_CALL(lantern_client_title_changes(f.client, NULL, &title_changes, &error), LANTERN_OK, &error);
    lantern_title_changes_free(title_changes);
    fixture_close(&f);
}

static void homebrew_cheats_saves_requests(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_server* s = &f.server;
    fake_add(s, "POST", "/api/lantern/v1/homebrew/updates*", 200, example(&f, "homebrew-page.json"));
    fake_add(s, "GET", "/api/lantern/v1/homebrew?*", 200, example(&f, "homebrew-page.json"));
    fake_add(s, "GET", "/api/lantern/v1/homebrew/*", 200, example(&f, "homebrew.json"));
    fake_add(s, "GET", "/api/lantern/v1/cheats?*", 200, example(&f, "cheats.json"));
    fake_add(s, "POST", "/api/lantern/v1/cheats", 201, example(&f, "cheat.json"));
    fake_add(s, "PUT", "/api/lantern/v1/cheats/*", 204, NULL);
    fake_add(s, "DELETE", "/api/lantern/v1/cheats/*", 204, NULL);
    fake_add(s, "GET", "/api/lantern/v1/saves*", 200, example(&f, "saves.json"));
    fake_add(s, "POST", "/api/lantern/v1/saves/0100ABCD00010000/uploads*", 201, example(&f, "upload.json"));
    fake_add(s, "POST", "/api/lantern/v1/saves/*", 201, example(&f, "save.json"));
    fake_add(s, "GET", "/api/lantern/v1/requests*", 200, example(&f, "requests.json"));
    fake_add(s, "POST", "/api/lantern/v1/requests", 201, example(&f, "request.json"));
    fake_add(s, "DELETE", "/api/lantern/v1/requests/*", 204, NULL);
    lantern_error error = LANTERN_INIT(lantern_error);

    lantern_homebrew_query query = LANTERN_INIT(lantern_homebrew_query);
    query.kind                   = "app";
    lantern_homebrew_page* page  = NULL;
    REQUIRE_CALL(lantern_client_homebrew(f.client, &query, &page, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "kind=app") != NULL);
    CHECK(lantern_homebrew_page_get_items_count(page) > 0);
    lantern_homebrew_page_free(page);
    lantern_homebrew* entry = NULL;
    REQUIRE_CALL(
        lantern_client_homebrew_entry(f.client, "org.example.frostline", &entry, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "/homebrew/org.example.frostline") != NULL);
    lantern_homebrew_free(entry);
    const lantern_installed_homebrew installed[] = { { "org.example.frostline", 10300 } };
    lantern_homebrew_updates_request updates     = LANTERN_INIT(lantern_homebrew_updates_request);
    updates.installed                            = installed;
    updates.installed_count                      = 1;
    REQUIRE_CALL(
        lantern_client_homebrew_updates(f.client, &updates, NULL, NULL, &page, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"build\":10300") != NULL);
    lantern_homebrew_page_free(page);

    lantern_cheats_query cheats = LANTERN_INIT(lantern_cheats_query);
    cheats.title_id             = "0100ABCD00010000";
    lantern_cheat_sets* sets    = NULL;
    REQUIRE_CALL(lantern_client_cheats(f.client, &cheats, &sets, &error), LANTERN_OK, &error);
    CHECK(lantern_cheat_sets_get_cheats_count(sets) == 2);
    CHECK(STR_EQ(lantern_cheat_set_get_source(lantern_cheat_sets_get_cheats_at(sets, 1)), "Noor's notes"));
    lantern_cheat_sets_free(sets);
    lantern_cheat_write write = LANTERN_INIT(lantern_cheat_write);
    write.platform            = "switch";
    write.title_id            = "0100ABCD00010000";
    write.build_id            = "4A1B2C3D4E5F6071";
    write.source              = "Lantern tests";
    write.text                = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    lantern_cheat_set* made   = NULL;
    REQUIRE_CALL(lantern_client_create_cheat_set(f.client, &write, &made, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"source\":\"Lantern tests\"") != NULL);
    lantern_cheat_set_free(made);
    CHECK_CALL(lantern_client_replace_cheat_set(f.client, "cs_Jt3Vx0", &write, &error), LANTERN_OK, &error);
    CHECK(strcmp(s->last_method, "PUT") == 0);
    CHECK_CALL(lantern_client_delete_cheat_set(f.client, "cs_Jt3Vx0", &error), LANTERN_OK, &error);
    CHECK(strcmp(s->last_method, "DELETE") == 0);

    lantern_saves* saves = NULL;
    REQUIRE_CALL(
        lantern_client_saves(f.client, "0100ABCD00010000", NULL, &saves, &error), LANTERN_OK, &error);
    CHECK(lantern_saves_get_saves_count(saves) > 0);
    lantern_saves_free(saves);
    const uint8_t archive[]    = { 'P', 'K', 5, 6, 0, 0, 0, 0 };
    lantern_save_info info     = LANTERN_INIT(lantern_save_info);
    info.kind                  = "account";
    info.profile               = "L\xC3\xA9"
                                 "a";
    info.has_game_version_code = true;
    info.game_version_code     = 196608;
    lantern_save* save         = NULL;
    REQUIRE_CALL(lantern_client_upload_save(
                     f.client, "0100ABCD00010000", archive, sizeof(archive), &info, &save, &error),
        LANTERN_OK, &error);
    char value[128];
    CHECK(fake_last_header(s, "Content-Digest", value, sizeof(value)) != NULL);
    CHECK(fake_last_header(s, "Lantern-Profile", value, sizeof(value)) != NULL
        && strcmp(value, "L%C3%A9a") == 0);
    CHECK(fake_last_header(s, "Lantern-Game-Version", value, sizeof(value)) != NULL
        && strcmp(value, "196608") == 0);
    CHECK(STR_EQ(lantern_save_get_save_id(save), "s_03"));
    lantern_save_free(save);
    lantern_upload_request upload = LANTERN_INIT(lantern_upload_request);
    upload.size                   = 40000;
    lantern_sha256(archive, sizeof(archive), upload.sha256);
    upload.kind                     = "account";
    lantern_upload_session* session = NULL;
    REQUIRE_CALL(lantern_client_open_upload(f.client, "0100ABCD00010000", &upload, NULL, &session, &error),
        LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"size\":40000") != NULL);
    CHECK(lantern_upload_session_get_upload(session).size > 0);
    lantern_upload_session_free(session);

    lantern_title_requests* requests = NULL;
    REQUIRE_CALL(lantern_client_requests(f.client, NULL, &requests, &error), LANTERN_OK, &error);
    lantern_title_requests_free(requests);
    lantern_request_create wish  = LANTERN_INIT(lantern_request_create);
    wish.title_id                = "0100FFFF00010000";
    lantern_title_request* asked = NULL;
    REQUIRE_CALL(lantern_client_request_title(f.client, &wish, &asked, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "0100FFFF00010000") != NULL);
    lantern_title_request_free(asked);
    CHECK_CALL(lantern_client_withdraw_request(f.client, "r_1", &error), LANTERN_OK, &error);
    fixture_close(&f);
}

static void administration(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_server* s = &f.server;
    fake_add(s, "GET", "/api/lantern/v1/admin/users*", 200, example(&f, "admin-users.json"));
    fake_add(s, "POST", "/api/lantern/v1/admin/users", 201, example(&f, "admin-user.json"));
    fake_add(s, "PATCH", "/api/lantern/v1/admin/users/*", 200, example(&f, "admin-user.json"));
    fake_add(s, "GET", "/api/lantern/v1/admin/devices*", 200, example(&f, "admin-devices.json"));
    fake_add(s, "DELETE", "/api/lantern/v1/admin/devices/*", 204, NULL);
    fake_add(s, "GET", "/api/lantern/v1/admin/pairings*", 200, example(&f, "admin-pairings.json"));
    fake_add(s, "POST", "/api/lantern/v1/admin/pairings/*", 204, NULL);
    fake_add(s, "GET", "/api/lantern/v1/admin/invitations*", 200, example(&f, "invitations.json"));
    fake_add(s, "POST", "/api/lantern/v1/admin/invitations", 201, example(&f, "invitation.json"));
    fake_add(s, "DELETE", "/api/lantern/v1/admin/invitations/*", 204, NULL);
    lantern_error error = LANTERN_INIT(lantern_error);

    lantern_page_query page    = LANTERN_INIT(lantern_page_query);
    page.page_size             = 10;
    lantern_admin_users* users = NULL;
    REQUIRE_CALL(lantern_client_admin_users(f.client, &page, &users, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "page_size=10") != NULL);
    CHECK(lantern_admin_users_get_items_count(users) > 0);
    lantern_admin_users_free(users);
    const char* const scopes[]       = { "library", "requests" };
    lantern_admin_user_create create = LANTERN_INIT(lantern_admin_user_create);
    create.name                      = "noor";
    create.scopes                    = scopes;
    create.scope_count               = 2;
    lantern_admin_user* user         = NULL;
    REQUIRE_CALL(lantern_client_admin_create_user(f.client, &create, &user, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"name\":\"noor\"") != NULL);
    lantern_admin_user_free(user);
    lantern_admin_user_update update = LANTERN_INIT(lantern_admin_user_update);
    update.state                     = "frozen";
    REQUIRE_CALL(
        lantern_client_admin_update_user(f.client, "noor", &update, &user, &error), LANTERN_OK, &error);
    CHECK(strcmp(s->last_method, "PATCH") == 0);
    CHECK(strstr(s->last_body, "\"state\":\"frozen\"") != NULL);
    CHECK(strstr(s->last_body, "scopes") == NULL);
    lantern_admin_user_free(user);
    lantern_admin_devices* devices = NULL;
    REQUIRE_CALL(lantern_client_admin_devices(f.client, "noor", NULL, &devices, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_url, "user=noor") != NULL);
    lantern_admin_devices_free(devices);
    CHECK_CALL(lantern_client_admin_revoke_device(f.client, "d_1", &error), LANTERN_OK, &error);
    lantern_admin_pairings* pairings = NULL;
    REQUIRE_CALL(lantern_client_admin_pairings(f.client, NULL, &pairings, &error), LANTERN_OK, &error);
    const lantern_admin_pairing* waiting = lantern_admin_pairings_get_items_at(pairings, 0);
    CHECK(waiting != NULL && lantern_admin_pairing_get_code(waiting).size > 0);
    lantern_admin_pairings_free(pairings);
    lantern_rating_cap_input cap            = LANTERN_INIT(lantern_rating_cap_input);
    cap.has_age                             = true;
    cap.age                                 = 12;
    lantern_admin_pairing_decision decision = LANTERN_INIT(lantern_admin_pairing_decision);
    decision.decision                       = "approve";
    decision.scopes                         = scopes;
    decision.scope_count                    = 1;
    decision.rating_cap                     = &cap;
    CHECK_CALL(
        lantern_client_admin_decide_pairing(f.client, "p_4Fh2", &decision, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"rating_cap\":{\"age\":12}") != NULL);
    lantern_invitations* invitations = NULL;
    REQUIRE_CALL(lantern_client_admin_invitations(f.client, NULL, &invitations, &error), LANTERN_OK, &error);
    lantern_invitations_free(invitations);
    lantern_invitation_create invite = LANTERN_INIT(lantern_invitation_create);
    invite.user                      = "noor";
    invite.scopes                    = scopes;
    invite.scope_count               = 1;
    invite.expires                   = "2026-11-06T12:00:00Z";
    invite.devices                   = 1;
    invite.note                      = "Noor's consoles";
    lantern_invitation* invitation   = NULL;
    REQUIRE_CALL(
        lantern_client_admin_create_invitation(f.client, &invite, &invitation, &error), LANTERN_OK, &error);
    lantern_invitation_link link = LANTERN_INIT(lantern_invitation_link);
    CHECK_CALL(lantern_parse_invitation_link(lantern_invitation_get_link(invitation).data, &link, &error),
        LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_invitation_get_code(invitation), link.code));
    lantern_invitation_free(invitation);
    CHECK_CALL(lantern_client_admin_revoke_invitation(f.client, "i_1", &error), LANTERN_OK, &error);
    fixture_close(&f);
}

static void errors_of_the_server(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_server* s = &f.server;
    fake_problem(s, "GET", "/api/lantern/v1/titles/0100FFFF00000000", 403, example(&f, "problem.json"));
    fake_route* later = fake_problem(s, "GET", "/api/lantern/v1/titles/0100EEEE00000000", 409,
        "{\"schema\":1,\"type\":\"about:blank\",\"title\":\"Later\",\"status\":409,\"code\":\"a_code_of_"
        "draft_9\","
        "\"detail\":\"A code this library does not know.\"}");
    (void)later;
    fake_route* busy = fake_problem(s, "GET", "/api/lantern/v1/titles/0100DDDD00000000", 503,
        "{\"schema\":1,\"type\":\"about:blank\",\"title\":\"Busy\",\"status\":503,\"code\":\"unavailable\"}");
    fake_header(busy, "Retry-After", "120");
    lantern_error error  = LANTERN_INIT(lantern_error);
    lantern_title* title = NULL;
    CHECK_STATUS(lantern_client_title(f.client, "0100FFFF00000000", &title, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(title == NULL);
    CHECK(error.status == LANTERN_ERROR_PROTOCOL);
    CHECK(error.http_status == 403);
    CHECK(error.code == LANTERN_CODE_ACCOUNT_FROZEN);
    CHECK(error.effective_code == LANTERN_CODE_ACCOUNT_FROZEN);
    CHECK(strcmp(error.code_text, "account_frozen") == 0);
    CHECK(strcmp(error.title, "Account frozen") == 0);
    CHECK(strcmp(error.detail, "Your access is paused until Sunday.") == 0);

    CHECK_STATUS(lantern_client_title(f.client, "0100EEEE00000000", &title, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.code == LANTERN_CODE_UNKNOWN);
    CHECK(error.effective_code == LANTERN_CODE_CONFLICT);
    CHECK(strcmp(error.code_text, "a_code_of_draft_9") == 0);

    CHECK_STATUS(lantern_client_title(f.client, "0100DDDD00000000", &title, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.retry_after == 120);
    CHECK(error.effective_code == LANTERN_CODE_UNAVAILABLE);

    /* No route: the fake's 404 */
    CHECK_STATUS(lantern_client_sections(f.client, NULL, &error), LANTERN_ERROR_USAGE);
    lantern_sections* sections = NULL;
    CHECK_STATUS(lantern_client_sections(f.client, &sections, &error), LANTERN_ERROR_PROTOCOL);
    CHECK(error.effective_code == LANTERN_CODE_NOT_FOUND);

    /* A document of a newer schema: absent, not an error */
    fake_add(
        s, "GET", "/api/lantern/v1/titles/0100CCCC00000000", 200, "{\"schema\":7,\"name\":\"From later\"}");
    lantern_error_init(&error);
    CHECK_STATUS(lantern_client_title(f.client, "0100CCCC00000000", &title, &error), LANTERN_ABSENT);
    CHECK(title == NULL);
    CHECK(error.status == LANTERN_OK);

    /* A transport that fails: its detail */
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = "https://other.example.org";
    config.user_agent            = "LanternCTests/0.4";
    config.transport             = f.transport;
    lantern_client* other        = NULL;
    REQUIRE_STATUS(lantern_client_create(&config, &other, NULL), LANTERN_OK);
    lantern_handshake* shake = NULL;
    CHECK_STATUS(lantern_client_handshake(other, &shake, &error), LANTERN_ERROR_TRANSPORT);
    CHECK(strcmp(error.detail, "not the fake server's origin") == 0);
    /* Before a handshake, a call is a usage error */
    CHECK_STATUS(lantern_client_sections(other, &sections, &error), LANTERN_ERROR_USAGE);
    lantern_client_free(other);

    /* A configuration the protocol does not allow */
    config.origin = "http://shelf.example.org";
    CHECK_STATUS(lantern_client_create(&config, &other, &error), LANTERN_ERROR_USAGE);
    CHECK(other == NULL);
    fixture_close(&f);
}

static int deprecations;
static void on_deprecation(void* user, lantern_str url, lantern_str deprecation, lantern_str sunset)
{
    (void)user;
    ++deprecations;
    CHECK(strstr(url.data, "/sections") != NULL);
    CHECK(STR_EQ(deprecation, "@1793318400"));
    CHECK(STR_EQ(sunset, "Sun, 01 Nov 2026 00:00:00 GMT"));
}

static void deprecations_and_unoffered_families(void)
{
    fixture f;
    memset(&f, 0, sizeof(f));
    fake_init(&f.server, ORIGIN);
    /* The example's handshake: no requests, no admin */
    fake_add(&f.server, "GET", "/.well-known/lantern", 200, example(&f, "handshake.json"));
    fake_route* old
        = fake_add(&f.server, "GET", "/api/lantern/v1/sections", 200, example(&f, "sections.json"));
    fake_header(old, "Deprecation", "@1793318400");
    fake_header(old, "Sunset", "Sun, 01 Nov 2026 00:00:00 GMT");
    f.transport                             = fake_transport(&f.server, NULL);
    lantern_deprecation_callbacks callbacks = LANTERN_INIT(lantern_deprecation_callbacks);
    callbacks.deprecated                    = on_deprecation;
    lantern_deprecation_log* log            = NULL;
    REQUIRE_STATUS(lantern_deprecation_log_create(&callbacks, NULL, &log, NULL), LANTERN_OK);
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = ORIGIN;
    config.user_agent            = "LanternCTests/0.4";
    config.transport             = f.transport;
    config.deprecations          = log;
    REQUIRE_STATUS(lantern_client_create(&config, &f.client, NULL), LANTERN_OK);
    REQUIRE_STATUS(lantern_client_handshake(f.client, &f.handshake, NULL), LANTERN_OK);
    lantern_sections* sections = NULL;
    deprecations               = 0;
    REQUIRE_STATUS(lantern_client_sections(f.client, &sections, NULL), LANTERN_OK);
    CHECK(deprecations == 1);
    lantern_sections_free(sections);
    lantern_title_requests* requests = NULL;
    lantern_error error              = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_client_requests(f.client, NULL, &requests, &error), LANTERN_ERROR_UNSUPPORTED);
    fixture_close(&f);
    lantern_deprecation_log_free(log);
}

/* A credential store in memory, as an app's keychain would be. */
typedef struct memory_store
{
    char uid[64];
    char token[128];
    bool has_key;
    uint8_t seed[32];
    int stores;
    int erases;
} memory_store;

static lantern_status store_load(void* user, lantern_str uid, lantern_credentials_sink* sink)
{
    memory_store* store = user;
    if (store->stores == 0 || strcmp(store->uid, uid.data) != 0)
        return LANTERN_OK;
    lantern_credentials kept = LANTERN_INIT(lantern_credentials);
    kept.token.data          = store->token;
    kept.token.size          = strlen(store->token);
    kept.has_key             = store->has_key;
    memcpy(kept.key_seed, store->seed, 32);
    return lantern_credentials_sink_set(sink, &kept);
}

static lantern_status store_store(void* user, lantern_str uid, const lantern_credentials* credentials)
{
    memory_store* store = user;
    snprintf(store->uid, sizeof(store->uid), "%s", uid.data);
    snprintf(store->token, sizeof(store->token), "%s", credentials->token.data);
    store->has_key = credentials->has_key;
    memcpy(store->seed, credentials->key_seed, 32);
    ++store->stores;
    return LANTERN_OK;
}

static lantern_status store_erase(void* user, lantern_str uid)
{
    (void)uid;
    memory_store* store = user;
    ++store->erases;
    store->stores = 0;
    return LANTERN_OK;
}

static lantern_credential_store* make_store(memory_store* memory)
{
    memset(memory, 0, sizeof(*memory));
    lantern_credential_callbacks callbacks = LANTERN_INIT(lantern_credential_callbacks);
    callbacks.user                         = memory;
    callbacks.load                         = store_load;
    callbacks.store                        = store_store;
    callbacks.erase                        = store_erase;
    lantern_credential_store* store        = NULL;
    lantern_credential_store_create(&callbacks, NULL, &store, NULL);
    return store;
}

static void pairing_with_a_key(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_server* s = &f.server;
    fake_add(s, "POST", "/api/lantern/v1/pairing", 201, example(&f, "pairing-code.json"));
    fake_route* waiting = fake_add(s, "GET", "/api/lantern/v1/pairing/p_4Fh2", 202, NULL);
    waiting->times      = 1;
    fake_add(s, "GET", "/api/lantern/v1/pairing/p_4Fh2", 200, example(&f, "pairing-token.json"));
    fake_add(s, "GET", "/api/lantern/v1/sections", 200, example(&f, "sections.json"));
    memory_store memory;
    lantern_credential_store* store = make_store(&memory);
    REQUIRE(store != NULL);
    lantern_error error = LANTERN_INIT(lantern_error);

    const char* const scopes[]      = { "library", "saves" };
    lantern_pairing_options options = LANTERN_INIT(lantern_pairing_options);
    options.device                  = "Lea's Switch";
    options.scopes                  = scopes;
    options.scope_count             = 2;
    lantern_pairing* pairing        = NULL;
    REQUIRE_CALL(lantern_client_start_pairing(f.client, &options, &pairing, &error), LANTERN_OK, &error);
    CHECK(strstr(s->last_body, "\"device\":\"Lea's Switch\"") != NULL);
    CHECK(strstr(s->last_body, "\"alg\":\"ed25519\"") != NULL);
    const lantern_pairing_code* code = lantern_pairing_get_code(pairing);
    CHECK(STR_EQ(lantern_pairing_code_get_code(code), "KQ4M-7TXD"));
    CHECK(lantern_is_pairing_code(lantern_pairing_code_get_code(code).data));
    CHECK(lantern_pairing_get_wait(pairing) == 5);
    CHECK(STR_EQ(lantern_pairing_get_fingerprint(pairing), "")); /* no trust given */
    uint8_t spki[32];
    CHECK(!lantern_pairing_get_spki(pairing, spki));
    const lantern_device_key* key = lantern_pairing_get_key(pairing);
    REQUIRE(key != NULL);

    lantern_poll_state state = LANTERN_POLL_PAIRED;
    REQUIRE_CALL(lantern_client_poll_pairing(f.client, pairing, store, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_WAITING);
    /* The poll is signed by the pairing's key, without a token */
    char value[512];
    CHECK(fake_last_header(s, "Signature-Input", value, sizeof(value)) != NULL);
    CHECK(fake_last_header(s, "Authorization", value, sizeof(value)) == NULL);
    REQUIRE_CALL(lantern_client_poll_pairing(f.client, pairing, store, &state, &error), LANTERN_OK, &error);
    CHECK(state == LANTERN_POLL_PAIRED);
    CHECK(lantern_client_has_token(f.client));
    CHECK(memory.stores == 1);
    CHECK(memory.has_key);
    CHECK(strcmp(memory.uid, "6f1c2a8e-4b7d-4e2a-9c31-8d5e2f0a7b14") == 0);
    CHECK(strcmp(memory.token, "et_c8V1nQ0xYb") == 0);
    uint8_t seed[32];
    lantern_device_key_seed(key, seed);
    CHECK(memcmp(seed, memory.seed, 32) == 0);
    const lantern_device_key* bound = lantern_client_device_key(f.client);
    REQUIRE(bound != NULL);
    char keyid[44];
    char pairing_keyid[44];
    lantern_device_key_keyid(bound, keyid);
    lantern_device_key_keyid(key, pairing_keyid);
    CHECK(strcmp(keyid, pairing_keyid) == 0);

    /* Every request is signed now, with the token */
    lantern_sections* sections = NULL;
    REQUIRE_CALL(lantern_client_sections(f.client, &sections, &error), LANTERN_OK, &error);
    CHECK(fake_last_header(s, "Authorization", value, sizeof(value)) != NULL
        && strcmp(value, "Bearer et_c8V1nQ0xYb") == 0);
    CHECK(
        fake_last_header(s, "Signature-Input", value, sizeof(value)) != NULL && strstr(value, keyid) != NULL);
    lantern_sections_free(sections);
    lantern_pairing_free(pairing);

    /* Another client signs in from the store */
    lantern_client_config config = LANTERN_INIT(lantern_client_config);
    config.origin                = ORIGIN;
    config.user_agent            = "LanternCTests/0.4";
    config.transport             = f.transport;
    config.random                = f.random;
    lantern_client* later        = NULL;
    REQUIRE_STATUS(lantern_client_create(&config, &later, NULL), LANTERN_OK);
    lantern_handshake* shake = NULL;
    REQUIRE_STATUS(lantern_client_handshake(later, &shake, NULL), LANTERN_OK);
    bool signed_in = false;
    REQUIRE_CALL(lantern_client_sign_in(later, store, &signed_in, &error), LANTERN_OK, &error);
    CHECK(signed_in);
    CHECK(lantern_client_has_token(later));
    lantern_device_key_keyid(lantern_client_device_key(later), pairing_keyid);
    CHECK(strcmp(keyid, pairing_keyid) == 0);
    REQUIRE_CALL(lantern_client_forget(later, store, &error), LANTERN_OK, &error);
    CHECK(memory.erases == 1);
    CHECK(!lantern_client_has_token(later));
    lantern_client_clear_token(f.client);
    CHECK(!lantern_client_has_token(f.client));
    lantern_handshake_free(shake);
    lantern_client_free(later);
    lantern_credential_store_free(store);
    fixture_close(&f);
}

static void credentials_set_by_hand(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    fake_add(&f.server, "GET", "/api/lantern/v1/sections", 200, example(&f, "sections.json"));
    uint8_t seed[32];
    REQUIRE(hex_to_bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32));
    lantern_device_key* key = NULL;
    REQUIRE_STATUS(lantern_device_key_from_seed(seed, NULL, &key, NULL), LANTERN_OK);
    lantern_error error = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_set_credentials(f.client, "et_c8V1nQ0xYb", key, &error), LANTERN_OK, &error);
    lantern_device_key_free(key); /* copied by the client */
    lantern_sections* sections = NULL;
    REQUIRE_CALL(lantern_client_sections(f.client, &sections, &error), LANTERN_OK, &error);
    char value[512];
    CHECK(fake_last_header(&f.server, "Signature-Input", value, sizeof(value)) != NULL
        && strstr(value, "keyid=\"If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk\"") != NULL);
    lantern_sections_free(sections);
    CHECK_CALL(lantern_client_set_bearer_token(f.client, "et_bearer0nly", &error), LANTERN_OK, &error);
    CHECK(lantern_client_device_key(f.client) == NULL);
    CHECK_STATUS(lantern_client_set_bearer_token(f.client, "not a token\n", &error), LANTERN_ERROR_USAGE);
    CHECK(lantern_client_clock_offset(f.client) == 0);
    fixture_close(&f);
}

/* A file's bytes, its listing's digest, and a server that cuts the first answer. */
static void downloads_checked_and_resumed(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    static char file[6000];
    for (size_t i = 0; i < sizeof(file); ++i)
        file[i] = (char)('a' + (char)(i % 26));
    lantern_download_target target = LANTERN_INIT(lantern_download_target);
    target.url                     = "/api/lantern/v1/files/f_1";
    target.size                    = sizeof(file);
    lantern_sha256((const uint8_t*)file, sizeof(file), target.sha256);
    char digest_field[55];
    lantern_format_digest_field(target.sha256, digest_field);

    fake_route* cut = fake_add(&f.server, "GET", "/api/lantern/v1/files/f_1", 200, NULL);
    cut->body       = file;
    cut->body_size  = sizeof(file);
    cut->cut_after  = 2500;
    cut->times      = 1;
    fake_header(cut, "Repr-Digest", digest_field);
    fake_header(cut, "ETag", "\"v1\"");
    fake_route* rest = fake_add(&f.server, "GET", "/api/lantern/v1/files/f_1", 206, NULL);
    rest->body       = file + 2500;
    rest->body_size  = sizeof(file) - 2500;
    rest->times      = 1;
    fake_header(rest, "Repr-Digest", digest_field);
    fake_header(rest, "Content-Range", "bytes 2500-5999/6000");
    fake_header(rest, "ETag", "\"v1\"");

    memory_sink bytes;
    lantern_download_sink* sink   = memory_sink_make(&bytes);
    lantern_download_state* state = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &state, NULL), LANTERN_OK);
    lantern_error error = LANTERN_INIT(lantern_error);
    CHECK_STATUS(lantern_client_download(f.client, &target, state, sink, &error), LANTERN_ERROR_TRANSPORT);
    CHECK(lantern_download_state_received(state) == 2500);

    /* Saved with the partial file, then taken up by a new state */
    lantern_string* saved = NULL;
    REQUIRE_CALL(lantern_download_state_save(state, &saved, &error), LANTERN_OK, &error);
    CHECK(strstr(lantern_string_view(saved).data, "\"schema\":1") != NULL);
    lantern_download_state* resumed = NULL;
    REQUIRE_STATUS(lantern_download_state_create(NULL, &resumed, NULL), LANTERN_OK);
    REQUIRE_CALL(lantern_download_state_load(
                     resumed, lantern_string_view(saved).data, lantern_string_view(saved).size, &error),
        LANTERN_OK, &error);
    CHECK(lantern_download_state_received(resumed) == 2500);
    REQUIRE_CALL(lantern_client_download(f.client, &target, resumed, sink, &error), LANTERN_OK, &error);
    char value[64];
    CHECK(fake_last_header(&f.server, "Range", value, sizeof(value)) != NULL
        && strcmp(value, "bytes=2500-") == 0);
    CHECK(fake_last_header(&f.server, "If-Range", value, sizeof(value)) != NULL
        && strcmp(value, "\"v1\"") == 0);
    CHECK(bytes.size == sizeof(file));
    CHECK(memcmp(bytes.bytes, file, sizeof(file)) == 0);

    /* The listing's digest is not this file's: refused, and the state starts over */
    fake_route* whole = fake_add(&f.server, "GET", "/api/lantern/v1/files/f_1", 200, NULL);
    whole->body       = file;
    whole->body_size  = sizeof(file);
    fake_header(whole, "Repr-Digest", digest_field);
    lantern_download_state_reset(state);
    memory_sink_clear(&bytes);
    target.sha256[0] ^= 1U;
    CHECK_STATUS(lantern_client_download(f.client, &target, state, sink, &error), LANTERN_ERROR_INTEGRITY);
    CHECK(lantern_download_state_received(state) == 0);

    lantern_string_free(saved);
    lantern_download_state_free(state);
    lantern_download_state_free(resumed);
    lantern_download_sink_free(sink);
    memory_sink_clear(&bytes);
    fixture_close(&f);
}

static void a_cheat_sets_text(void)
{
    fixture f;
    if (!fixture_open(&f))
    {
        fixture_close(&f);
        REQUIRE(false);
    }
    const char* text = "[Endless lamp oil]\n04000000 00ABCDEF 00000063\n";
    uint8_t digest[32];
    lantern_sha256((const uint8_t*)text, strlen(text), digest);
    char hex[65];
    lantern_digest_to_hex(digest, hex);
    char document[512];
    snprintf(document, sizeof(document),
        "{\"schema\":1,\"id\":\"cs_1\",\"platform\":\"switch\",\"title_id\":\"0100ABCD00010000\","
        "\"build_id\":\"4A1B2C3D4E5F6071\",\"source\":\"Lantern tests\",\"updated\":\"2026-10-30T07:30:00Z\","
        "\"size\":%u,\"sha256\":\"%s\"}",
        (unsigned)strlen(text), hex);
    lantern_cheat_set* set = NULL;
    REQUIRE_STATUS(lantern_read_cheat_set(document, strlen(document), NULL, NULL, &set, NULL), LANTERN_OK);
    char field[55];
    lantern_format_digest_field(digest, field);
    fake_route* route = fake_add(&f.server, "GET", "/api/lantern/v1/cheats/cs_1", 200, text);
    fake_header(route, "Repr-Digest", field);
    lantern_string* got = NULL;
    lantern_error error = LANTERN_INIT(lantern_error);
    REQUIRE_CALL(lantern_client_cheat_text(f.client, set, &got, &error), LANTERN_OK, &error);
    CHECK(STR_EQ(lantern_string_view(got), text));
    lantern_string_free(got);
    lantern_cheat_set_free(set);
    fixture_close(&f);
}

const test_case client_tests[] = {
    { "client: the handshake and the families", handshake_and_families },
    { "client: the library, its cursors, missing, changes, titles", library_calls },
    { "client: homebrew, cheats, saves and requests", homebrew_cheats_saves_requests },
    { "client: the administration API", administration },
    { "client: a server's errors, problem+json, newer documents", errors_of_the_server },
    { "client: deprecations, and a family not offered", deprecations_and_unoffered_families },
    { "client: pairing with a key, a store, signed requests", pairing_with_a_key },
    { "client: credentials set by hand", credentials_set_by_hand },
    { "client: a download checked, cut, saved, resumed", downloads_checked_and_resumed },
    { "client: a cheat set's text", a_cheat_sets_text },
};
const size_t client_test_count = sizeof(client_tests) / sizeof(client_tests[0]);
