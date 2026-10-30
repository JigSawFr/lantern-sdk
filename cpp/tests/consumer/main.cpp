// Reads a handshake, and a document of a newer schema, as an app would.
#include <lantern/lantern.hpp>

int main()
{
    const auto handshake
        = lantern::read_handshake(R"({"schema":1,"uid":"6f1c2a8e-0000-4000-8000-000000000001",
        "name":"Living room shelf","base":"/api/lantern","versions":[1],"platforms":["switch"],
        "account":{"state":"anonymous","scopes":[]},"features":{"library":1,"pairing":1}})");
    if (!handshake || !*handshake || (*handshake)->name != "Living room shelf")
        return 1;
    const auto newer = lantern::read_handshake(R"({"schema":2})");
    if (!newer || *newer)
        return 2;
    return lantern::find_profile("switch") != nullptr ? 0 : 3;
}
