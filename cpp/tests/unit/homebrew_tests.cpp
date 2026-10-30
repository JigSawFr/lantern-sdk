#include <doctest.h>

#include <map>
#include <string>

#include "support.hpp"

using namespace lantern;
using lantern::test::spec_file;

namespace
{

Homebrew entry_of(std::string_view text)
{
    auto read = read_homebrew(text);
    REQUIRE(read);
    REQUIRE(*read);
    return std::move(**read);
}

// Whether a client refuses the entry somewhere between reading it and
// installing it (SPEC.md 8.2 to 8.6).
bool refused(std::string_view text)
{
    const auto read = read_homebrew(text);
    if (!read || !*read)
        return true;
    const Homebrew& entry = **read;
    const auto package    = pick_package(entry, "aarch64");
    if (!package)
        return true;
    if (!plan_install(entry, **package) || !check_port(entry) || !verify_package_signature(entry, **package))
        return true;
    return false;
}

// A manifest entry's JSON.
std::string file(std::string_view path,
    std::string_view sha = "cde0fb0dec1400c54a0f7e7eafa73624c53e4da258bbd34b3380a0defeba95c1", int size = 96)
{
    return R"({"path":")" + std::string(path) + R"(","sha256":")" + std::string(sha) + R"(","size":)"
        + std::to_string(size) + "}";
}

// An entry of `platform` whose package is a zip of `files`, its
// manifest_sha256 computed.
std::string zip_entry(std::string_view platform, std::string_view id, const std::vector<std::string>& files,
    std::string_view extra = "")
{
    std::string manifest = "[";
    for (std::size_t i = 0; i < files.size(); ++i)
        manifest += (i ? "," : "") + files[i];
    manifest += "]";
    // The canonical form, by the library itself, from a first reading
    const std::string draft = R"({"schema":1,"id":")" + std::string(id) + R"(","platform":")"
        + std::string(platform)
        + R"(","kind":"app","name":"Moss","version":"1","build":1,"package":{"format":"zip","file":"/f","size":1,"sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4","manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4","manifest":)"
        + manifest + "}" + std::string(extra) + "}";
    const Homebrew first = entry_of(draft);
    const auto hex       = to_hex(manifest_digest(first.package.manifest));
    std::string out      = draft;
    const std::string old
        = R"("manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4")";
    out.replace(
        out.find(old), old.size(), R"("manifest_sha256":")" + std::string(hex.data(), hex.size()) + "\"");
    return out;
}

} // namespace

TEST_CASE("homebrew: the specification's example installs, in the roots that need no consent")
{
    const Homebrew entry = entry_of(spec_file("examples/v1/homebrew.json"));
    const auto package   = pick_package(entry, "aarch64");
    REQUIRE(package);
    const auto plan = plan_install(entry, **package);
    REQUIRE(plan);
    CHECK(plan->placement == Placement::archive);
    CHECK(plan->files.size() == 2);
    CHECK(plan->consent_count == 0);
    CHECK(plan->files[1].path == "/switch/org.example.frostline/frostline.nro");
    CHECK(check_port(entry));
}

TEST_CASE("homebrew: the specification's invalid entries are refused, or read as SPEC.md says")
{
    // Read as the text says: an unknown genre is `other`, a condition that
    // cannot be read is a warning (requires_tests.cpp), `category` is gone
    const std::vector<std::string> tolerated { "category", "glibc-not-dotted", "gpu-empty", "gpu-unknown",
        "ram-as-text", "screen-form", "unknown-genre" };
    for (const char* name : { "arch-not-a-list", "category", "dotdot-path", "drive-path", "glibc-not-dotted",
             "gpu-empty", "gpu-unknown", "linux-single-file", "no-sha256", "packages-without-arch",
             "port-absolute-data", "port-accept-without-hash", "port-backslash-data", "port-dotdot-data-root",
             "port-dotdot-data", "port-dotdot-in-group", "port-drive-data", "port-relative-data-root",
             "port-without-port", "port-without-requires-data", "ram-as-text", "relative-path", "screen-form",
             "tag-too-long", "unc-path", "unknown-arch-format", "unknown-genre", "zip-without-manifest" })
    {
        CAPTURE(name);
        const std::string text = spec_file("examples/v1/invalid/homebrew." + std::string(name) + ".json");
        REQUIRE_FALSE(text.empty());
        const bool expected = std::find(tolerated.begin(), tolerated.end(), name) == tolerated.end();
        CHECK(refused(text) == expected);
    }
}

TEST_CASE("homebrew: a single file, where its profile puts it")
{
    // Paper Lamp, as the reference server serves it
    const std::string lamp = R"({"schema":1,"id":"org.example.paperlamp","platform":"switch","kind":"game",
        "name":"Paper Lamp","version":"0.9.2","build":902,"package":{"format":"nro","file":"/f","size":16664,
        "sha256":"b89d5785039159b12b51f4a6ffc0b31977e7861593c09093583ce71bdae9d991",
        "path":"/switch/org.example.paperlamp/org.example.paperlamp.nro",
        "manifest_sha256":"d575c77f3cf22a11d4db1441478108d2cd76bc219a10dddbd775f045ae1f139e"}})";
    const Homebrew entry   = entry_of(lamp);
    const auto plan        = plan_install(entry, entry.package);
    REQUIRE(plan);
    CHECK(plan->placement == Placement::single_file);
    REQUIRE(plan->files.size() == 1);
    CHECK(plan->files[0].size == 16664);
    CHECK(plan->consent_count == 0);

    // Elsewhere than /switch/<id>/<id>.nro
    std::string moved      = lamp;
    const std::string path = "/switch/org.example.paperlamp/org.example.paperlamp.nro";
    moved.replace(moved.find(path), path.size(), "/switch/org.example.paperlamp/lamp.nro");
    const Homebrew misplaced = entry_of(moved);
    const auto refused_plan  = plan_install(misplaced, misplaced.package);
    REQUIRE_FALSE(refused_plan);
    CHECK(refused_plan.error().category() == Category::refused);

    // A manifest_sha256 that is not the file's manifest of one
    std::string wrong = lamp;
    wrong.replace(wrong.find("d575c77f"), 8, "e575c77f");
    CHECK_FALSE(plan_install(entry_of(wrong), entry_of(wrong).package));
}

TEST_CASE("homebrew: roots that need consent, and those outside")
{
    // An overlay: a single file in /switch/.overlays/, with consent
    {
        const std::string text
            = R"({"schema":1,"id":"org.example.ember-overlay","platform":"switch","kind":"overlay",
            "name":"Ember Overlay","version":"1.2.0","build":120,"package":{"format":"ovl","file":"/f","size":256,
            "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4","path":"/switch/.overlays/ember.ovl",
            "manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"}})";
        Homebrew entry = entry_of(text);
        ManifestEntry single;
        single.path                   = entry.package.path;
        single.size                   = entry.package.size;
        single.sha256                 = entry.package.sha256;
        entry.package.manifest_sha256 = manifest_digest(std::span(&single, 1));
        const auto plan               = plan_install(entry, entry.package);
        REQUIRE(plan);
        CHECK(plan->consent_count == 1);
        CHECK(plan->files[0].needs_consent);
    }
    // A sysmodule in /atmosphere/: consent; the bootloader's folder: refused
    const auto with
        = [](std::vector<std::string> files) { return zip_entry("switch", "org.example.moss", files); };
    const Homebrew mixed  = entry_of(with({ file("/switch/org.example.moss/moss.nro"),
         file("/atmosphere/contents/0100000000001000/exefs.nsp") }));
    const auto mixed_plan = plan_install(mixed, mixed.package);
    REQUIRE(mixed_plan);
    CHECK(mixed_plan->consent_count == 1);
    CHECK_FALSE(mixed_plan->files[0].needs_consent);
    CHECK(mixed_plan->files[1].needs_consent);

    const Homebrew outside = entry_of(with({ file("/bootloader/hekate_ipl.ini") }));
    CHECK_FALSE(plan_install(outside, outside.package));
    const Homebrew other_id = entry_of(with({ file("/switch/org.example.other/x.nro") }));
    CHECK_FALSE(plan_install(other_id, other_id.package));

    // Two paths the same when case is ignored; a file under another
    const Homebrew twice
        = entry_of(with({ file("/switch/org.example.moss/A.txt"), file("/switch/org.example.moss/a.TXT") }));
    CHECK_FALSE(plan_install(twice, twice.package));
    const Homebrew nested
        = entry_of(with({ file("/switch/org.example.moss/data"), file("/switch/org.example.moss/data/x") }));
    CHECK_FALSE(plan_install(nested, nested.package));
    const Homebrew siblings = entry_of(
        with({ file("/switch/org.example.moss/data-x"), file("/switch/org.example.moss/data/x") }));
    CHECK(plan_install(siblings, siblings.package));
}

TEST_CASE("homebrew: the system's installer")
{
    const std::string apk = R"({"schema":1,"id":"org.example.mossremote","platform":"android","kind":"tool",
        "name":"Moss Remote","version":"3.0","build":30,"system_id":"org.example.mossremote","package":{"format":"apk",
        "file":"/f","size":300,"arch":["aarch64","armhf"],"manifest":[],
        "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4",
        "manifest_sha256":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}})";
    const Homebrew entry  = entry_of(apk);
    const auto plan       = plan_install(entry, entry.package);
    REQUIRE(plan);
    CHECK(plan->placement == Placement::system_installer);
    CHECK(plan->files.empty());
    CHECK_FALSE(plan->ask_before_installer);

    // An entry whose system_id another homebrew installed
    const std::array<InstalledSystemId, 1> mine {
        { { "org.example.mossremote", "org.example.mossremote" } }
    };
    CHECK(check_system_id(entry, mine));
    const std::array<InstalledSystemId, 1> theirs {
        { { "org.example.impostor", "org.example.mossremote" } }
    };
    const auto taken = check_system_id(entry, theirs);
    REQUIRE_FALSE(taken);
    CHECK(taken.error().category() == Category::refused);

    // A platform with no profile: nothing installed
    std::string ios = apk;
    ios.replace(ios.find("\"android\""), 9, "\"ios\"");
    const auto open = plan_install(entry_of(ios), entry_of(ios).package);
    REQUIRE_FALSE(open);
    CHECK(open.error().category() == Category::unsupported);
}

TEST_CASE("homebrew: the package for the device's architecture")
{
    // Harbor Lights for Linux, as the reference library builds it: arm,
    // x86_64 and riscv64 packages
    const auto package = [](std::string_view arch)
    {
        return R"({"format":"zip","file":"/f","size":1,"arch":[)" + std::string(arch)
            + R"(],"manifest":[],"sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4","manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"})";
    };
    const std::string harbor
        = R"({"schema":1,"id":"org.example.harborlights","platform":"linux","kind":"port",
        "name":"Harbor Lights","version":"2.1.0","build":20100,"package":)"
        + package(R"("aarch64","armhf")") + R"(,"packages":[)" + package(R"("x86_64")") + ","
        + package(R"("riscv64")") + "]}";
    const Homebrew entry = entry_of(harbor);
    CHECK(*pick_package(entry, "aarch64") == &entry.package);
    CHECK(*pick_package(entry, "armhf") == &entry.package);
    CHECK(*pick_package(entry, "x86_64") == &entry.packages[0]);
    CHECK(*pick_package(entry, "riscv64") == &entry.packages[1]);
    const auto none = pick_package(entry, "x86");
    REQUIRE_FALSE(none);
    CHECK(none.error().category() == Category::unsupported);

    // A package without arch runs on every architecture of its platform
    const std::string bytecode = R"({"schema":1,"id":"org.example.lanternlight-runtime","platform":"linux",
        "kind":"tool","name":"Runtime","version":"2","build":200,"package":{"format":"zip","file":"/f","size":1,
        "manifest":[],"sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4",
        "manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"},"packages":[)"
        + package(R"("x86_64")") + "]}";
    const Homebrew runtime = entry_of(bytecode);
    CHECK(*pick_package(runtime, "x86_64") == &runtime.packages[0]);
    CHECK(*pick_package(runtime, "riscv64") == &runtime.package);
    // A name of a later version, well formed: never this device's
    CHECK(*pick_package(runtime, "loongarch64") == &runtime.package);

    // A Switch package with an arch (the reference library's port-x86)
    const std::string switch_arch
        = R"({"schema":1,"id":"org.example.port-x86","platform":"switch","kind":"app",
        "name":"P","version":"1","build":1,"package":)"
        + package(R"("aarch64")") + "}";
    const auto one_arch = pick_package(entry_of(switch_arch), "aarch64");
    REQUIRE_FALSE(one_arch);
    CHECK(one_arch.error().category() == Category::refused);
}

TEST_CASE("homebrew: an update removes the files the new manifest no longer has")
{
    const Homebrew old_entry = entry_of(zip_entry("switch", "org.example.moss",
        { file("/switch/org.example.moss/moss.nro"), file("/switch/org.example.moss/old.dat") }));
    const Homebrew new_entry = entry_of(zip_entry("switch", "org.example.moss",
        { file("/switch/org.example.moss/moss.nro"), file("/switch/org.example.moss/new.dat") }));
    const auto removed       = files_to_remove(old_entry.package.manifest, new_entry.package.manifest);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0] == "/switch/org.example.moss/old.dat");
}

namespace
{

// The reference library's port (spec/tests/library.py): frost.pak 1.0, 1.1
// and the 1.1 Gold edition, known by SHA-256, or SHA-1 alone.
std::string repeat(std::string_view text, int times)
{
    std::string out;
    for (int i = 0; i < times; ++i)
        out += text;
    return out;
}

const std::string frost_10   = repeat("frost.pak 1.0 ", 64);
const std::string frost_11   = repeat("frost.pak 1.1 ", 64);
const std::string frost_gold = repeat("frost.pak 1.1 gold ", 48);

std::string sha(std::string_view text)
{
    const auto hex = to_hex(Sha256::of(text));
    return { hex.data(), hex.size() };
}

std::string port_entry(std::string_view data_root, std::string_view requires_data)
{
    return R"({"schema":1,"id":"org.example.frostline-port","platform":"switch","kind":"port","name":"Frostline Port",
        "version":"0.3.0","build":300,"package":{"format":"zip","file":"/f","size":1,"manifest":[],
        "sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4",
        "manifest_sha256":"fa17de19989d9c203230b0689ac3bc22537d25f22013d02a104fbcff494733d4"},
        "port":{"original":{"name":"Frostline Tales","year":2004},"engine":{"name":"Lanternlight"},
        "data_root":")"
        + std::string(data_root) + R"(","assets":"user_owned","requires_data":)" + std::string(requires_data)
        + "}}";
}

std::string frostline_data()
{
    return R"([{"path":"data/frost.pak","size":)" + std::to_string(frost_10.size()) + R"(,"accept":[
        {"label":"1.0","sha256":")"
        + sha(frost_10) + R"("},{"label":"1.1","sha256":")" + sha(frost_11) + R"("},
        {"label":"1.1 Gold edition","sha1":"0123456789abcdef0123456789abcdef01234567"}],
        "hint":"frost.pak, in the folder Frostline Tales is installed in."},
      {"one_of":[[{"path":"music/full.pak","hint":"From the soundtrack edition."},
                  {"path":"music/full.idx","hint":"Next to full.pak."}],
                 [{"path":"music/demo.pak","hint":"From the free demo."}]]},
      {"path":"Extras/Bonus Maps.pak","optional":true,"hint":"Bonus Maps.pak, from the soundtrack edition."}])";
}

class SdCard final : public DataProbe
{
  public:
    std::map<std::string, std::string> files;

    Result<std::optional<std::uint64_t>> size(std::string_view path) override
    {
        const auto found = files.find(std::string(path));
        if (found == files.end())
            return std::optional<std::uint64_t> {};
        return std::optional<std::uint64_t>(found->second.size());
    }
    Result<Digest> sha256(std::string_view path) override { return Sha256::of(files.at(std::string(path))); }
};

} // namespace

TEST_CASE("ports: SPEC.md 8.6's checks")
{
    CHECK(check_port(entry_of(port_entry("/switch/frostline/", frostline_data()))));
    // The reference library's ports a client refuses
    const std::pair<std::string, std::string> refused_ports[] = {
        { "/atmosphere/frost/", frostline_data() }, // outside the areas
        { "/switch/", frostline_data() }, // the area itself
        { "switch/frostline/", frostline_data() }, // relative
        { "/switch/frostline", frostline_data() }, // not a folder
        { "/switch/../atmosphere/", frostline_data() }, // an escape
        { "/switch/frostline/", R"([{"path":"../../atmosphere/contents/x","hint":"Nowhere."}])" },
        { "/switch/frostline/", R"([{"path":"/switch/frostline/frost.pak","hint":"Nowhere."}])" },
        { "/switch/frostline/", R"([{"path":"C:/frost.pak","hint":"Nowhere."}])" },
        { "/switch/frostline/", R"([{"path":"data\\frost.pak","hint":"Nowhere."}])" },
        { "/switch/frostline/", R"([{"one_of":[[{"path":"music/full.pak","hint":"Alone."}]]}])" },
        { "/switch/frostline/", R"([{"one_of":[[{"path":"a","hint":"x"}],[{"path":"../b","hint":"y"}]]}])" },
        { "/switch/frostline/", R"([{"path":"a","hint":"x","accept":[{"label":"no hash"}]}])" },
        { "/switch/frostline/", R"([{"path":"a","hint":""}])" },
    };
    for (const auto& [root, data] : refused_ports)
    {
        CAPTURE(root);
        CAPTURE(data);
        const auto checked = check_port(entry_of(port_entry(root, data)));
        REQUIRE_FALSE(checked);
        CHECK(checked.error().category() == Category::refused);
    }
    // Not a port: nothing to check
    CHECK(check_port(entry_of(spec_file("examples/v1/homebrew.json"))));
}

TEST_CASE("ports: what the device has before the port launches")
{
    const Homebrew entry = entry_of(port_entry("/switch/frostline/", frostline_data()));
    REQUIRE(entry.port);
    SdCard sd;

    // Nothing there: frost.pak and a music alternative missing
    auto check = launch_check(*entry.port, sd);
    REQUIRE(check);
    CHECK_FALSE(check->ready);
    REQUIRE(check->issues.size() == 4);
    CHECK(check->issues[0].path == "data/frost.pak");
    CHECK(check->issues[0].hint == "frost.pak, in the folder Frostline Tales is installed in.");
    CHECK(check->issues[0].issue == DataIssue::missing);
    CHECK(check->issues[1].in_group);

    // frost.pak 1.1 and the demo's music: ready
    sd.files["/switch/frostline/data/frost.pak"] = frost_11;
    sd.files["/switch/frostline/music/demo.pak"] = "demo";
    check                                        = launch_check(*entry.port, sd);
    REQUIRE(check);
    CHECK(check->ready);
    CHECK_FALSE(check->unverified);
    CHECK(check->issues.empty());

    // A version the port does not know, of the right size
    std::string modded                           = frost_10;
    modded[0]                                    = 'F';
    sd.files["/switch/frostline/data/frost.pak"] = modded;
    check                                        = launch_check(*entry.port, sd);
    REQUIRE(check);
    // Taken on presence: the Gold edition is known by SHA-1 alone
    CHECK(check->ready);
    CHECK(check->unverified);

    // The wrong size
    sd.files["/switch/frostline/data/frost.pak"] = "short";
    check                                        = launch_check(*entry.port, sd);
    REQUIRE(check);
    CHECK_FALSE(check->ready);
    CHECK(check->issues[0].issue == DataIssue::wrong_size);
}

TEST_CASE("ports: a version known by SHA-256 alone, and an unknown one")
{
    const std::string data = R"([{"path":"HARBOR.PAK","accept":[{"label":"1.0","sha256":")"
        + sha("HARBOR 1.0") + R"("}],"hint":"HARBOR.PAK, in the folder where Harbor Lights is installed."}])";
    const Homebrew entry = entry_of(port_entry("/switch/harbor/", data));
    SdCard sd;
    sd.files["/switch/harbor/HARBOR.PAK"] = "HARBOR 2.0";
    auto check                            = launch_check(*entry.port, sd);
    REQUIRE(check);
    CHECK_FALSE(check->ready);
    REQUIRE(check->issues.size() == 1);
    CHECK(check->issues[0].issue == DataIssue::unknown_version);
    sd.files["/switch/harbor/HARBOR.PAK"] = "HARBOR 1.0";
    CHECK(launch_check(*entry.port, sd)->ready);
}
