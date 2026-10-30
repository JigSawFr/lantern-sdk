// What the unit tests share: the specification's files, and a transport
// that answers from memory.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lantern/lantern.hpp>

namespace lantern::test
{

// A file of the specification (LANTERN_SPEC_DIR), whole; empty when missing.
inline std::string spec_file(std::string_view relative)
{
    std::string path = LANTERN_SPEC_DIR;
    path += '/';
    path += relative;
    std::string out;
    std::FILE* file = std::fopen(path.c_str(), "rb");
    if (file == nullptr)
        return out;
    char buffer[4096];
    std::size_t got = 0;
    while ((got = std::fread(buffer, 1, sizeof buffer, file)) > 0)
        out.append(buffer, got);
    std::fclose(file);
    return out;
}

struct Recorded
{
    std::string method;
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    [[nodiscard]] const std::string* header(std::string_view name) const
    {
        for (const auto& [key, value] : headers)
        {
            if (key == name)
                return &value;
        }
        return nullptr;
    }
};

struct Answer
{
    std::uint16_t status = 200;
    std::vector<std::pair<std::string, std::string>> headers { { "Content-Type", "application/json" } };
    std::string body;
    // Cut the body after this many bytes, then fail as a broken connection.
    std::size_t cut_after = std::string::npos;
};

// Answers each request with what `respond` returns, and records it.
class FakeTransport final : public Transport
{
  public:
    std::function<Answer(const Recorded&)> respond;
    std::vector<Recorded> requests;

    Result<void> send(const Request& request, ResponseHandler& handler) override
    {
        Recorded recorded;
        recorded.method = std::string(method_name(request.method));
        recorded.url    = std::string(request.url);
        for (const Header& header : request.headers)
            recorded.headers.emplace_back(std::string(header.name), std::string(header.value));
        recorded.body.assign(reinterpret_cast<const char*>(request.body.data()), request.body.size());
        requests.push_back(recorded);
        const Answer answer = respond(recorded);
        if (!handler.on_status(answer.status))
            return {};
        for (const auto& [name, value] : answer.headers)
        {
            if (!handler.on_header(name, value))
                return {};
        }
        const std::size_t length = std::min(answer.body.size(), answer.cut_after);
        // In chunks of 7 bytes, to exercise the streaming
        for (std::size_t at = 0; at < length; at += 7)
        {
            const std::string_view chunk
                = std::string_view(answer.body).substr(at, std::min<std::size_t>(7, length - at));
            if (!handler.on_body(std::as_bytes(std::span(chunk.data(), chunk.size()))))
                return {};
        }
        if (answer.cut_after != std::string::npos)
            return fail(Category::transport, "connection reset");
        return {};
    }
};

} // namespace lantern::test
