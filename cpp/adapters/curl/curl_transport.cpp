#include "curl_transport.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <curl/curl.h>

#include <lantern/url.hpp>

namespace lantern::curl
{

namespace
{

// What one request's callbacks share.
struct Transfer
{
    ResponseHandler* handler = nullptr;
    ServerTrust* trust       = nullptr;
    CURL* handle             = nullptr;
    bool informational       = false; // headers of a 1xx answer, skipped
    bool stopped             = false; // the handler asked to stop
    bool key_refused         = false;
};

bool ascii_digit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

std::string_view trim(std::string_view text) noexcept
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    while (!text.empty()
        && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' || text.back() == '\n'))
        text.remove_suffix(1);
    return text;
}

std::size_t on_header_line(char* data, std::size_t size, std::size_t count, void* user)
{
    auto& transfer              = *static_cast<Transfer*>(user);
    const std::size_t length    = size * count;
    const std::string_view line = trim(std::string_view(data, length));
    if (line.starts_with("HTTP/"))
    {
        // "HTTP/1.1 200 OK", "HTTP/2 200": each answer's status line, 1xx included
        const std::size_t space = line.find(' ');
        if (space == std::string_view::npos || line.size() < space + 4 || !ascii_digit(line[space + 1])
            || !ascii_digit(line[space + 2]) || !ascii_digit(line[space + 3]))
            return 0;
        const auto status = static_cast<std::uint16_t>(
            (line[space + 1] - '0') * 100 + (line[space + 2] - '0') * 10 + (line[space + 3] - '0'));
        transfer.informational = status < 200;
        if (transfer.informational)
            return length;
        if (!transfer.handler->on_status(status))
        {
            transfer.stopped = true;
            return 0;
        }
        return length;
    }
    if (transfer.informational || line.empty())
        return length;
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos)
        return length;
    if (!transfer.handler->on_header(line.substr(0, colon), trim(line.substr(colon + 1))))
    {
        transfer.stopped = true;
        return 0;
    }
    return length;
}

std::size_t on_body(char* data, std::size_t size, std::size_t count, void* user)
{
    auto& transfer           = *static_cast<Transfer*>(user);
    const std::size_t length = size * count;
    if (!transfer.handler->on_body(std::as_bytes(std::span(data, length))))
    {
        transfer.stopped = true;
        return 0;
    }
    return length;
}

// The leaf certificate, in PEM, as libcurl's certinfo gives it.
std::optional<std::string> leaf_pem(CURL* handle)
{
    const curl_certinfo* info = nullptr;
    if (curl_easy_getinfo(handle, CURLINFO_CERTINFO, &info) != CURLE_OK || info == nullptr
        || info->num_of_certs < 1)
        return std::nullopt;
    for (const curl_slist* item = info->certinfo[0]; item != nullptr; item = item->next)
    {
        const std::string_view entry = item->data;
        if (entry.starts_with("Cert:"))
            return std::string(entry.substr(5));
    }
    return std::nullopt;
}

// Before the request is sent, on the connection made: the server's key,
// through the app's ServerTrust (SPEC.md § 5.3).
int on_connected(
    void* user, char* /*primary_ip*/, char* /*local_ip*/, int /*primary_port*/, int /*local_port*/)
{
    auto& transfer = *static_cast<Transfer*>(user);
    if (transfer.trust == nullptr)
        return CURL_PREREQFUNC_OK;
    long connects = 0;
    curl_easy_getinfo(transfer.handle, CURLINFO_NUM_CONNECTS, &connects);
    const auto pem = leaf_pem(transfer.handle);
    if (!pem)
    {
        // A connection kept from an earlier request was checked when it was
        // made (a change of trust opens a new one: send() sees to it);
        // anything else without a certificate is refused
        if (connects == 0)
            return CURL_PREREQFUNC_OK;
        transfer.key_refused = true;
        return CURL_PREREQFUNC_ABORT;
    }
    const auto der = pem_certificate(*pem);
    const auto spki
        = der ? certificate_spki(*der) : Result<std::span<const std::uint8_t>>(std::unexpected(der.error()));
    // With a pin, or before pairing, libcurl did not check the chain; with
    // the CA store, it did, and refused before this point if it failed
    const bool ca_verified = transfer.trust->mode() == ServerTrust::Mode::ca;
    if (!spki || !transfer.trust->accept(*spki, ca_verified))
    {
        transfer.key_refused = true;
        return CURL_PREREQFUNC_ABORT;
    }
    return CURL_PREREQFUNC_OK;
}

class HeaderList
{
  public:
    HeaderList()                             = default;
    HeaderList(const HeaderList&)            = delete;
    HeaderList& operator=(const HeaderList&) = delete;
    HeaderList(HeaderList&&)                 = delete;
    HeaderList& operator=(HeaderList&&)      = delete;
    ~HeaderList() { curl_slist_free_all(list_); }

    bool add(std::string_view line)
    {
        const std::string text(line);
        curl_slist* next = curl_slist_append(list_, text.c_str());
        if (next == nullptr)
            return false;
        list_ = next;
        return true;
    }
    [[nodiscard]] curl_slist* get() const noexcept { return list_; }

  private:
    curl_slist* list_ = nullptr;
};

bool clean(std::string_view text) noexcept
{
    return std::ranges::none_of(text, [](char c) { return c == '\r' || c == '\n' || c == '\0'; });
}

} // namespace

Result<CurlTransport> CurlTransport::create(const Options& options)
{
    CurlTransport transport;
    transport.handle_ = curl_easy_init();
    if (transport.handle_ == nullptr)
        return fail(Category::transport, "libcurl could not make a handle");
    transport.options_ = options;
    transport.ca_file_.assign(options.ca_file);
    transport.options_.ca_file = {};
    if (options.trust != nullptr)
        transport.trust_generation_ = options.trust->generation();
    return transport;
}

CurlTransport::CurlTransport(CurlTransport&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr))
    , options_(other.options_)
    , ca_file_(std::move(other.ca_file_))
    , trust_generation_(other.trust_generation_)
{
}

CurlTransport& CurlTransport::operator=(CurlTransport&& other) noexcept
{
    std::swap(handle_, other.handle_);
    options_          = other.options_;
    ca_file_          = std::move(other.ca_file_);
    trust_generation_ = other.trust_generation_;
    return *this;
}

CurlTransport::~CurlTransport()
{
    if (handle_ != nullptr)
        curl_easy_cleanup(static_cast<CURL*>(handle_));
}

Result<void> CurlTransport::send(const Request& request, ResponseHandler& handler)
{
    const auto url = split_url(request.url);
    if (!url)
        return std::unexpected(url.error());
    if (auto scheme = check_scheme(*url); !scheme)
        return scheme;
    CURL* handle = static_cast<CURL*>(handle_);
    curl_easy_reset(handle);

    HeaderList headers;
    for (const Header& header : request.headers)
    {
        if (!clean(header.name) || !clean(header.value) || header.name.empty() || header.name.contains(':'))
            return fail(Category::usage, "a header that would break the request");
        std::string line(header.name);
        line += ": ";
        line += header.value;
        if (!headers.add(line))
            return fail(Category::memory, "libcurl could not hold the headers");
    }
    // No 100-continue round trip, and no Content-Type of libcurl's own
    if (!headers.add("Expect:") || (request.body.empty() && !headers.add("Content-Type:")))
        return fail(Category::memory, "libcurl could not hold the headers");

    const std::string target(request.url);
    Transfer transfer;
    transfer.handler = &handler;
    transfer.trust   = options_.trust;
    transfer.handle  = handle;

    curl_easy_setopt(handle, CURLOPT_URL, target.c_str());
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, on_header_line);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, &transfer);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &transfer);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options_.connect_timeout.count()));
    curl_easy_setopt(handle, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(handle, CURLOPT_LOW_SPEED_TIME, static_cast<long>(options_.stall_timeout.count()));
    if (!ca_file_.empty())
        curl_easy_setopt(handle, CURLOPT_CAINFO, ca_file_.c_str());

    switch (request.method)
    {
        case Method::get:
            curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
            break;
        case Method::head:
            curl_easy_setopt(handle, CURLOPT_NOBODY, 1L);
            break;
        case Method::post:
        case Method::put:
        case Method::patch:
        case Method::delete_:
        {
            const std::string method(method_name(request.method));
            curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, method.c_str()); // copied too
            if (request.method != Method::delete_ || !request.body.empty())
            {
                curl_easy_setopt(
                    handle, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
                curl_easy_setopt(handle, CURLOPT_POSTFIELDS,
                    request.body.empty() ? "" : reinterpret_cast<const char*>(request.body.data()));
            }
            break;
        }
    }

    // The server's key (SPEC.md § 5.3)
    if (options_.trust != nullptr)
    {
        const ServerTrust::Mode mode = options_.trust->mode();
        const bool by_ca             = mode == ServerTrust::Mode::ca;
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, by_ca ? 1L : 0L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, by_ca ? 2L : 0L);
        curl_easy_setopt(handle, CURLOPT_CERTINFO, 1L);
        curl_easy_setopt(handle, CURLOPT_PREREQFUNCTION, on_connected);
        curl_easy_setopt(handle, CURLOPT_PREREQDATA, &transfer);
        // A connection made under another trust is not taken again
        if (options_.trust->generation() != trust_generation_)
        {
            curl_easy_setopt(handle, CURLOPT_FRESH_CONNECT, 1L);
            trust_generation_ = options_.trust->generation();
        }
    }

    const CURLcode code = curl_easy_perform(handle);
    if (transfer.key_refused)
        return fail(Category::refused,
            "the server's key is not the one pinned, or no CA vouches for it (SPEC.md 5.3)");
    if (transfer.stopped || code == CURLE_OK)
        return {};
    switch (code)
    {
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_SSL_CACERT_BADFILE:
            return fail(Category::refused,
                "no CA the client trusts vouches for the server's certificate (SPEC.md 2)");
        case CURLE_OPERATION_TIMEDOUT:
            return fail(Category::transport, "the server stopped answering (timed out)");
        default:
            return fail(Category::transport, curl_easy_strerror(code));
    }
}

} // namespace lantern::curl
