#include "mbedtls_transport.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

#include <lantern/url.hpp>

#include "http1.hpp"
#include "tcp.hpp"

#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#if MBEDTLS_VERSION_MAJOR >= 3
#include <psa/crypto.h>
#endif

#include <poll.h>
#include <sys/socket.h>
#include <cerrno>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace lantern::mbedtls
{

namespace
{

// mbedTLS's randomness: the app's source.
int random_bytes(void* source, unsigned char* out, std::size_t size)
{
    auto* random = static_cast<RandomSource*>(source);
    return random->fill(std::span(out, size)) ? 0 : -1;
}

// What the verification callback learns of one handshake.
struct Verification
{
    ServerTrust* trust  = nullptr;
    std::uint32_t chain = 0; // flags of the certificates above the leaf
    bool leaf_seen      = false;
    bool accepted       = false;
};

// Called for each certificate of the chain, the root first and the leaf
// (depth 0) last: the leaf's SPKI goes to the ServerTrust (SPEC.md § 5.3).
int verify(void* data, mbedtls_x509_crt* certificate, int depth, std::uint32_t* flags)
{
    auto& verification = *static_cast<Verification*>(data);
    if (depth != 0)
    {
        verification.chain |= *flags;
        if (verification.trust != nullptr && verification.trust->mode() != ServerTrust::Mode::ca)
            *flags = 0; // the pin decides, not the chain
        return 0;
    }
    verification.leaf_seen = true;
    const bool ca_verified = (verification.chain | *flags) == 0;
    if (verification.trust == nullptr)
    {
        verification.accepted = ca_verified;
        return 0;
    }
    const auto spki
        = certificate_spki(std::span<const std::uint8_t>(certificate->raw.p, certificate->raw.len));
    verification.accepted = spki && verification.trust->accept(*spki, ca_verified);
    if (verification.trust->mode() == ServerTrust::Mode::ca)
        return 0; // mbedTLS's own flags stand
    *flags = verification.accepted ? 0U : static_cast<std::uint32_t>(MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    return 0;
}

// The socket under mbedTLS, with a timeout on each read.
struct Bio
{
    http1::TcpSocket* socket = nullptr;
};

bool would_block(int error) noexcept
{
#if EAGAIN == EWOULDBLOCK
    return error == EAGAIN;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

int bio_send(void* context, const unsigned char* data, std::size_t size)
{
    auto& bio       = *static_cast<Bio*>(context);
    const auto sent = ::send(bio.socket->fd(), data, size, MSG_NOSIGNAL);
    if (sent < 0)
        return would_block(errno) ? MBEDTLS_ERR_SSL_WANT_WRITE : -1;
    return static_cast<int>(sent);
}

// mbedTLS's read, within the configuration's read timeout.
int bio_receive(void* context, unsigned char* data, std::size_t size, std::uint32_t timeout_ms)
{
    auto& bio = *static_cast<Bio*>(context);
    pollfd wanted {};
    wanted.fd       = bio.socket->fd();
    wanted.events   = POLLIN;
    const int ready = ::poll(&wanted, 1, timeout_ms == 0 ? -1 : static_cast<int>(timeout_ms));
    if (ready == 0)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    if (ready < 0)
        return -1;
    const auto got = ::recv(bio.socket->fd(), data, size, 0);
    if (got < 0)
        return -1;
    return static_cast<int>(got);
}

// The TLS session as an http1::Stream.
class TlsStream final : public http1::Stream
{
  public:
    explicit TlsStream(mbedtls_ssl_context& ssl) noexcept
        : ssl_(ssl)
    {
    }

    Result<void> write(std::span<const char> bytes) override
    {
        while (!bytes.empty())
        {
            const int sent = mbedtls_ssl_write(
                &ssl_, reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
            if (sent == MBEDTLS_ERR_SSL_WANT_READ || sent == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            if (sent <= 0)
                return fail(Category::transport, "the TLS connection broke while sending");
            bytes = bytes.subspan(static_cast<std::size_t>(sent));
        }
        return {};
    }

    Result<std::size_t> read(std::span<char> buffer) override
    {
        for (;;)
        {
            const int got
                = mbedtls_ssl_read(&ssl_, reinterpret_cast<unsigned char*>(buffer.data()), buffer.size());
            if (got == MBEDTLS_ERR_SSL_WANT_READ || got == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            if (got == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
                continue;
#endif
            if (got == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || got == 0)
                return std::size_t { 0 };
            if (got < 0)
                return fail(Category::transport, "the TLS connection broke, or timed out");
            return static_cast<std::size_t>(got);
        }
    }

  private:
    mbedtls_ssl_context& ssl_;
};

class Session
{
  public:
    Session() { mbedtls_ssl_init(&ssl); }
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&)                 = delete;
    Session& operator=(Session&&)      = delete;
    ~Session() { mbedtls_ssl_free(&ssl); }
    mbedtls_ssl_context ssl {};
};

} // namespace

struct MbedTlsTransport::State
{
    Options options;
    std::string ca_pem; // mbedTLS parses a PEM with its final NUL
    mbedtls_ssl_config config {};
    mbedtls_x509_crt ca {};

    State() noexcept
    {
        mbedtls_ssl_config_init(&config);
        mbedtls_x509_crt_init(&ca);
    }
    State(const State&)            = delete;
    State& operator=(const State&) = delete;
    State(State&&)                 = delete;
    State& operator=(State&&)      = delete;
    ~State()
    {
        mbedtls_x509_crt_free(&ca);
        mbedtls_ssl_config_free(&config);
    }
};

Result<MbedTlsTransport> MbedTlsTransport::create(const Options& options)
{
    if (options.random == nullptr)
        return fail(Category::usage, "the mbedTLS adapter needs a RandomSource");
#if MBEDTLS_VERSION_MAJOR >= 3
    if (psa_crypto_init() != PSA_SUCCESS)
        return fail(Category::transport, "mbedTLS's PSA crypto did not start");
#endif
    MbedTlsTransport transport;
    transport.state_ = std::make_unique<State>();
    State& state     = *transport.state_;
    state.options    = options;
    state.ca_pem.assign(options.ca_pem);
    if (!state.ca_pem.empty()
        && mbedtls_x509_crt_parse(&state.ca, reinterpret_cast<const unsigned char*>(state.ca_pem.c_str()),
               state.ca_pem.size() + 1)
            != 0)
        return fail(Category::usage, "the CA bundle is not PEM certificates");
    if (mbedtls_ssl_config_defaults(
            &state.config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)
        != 0)
        return fail(Category::transport, "mbedTLS's defaults could not be set");
    // REQUIRED: a certificate the callback leaves flagged ends the handshake.
    // The CA chain is set even when empty: without one, mbedTLS refuses
    // before asking the callback
    mbedtls_ssl_conf_authmode(&state.config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&state.config, &state.ca, nullptr);
    mbedtls_ssl_conf_rng(&state.config, random_bytes, options.random);
    mbedtls_ssl_conf_read_timeout(&state.config, static_cast<std::uint32_t>(options.timeout.count()));
    return transport;
}

MbedTlsTransport::MbedTlsTransport(MbedTlsTransport&& other) noexcept            = default;
MbedTlsTransport& MbedTlsTransport::operator=(MbedTlsTransport&& other) noexcept = default;
MbedTlsTransport::~MbedTlsTransport()                                            = default;

Result<void> MbedTlsTransport::send(const Request& request, ResponseHandler& handler)
{
    const auto url = split_url(request.url);
    if (!url)
        return std::unexpected(url.error());
    if (url->scheme != "https")
        return fail(Category::usage, "the mbedTLS adapter speaks HTTPS only");
    const State& state = *state_;
    auto socket        = http1::TcpSocket::connect(url->host, url->port, state.options.timeout, false);
    if (!socket)
        return std::unexpected(socket.error());

    Verification verification;
    verification.trust = state.options.trust;
    Bio bio { &*socket };
    Session session;
    if (mbedtls_ssl_setup(&session.ssl, &state.config) != 0)
        return fail(Category::transport, "mbedTLS could not set up a session");
    // The name a certificate is checked against (an address too, with 3.x)
    const std::string host(url->host);
    if (mbedtls_ssl_set_hostname(&session.ssl, host.c_str()) != 0)
        return fail(Category::transport, "mbedTLS refused the server's name");
    mbedtls_ssl_set_verify(&session.ssl, verify, &verification);
    mbedtls_ssl_set_bio(&session.ssl, &bio, bio_send, nullptr, bio_receive);
    int done = 0;
    while ((done = mbedtls_ssl_handshake(&session.ssl)) != 0)
    {
        if (done == MBEDTLS_ERR_SSL_WANT_READ || done == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (verification.leaf_seen && !verification.accepted)
            return fail(Category::refused,
                "the server's key is not the one pinned, or no CA vouches for it (SPEC.md 5.3)");
        if (done == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            return fail(Category::refused,
                "no CA the client trusts vouches for the server's certificate (SPEC.md 2)");
        return fail(Category::transport, "the TLS handshake failed");
    }
    if (!verification.leaf_seen || !verification.accepted)
        return fail(Category::refused,
            "the server's key is not the one pinned, or no CA vouches for it (SPEC.md 5.3)");

    TlsStream stream(session.ssl);
    auto exchanged = http1::exchange(stream, *url, request, handler);
    static_cast<void>(mbedtls_ssl_close_notify(&session.ssl));
    return exchanged;
}

} // namespace lantern::mbedtls
