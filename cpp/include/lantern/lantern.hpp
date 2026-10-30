// Lantern: the client library of the Lantern protocol (draft 0.4).
// Everything at once; each header can also be included alone.
#pragma once

#include <lantern/client.hpp>
#include <lantern/credentials.hpp>
#include <lantern/device_key.hpp>
#include <lantern/digest.hpp>
#include <lantern/discovery.hpp>
#include <lantern/document.hpp>
#include <lantern/download.hpp>
#include <lantern/ed25519.hpp>
#include <lantern/encoding.hpp>
#include <lantern/error.hpp>
#include <lantern/homebrew.hpp>
#include <lantern/http_signature.hpp>
#include <lantern/json.hpp>
#include <lantern/memory.hpp>
#include <lantern/paths.hpp>
#include <lantern/pinning.hpp>
#include <lantern/profiles.hpp>
#include <lantern/requires.hpp>
#include <lantern/sha256.hpp>
#include <lantern/tls.hpp>
#include <lantern/transport.hpp>
#include <lantern/types.hpp>
#include <lantern/url.hpp>

namespace lantern
{

// The specification's draft this version follows.
inline constexpr std::string_view spec_draft = "0.4";

} // namespace lantern
