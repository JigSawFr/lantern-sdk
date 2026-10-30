#include <lantern/pinning.hpp>

namespace lantern
{

Result<PinCheck> check_pin(
    KeyPinStore& store, std::string_view platform, std::string_view id, const PackageSignature& signature)
{
    const auto pinned = store.load(platform, id);
    if (!pinned)
        return std::unexpected(pinned.error());
    PinCheck check;
    check.pinned             = *pinned;
    check.offered.is_signed  = signature.is_signed;
    check.offered.public_key = signature.is_signed ? signature.public_key : PublicKey {};
    if (!check.pinned)
        check.verdict = PinVerdict::first_install;
    else if (!check.pinned->is_signed)
        check.verdict = signature.is_signed ? PinVerdict::newly_signed : PinVerdict::same;
    else if (!signature.is_signed)
        check.verdict = PinVerdict::signature_removed;
    else
        check.verdict
            = check.pinned->public_key == signature.public_key ? PinVerdict::same : PinVerdict::key_changed;
    return check;
}

Result<void> commit_pin(KeyPinStore& store, std::string_view platform, std::string_view id,
    const PinCheck& check, bool user_accepted_change)
{
    if (check.needs_consent() && !user_accepted_change)
        return fail(
            Category::signature, "the homebrew's key changed and the user did not accept it (SPEC.md 8.4)");
    if (check.verdict == PinVerdict::same)
        return {};
    return store.store(platform, id, check.offered);
}

} // namespace lantern
