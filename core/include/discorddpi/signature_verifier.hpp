#pragma once

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace discorddpi {

struct SignatureResult {
    bool signature_valid{false};
    bool signer_matched{false};
    std::wstring signer_subject{};
    uint32_t win32_status{0};
};

class SignatureVerifier {
public:
    explicit SignatureVerifier(std::wstring required_signer = L"Discord Inc.");

    // Verifies Authenticode signature offline (no network CRL fetch) and checks
    // whether the signer's simple display name matches `required_signer_`.
    // Results are cached by (normalized_path, file_size, last_write_time).
    [[nodiscard]] SignatureResult verify_file(const std::wstring& file_path) const;

    [[nodiscard]] const std::wstring& required_signer() const noexcept {
        return required_signer_;
    }

    [[nodiscard]] std::size_t cache_size() const;
    void clear_cache();

private:
    struct CacheEntry {
        uint64_t file_size{0};
        uint64_t last_write_time{0};
        SignatureResult result{};
    };

    [[nodiscard]] static SignatureResult verify_file_uncached(
        const std::wstring& file_path,
        const std::wstring& required_signer);

    std::wstring required_signer_;
    mutable std::shared_mutex mutex_;
    mutable std::unordered_map<std::wstring, CacheEntry> cache_;
};

} // namespace discorddpi
