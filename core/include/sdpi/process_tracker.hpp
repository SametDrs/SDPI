#pragma once

#include "sdpi/signature_verifier.hpp"
#include "sdpi/types.hpp"

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace discorddpi {

struct ProcessTrackerConfig {
    std::vector<std::wstring> install_roots{
        L"%LOCALAPPDATA%\\Discord",
        L"%LOCALAPPDATA%\\DiscordPTB",
        L"%LOCALAPPDATA%\\DiscordCanary",
    };
    std::wstring required_signer{L"Discord Inc."};
    bool verify_signature{true};
    bool discover_all_user_profiles{true};
};

class ProcessTracker {
public:
    explicit ProcessTracker(ProcessTrackerConfig config = {});
    ~ProcessTracker();

    ProcessTracker(const ProcessTracker&) = delete;
    ProcessTracker& operator=(const ProcessTracker&) = delete;

    // Pre-warms Authenticode signature cache for installed Discord executables so
    // cold-start launch detection completes in microseconds without WinVerifyTrust lag.
    void prewarm_signatures();

    // Performs a full process snapshot scan, registers newly discovered Discord
    // processes, removes exited ones, and returns PIDs that exited since last check.
    std::vector<uint32_t> scan_and_reap();

    // Checks only currently tracked processes for termination (O(K) where K is
    // number of active Discord processes, typically 6-10) and returns exited PIDs.
    std::vector<uint32_t> reap_exited();

    // Fast path + on-demand inspection for SOCKET/FLOW events.
    // Returns ProcessIdentity if and only if `pid` is currently alive and verified
    // as a genuine Discord process.
    [[nodiscard]] std::optional<ProcessIdentity> classify_pid(uint32_t pid);

    [[nodiscard]] bool is_discord_pid(uint32_t pid);

    [[nodiscard]] std::vector<ProcessIdentity> active_discord_processes() const;
    [[nodiscard]] uint32_t active_discord_count() const;
    [[nodiscard]] const std::vector<std::wstring>& normalized_roots() const noexcept {
        return normalized_roots_;
    }

    // Pure helper exposed for unit testing path boundary logic.
    [[nodiscard]] static bool is_path_under_roots(
        const std::wstring& exe_path,
        const std::vector<std::wstring>& normalized_roots);

    [[nodiscard]] static std::wstring normalize_directory_root(const std::wstring& raw_root);

private:
    struct TrackedProcess {
        ProcessIdentity identity{};
        void* sync_handle{nullptr}; // HANDLE with SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
    };

    struct NegativeEntry {
        uint64_t creation_time_100ns{0};
        TimePoint verified_at{};
    };

    [[nodiscard]] bool matches_discord_binary_unlocked(
        const std::wstring& exe_path,
        SignatureResult& out_sig) const;

    static void close_handle_safe(void*& h) noexcept;

    ProcessTrackerConfig config_;
    SignatureVerifier verifier_;
    std::vector<std::wstring> normalized_roots_;

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, TrackedProcess> discord_procs_;
    std::unordered_map<uint32_t, NegativeEntry> non_discord_cache_;
};

} // namespace discorddpi
