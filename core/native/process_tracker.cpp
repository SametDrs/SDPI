#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include "discorddpi/process_tracker.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <mutex>

namespace discorddpi {

namespace {

std::wstring expand_env_vars(const std::wstring& input) {
    if (input.empty()) {
        return {};
    }
    const DWORD needed = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);
    if (needed == 0) {
        return input;
    }
    std::wstring out(needed, L'\0');
    const DWORD written = ExpandEnvironmentStringsW(input.c_str(), out.data(), needed);
    if (written == 0) {
        return input;
    }
    if (!out.empty() && out.back() == L'\0') {
        out.pop_back();
    }
    return out;
}

std::wstring normalize_file_path(const std::wstring& raw_path) {
    if (raw_path.empty()) {
        return {};
    }
    std::error_code ec;
    std::filesystem::path p(raw_path);
    std::wstring norm = p.lexically_normal().wstring();
    std::transform(norm.begin(), norm.end(), norm.begin(), [](wchar_t ch) {
        if (ch == L'/') {
            return L'\\';
        }
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return norm;
}

bool is_allowed_discord_exe_name(const std::wstring& normalized_full_path) {
    const auto pos = normalized_full_path.find_last_of(L'\\');
    const std::wstring filename =
        (pos == std::wstring::npos) ? normalized_full_path : normalized_full_path.substr(pos + 1);

    return filename == L"discord.exe" ||
           filename == L"discordptb.exe" ||
           filename == L"discordcanary.exe" ||
           filename == L"update.exe" ||
           filename == L"updater_launcher.exe" ||
           filename == L"discordsystemhelper.exe" ||
           filename == L"discordhookhelper.exe" ||
           filename == L"discordhookhelper64.exe" ||
           filename == L"audio_effects_helper.exe" ||
           filename == L"gpu_encoder_helper.exe";
}

std::wstring query_process_command_line_lower(HANDLE proc) {
    struct UnicodeStringLayout {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };
    using NtQueryInformationProcessFn =
        LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    static const auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (fn == nullptr || proc == nullptr) {
        return {};
    }

    constexpr ULONG kProcessCommandLineInformation = 60;
    ULONG needed = 0;
    (void)fn(proc, kProcessCommandLineInformation, nullptr, 0, &needed);
    if (needed < sizeof(UnicodeStringLayout) || needed > 65536) {
        return {};
    }

    std::vector<uint8_t> buf(needed, 0);
    const LONG status =
        fn(proc, kProcessCommandLineInformation, buf.data(), needed, &needed);
    if (status < 0) {
        return {};
    }

    const auto* us = reinterpret_cast<const UnicodeStringLayout*>(buf.data());
    if (us->Buffer == nullptr || us->Length == 0) {
        return {};
    }

    const auto* raw_start = reinterpret_cast<const uint8_t*>(us->Buffer);
    if (raw_start < buf.data() || raw_start + us->Length > buf.data() + buf.size()) {
        return {};
    }

    std::wstring cmd(us->Buffer, us->Length / sizeof(wchar_t));
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return cmd;
}

ProcessRole infer_role_from_path_and_cmdline(
    const std::wstring& normalized_full_path,
    const std::wstring& lower_cmdline,
    bool parent_is_discord) {
    const auto pos = normalized_full_path.find_last_of(L'\\');
    const std::wstring filename =
        (pos == std::wstring::npos) ? normalized_full_path : normalized_full_path.substr(pos + 1);

    if (filename == L"update.exe" || filename == L"updater_launcher.exe") {
        return ProcessRole::Updater;
    }
    if (filename == L"audio_effects_helper.exe" || filename == L"gpu_encoder_helper.exe") {
        return ProcessRole::GpuOrMedia;
    }
    if (!lower_cmdline.empty()) {
        if (lower_cmdline.find(L"network.mojom.networkservice") != std::wstring::npos) {
            return ProcessRole::NetworkUtility;
        }
        if (lower_cmdline.find(L"--type=renderer") != std::wstring::npos) {
            return ProcessRole::Renderer;
        }
        if (lower_cmdline.find(L"--type=gpu-process") != std::wstring::npos ||
            lower_cmdline.find(L"audio.mojom.audioservice") != std::wstring::npos) {
            return ProcessRole::GpuOrMedia;
        }
        if (lower_cmdline.find(L"--type=") != std::wstring::npos) {
            return ProcessRole::OtherChild;
        }
    }
    return parent_is_discord ? ProcessRole::OtherChild : ProcessRole::Main;
}

bool query_process_details(
    HANDLE proc,
    std::wstring& out_exe_path,
    uint64_t& out_creation_time_100ns) {
    FILETIME create_ft{}, exit_ft{}, kernel_ft{}, user_ft{};
    if (!GetProcessTimes(proc, &create_ft, &exit_ft, &kernel_ft, &user_ft)) {
        return false;
    }
    out_creation_time_100ns =
        (static_cast<uint64_t>(create_ft.dwHighDateTime) << 32) | create_ft.dwLowDateTime;

    std::wstring buf(1024, L'\0');
    DWORD size = static_cast<DWORD>(buf.size());
    if (!QueryFullProcessImageNameW(proc, 0, buf.data(), &size)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(4096, L'\0');
            size = static_cast<DWORD>(buf.size());
            if (!QueryFullProcessImageNameW(proc, 0, buf.data(), &size)) {
                return false;
            }
        } else {
            return false;
        }
    }
    buf.resize(size);
    out_exe_path = std::move(buf);
    return true;
}

bool is_handle_exited(HANDLE h) noexcept {
    if (h == nullptr) {
        return true;
    }
    return WaitForSingleObject(h, 0) != WAIT_TIMEOUT;
}

void add_unique_root(std::vector<std::wstring>& roots, const std::wstring& candidate) {
    const std::wstring norm = ProcessTracker::normalize_directory_root(candidate);
    if (norm.empty()) {
        return;
    }
    if (std::find(roots.begin(), roots.end(), norm) == roots.end()) {
        roots.push_back(norm);
    }
}

} // namespace

std::wstring ProcessTracker::normalize_directory_root(const std::wstring& raw_root) {
    const std::wstring expanded = expand_env_vars(raw_root);
    std::wstring norm = normalize_file_path(expanded);
    while (!norm.empty() && norm.back() == L'\\') {
        norm.pop_back();
    }
    if (norm.empty()) {
        return {};
    }
    norm.push_back(L'\\');
    return norm;
}

bool ProcessTracker::is_path_under_roots(
    const std::wstring& exe_path,
    const std::vector<std::wstring>& normalized_roots) {
    const std::wstring norm_exe = normalize_file_path(exe_path);
    if (norm_exe.empty() || !is_allowed_discord_exe_name(norm_exe)) {
        return false;
    }
    for (const auto& root : normalized_roots) {
        if (!root.empty() && norm_exe.size() > root.size() &&
            norm_exe.compare(0, root.size(), root) == 0) {
            return true;
        }
    }
    return false;
}

ProcessTracker::ProcessTracker(ProcessTrackerConfig config)
    : config_(std::move(config)),
      verifier_(config_.required_signer) {
    for (const auto& r : config_.install_roots) {
        add_unique_root(normalized_roots_, r);
    }

    if (config_.discover_all_user_profiles) {
        std::error_code ec;
        const std::filesystem::path users_dir(expand_env_vars(L"%SystemDrive%\\Users"));
        if (std::filesystem::exists(users_dir, ec) && std::filesystem::is_directory(users_dir, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(users_dir, ec)) {
                if (!entry.is_directory(ec)) {
                    continue;
                }
                const auto local_appdata = entry.path() / L"AppData" / L"Local";
                for (const wchar_t* variant : {L"Discord", L"DiscordPTB", L"DiscordCanary"}) {
                    const auto candidate = local_appdata / variant;
                    if (std::filesystem::exists(candidate, ec)) {
                        add_unique_root(normalized_roots_, candidate.wstring());
                    }
                }
            }
        }
    }
}

ProcessTracker::~ProcessTracker() {
    std::unique_lock lock(mutex_);
    for (auto& [pid, tracked] : discord_procs_) {
        close_handle_safe(tracked.sync_handle);
    }
    discord_procs_.clear();
}

void ProcessTracker::close_handle_safe(void*& h) noexcept {
    if (h != nullptr) {
        CloseHandle(static_cast<HANDLE>(h));
        h = nullptr;
    }
}

bool ProcessTracker::matches_discord_binary_unlocked(
    const std::wstring& exe_path,
    SignatureResult& out_sig) const {
    if (!is_path_under_roots(exe_path, normalized_roots_)) {
        return false;
    }
    if (!config_.verify_signature) {
        out_sig = SignatureResult{true, true, L"(unverified)", 0};
        return true;
    }
    out_sig = verifier_.verify_file(exe_path);
    return out_sig.signature_valid && out_sig.signer_matched;
}

void ProcessTracker::prewarm_signatures() {
    if (!config_.verify_signature) {
        return;
    }
    std::error_code ec;
    for (const auto& root : normalized_roots_) {
        if (root.empty() || !std::filesystem::exists(root, ec)) {
            continue;
        }
        std::filesystem::recursive_directory_iterator it(
            root,
            std::filesystem::directory_options::skip_permission_denied,
            ec);
        const std::filesystem::recursive_directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            if (it.depth() > 5) {
                it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file(ec)) {
                continue;
            }
            const std::wstring candidate = it->path().wstring();
            if (is_path_under_roots(candidate, normalized_roots_)) {
                (void)verifier_.verify_file(candidate);
            }
        }
        ec.clear();
    }
}

std::vector<uint32_t> ProcessTracker::reap_exited() {
    std::vector<uint32_t> exited;
    std::unique_lock lock(mutex_);
    for (auto it = discord_procs_.begin(); it != discord_procs_.end();) {
        if (is_handle_exited(static_cast<HANDLE>(it->second.sync_handle))) {
            exited.push_back(it->first);
            close_handle_safe(it->second.sync_handle);
            it = discord_procs_.erase(it);
        } else {
            ++it;
        }
    }
    return exited;
}

std::vector<uint32_t> ProcessTracker::scan_and_reap() {
    std::vector<uint32_t> exited = reap_exited();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return exited;
    }

    struct RawProc {
        uint32_t pid{0};
        uint32_t parent_pid{0};
    };
    std::vector<RawProc> snapshot_procs;
    snapshot_procs.reserve(256);

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4) {
                snapshot_procs.push_back(RawProc{pe.th32ProcessID, pe.th32ParentProcessID});
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    for (const auto& rp : snapshot_procs) {
        {
            std::shared_lock lock(mutex_);
            if (discord_procs_.find(rp.pid) != discord_procs_.end()) {
                continue;
            }
        }
        auto id_opt = classify_pid(rp.pid);
        if (id_opt.has_value() && rp.parent_pid != 0) {
            std::unique_lock lock(mutex_);
            auto it = discord_procs_.find(rp.pid);
            if (it != discord_procs_.end()) {
                it->second.identity.parent_pid = rp.parent_pid;
                const bool parent_is_discord =
                    (discord_procs_.find(rp.parent_pid) != discord_procs_.end());
                if (parent_is_discord && it->second.identity.role == ProcessRole::Main) {
                    it->second.identity.role = ProcessRole::OtherChild;
                }
            }
        }
    }

    // Second pass over tracked Discord processes to finalize Main vs Child roles
    // regardless of PID ordering in the snapshot, preserving specific roles
    // (NetworkUtility, Renderer, GpuOrMedia, Updater).
    {
        std::unique_lock lock(mutex_);
        for (auto& [pid, tracked] : discord_procs_) {
            if (tracked.identity.parent_pid != 0) {
                const bool parent_is_discord =
                    (discord_procs_.find(tracked.identity.parent_pid) != discord_procs_.end());
                if (parent_is_discord && tracked.identity.role == ProcessRole::Main) {
                    tracked.identity.role = ProcessRole::OtherChild;
                }
            }
        }
    }

    return exited;
}

std::optional<ProcessIdentity> ProcessTracker::classify_pid(uint32_t pid) {
    if (pid <= 4) {
        return std::nullopt;
    }

    // 1. Fast positive check on already-tracked Discord process.
    {
        std::shared_lock lock(mutex_);
        const auto it = discord_procs_.find(pid);
        if (it != discord_procs_.end()) {
            if (!is_handle_exited(static_cast<HANDLE>(it->second.sync_handle))) {
                return it->second.identity;
            }
        }
    }

    // 2. Open process to inspect creation time & full image path.
    HANDLE h = OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        static_cast<DWORD>(pid));
    if (h == nullptr) {
        // Fallback without SYNCHRONIZE in case of protected non-Discord system processes.
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (h == nullptr) {
            return std::nullopt;
        }
    }

    std::wstring exe_path;
    uint64_t creation_time = 0;
    if (!query_process_details(h, exe_path, creation_time)) {
        CloseHandle(h);
        return std::nullopt;
    }

    // 3. Check negative cache keyed by (pid, exact creation_time) so PID reuse
    // can NEVER cause a stale negative cache hit.
    {
        std::shared_lock lock(mutex_);
        const auto neg_it = non_discord_cache_.find(pid);
        if (neg_it != non_discord_cache_.end() &&
            neg_it->second.creation_time_100ns == creation_time) {
            CloseHandle(h);
            return std::nullopt;
        }
    }

    // 4. Verify path boundary + Authenticode signature.
    SignatureResult sig{};
    if (!matches_discord_binary_unlocked(exe_path, sig)) {
        CloseHandle(h);
        std::unique_lock lock(mutex_);
        if (non_discord_cache_.size() >= 2048) {
            non_discord_cache_.clear();
        }
        non_discord_cache_[pid] = NegativeEntry{creation_time, SteadyClock::now()};
        return std::nullopt;
    }

    // 5. Verified genuine Discord process!
    const std::wstring lower_cmdline = query_process_command_line_lower(h);

    ProcessIdentity identity{};
    identity.pid = pid;
    identity.creation_time_100ns = creation_time;
    identity.exe_path = std::move(exe_path);
    identity.signer_name = std::move(sig.signer_subject);
    identity.signature_valid = sig.signature_valid;
    identity.role = infer_role_from_path_and_cmdline(
        normalize_file_path(identity.exe_path), lower_cmdline, false);

    std::unique_lock lock(mutex_);
    auto existing = discord_procs_.find(pid);
    if (existing != discord_procs_.end()) {
        if (!is_handle_exited(static_cast<HANDLE>(existing->second.sync_handle)) &&
            existing->second.identity.creation_time_100ns == creation_time) {
            CloseHandle(h);
            return existing->second.identity;
        }
        close_handle_safe(existing->second.sync_handle);
        discord_procs_.erase(existing);
    }

    non_discord_cache_.erase(pid);
    discord_procs_[pid] = TrackedProcess{identity, h};
    return identity;
}

bool ProcessTracker::is_discord_pid(uint32_t pid) {
    return classify_pid(pid).has_value();
}

std::vector<ProcessIdentity> ProcessTracker::active_discord_processes() const {
    std::vector<ProcessIdentity> result;
    std::shared_lock lock(mutex_);
    result.reserve(discord_procs_.size());
    for (const auto& [pid, tracked] : discord_procs_) {
        if (!is_handle_exited(static_cast<HANDLE>(tracked.sync_handle))) {
            result.push_back(tracked.identity);
        }
    }
    return result;
}

uint32_t ProcessTracker::active_discord_count() const {
    uint32_t count = 0;
    std::shared_lock lock(mutex_);
    for (const auto& [pid, tracked] : discord_procs_) {
        if (!is_handle_exited(static_cast<HANDLE>(tracked.sync_handle))) {
            ++count;
        }
    }
    return count;
}

} // namespace discorddpi
