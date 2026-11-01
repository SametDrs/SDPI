#pragma once

#include "sdpi/dpi_engine.hpp"
#include "sdpi/types.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace discorddpi {

struct IpcStatusPayload {
    std::string engine_version{"1.0.0"};
    bool running{false};
    std::string mode{"active"};
    bool enable_ipv6{true};
    std::string network_filter{};
    DpiEngineConfig dpi_config{};
    EngineStatsSnapshot stats{};
    std::vector<ProcessIdentity> processes{};
    std::vector<FlowRecord> flows{};
    std::string last_warning{};
    std::string last_error{};
};

struct IpcConfigUpdate {
    std::optional<bool> tcp_enabled{};
    std::optional<TcpSplitMode> split_mode{};
    std::optional<bool> reverse_order{};
    std::optional<QuicStrategy> quic_strategy{};
    std::optional<bool> reset_discord_on_stop{};
};

struct IpcServerConfig {
    // Validated pipe token ([A-Za-z0-9._-], 1..64 chars). Full path becomes \\.\pipe\<token>.
    std::string pipe_token{"DiscordDPI.Engine"};
    // Optional launching GUI user SID string (e.g. L"S-1-5-21-...").
    // If empty, current process token user SID is used.
    std::wstring allowed_client_sid{};
};

struct IpcStartResult {
    bool ok{false};
    uint32_t win32_error{0};
    std::string pipe_path{};
    std::string message{};
};

class IpcServer {
public:
    using StatusCallback = std::function<IpcStatusPayload()>;
    using ConfigUpdateCallback = std::function<bool(const IpcConfigUpdate&, std::string& out_err)>;
    using ShutdownCallback = std::function<void(std::optional<bool> reset_discord_override)>;

    IpcServer(
        IpcServerConfig config,
        StatusCallback on_status,
        ConfigUpdateCallback on_update_config,
        ShutdownCallback on_shutdown);
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    [[nodiscard]] IpcStartResult start();
    void stop();

    [[nodiscard]] bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    [[nodiscard]] const std::string& pipe_path() const noexcept {
        return pipe_path_;
    }

    // Validates a pipe token ([A-Za-z0-9._-], 1..64 chars).
    [[nodiscard]] static bool is_valid_pipe_token(std::string_view token) noexcept;

    // Queries the current process token user SID as an SDDL SID string (e.g. L"S-1-5-21-...").
    [[nodiscard]] static bool query_current_user_sid(std::wstring& out_sid);

    // Processes a single UTF-8 JSON command line (without trailing '\n') and returns
    // a single-line UTF-8 JSON response (without trailing '\n').
    [[nodiscard]] std::string handle_json_line(
        std::string_view line,
        bool& out_request_shutdown);

    [[nodiscard]] std::string handle_json_line(
        std::string_view line,
        bool& out_request_shutdown,
        std::optional<bool>& out_reset_discord_override);

private:
    void server_thread_loop();

    IpcServerConfig config_;
    StatusCallback on_status_;
    ConfigUpdateCallback on_update_config_;
    ShutdownCallback on_shutdown_;

    std::string pipe_path_{};
    void* pipe_handle_{nullptr};
    void* stop_event_{nullptr};
    std::atomic<bool> running_{false};
    std::thread server_thread_{};
};

} // namespace discorddpi
