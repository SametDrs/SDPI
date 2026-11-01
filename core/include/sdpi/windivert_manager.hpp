#pragma once

#include "sdpi/dpi_engine.hpp"
#include "sdpi/flow_tracker.hpp"
#include "sdpi/process_tracker.hpp"
#include "sdpi/socket_monitor.hpp"
#include "sdpi/types.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace discorddpi {

enum class NetworkMode : uint8_t {
    ObserveSniff = 0,  // Read-only kernel copy (SNIFF | RECV_ONLY), zero packet delay
    ObserveDivert = 1, // Narrow divert + deferred queue + 100% unchanged re-injection
    ActiveDpi = 2,     // Process-scoped DPI engine for verified Discord flows only
};

struct EngineConfig {
    NetworkMode mode{NetworkMode::ObserveSniff};
    bool enable_ipv6{true};
    FlowTrackerConfig flow_config{};
    ProcessTrackerConfig process_config{};
    DpiEngineConfig dpi_config{};
};

struct EngineStartResult {
    bool ok{false};
    uint32_t win32_error{0};
    std::string message{};
};

class WinDivertManager {
public:
    explicit WinDivertManager(EngineConfig config = {});
    ~WinDivertManager();

    WinDivertManager(const WinDivertManager&) = delete;
    WinDivertManager& operator=(const WinDivertManager&) = delete;

    [[nodiscard]] EngineStartResult start();
    void stop();

    [[nodiscard]] bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    void update_dpi_config(DpiEngineConfig new_dpi_config);
    [[nodiscard]] DpiEngineConfig current_dpi_config() const;

    [[nodiscard]] EngineStatsSnapshot snapshot_stats() const;
    [[nodiscard]] std::vector<ProcessIdentity> active_discord_processes() const;
    [[nodiscard]] std::vector<FlowRecord> active_discord_flows() const;

    // Resets active network connections owned strictly by verified Discord processes
    // (deletes IPv4 TCP TCBs via SetTcpEntry and recycles Discord's out-of-process
    // Chromium NetworkService child so IPv6 connections and TLS/ECH session caches reset
    // while keeping Discord's main window open). Call after stop().
    uint32_t reset_discord_connections();

    // Validates a WinDivert filter expression without opening a kernel handle.
    [[nodiscard]] static bool validate_filter_syntax(
        const std::string& filter,
        std::string& out_error);

    [[nodiscard]] std::string build_network_filter() const;

private:
    void network_thread_loop();
    void housekeeping_thread_loop();

    void handle_verified_discord_packet(
        const FlowKey& flow_key,
        bool outbound,
        const uint8_t* packet_bytes,
        uint32_t packet_len,
        const void* windivert_addr) noexcept;

    void reinject_unchanged(
        const uint8_t* packet_bytes,
        uint32_t packet_len,
        const void* windivert_addr) noexcept;

    [[nodiscard]] bool inject_tcp_segments(
        const std::vector<std::vector<uint8_t>>& segments,
        const void* base_windivert_addr) noexcept;

    EngineConfig config_;
    ProcessTracker process_tracker_;
    FlowTracker flow_tracker_;
    SocketMonitor socket_monitor_;
    DpiEngine dpi_engine_;

    void* network_handle_{nullptr};
    std::atomic<bool> running_{false};
    TimePoint start_time_{};

    uint32_t driver_major_{0};
    uint32_t driver_minor_{0};

    std::atomic<uint64_t> packets_seen_total_{0};
    std::atomic<uint64_t> packets_invalid_passthrough_{0};
    std::atomic<uint64_t> packets_unknown_passthrough_{0};
    std::atomic<uint64_t> packets_modified_{0};

    std::atomic<uint64_t> tls_client_hellos_detected_{0};
    std::atomic<uint64_t> tcp_packets_segmented_{0};
    std::atomic<uint64_t> tcp_segments_injected_{0};
    std::atomic<uint64_t> quic_packets_dropped_discord_{0};

    std::thread network_thread_;
    std::thread housekeeping_thread_;
    mutable std::mutex send_mutex_;
};

} // namespace discorddpi
