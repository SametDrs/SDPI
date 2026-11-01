#pragma once

#include "discorddpi/process_tracker.hpp"
#include "discorddpi/types.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace discorddpi {

struct FlowTrackerConfig {
    std::chrono::milliseconds pending_timeout{75};
    std::size_t pending_max_packets{256};
    std::chrono::seconds flow_idle_timeout{120};
    std::chrono::seconds non_discord_flow_ttl{60};
};

struct PendingPacket {
    FlowKey key{};
    bool outbound{false};
    std::vector<uint8_t> packet_bytes{};
    std::array<uint8_t, 80> raw_windivert_addr{}; // Exact storage for WINDIVERT_ADDRESS
    TimePoint enqueue_time{};
    TimePoint deadline{};
};

class FlowTracker {
public:
    using PacketDecisionCallback =
        std::function<void(PendingPacket&& pkt, FlowClassification classification)>;

    FlowTracker(ProcessTracker& process_tracker, FlowTrackerConfig config = {});
    ~FlowTracker();

    FlowTracker(const FlowTracker&) = delete;
    FlowTracker& operator=(const FlowTracker&) = delete;

    // Starts/stops the asynchronous deferred-classification worker thread.
    // On stop, any queued packets are immediately flushed as Unknown (unchanged passthrough).
    void start_pending_worker(PacketDecisionCallback callback);
    void stop_pending_worker();

    // Seeds pre-existing TCP/UDP IPv4/IPv6 connections via Windows IP Helper API.
    void seed_existing_connections();

    // Called by SocketMonitor on WINDIVERT_LAYER_SOCKET events.
    void on_socket_connect_or_accept(
        const FlowKey& key,
        uint32_t pid,
        uint64_t endpoint_id);

    void on_socket_bind(
        const IpAddress128& local_addr,
        uint16_t local_port,
        uint8_t protocol,
        uint32_t pid,
        uint64_t endpoint_id);

    void on_socket_close(
        const FlowKey& key,
        uint32_t pid,
        uint64_t endpoint_id);

    // Called by SocketMonitor on WINDIVERT_LAYER_FLOW events.
    void on_flow_established(
        const FlowKey& key,
        uint32_t pid,
        uint64_t endpoint_id);

    void on_flow_deleted(
        const FlowKey& key,
        uint32_t pid,
        uint64_t endpoint_id);

    // Looks up packet classification and updates counters if known.
    [[nodiscard]] FlowClassification classify_and_account_packet(
        const FlowKey& key,
        bool outbound,
        uint32_t packet_bytes_len);

    // Enqueues an Unknown packet for up to `pending_timeout` waiting for its
    // SOCKET/FLOW event. Returns false if queue is full or worker not running
    // (caller must immediately re-inject unchanged).
    [[nodiscard]] bool enqueue_pending_packet(PendingPacket&& pkt);

    // Purges all flows and port bindings owned by an exited PID.
    std::size_t purge_process_flows(uint32_t pid);

    // Purges flows that have been idle longer than configured timeouts.
    std::size_t cleanup_expired_flows(TimePoint now = SteadyClock::now());

    // Per-flow TLS handshake stage tracking so mid-stream bulk transfers are untouched.
    [[nodiscard]] bool allow_discord_tls_processing(const FlowKey& key) const;
    void record_discord_tls_hello(const FlowKey& key);

    [[nodiscard]] std::vector<FlowRecord> active_discord_flows() const;
    void populate_stats(EngineStatsSnapshot& out_stats) const;

private:
    struct PartialConnectKey {
        IpAddress128 remote_addr{};
        uint16_t local_port{0};
        uint16_t remote_port{0};
        uint8_t protocol{0};

        constexpr bool operator==(const PartialConnectKey& other) const noexcept = default;
    };

    struct PartialConnectKeyHash {
        [[nodiscard]] std::size_t operator()(const PartialConnectKey& k) const noexcept {
            FlowKey fk{};
            fk.remote_addr = k.remote_addr;
            fk.local_port = k.local_port;
            fk.remote_port = k.remote_port;
            fk.protocol = k.protocol;
            return FlowKeyHash{}(fk);
        }
    };

    struct PartialConnectEntry {
        uint32_t pid{0};
        uint64_t process_creation_time{0};
        uint64_t endpoint_id{0};
        FlowClassification classification{FlowClassification::Unknown};
        TimePoint created_at{};
    };

    struct UdpPortOwner {
        uint32_t pid{0};
        uint64_t process_creation_time{0};
        uint64_t endpoint_id{0};
        IpAddress128 local_addr{};
        FlowClassification classification{FlowClassification::Unknown};
    };

    [[nodiscard]] FlowClassification resolve_pid_classification(
        uint32_t pid,
        uint64_t& out_creation_time) const;

    void upsert_flow_locked(
        const FlowKey& key,
        uint32_t pid,
        uint64_t creation_time,
        uint64_t endpoint_id,
        FlowClassification classification,
        FlowSource source,
        TimePoint now);

    [[nodiscard]] std::optional<FlowClassification> lookup_classification_locked(
        const FlowKey& key,
        TimePoint now);

    void pending_worker_loop();
    void notify_pending_for_flow();

    ProcessTracker& process_tracker_;
    FlowTrackerConfig config_;

    mutable std::shared_mutex flow_mutex_;
    std::unordered_map<FlowKey, FlowRecord, FlowKeyHash> flows_;
    std::unordered_map<PartialConnectKey, PartialConnectEntry, PartialConnectKeyHash> partial_connects_;
    std::unordered_map<uint16_t, std::vector<UdpPortOwner>> udp_port_bindings_;

    // Atomic counters
    std::atomic<uint64_t> socket_events_total_{0};
    std::atomic<uint64_t> flow_events_total_{0};
    std::atomic<uint64_t> packets_discord_seen_{0};
    std::atomic<uint64_t> packets_non_discord_passthrough_{0};
    std::atomic<uint64_t> bytes_discord_out_{0};
    std::atomic<uint64_t> bytes_discord_in_{0};

    std::atomic<uint64_t> pending_enqueued_{0};
    std::atomic<uint64_t> pending_hit_discord_{0};
    std::atomic<uint64_t> pending_hit_non_discord_{0};
    std::atomic<uint64_t> pending_timeout_passthrough_{0};
    std::atomic<uint64_t> pending_overflow_passthrough_{0};

    // Deferred packet queue state
    mutable std::mutex pending_mutex_;
    std::condition_variable pending_cv_;
    std::deque<PendingPacket> pending_queue_;
    PacketDecisionCallback pending_callback_;
    std::thread pending_thread_;
    bool pending_running_{false};
};

} // namespace discorddpi
