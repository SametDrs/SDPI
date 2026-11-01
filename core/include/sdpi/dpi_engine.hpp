#pragma once

#include "sdpi/tls_parser.hpp"
#include "sdpi/types.hpp"

#include <cstdint>
#include <shared_mutex>
#include <vector>

namespace discorddpi {

struct TcpStrategyConfig {
    bool enabled{true};
    std::vector<uint16_t> target_ports{443, 2053, 2083, 2087, 2096, 8443}; // Empty = any remote TCP port
    TcpSplitMode split_mode{TcpSplitMode::RecordAndSni};
    bool reverse_order{true};
};

struct UdpStrategyConfig {
    // Voice/video encrypted RTP/DTLS packets on dynamic ports are NEVER modified.
    QuicStrategy quic_strategy{QuicStrategy::DropDiscordQuic443};
};

struct DpiEngineConfig {
    TcpStrategyConfig tcp{};
    UdpStrategyConfig udp{};
};

enum class DpiAction : uint8_t {
    PassthroughUnchanged = 0, // Re-inject original packet byte-for-byte unchanged
    ReplaceWithSegments = 1,  // Inject `segments` instead of original single TCP packet
    DropPacket = 2,           // Drop packet (used ONLY for Discord outbound UDP 443 QUIC fallback)
};

struct DpiDecision {
    DpiAction action{DpiAction::PassthroughUnchanged};
    bool detected_tls_client_hello{false};
    std::vector<std::vector<uint8_t>> segments{};
};

class DpiEngine {
public:
    explicit DpiEngine(DpiEngineConfig config = {});

    void update_config(DpiEngineConfig config);
    [[nodiscard]] DpiEngineConfig config() const;

    // Processes an OUTBOUND packet that has ALREADY been verified by FlowTracker
    // as belonging to a genuine Discord process.
    // Never modifies UDP media packets; never produces invalid checksums.
    [[nodiscard]] DpiDecision process_discord_outbound_packet(
        const uint8_t* packet_bytes,
        uint32_t packet_len,
        uint8_t protocol,
        uint16_t remote_port) const;

    // Pure TCP segment splitter exposed for deterministic unit testing.
    [[nodiscard]] static bool split_tcp_packet(
        const uint8_t* packet_bytes,
        uint32_t packet_len,
        const std::vector<uint32_t>& payload_split_offsets,
        bool reverse_order,
        std::vector<std::vector<uint8_t>>& out_segments);

private:
    [[nodiscard]] static bool is_target_tcp_port(
        const TcpStrategyConfig& tcp_cfg,
        uint16_t remote_port) noexcept;

    mutable std::shared_mutex config_mutex_;
    DpiEngineConfig config_;
};

} // namespace discorddpi
