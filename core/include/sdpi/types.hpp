#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>

namespace discorddpi {

using SteadyClock = std::chrono::steady_clock;
using TimePoint = SteadyClock::time_point;

enum class Protocol : uint8_t {
    Tcp = 6,
    Udp = 17,
};

enum class FlowClassification : uint8_t {
    Unknown = 0,
    Discord = 1,
    NonDiscord = 2,
};

enum class FlowSource : uint8_t {
    Unknown = 0,
    SocketLayer = 1,
    FlowLayer = 2,
    IpHelperSeed = 3,
    UdpPortBinding = 4,
};

enum class ProcessRole : uint8_t {
    Unknown = 0,
    Main = 1,
    NetworkUtility = 2,
    Renderer = 3,
    GpuOrMedia = 4,
    Updater = 5,
    OtherChild = 6,
};

enum class TcpSplitMode : uint8_t {
    None = 0,
    FirstByte = 1,    // 2 segments: [0..2), [2..N)
    SniMiddle = 2,    // 2 segments: [0..sni_mid), [sni_mid..N) (fallback offset 2)
    RecordAndSni = 3, // 3 segments: [0..2), [2..sni_mid), [sni_mid..N)
};

enum class QuicStrategy : uint8_t {
    Observe = 0,            // Pass Discord UDP 443 untouched
    DropDiscordQuic443 = 1, // Drop outbound UDP 443 ONLY for verified Discord PIDs
};

// Unified 128-bit IP address matching WinDivert's host-byte-order UINT32[4] layout:
// - For IPv4 a.b.c.d (host uint32 = (a<<24)|(b<<16)|(c<<8)|d):
//     words[0] = ipv4_host
//     words[1] = 0x0000FFFFu
//     words[2] = 0
//     words[3] = 0
// - For IPv6: matches WinDivertHelperNtohIPv6Address() output and
//   WINDIVERT_DATA_SOCKET / WINDIVERT_DATA_FLOW LocalAddr/RemoteAddr.
struct IpAddress128 {
    std::array<uint32_t, 4> words{0, 0, 0, 0};

    constexpr bool operator==(const IpAddress128& other) const noexcept = default;

    [[nodiscard]] static constexpr IpAddress128 from_ipv4_host(uint32_t ipv4_host) noexcept {
        return IpAddress128{{ipv4_host, 0x0000FFFFu, 0u, 0u}};
    }

    [[nodiscard]] static IpAddress128 from_windivert_words(const uint32_t w[4]) noexcept {
        return IpAddress128{{w[0], w[1], w[2], w[3]}};
    }

    [[nodiscard]] constexpr bool is_ipv4_mapped() const noexcept {
        return words[1] == 0x0000FFFFu && words[2] == 0u && words[3] == 0u;
    }

    [[nodiscard]] constexpr bool is_zero() const noexcept {
        return words[0] == 0u && words[1] == 0u && words[2] == 0u && words[3] == 0u;
    }

    [[nodiscard]] constexpr bool is_ipv4_wildcard() const noexcept {
        return words[0] == 0u && words[1] == 0x0000FFFFu && words[2] == 0u && words[3] == 0u;
    }

    [[nodiscard]] constexpr bool is_wildcard() const noexcept {
        return is_zero() || is_ipv4_wildcard();
    }

    [[nodiscard]] constexpr uint32_t ipv4_host() const noexcept {
        return words[0];
    }

    [[nodiscard]] std::string to_string() const;
};

// Canonical bidirectional 5-tuple normalized to (local, remote).
// Outbound packet: local = src, remote = dst.
// Inbound packet : local = dst, remote = src.
struct FlowKey {
    IpAddress128 local_addr{};
    IpAddress128 remote_addr{};
    uint16_t local_port{0};
    uint16_t remote_port{0};
    uint8_t protocol{0};

    constexpr bool operator==(const FlowKey& other) const noexcept = default;

    [[nodiscard]] constexpr bool is_ipv6() const noexcept {
        return !local_addr.is_ipv4_mapped() && !remote_addr.is_ipv4_mapped();
    }
};

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& k) const noexcept {
        uint64_t h = 0x9E3779B97F4A7C15ULL;
        auto mix = [&h](uint64_t v) noexcept {
            v ^= v >> 30;
            v *= 0xBF58476D1CE4E5B9ULL;
            v ^= v >> 27;
            v *= 0x94D049BB133111EBULL;
            v ^= v >> 31;
            h ^= v + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
        };
        mix((static_cast<uint64_t>(k.local_addr.words[0]) << 32) | k.local_addr.words[1]);
        mix((static_cast<uint64_t>(k.local_addr.words[2]) << 32) | k.local_addr.words[3]);
        mix((static_cast<uint64_t>(k.remote_addr.words[0]) << 32) | k.remote_addr.words[1]);
        mix((static_cast<uint64_t>(k.remote_addr.words[2]) << 32) | k.remote_addr.words[3]);
        mix((static_cast<uint64_t>(k.local_port) << 32) |
            (static_cast<uint64_t>(k.remote_port) << 16) |
            static_cast<uint64_t>(k.protocol));
        return static_cast<std::size_t>(h);
    }
};

struct ProcessIdentity {
    uint32_t pid{0};
    uint32_t parent_pid{0};
    uint64_t creation_time_100ns{0};
    std::wstring exe_path{};
    std::wstring signer_name{};
    bool signature_valid{false};
    ProcessRole role{ProcessRole::Unknown};
};

struct FlowRecord {
    FlowKey key{};
    uint32_t pid{0};
    uint64_t process_creation_time{0};
    uint64_t endpoint_id{0};
    FlowClassification classification{FlowClassification::Unknown};
    FlowSource source{FlowSource::Unknown};
    TimePoint first_seen{};
    TimePoint last_seen{};
    uint64_t packets_out{0};
    uint64_t packets_in{0};
    uint64_t bytes_out{0};
    uint64_t bytes_in{0};
    uint32_t tls_hellos_processed{0};
    bool tls_established{false};
    bool closing{false};
};

struct EngineStatsSnapshot {
    uint32_t windivert_version_major{0};
    uint32_t windivert_version_minor{0};
    uint64_t uptime_ms{0};

    uint32_t active_discord_processes{0};
    uint32_t active_discord_flows{0};
    uint32_t active_discord_tcp_flows{0};
    uint32_t active_discord_udp_flows{0};
    uint32_t active_discord_ipv4_flows{0};
    uint32_t active_discord_ipv6_flows{0};
    uint32_t active_non_discord_flows{0};

    uint64_t socket_events_total{0};
    uint64_t flow_events_total{0};

    uint64_t packets_seen_total{0};
    uint64_t packets_invalid_passthrough{0};
    uint64_t packets_discord_seen{0};
    uint64_t packets_non_discord_passthrough{0};
    uint64_t packets_unknown_passthrough{0};
    uint64_t packets_modified{0};
    uint64_t packets_non_discord_modified{0}; // Hard safety invariant: MUST always be 0

    // Phase 3 DPI Engine counters
    uint64_t tls_client_hellos_detected{0};
    uint64_t tcp_packets_segmented{0};
    uint64_t tcp_segments_injected{0};
    uint64_t quic_packets_dropped_discord{0};

    uint64_t bytes_discord_out{0};
    uint64_t bytes_discord_in{0};

    uint64_t pending_enqueued{0};
    uint64_t pending_hit_discord{0};
    uint64_t pending_hit_non_discord{0};
    uint64_t pending_timeout_passthrough{0};
    uint64_t pending_overflow_passthrough{0};
};

[[nodiscard]] const char* to_string(FlowClassification c) noexcept;
[[nodiscard]] const char* to_string(FlowSource s) noexcept;
[[nodiscard]] const char* to_string(ProcessRole r) noexcept;
[[nodiscard]] const char* to_string(TcpSplitMode m) noexcept;
[[nodiscard]] const char* to_string(QuicStrategy q) noexcept;

} // namespace discorddpi
