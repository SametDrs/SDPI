#pragma once

#include "discorddpi/types.hpp"

#include <cstddef>
#include <cstdint>

namespace discorddpi {

struct ParsedPacket {
    bool valid_ip{false};
    bool valid_five_tuple{false};
    bool is_ipv6{false};
    bool is_ip_fragment{false};
    bool outbound{false};

    FlowKey flow_key{};

    uint8_t tcp_flags{0};
    bool tcp_syn{false};
    bool tcp_ack{false};
    bool tcp_fin{false};
    bool tcp_rst{false};
    bool tcp_psh{false};

    const uint8_t* payload{nullptr};
    uint32_t payload_len{0};
    uint32_t total_len{0};
};

class PacketFilter {
public:
    // Parses an IPv4/IPv6 packet and extracts a canonical bidirectional FlowKey
    // normalized to (local, remote) according to `outbound`.
    // Never throws and never modifies `packet_bytes`.
    [[nodiscard]] static ParsedPacket parse(
        const uint8_t* packet_bytes,
        uint32_t packet_len,
        bool outbound) noexcept;

    // Quick structural check for TLS record header starting with Handshake (0x16)
    // and ClientHello (handshake type 0x01). Never logs payload contents.
    [[nodiscard]] static bool looks_like_tls_client_hello(
        const uint8_t* payload,
        uint32_t payload_len) noexcept;
};

} // namespace discorddpi
