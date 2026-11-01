#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include "windivert.h"

#include "sdpi/dpi_engine.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace discorddpi {

DpiEngine::DpiEngine(DpiEngineConfig config)
    : config_(std::move(config)) {}

void DpiEngine::update_config(DpiEngineConfig config) {
    std::unique_lock lock(config_mutex_);
    config_ = std::move(config);
}

DpiEngineConfig DpiEngine::config() const {
    std::shared_lock lock(config_mutex_);
    return config_;
}

bool DpiEngine::is_target_tcp_port(
    const TcpStrategyConfig& tcp_cfg,
    uint16_t remote_port) noexcept {
    if (tcp_cfg.target_ports.empty()) {
        return true;
    }
    for (const uint16_t p : tcp_cfg.target_ports) {
        if (p == remote_port) {
            return true;
        }
    }
    return false;
}

bool DpiEngine::split_tcp_packet(
    const uint8_t* packet_bytes,
    uint32_t packet_len,
    const std::vector<uint32_t>& payload_split_offsets,
    bool reverse_order,
    std::vector<std::vector<uint8_t>>& out_segments) {
    out_segments.clear();
    if (packet_bytes == nullptr || packet_len < 40 || payload_split_offsets.empty()) {
        return false;
    }

    PWINDIVERT_IPHDR ip_hdr = nullptr;
    PWINDIVERT_IPV6HDR ipv6_hdr = nullptr;
    UINT8 protocol = 0;
    PWINDIVERT_TCPHDR tcp_hdr = nullptr;
    PVOID payload_ptr = nullptr;
    UINT payload_len = 0;

    if (!WinDivertHelperParsePacket(
            packet_bytes,
            static_cast<UINT>(packet_len),
            &ip_hdr,
            &ipv6_hdr,
            &protocol,
            nullptr,
            nullptr,
            &tcp_hdr,
            nullptr,
            &payload_ptr,
            &payload_len,
            nullptr,
            nullptr)) {
        return false;
    }

    if (protocol != static_cast<uint8_t>(Protocol::Tcp) || tcp_hdr == nullptr ||
        payload_ptr == nullptr || payload_len < 3) {
        return false;
    }
    if (ip_hdr == nullptr && ipv6_hdr == nullptr) {
        return false;
    }

    // Refuse to split IP-fragmented packets or TCP SYN/RST packets.
    if (ip_hdr != nullptr) {
        if (WINDIVERT_IPHDR_GET_FRAGOFF(ip_hdr) != 0 || WINDIVERT_IPHDR_GET_MF(ip_hdr)) {
            return false;
        }
    }
    if (tcp_hdr->Syn != 0 || tcp_hdr->Rst != 0) {
        return false;
    }

    const auto* tcp_hdr_bytes_ptr = reinterpret_cast<const uint8_t*>(tcp_hdr);
    const auto* payload_bytes_ptr = static_cast<const uint8_t*>(payload_ptr);

    if (tcp_hdr_bytes_ptr < packet_bytes || payload_bytes_ptr < tcp_hdr_bytes_ptr) {
        return false;
    }

    const uint32_t ip_block_len = static_cast<uint32_t>(tcp_hdr_bytes_ptr - packet_bytes);
    const uint32_t tcp_hdr_len = static_cast<uint32_t>(tcp_hdr->HdrLength) * 4u;
    if (tcp_hdr_len < 20 ||
        static_cast<uint32_t>(payload_bytes_ptr - tcp_hdr_bytes_ptr) != tcp_hdr_len) {
        return false;
    }

    const uint32_t header_total_len = ip_block_len + tcp_hdr_len;
    if (header_total_len + payload_len > packet_len) {
        return false;
    }
    if (ip_hdr != nullptr && ip_block_len < 20) {
        return false;
    }
    if (ipv6_hdr != nullptr && ip_block_len < 40) {
        return false;
    }

    // Sanitize, sort, and deduplicate strictly interior split points (0 < off < payload_len).
    std::vector<uint32_t> boundaries;
    boundaries.reserve(payload_split_offsets.size() + 2);
    boundaries.push_back(0u);
    for (const uint32_t off : payload_split_offsets) {
        if (off > 0u && off < payload_len) {
            boundaries.push_back(off);
        }
    }
    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());
    boundaries.push_back(payload_len);

    if (boundaries.size() < 3) {
        // Fewer than 2 resulting segments -> nothing to split.
        return false;
    }

    const uint32_t orig_seq = WinDivertHelperNtohl(tcp_hdr->SeqNum);
    const uint16_t orig_ip_id = (ip_hdr != nullptr) ? WinDivertHelperNtohs(ip_hdr->Id) : 0;
    const uint16_t orig_psh = tcp_hdr->Psh;
    const uint16_t orig_fin = tcp_hdr->Fin;

    const std::size_t num_segments = boundaries.size() - 1;
    out_segments.reserve(num_segments);

    for (std::size_t i = 0; i < num_segments; ++i) {
        const uint32_t seg_start = boundaries[i];
        const uint32_t seg_end = boundaries[i + 1];
        const uint32_t seg_payload_len = seg_end - seg_start;
        const uint32_t seg_total_len = header_total_len + seg_payload_len;

        if (seg_total_len > 65535u) {
            out_segments.clear();
            return false;
        }

        std::vector<uint8_t> seg(seg_total_len);
        // Copy IP header (including any IPv4 options or IPv6 extension headers) + TCP header (including TCP options)
        std::memcpy(seg.data(), packet_bytes, header_total_len);
        // Copy segment slice of TCP payload
        std::memcpy(seg.data() + header_total_len, payload_bytes_ptr + seg_start, seg_payload_len);

        if (ip_hdr != nullptr) {
            auto* seg_ip = reinterpret_cast<PWINDIVERT_IPHDR>(seg.data());
            seg_ip->Length = WinDivertHelperHtons(static_cast<uint16_t>(seg_total_len));
            seg_ip->Id = WinDivertHelperHtons(
                static_cast<uint16_t>(orig_ip_id + static_cast<uint16_t>(i)));
        } else {
            auto* seg_ip6 = reinterpret_cast<PWINDIVERT_IPV6HDR>(seg.data());
            // IPv6 Payload Length excludes the fixed 40-byte IPv6 header
            const uint32_t ipv6_plen = seg_total_len - 40u;
            if (ipv6_plen > 65535u) {
                out_segments.clear();
                return false;
            }
            seg_ip6->Length = WinDivertHelperHtons(static_cast<uint16_t>(ipv6_plen));
        }

        auto* seg_tcp = reinterpret_cast<PWINDIVERT_TCPHDR>(seg.data() + ip_block_len);
        // 32-bit unsigned addition implements RFC 793 modulo 2^32 sequence arithmetic
        seg_tcp->SeqNum = WinDivertHelperHtonl(orig_seq + seg_start);

        const bool is_final_logical_segment = (i + 1 == num_segments);
        seg_tcp->Psh = is_final_logical_segment ? orig_psh : 0;
        seg_tcp->Fin = is_final_logical_segment ? orig_fin : 0;

        if (!WinDivertHelperCalcChecksums(
                seg.data(), static_cast<UINT>(seg_total_len), nullptr, 0)) {
            out_segments.clear();
            return false;
        }

        out_segments.push_back(std::move(seg));
    }

    if (reverse_order) {
        std::reverse(out_segments.begin(), out_segments.end());
    }

    return true;
}

DpiDecision DpiEngine::process_discord_outbound_packet(
    const uint8_t* packet_bytes,
    uint32_t packet_len,
    uint8_t protocol,
    uint16_t remote_port) const {
    DpiDecision decision{};
    if (packet_bytes == nullptr || packet_len < 20) {
        return decision;
    }

    const DpiEngineConfig cfg = config();

    // 1. UDP handling: NEVER touch voice/video RTP/DTLS payloads.
    // Only apply Discord-scoped QUIC policy on outbound UDP destination port 443.
    if (protocol == static_cast<uint8_t>(Protocol::Udp)) {
        if (remote_port == 443 &&
            cfg.udp.quic_strategy == QuicStrategy::DropDiscordQuic443) {
            decision.action = DpiAction::DropPacket;
        }
        return decision;
    }

    // 2. TCP handling: only process target ports when TCP strategy is enabled.
    if (protocol != static_cast<uint8_t>(Protocol::Tcp) ||
        !cfg.tcp.enabled ||
        cfg.tcp.split_mode == TcpSplitMode::None ||
        !is_target_tcp_port(cfg.tcp, remote_port)) {
        return decision;
    }

    PWINDIVERT_TCPHDR tcp_hdr = nullptr;
    PVOID payload_ptr = nullptr;
    UINT payload_len = 0;
    if (!WinDivertHelperParsePacket(
            packet_bytes,
            static_cast<UINT>(packet_len),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &tcp_hdr,
            nullptr,
            &payload_ptr,
            &payload_len,
            nullptr,
            nullptr)) {
        return decision;
    }

    if (tcp_hdr == nullptr || payload_ptr == nullptr || payload_len < 44) {
        return decision;
    }

    const auto tls_info = TlsParser::parse_client_hello(
        static_cast<const uint8_t*>(payload_ptr),
        static_cast<uint32_t>(payload_len));

    if (!tls_info.is_client_hello) {
        return decision;
    }

    decision.detected_tls_client_hello = true;

    std::vector<uint32_t> split_offsets;
    const uint32_t sni_mid = tls_info.sni_split_offset();

    switch (cfg.tcp.split_mode) {
        case TcpSplitMode::FirstByte:
            split_offsets.push_back(2u);
            break;
        case TcpSplitMode::SniMiddle:
            if (sni_mid >= 2u && sni_mid < payload_len) {
                split_offsets.push_back(sni_mid);
            } else {
                split_offsets.push_back(2u);
            }
            break;
        case TcpSplitMode::RecordAndSni:
            split_offsets.push_back(2u);
            if (sni_mid > 2u && sni_mid < payload_len) {
                split_offsets.push_back(sni_mid);
            }
            break;
        case TcpSplitMode::None:
        default:
            return decision;
    }

    if (split_tcp_packet(
            packet_bytes,
            packet_len,
            split_offsets,
            cfg.tcp.reverse_order,
            decision.segments)) {
        decision.action = DpiAction::ReplaceWithSegments;
    }

    return decision;
}

} // namespace discorddpi
