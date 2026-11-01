#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include "windivert.h"

#include "discorddpi/packet_filter.hpp"

namespace discorddpi {

std::string IpAddress128::to_string() const {
    char buf[64]{};
    if (is_ipv4_mapped()) {
        if (WinDivertHelperFormatIPv4Address(words[0], buf, sizeof(buf))) {
            return std::string(buf);
        }
        return "0.0.0.0";
    }
    if (WinDivertHelperFormatIPv6Address(words.data(), buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "::";
}

const char* to_string(FlowClassification c) noexcept {
    switch (c) {
        case FlowClassification::Discord:
            return "Discord";
        case FlowClassification::NonDiscord:
            return "NonDiscord";
        case FlowClassification::Unknown:
        default:
            return "Unknown";
    }
}

const char* to_string(FlowSource s) noexcept {
    switch (s) {
        case FlowSource::SocketLayer:
            return "SocketLayer";
        case FlowSource::FlowLayer:
            return "FlowLayer";
        case FlowSource::IpHelperSeed:
            return "IpHelperSeed";
        case FlowSource::UdpPortBinding:
            return "UdpPortBinding";
        case FlowSource::Unknown:
        default:
            return "Unknown";
    }
}

const char* to_string(ProcessRole r) noexcept {
    switch (r) {
        case ProcessRole::Main:
            return "Main";
        case ProcessRole::NetworkUtility:
            return "NetworkUtility";
        case ProcessRole::Renderer:
            return "Renderer";
        case ProcessRole::GpuOrMedia:
            return "GpuOrMedia";
        case ProcessRole::Updater:
            return "Updater";
        case ProcessRole::OtherChild:
            return "Child";
        case ProcessRole::Unknown:
        default:
            return "Unknown";
    }
}

const char* to_string(TcpSplitMode m) noexcept {
    switch (m) {
        case TcpSplitMode::FirstByte:
            return "first_byte";
        case TcpSplitMode::SniMiddle:
            return "sni_middle";
        case TcpSplitMode::RecordAndSni:
            return "record_and_sni";
        case TcpSplitMode::None:
        default:
            return "none";
    }
}

const char* to_string(QuicStrategy q) noexcept {
    switch (q) {
        case QuicStrategy::DropDiscordQuic443:
            return "drop_discord_quic_443";
        case QuicStrategy::Observe:
        default:
            return "observe";
    }
}

ParsedPacket PacketFilter::parse(
    const uint8_t* packet_bytes,
    uint32_t packet_len,
    bool outbound) noexcept {
    ParsedPacket out{};
    out.outbound = outbound;
    out.total_len = packet_len;

    if (packet_bytes == nullptr || packet_len < 20) {
        return out;
    }

    PWINDIVERT_IPHDR ip_hdr = nullptr;
    PWINDIVERT_IPV6HDR ipv6_hdr = nullptr;
    UINT8 protocol = 0;
    PWINDIVERT_TCPHDR tcp_hdr = nullptr;
    PWINDIVERT_UDPHDR udp_hdr = nullptr;
    PVOID data_ptr = nullptr;
    UINT data_len = 0;

    const BOOL ok = WinDivertHelperParsePacket(
        packet_bytes,
        static_cast<UINT>(packet_len),
        &ip_hdr,
        &ipv6_hdr,
        &protocol,
        nullptr,
        nullptr,
        &tcp_hdr,
        &udp_hdr,
        &data_ptr,
        &data_len,
        nullptr,
        nullptr);

    if (!ok || (ip_hdr == nullptr && ipv6_hdr == nullptr)) {
        return out;
    }

    IpAddress128 src_addr{};
    IpAddress128 dst_addr{};

    if (ip_hdr != nullptr) {
        const uint32_t ip_hdr_bytes = static_cast<uint32_t>(ip_hdr->HdrLength) * 4u;
        const uint32_t ip_total_len = WinDivertHelperNtohs(ip_hdr->Length);
        if (ip_hdr->Version != 4 || ip_hdr_bytes < 20 || ip_total_len < ip_hdr_bytes ||
            ip_total_len > packet_len) {
            return out;
        }
        out.valid_ip = true;
        out.is_ipv6 = false;

        if (WINDIVERT_IPHDR_GET_FRAGOFF(ip_hdr) != 0 || WINDIVERT_IPHDR_GET_MF(ip_hdr)) {
            out.is_ip_fragment = true;
        }

        src_addr = IpAddress128::from_ipv4_host(WinDivertHelperNtohl(ip_hdr->SrcAddr));
        dst_addr = IpAddress128::from_ipv4_host(WinDivertHelperNtohl(ip_hdr->DstAddr));
    } else {
        if (packet_len < 40 || ipv6_hdr->Version != 6) {
            return out;
        }
        const uint32_t ipv6_payload_len = WinDivertHelperNtohs(ipv6_hdr->Length);
        if (40u + ipv6_payload_len > packet_len) {
            return out;
        }
        out.valid_ip = true;
        out.is_ipv6 = true;

        UINT src_words[4]{};
        UINT dst_words[4]{};
        WinDivertHelperNtohIPv6Address(ipv6_hdr->SrcAddr, src_words);
        WinDivertHelperNtohIPv6Address(ipv6_hdr->DstAddr, dst_words);
        src_addr = IpAddress128::from_windivert_words(src_words);
        dst_addr = IpAddress128::from_windivert_words(dst_words);
    }

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (protocol == static_cast<uint8_t>(Protocol::Tcp) && tcp_hdr != nullptr) {
        const uint32_t tcp_hdr_bytes = static_cast<uint32_t>(tcp_hdr->HdrLength) * 4u;
        if (tcp_hdr_bytes < 20) {
            return out;
        }
        src_port = WinDivertHelperNtohs(tcp_hdr->SrcPort);
        dst_port = WinDivertHelperNtohs(tcp_hdr->DstPort);

        out.tcp_fin = (tcp_hdr->Fin != 0);
        out.tcp_syn = (tcp_hdr->Syn != 0);
        out.tcp_rst = (tcp_hdr->Rst != 0);
        out.tcp_psh = (tcp_hdr->Psh != 0);
        out.tcp_ack = (tcp_hdr->Ack != 0);
        out.tcp_flags = static_cast<uint8_t>(
            (out.tcp_fin ? 0x01u : 0u) |
            (out.tcp_syn ? 0x02u : 0u) |
            (out.tcp_rst ? 0x04u : 0u) |
            (out.tcp_psh ? 0x08u : 0u) |
            (out.tcp_ack ? 0x10u : 0u));
        out.valid_five_tuple = true;
    } else if (protocol == static_cast<uint8_t>(Protocol::Udp) && udp_hdr != nullptr) {
        const uint32_t udp_len = WinDivertHelperNtohs(udp_hdr->Length);
        if (udp_len < 8) {
            return out;
        }
        src_port = WinDivertHelperNtohs(udp_hdr->SrcPort);
        dst_port = WinDivertHelperNtohs(udp_hdr->DstPort);
        out.valid_five_tuple = true;
    } else {
        return out;
    }

    out.flow_key.protocol = protocol;
    if (outbound) {
        out.flow_key.local_addr = src_addr;
        out.flow_key.local_port = src_port;
        out.flow_key.remote_addr = dst_addr;
        out.flow_key.remote_port = dst_port;
    } else {
        out.flow_key.local_addr = dst_addr;
        out.flow_key.local_port = dst_port;
        out.flow_key.remote_addr = src_addr;
        out.flow_key.remote_port = src_port;
    }

    out.payload = static_cast<const uint8_t*>(data_ptr);
    out.payload_len = static_cast<uint32_t>(data_len);
    return out;
}

bool PacketFilter::looks_like_tls_client_hello(
    const uint8_t* payload,
    uint32_t payload_len) noexcept {
    // TLS record header (5 bytes):
    //   [0]    = 0x16 (ContentType::handshake)
    //   [1..2] = 0x03 0x01..0x04 (legacy record version)
    //   [3..4] = record length (>= 4)
    // Handshake header (4 bytes):
    //   [5]    = 0x01 (HandshakeType::client_hello)
    //   [6..8] = 24-bit ClientHello length
    // ClientHello version (2 bytes):
    //   [9..10] = 0x03 0x01..0x04
    if (payload == nullptr || payload_len < 43) {
        return false;
    }
    if (payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04) {
        return false;
    }
    const uint16_t record_len =
        static_cast<uint16_t>((static_cast<uint16_t>(payload[3]) << 8) | payload[4]);
    if (record_len < 38) {
        return false;
    }
    if (payload[5] != 0x01) {
        return false;
    }
    if (payload[9] != 0x03 || payload[10] > 0x04) {
        return false;
    }
    return true;
}

} // namespace discorddpi
