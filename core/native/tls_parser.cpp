#include "sdpi/tls_parser.hpp"

#include <algorithm>

namespace discorddpi {

namespace {

constexpr uint16_t read_u16_be(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

constexpr uint32_t read_u24_be(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

} // namespace

TlsClientHelloInfo TlsParser::parse_client_hello(
    const uint8_t* payload,
    uint32_t payload_len) noexcept {
    TlsClientHelloInfo info{};

    // Minimum bytes required up through session_id_len:
    // 5 (TLS record) + 4 (Handshake hdr) + 2 (client_version) + 32 (Random) + 1 (sid_len) = 44
    if (payload == nullptr || payload_len < 44) {
        return info;
    }

    // TLS Record Header: ContentType::handshake (0x16), legacy version 0x0300..0x0304
    if (payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04) {
        return info;
    }

    const uint16_t record_ver = read_u16_be(payload + 1);
    const uint16_t record_len = read_u16_be(payload + 3);
    if (record_len < 39) {
        return info;
    }

    // Handshake Header: HandshakeType::client_hello (0x01)
    if (payload[5] != 0x01) {
        return info;
    }
    const uint32_t hs_len = read_u24_be(payload + 6);
    if (hs_len < 35) {
        return info;
    }

    // ClientHello legacy_version: 0x0300..0x0304
    if (payload[9] != 0x03 || payload[10] > 0x04) {
        return info;
    }

    const uint32_t full_record_end = 5u + static_cast<uint32_t>(record_len);
    const uint32_t full_hs_end = 9u + hs_len;
    if (full_hs_end > full_record_end) {
        return info;
    }

    // Support both single-segment ClientHello and multi-MSS (e.g., X25519MLKEM768)
    // ClientHello where the TLS record continues in the next TCP segment.
    const uint32_t avail_end = std::min(payload_len, full_hs_end);

    uint32_t cursor = 43; // Offset of session_id_length
    const uint8_t session_id_len = payload[cursor];
    cursor += 1;
    if (session_id_len > 32 || cursor + session_id_len > avail_end) {
        return info;
    }
    cursor += session_id_len;

    // Cipher suites
    if (cursor + 2 > avail_end) {
        return info;
    }
    const uint16_t cipher_suites_len = read_u16_be(payload + cursor);
    cursor += 2;
    if (cipher_suites_len < 2 || (cipher_suites_len % 2) != 0 ||
        cursor + cipher_suites_len > avail_end) {
        return info;
    }
    cursor += cipher_suites_len;

    // Compression methods
    if (cursor + 1 > avail_end) {
        return info;
    }
    const uint8_t comp_methods_len = payload[cursor];
    cursor += 1;
    if (comp_methods_len < 1 || cursor + comp_methods_len > avail_end) {
        return info;
    }
    cursor += comp_methods_len;

    // At this point we have structurally verified a genuine TLS ClientHello!
    info.is_client_hello = true;
    info.record_complete_in_segment = (full_record_end <= payload_len);
    info.record_version = record_ver;
    info.record_length = record_len;
    info.handshake_length = hs_len;

    // Extensions block (optional in TLS 1.2, mandatory in TLS 1.3)
    if (cursor + 2 > avail_end) {
        return info;
    }
    const uint16_t extensions_total_len = read_u16_be(payload + cursor);
    cursor += 2;

    const uint32_t logical_ext_end = cursor + static_cast<uint32_t>(extensions_total_len);
    if (logical_ext_end > full_hs_end) {
        // Malformed extensions length; return ClientHello without SNI offset.
        return info;
    }
    const uint32_t ext_avail_end = std::min(avail_end, logical_ext_end);

    while (cursor + 4 <= ext_avail_end) {
        const uint32_t ext_start = cursor;
        const uint16_t ext_type = read_u16_be(payload + cursor);
        const uint16_t ext_len = read_u16_be(payload + cursor + 2);
        cursor += 4;

        if (cursor + ext_len > ext_avail_end) {
            // Extension straddles the TCP segment boundary; stop scanning cleanly.
            break;
        }

        if (ext_type == 0x0000 && ext_len >= 5) { // server_name (RFC 6066)
            const uint32_t sni_end = cursor + ext_len;
            const uint16_t list_len = read_u16_be(payload + cursor);
            uint32_t sni_cur = cursor + 2;
            if (sni_cur + list_len <= sni_end) {
                const uint32_t list_end = sni_cur + list_len;
                while (sni_cur + 3 <= list_end) {
                    const uint8_t name_type = payload[sni_cur];
                    const uint16_t name_len = read_u16_be(payload + sni_cur + 1);
                    sni_cur += 3;
                    if (sni_cur + name_len > list_end) {
                        break;
                    }
                    if (name_type == 0x00 && name_len > 0) { // host_name
                        info.has_sni = true;
                        info.sni_ext_offset = ext_start;
                        info.sni_host_offset = sni_cur;
                        info.sni_host_length = name_len;
                        return info;
                    }
                    sni_cur += name_len;
                }
            }
        }

        cursor += ext_len;
    }

    return info;
}

} // namespace discorddpi
