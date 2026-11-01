#pragma once

#include <cstdint>

namespace discorddpi {

struct TlsClientHelloInfo {
    bool is_client_hello{false};
    bool record_complete_in_segment{false};
    uint16_t record_version{0};
    uint16_t record_length{0};
    uint32_t handshake_length{0};

    bool has_sni{false};
    uint32_t sni_ext_offset{0};
    uint32_t sni_host_offset{0};
    uint16_t sni_host_length{0};

    // Returns midpoint byte offset inside the SNI host_name, or 0 if no SNI was
    // found within the current TCP segment.
    [[nodiscard]] constexpr uint32_t sni_split_offset() const noexcept {
        if (!has_sni || sni_host_length < 2) {
            return 0;
        }
        return sni_host_offset + static_cast<uint32_t>(sni_host_length / 2u);
    }
};

class TlsParser {
public:
    // Parses a TCP payload to detect a TLS 1.2 / 1.3 ClientHello (including
    // post-quantum multi-MSS ClientHello segments where record_length exceeds a
    // single TCP segment's payload_len) and locates the SNI host_name byte range.
    // Strictly bounds-checked; never copies or logs SNI text.
    [[nodiscard]] static TlsClientHelloInfo parse_client_hello(
        const uint8_t* payload,
        uint32_t payload_len) noexcept;
};

} // namespace discorddpi
