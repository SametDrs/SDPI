#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "windivert.h"

#include "sdpi/packet_filter.hpp"
#include "sdpi/windivert_manager.hpp"

#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace discorddpi {

static_assert(
    sizeof(WINDIVERT_ADDRESS) <= sizeof(PendingPacket{}.raw_windivert_addr),
    "PendingPacket::raw_windivert_addr must hold WINDIVERT_ADDRESS");

WinDivertManager::WinDivertManager(EngineConfig config)
    : config_(std::move(config)),
      process_tracker_(config_.process_config),
      flow_tracker_(process_tracker_, config_.flow_config),
      socket_monitor_(flow_tracker_, config_.enable_ipv6),
      dpi_engine_(config_.dpi_config) {}

WinDivertManager::~WinDivertManager() {
    stop();
}

void WinDivertManager::update_dpi_config(DpiEngineConfig new_dpi_config) {
    dpi_engine_.update_config(std::move(new_dpi_config));
}

DpiEngineConfig WinDivertManager::current_dpi_config() const {
    return dpi_engine_.config();
}

bool WinDivertManager::validate_filter_syntax(
    const std::string& filter,
    std::string& out_error) {
    const char* err_str = nullptr;
    UINT err_pos = 0;
    if (!WinDivertHelperCompileFilter(
            filter.c_str(),
            WINDIVERT_LAYER_NETWORK,
            nullptr,
            0,
            &err_str,
            &err_pos)) {
        out_error = std::string(err_str ? err_str : "Gecersiz filtre") +
                    " (konum " + std::to_string(err_pos) + ")";
        return false;
    }
    out_error.clear();
    return true;
}

std::string WinDivertManager::build_network_filter() const {
    const std::string ip_clause = config_.enable_ipv6 ? "" : "ip and ";
    if (config_.mode == NetworkMode::ObserveSniff) {
        return ip_clause + "!loopback and (tcp or udp)";
    }

    if (config_.mode == NetworkMode::ObserveDivert) {
        return ip_clause +
               "!loopback and !impostor and outbound and "
               "((tcp and tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16) or "
               "(udp and udp.PayloadLength > 0))";
    }

    // ActiveDpi mode: surgical kernel filter targeting ONLY outbound TLS Handshake
    // initial segments (and optionally outbound UDP 443 when QUIC policy is active).
    const DpiEngineConfig dcfg = dpi_engine_.config();
    std::string tcp_port_clause;
    if (!dcfg.tcp.target_ports.empty()) {
        tcp_port_clause = " and (";
        for (std::size_t i = 0; i < dcfg.tcp.target_ports.size(); ++i) {
            if (i > 0) {
                tcp_port_clause += " or ";
            }
            tcp_port_clause += "tcp.DstPort == " + std::to_string(dcfg.tcp.target_ports[i]);
        }
        tcp_port_clause += ")";
    }

    const std::string tcp_clause =
        "(tcp" + tcp_port_clause + " and tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16)";

    // Always divert outbound UDP 443 in ActiveDpi mode so QUIC strategy can be toggled
    // live via Named Pipe IPC without reopening WinDivert handles (non-Discord UDP 443
    // and Observe mode pass through byte-for-byte unchanged).
    return ip_clause + "!loopback and !impostor and outbound and (" + tcp_clause +
           " or (udp and udp.DstPort == 443 and udp.PayloadLength > 0))";
}

EngineStartResult WinDivertManager::start() {
    if (running_.load(std::memory_order_acquire)) {
        return EngineStartResult{true, 0, "Motor zaten aktif."};
    }

    const std::string net_filter = build_network_filter();
    std::string filter_err;
    if (!validate_filter_syntax(net_filter, filter_err)) {
        return EngineStartResult{
            false, ERROR_INVALID_PARAMETER, "Filtre derleme hatasi: " + filter_err};
    }

    // Step 1: Pre-warm Authenticode signature cache on installed Discord binaries and
    // discover currently running Discord processes before opening WinDivert listeners.
    process_tracker_.prewarm_signatures();
    process_tracker_.scan_and_reap();

    // Step 2: Start SOCKET and FLOW listeners BEFORE seeding tables.
    const auto sm_res = socket_monitor_.start();
    if (!sm_res.ok) {
        return EngineStartResult{false, sm_res.win32_error, sm_res.message};
    }

    // Step 3: Seed pre-existing connections.
    flow_tracker_.seed_existing_connections();

    // Step 4: Open NETWORK handle.
    const UINT64 net_flags = (config_.mode == NetworkMode::ObserveSniff)
                                 ? (WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)
                                 : 0ULL;

    HANDLE nh = WinDivertOpen(net_filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, net_flags);
    if (nh == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        socket_monitor_.stop();
        return EngineStartResult{
            false,
            err,
            "WINDIVERT_LAYER_NETWORK acilamadi (Win32 hata kodu " + std::to_string(err) + ")."};
    }

    WinDivertSetParam(nh, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(nh, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(nh, WINDIVERT_PARAM_QUEUE_SIZE, 8388608);

    UINT64 v_major = 0;
    UINT64 v_minor = 0;
    if (WinDivertGetParam(nh, WINDIVERT_PARAM_VERSION_MAJOR, &v_major)) {
        driver_major_ = static_cast<uint32_t>(v_major);
    }
    if (WinDivertGetParam(nh, WINDIVERT_PARAM_VERSION_MINOR, &v_minor)) {
        driver_minor_ = static_cast<uint32_t>(v_minor);
    }

    network_handle_ = nh;
    start_time_ = SteadyClock::now();

    if (config_.mode == NetworkMode::ObserveDivert || config_.mode == NetworkMode::ActiveDpi) {
        flow_tracker_.start_pending_worker(
            [this](PendingPacket&& pkt, FlowClassification cls) {
                // Hard safety rule: ONLY verified Discord packets in ActiveDpi mode
                // may enter handle_verified_discord_packet; everything else is
                // re-injected byte-for-byte unchanged!
                if (config_.mode == NetworkMode::ActiveDpi &&
                    cls == FlowClassification::Discord &&
                    running_.load(std::memory_order_acquire)) {
                    handle_verified_discord_packet(
                        pkt.key,
                        pkt.outbound,
                        pkt.packet_bytes.data(),
                        static_cast<uint32_t>(pkt.packet_bytes.size()),
                        pkt.raw_windivert_addr.data());
                } else {
                    reinject_unchanged(
                        pkt.packet_bytes.data(),
                        static_cast<uint32_t>(pkt.packet_bytes.size()),
                        pkt.raw_windivert_addr.data());
                }
            });
    }

    running_.store(true, std::memory_order_release);
    network_thread_ = std::thread(&WinDivertManager::network_thread_loop, this);
    housekeeping_thread_ = std::thread(&WinDivertManager::housekeeping_thread_loop, this);

    return EngineStartResult{true, 0, "Motor basariyla baslatildi."};
}

void WinDivertManager::stop() {
    const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (!was_running && network_handle_ == nullptr) {
        socket_monitor_.stop();
        return;
    }

    // 1. Stop receiving new packets, keeping SEND path open so pending packets flush cleanly.
    if (network_handle_ != nullptr) {
        WinDivertShutdown(static_cast<HANDLE>(network_handle_), WINDIVERT_SHUTDOWN_RECV);
    }

    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (housekeeping_thread_.joinable()) {
        housekeeping_thread_.join();
    }

    // 2. Flush and re-inject any deferred packets unchanged before closing NETWORK handle.
    flow_tracker_.stop_pending_worker();

    // 3. Close NETWORK handle, then stop SOCKET/FLOW listeners.
    if (network_handle_ != nullptr) {
        WinDivertShutdown(static_cast<HANDLE>(network_handle_), WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(static_cast<HANDLE>(network_handle_));
        network_handle_ = nullptr;
    }

    socket_monitor_.stop();
}

void WinDivertManager::reinject_unchanged(
    const uint8_t* packet_bytes,
    uint32_t packet_len,
    const void* windivert_addr) noexcept {
    if (network_handle_ == nullptr || packet_bytes == nullptr || packet_len == 0 ||
        windivert_addr == nullptr) {
        return;
    }
    std::lock_guard lock(send_mutex_);
    if (network_handle_ != nullptr) {
        WinDivertSend(
            static_cast<HANDLE>(network_handle_),
            packet_bytes,
            static_cast<UINT>(packet_len),
            nullptr,
            static_cast<const WINDIVERT_ADDRESS*>(windivert_addr));
    }
}

bool WinDivertManager::inject_tcp_segments(
    const std::vector<std::vector<uint8_t>>& segments,
    const void* base_windivert_addr) noexcept {
    if (network_handle_ == nullptr || segments.empty() || base_windivert_addr == nullptr) {
        return false;
    }

    WINDIVERT_ADDRESS seg_addr = *static_cast<const WINDIVERT_ADDRESS*>(base_windivert_addr);
    seg_addr.IPChecksum = 1;
    seg_addr.TCPChecksum = 1;

    std::lock_guard lock(send_mutex_);
    if (network_handle_ == nullptr) {
        return false;
    }

    for (std::size_t i = 0; i < segments.size(); ++i) {
        const auto& seg = segments[i];
        const BOOL sent = WinDivertSend(
            static_cast<HANDLE>(network_handle_),
            seg.data(),
            static_cast<UINT>(seg.size()),
            nullptr,
            &seg_addr);
        if (!sent && i == 0) {
            // Nothing put on wire yet -> allow caller to fall back to unchanged original!
            return false;
        }
    }
    return true;
}

void WinDivertManager::handle_verified_discord_packet(
    const FlowKey& flow_key,
    bool outbound,
    const uint8_t* packet_bytes,
    uint32_t packet_len,
    const void* windivert_addr) noexcept {
    if (!outbound) {
        reinject_unchanged(packet_bytes, packet_len, windivert_addr);
        return;
    }

    if (flow_key.protocol == static_cast<uint8_t>(Protocol::Tcp) &&
        !flow_tracker_.allow_discord_tls_processing(flow_key)) {
        reinject_unchanged(packet_bytes, packet_len, windivert_addr);
        return;
    }

    const DpiDecision decision = dpi_engine_.process_discord_outbound_packet(
        packet_bytes, packet_len, flow_key.protocol, flow_key.remote_port);

    if (decision.detected_tls_client_hello) {
        tls_client_hellos_detected_.fetch_add(1, std::memory_order_relaxed);
        flow_tracker_.record_discord_tls_hello(flow_key);
    }

    switch (decision.action) {
        case DpiAction::ReplaceWithSegments: {
            if (inject_tcp_segments(decision.segments, windivert_addr)) {
                packets_modified_.fetch_add(1, std::memory_order_relaxed);
                tcp_packets_segmented_.fetch_add(1, std::memory_order_relaxed);
                tcp_segments_injected_.fetch_add(
                    decision.segments.size(), std::memory_order_relaxed);
            } else {
                // Fail-open safety: re-inject original packet unchanged.
                reinject_unchanged(packet_bytes, packet_len, windivert_addr);
            }
            break;
        }
        case DpiAction::DropPacket: {
            // Used exclusively for verified Discord outbound UDP 443 QUIC fallback.
            packets_modified_.fetch_add(1, std::memory_order_relaxed);
            quic_packets_dropped_discord_.fetch_add(1, std::memory_order_relaxed);
            break;
        }
        case DpiAction::PassthroughUnchanged:
        default: {
            reinject_unchanged(packet_bytes, packet_len, windivert_addr);
            break;
        }
    }
}

void WinDivertManager::network_thread_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    HANDLE h = static_cast<HANDLE>(network_handle_);
    const bool is_sniff = (config_.mode == NetworkMode::ObserveSniff);
    const bool is_active_dpi = (config_.mode == NetworkMode::ActiveDpi);

    std::vector<uint8_t> buffer(WINDIVERT_MTU_MAX);
    WINDIVERT_ADDRESS addr{};
    UINT recv_len = 0;

    while (running_.load(std::memory_order_acquire)) {
        if (!WinDivertRecv(
                h,
                buffer.data(),
                static_cast<UINT>(buffer.size()),
                &recv_len,
                &addr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || !running_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        packets_seen_total_.fetch_add(1, std::memory_order_relaxed);

        const ParsedPacket parsed =
            PacketFilter::parse(buffer.data(), recv_len, addr.Outbound != 0);

        if (!parsed.valid_five_tuple || parsed.is_ip_fragment) {
            packets_invalid_passthrough_.fetch_add(1, std::memory_order_relaxed);
            if (!is_sniff) {
                reinject_unchanged(buffer.data(), recv_len, &addr);
            }
            continue;
        }

        const FlowClassification cls = flow_tracker_.classify_and_account_packet(
            parsed.flow_key, parsed.outbound, recv_len);

        if (is_sniff) {
            if (cls == FlowClassification::Unknown) {
                packets_unknown_passthrough_.fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }

        // Strict Non-Discord isolation fast path: NEVER touch non-Discord packets!
        if (cls == FlowClassification::NonDiscord) {
            reinject_unchanged(buffer.data(), recv_len, &addr);
            continue;
        }

        if (cls == FlowClassification::Discord) {
            if (is_active_dpi) {
                handle_verified_discord_packet(
                    parsed.flow_key, parsed.outbound, buffer.data(), recv_len, &addr);
            } else {
                reinject_unchanged(buffer.data(), recv_len, &addr);
            }
            continue;
        }

        // Unknown classification: defer up to 25 ms waiting for SOCKET/FLOW event.
        PendingPacket pending{};
        pending.key = parsed.flow_key;
        pending.outbound = parsed.outbound;
        pending.packet_bytes.assign(buffer.data(), buffer.data() + recv_len);
        std::memcpy(pending.raw_windivert_addr.data(), &addr, sizeof(WINDIVERT_ADDRESS));

        if (!flow_tracker_.enqueue_pending_packet(std::move(pending))) {
            packets_unknown_passthrough_.fetch_add(1, std::memory_order_relaxed);
            reinject_unchanged(buffer.data(), recv_len, &addr);
        }
    }
}

void WinDivertManager::housekeeping_thread_loop() {
    uint32_t tick = 0;
    while (running_.load(std::memory_order_acquire)) {
        for (int i = 0; i < 10 && running_.load(std::memory_order_acquire); ++i) {
            Sleep(100);
        }
        if (!running_.load(std::memory_order_acquire)) {
            break;
        }

        ++tick;
        std::vector<uint32_t> exited_pids =
            (tick % 3 == 0) ? process_tracker_.scan_and_reap() : process_tracker_.reap_exited();

        for (const uint32_t pid : exited_pids) {
            flow_tracker_.purge_process_flows(pid);
        }

        if (tick % 5 == 0) {
            flow_tracker_.cleanup_expired_flows();
        }
    }
}

EngineStatsSnapshot WinDivertManager::snapshot_stats() const {
    EngineStatsSnapshot s{};
    s.windivert_version_major = driver_major_;
    s.windivert_version_minor = driver_minor_;
    if (running_.load(std::memory_order_acquire)) {
        s.uptime_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                SteadyClock::now() - start_time_)
                .count());
    }
    s.packets_seen_total = packets_seen_total_.load(std::memory_order_relaxed);
    s.packets_invalid_passthrough = packets_invalid_passthrough_.load(std::memory_order_relaxed);
    s.packets_unknown_passthrough = packets_unknown_passthrough_.load(std::memory_order_relaxed);
    s.packets_modified = packets_modified_.load(std::memory_order_relaxed);
    s.packets_non_discord_modified = 0;

    s.tls_client_hellos_detected = tls_client_hellos_detected_.load(std::memory_order_relaxed);
    s.tcp_packets_segmented = tcp_packets_segmented_.load(std::memory_order_relaxed);
    s.tcp_segments_injected = tcp_segments_injected_.load(std::memory_order_relaxed);
    s.quic_packets_dropped_discord =
        quic_packets_dropped_discord_.load(std::memory_order_relaxed);

    flow_tracker_.populate_stats(s);
    return s;
}

std::vector<ProcessIdentity> WinDivertManager::active_discord_processes() const {
    return process_tracker_.active_discord_processes();
}

std::vector<FlowRecord> WinDivertManager::active_discord_flows() const {
    return flow_tracker_.active_discord_flows();
}

uint32_t WinDivertManager::reset_discord_connections() {
    process_tracker_.scan_and_reap();
    const auto procs = process_tracker_.active_discord_processes();
    if (procs.empty()) {
        return 0;
    }

    const DWORD self_pid = GetCurrentProcessId();
    std::unordered_map<uint32_t, ProcessIdentity> verified_by_pid;
    verified_by_pid.reserve(procs.size());
    for (const auto& p : procs) {
        if (p.pid <= 4 || p.pid == self_pid) {
            continue;
        }
        if (config_.process_config.verify_signature && !p.signature_valid) {
            continue;
        }
        verified_by_pid.emplace(p.pid, p);
    }

    if (verified_by_pid.empty()) {
        return 0;
    }

    uint32_t reset_count = 0;
    std::unordered_set<uint32_t> pids_with_listen_socket;
    std::unordered_set<uint32_t> pids_with_remote_tcp;

    // 1. Delete non-loopback IPv4 TCP TCBs owned strictly by verified Discord PIDs.
    ULONG v4_size = 0;
    DWORD v4_rc = GetExtendedTcpTable(
        nullptr, &v4_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> v4_buf;
    for (int attempt = 0; attempt < 3 && v4_rc == ERROR_INSUFFICIENT_BUFFER && v4_size > 0;
         ++attempt) {
        v4_buf.resize(v4_size);
        v4_rc = GetExtendedTcpTable(
            v4_buf.data(), &v4_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    if (v4_rc == NO_ERROR && v4_buf.size() >= sizeof(DWORD)) {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(v4_buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (verified_by_pid.find(row.dwOwningPid) == verified_by_pid.end()) {
                continue;
            }
            if (row.dwState == MIB_TCP_STATE_LISTEN) {
                pids_with_listen_socket.insert(row.dwOwningPid);
                continue;
            }

            const uint32_t local_host = ntohl(row.dwLocalAddr);
            const uint32_t remote_host = ntohl(row.dwRemoteAddr);
            if (remote_host == 0 || (local_host >> 24) == 127 || (remote_host >> 24) == 127) {
                continue;
            }

            pids_with_remote_tcp.insert(row.dwOwningPid);

            MIB_TCPROW del_row{};
            del_row.dwState = MIB_TCP_STATE_DELETE_TCB;
            del_row.dwLocalAddr = row.dwLocalAddr;
            del_row.dwLocalPort = row.dwLocalPort;
            del_row.dwRemoteAddr = row.dwRemoteAddr;
            del_row.dwRemotePort = row.dwRemotePort;
            if (SetTcpEntry(&del_row) == NO_ERROR) {
                ++reset_count;
            }
        }
    }

    // 2. Inspect IPv6 TCP table for verified Discord processes (Windows iphlpapi has no
    //    SetTcp6Entry; Discord's IPv6 HTTP/2 & WebSocket tunnels and in-memory TLS/ECH
    //    session cache live inside Chromium's out-of-process NetworkService child).
    auto is_v6_unspec_or_loopback = [](const UCHAR (&addr)[16]) noexcept -> bool {
        for (int idx = 0; idx < 15; ++idx) {
            if (addr[idx] != 0) {
                return false;
            }
        }
        return addr[15] == 0 || addr[15] == 1;
    };

    ULONG v6_size = 0;
    DWORD v6_rc = GetExtendedTcpTable(
        nullptr, &v6_size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> v6_buf;
    for (int attempt = 0; attempt < 3 && v6_rc == ERROR_INSUFFICIENT_BUFFER && v6_size > 0;
         ++attempt) {
        v6_buf.resize(v6_size);
        v6_rc = GetExtendedTcpTable(
            v6_buf.data(), &v6_size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    if (v6_rc == NO_ERROR && v6_buf.size() >= sizeof(DWORD)) {
        const auto* table6 = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(v6_buf.data());
        for (DWORD i = 0; i < table6->dwNumEntries; ++i) {
            const auto& row = table6->table[i];
            if (verified_by_pid.find(row.dwOwningPid) == verified_by_pid.end()) {
                continue;
            }
            if (row.dwState == MIB_TCP_STATE_LISTEN) {
                pids_with_listen_socket.insert(row.dwOwningPid);
                continue;
            }
            if (is_v6_unspec_or_loopback(row.ucLocalAddr) ||
                is_v6_unspec_or_loopback(row.ucRemoteAddr)) {
                continue;
            }
            pids_with_remote_tcp.insert(row.dwOwningPid);
        }
    }

    // 3. Recycle verified Discord NetworkUtility (network.mojom.NetworkService) child
    //    process(es) so IPv6 sockets and Chromium's TLS 1.3 / ECH cache reset immediately
    //    while keeping Discord's Main window and Renderer intact.
    std::vector<ProcessIdentity> network_children;
    for (const auto& [pid, id] : verified_by_pid) {
        if (id.role == ProcessRole::NetworkUtility) {
            network_children.push_back(id);
        }
    }

    // Fallback if command-line inspection was unavailable: target only OtherChild
    // processes that own remote TCP connections and NO listening sockets (never Main,
    // Renderer, GpuOrMedia, or Updater).
    if (network_children.empty()) {
        for (const auto& [pid, id] : verified_by_pid) {
            if (id.role == ProcessRole::OtherChild &&
                pids_with_remote_tcp.find(pid) != pids_with_remote_tcp.end() &&
                pids_with_listen_socket.find(pid) == pids_with_listen_socket.end()) {
                network_children.push_back(id);
            }
        }
    }

    for (const auto& target : network_children) {
        HANDLE h = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(target.pid));
        if (h == nullptr) {
            continue;
        }

        FILETIME create_ft{}, exit_ft{}, kernel_ft{}, user_ft{};
        if (GetProcessTimes(h, &create_ft, &exit_ft, &kernel_ft, &user_ft)) {
            const uint64_t live_creation =
                (static_cast<uint64_t>(create_ft.dwHighDateTime) << 32) |
                create_ft.dwLowDateTime;
            // Exact creation-time verification eliminates any TOCTOU PID-reuse risk.
            if (live_creation == target.creation_time_100ns) {
                if (TerminateProcess(h, 0)) {
                    (void)WaitForSingleObject(h, 250);
                    ++reset_count;
                }
            }
        }
        CloseHandle(h);
    }

    (void)process_tracker_.reap_exited();
    return reset_count;
}

} // namespace discorddpi
