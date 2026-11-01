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

#include "discorddpi/flow_tracker.hpp"

#include <algorithm>

namespace discorddpi {

namespace {

bool is_multicast_or_broadcast(const IpAddress128& addr) noexcept {
    if (addr.is_ipv4_mapped()) {
        const uint32_t v4 = addr.ipv4_host();
        if (v4 == 0xFFFFFFFFu) {
            return true;
        }
        // 224.0.0.0/4 multicast
        if ((v4 & 0xF0000000u) == 0xE0000000u) {
            return true;
        }
        return false;
    }
    // IPv6 ff00::/8 multicast: most-significant byte is in words[3] >> 24
    return ((addr.words[3] >> 24) & 0xFFu) == 0xFFu;
}

} // namespace

FlowTracker::FlowTracker(ProcessTracker& process_tracker, FlowTrackerConfig config)
    : process_tracker_(process_tracker),
      config_(config) {}

FlowTracker::~FlowTracker() {
    stop_pending_worker();
}

void FlowTracker::start_pending_worker(PacketDecisionCallback callback) {
    stop_pending_worker();
    {
        std::lock_guard lock(pending_mutex_);
        pending_callback_ = std::move(callback);
        pending_running_ = true;
    }
    pending_thread_ = std::thread(&FlowTracker::pending_worker_loop, this);
}

void FlowTracker::stop_pending_worker() {
    PacketDecisionCallback cb_copy;
    std::deque<PendingPacket> remaining;

    {
        std::lock_guard lock(pending_mutex_);
        if (!pending_running_ && !pending_thread_.joinable()) {
            return;
        }
        pending_running_ = false;
        cb_copy = pending_callback_;
    }
    pending_cv_.notify_all();

    if (pending_thread_.joinable()) {
        pending_thread_.join();
    }

    {
        std::lock_guard lock(pending_mutex_);
        remaining.swap(pending_queue_);
    }

    // Safety invariant: flush every remaining queued packet unchanged on shutdown.
    if (cb_copy) {
        while (!remaining.empty()) {
            PendingPacket pkt = std::move(remaining.front());
            remaining.pop_front();
            pending_timeout_passthrough_.fetch_add(1, std::memory_order_relaxed);
            cb_copy(std::move(pkt), FlowClassification::Unknown);
        }
    }
}

FlowClassification FlowTracker::resolve_pid_classification(
    uint32_t pid,
    uint64_t& out_creation_time) const {
    out_creation_time = 0;
    if (pid <= 4 || pid == GetCurrentProcessId()) {
        return FlowClassification::NonDiscord;
    }
    auto identity = process_tracker_.classify_pid(pid);
    if (identity.has_value()) {
        out_creation_time = identity->creation_time_100ns;
        return FlowClassification::Discord;
    }
    return FlowClassification::NonDiscord;
}

void FlowTracker::upsert_flow_locked(
    const FlowKey& key,
    uint32_t pid,
    uint64_t creation_time,
    uint64_t endpoint_id,
    FlowClassification classification,
    FlowSource source,
    TimePoint now) {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowRecord rec{};
        rec.key = key;
        rec.pid = pid;
        rec.process_creation_time = creation_time;
        rec.endpoint_id = endpoint_id;
        rec.classification = classification;
        rec.source = source;
        rec.first_seen = now;
        rec.last_seen = now;
        flows_.emplace(key, rec);
    } else {
        // Protect verified Discord flows from spurious kernel (System PID <= 4) or
        // self-injection (engine PID after WinDivertSend segment injection) overwrites.
        if (it->second.classification == FlowClassification::Discord &&
            classification != FlowClassification::Discord) {
            if (pid <= 4 || pid == GetCurrentProcessId() ||
                process_tracker_.is_discord_pid(it->second.pid)) {
                if (endpoint_id != 0 && it->second.endpoint_id == 0) {
                    it->second.endpoint_id = endpoint_id;
                }
                it->second.last_seen = now;
                it->second.closing = false;
                return;
            }
        }
        it->second.pid = pid;
        if (creation_time != 0) {
            it->second.process_creation_time = creation_time;
        }
        if (endpoint_id != 0) {
            it->second.endpoint_id = endpoint_id;
        }
        it->second.classification = classification;
        it->second.source = source;
        it->second.last_seen = now;
        it->second.closing = false;
    }
}

void FlowTracker::on_socket_connect_or_accept(
    const FlowKey& key,
    uint32_t pid,
    uint64_t endpoint_id) {
    socket_events_total_.fetch_add(1, std::memory_order_relaxed);

    uint64_t creation_time = 0;
    const FlowClassification cls = resolve_pid_classification(pid, creation_time);
    const TimePoint now = SteadyClock::now();

    {
        std::unique_lock lock(flow_mutex_);
        if (!key.local_addr.is_wildcard() && !key.remote_addr.is_wildcard() &&
            key.local_port != 0 && key.remote_port != 0) {
            upsert_flow_locked(
                key, pid, creation_time, endpoint_id, cls, FlowSource::SocketLayer, now);
        } else if (key.local_port != 0 && !key.remote_addr.is_wildcard() && key.remote_port != 0) {
            // Wildcard local IP during early connect(): record partial entry so first
            // packet with concrete local IP promotes it into exact `flows_`.
            PartialConnectKey pk{key.remote_addr, key.local_port, key.remote_port, key.protocol};
            partial_connects_[pk] = PartialConnectEntry{
                pid, creation_time, endpoint_id, cls, now};
        }
    }

    notify_pending_for_flow();
}

void FlowTracker::on_socket_bind(
    const IpAddress128& local_addr,
    uint16_t local_port,
    uint8_t protocol,
    uint32_t pid,
    uint64_t endpoint_id) {
    socket_events_total_.fetch_add(1, std::memory_order_relaxed);

    if (protocol != static_cast<uint8_t>(Protocol::Udp) || local_port == 0) {
        return;
    }

    uint64_t creation_time = 0;
    const FlowClassification cls = resolve_pid_classification(pid, creation_time);

    {
        std::unique_lock lock(flow_mutex_);
        auto& owners = udp_port_bindings_[local_port];
        auto existing = std::find_if(owners.begin(), owners.end(), [&](const UdpPortOwner& o) {
            return (endpoint_id != 0 && o.endpoint_id == endpoint_id) ||
                   (o.pid == pid && o.local_addr == local_addr);
        });
        if (existing != owners.end()) {
            existing->classification = cls;
            existing->process_creation_time = creation_time;
            existing->endpoint_id = endpoint_id;
        } else {
            owners.push_back(UdpPortOwner{pid, creation_time, endpoint_id, local_addr, cls});
        }
    }

    notify_pending_for_flow();
}

void FlowTracker::on_socket_close(
    const FlowKey& key,
    uint32_t pid,
    uint64_t endpoint_id) {
    socket_events_total_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(flow_mutex_);
    if (!key.remote_addr.is_wildcard() && key.local_port != 0 && key.remote_port != 0) {
        auto it = flows_.find(key);
        if (it != flows_.end()) {
            if (endpoint_id == 0 || it->second.endpoint_id == 0 ||
                it->second.endpoint_id == endpoint_id) {
                flows_.erase(it);
            }
        }
    }
    if (key.protocol == static_cast<uint8_t>(Protocol::Udp) && key.local_port != 0) {
        auto bit = udp_port_bindings_.find(key.local_port);
        if (bit != udp_port_bindings_.end()) {
            auto& owners = bit->second;
            owners.erase(
                std::remove_if(owners.begin(), owners.end(), [&](const UdpPortOwner& o) {
                    if (endpoint_id != 0 && o.endpoint_id != 0) {
                        return o.endpoint_id == endpoint_id;
                    }
                    return o.pid == pid;
                }),
                owners.end());
            if (owners.empty()) {
                udp_port_bindings_.erase(bit);
            }
        }
    }
}

void FlowTracker::on_flow_established(
    const FlowKey& key,
    uint32_t pid,
    uint64_t endpoint_id) {
    flow_events_total_.fetch_add(1, std::memory_order_relaxed);

    uint64_t creation_time = 0;
    const FlowClassification cls = resolve_pid_classification(pid, creation_time);
    const TimePoint now = SteadyClock::now();

    {
        std::unique_lock lock(flow_mutex_);
        upsert_flow_locked(key, pid, creation_time, endpoint_id, cls, FlowSource::FlowLayer, now);

        PartialConnectKey pk{key.remote_addr, key.local_port, key.remote_port, key.protocol};
        partial_connects_.erase(pk);
    }

    notify_pending_for_flow();
}

void FlowTracker::on_flow_deleted(
    const FlowKey& key,
    uint32_t /*pid*/,
    uint64_t /*endpoint_id*/) {
    flow_events_total_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lock(flow_mutex_);
    flows_.erase(key);
}

std::optional<FlowClassification> FlowTracker::lookup_classification_locked(
    const FlowKey& key,
    TimePoint now) {
    // 1. Exact 5-tuple lookup
    const auto it = flows_.find(key);
    if (it != flows_.end()) {
        return it->second.classification;
    }

    // 2. Partial connect lookup (when SOCKET_CONNECT had wildcard local address)
    const PartialConnectKey pk{key.remote_addr, key.local_port, key.remote_port, key.protocol};
    const auto pit = partial_connects_.find(pk);
    if (pit != partial_connects_.end()) {
        if ((now - pit->second.created_at) <= std::chrono::seconds(10)) {
            return pit->second.classification;
        }
    }

    // 3. Unambiguous UDP local port binding lookup (for unconnected UDP sendto/recvfrom)
    if (key.protocol == static_cast<uint8_t>(Protocol::Udp) &&
        !is_multicast_or_broadcast(key.remote_addr)) {
        const auto bit = udp_port_bindings_.find(key.local_port);
        if (bit != udp_port_bindings_.end() && !bit->second.empty()) {
            bool any_discord = false;
            bool any_non_discord = false;
            for (const auto& owner : bit->second) {
                if (!owner.local_addr.is_wildcard() && owner.local_addr != key.local_addr) {
                    continue;
                }
                if (owner.classification == FlowClassification::Discord) {
                    any_discord = true;
                } else {
                    any_non_discord = true;
                }
            }
            // Safety rule: ONLY classify as Discord if every matching socket binding on
            // this local port belongs exclusively to Discord (never if ambiguous/shared).
            if (any_discord && !any_non_discord) {
                return FlowClassification::Discord;
            }
            if (any_non_discord && !any_discord) {
                return FlowClassification::NonDiscord;
            }
        }
    }

    return std::nullopt;
}

FlowClassification FlowTracker::classify_and_account_packet(
    const FlowKey& key,
    bool outbound,
    uint32_t packet_bytes_len) {
    const TimePoint now = SteadyClock::now();

    std::unique_lock lock(flow_mutex_);

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        // Check if partial connect can be promoted to an exact 5-tuple flow
        const PartialConnectKey pk{key.remote_addr, key.local_port, key.remote_port, key.protocol};
        const auto pit = partial_connects_.find(pk);
        if (pit != partial_connects_.end()) {
            const auto entry = pit->second;
            partial_connects_.erase(pit);
            if ((now - entry.created_at) <= std::chrono::seconds(10)) {
                upsert_flow_locked(
                    key,
                    entry.pid,
                    entry.process_creation_time,
                    entry.endpoint_id,
                    entry.classification,
                    FlowSource::SocketLayer,
                    now);
                it = flows_.find(key);
            }
        }
    }

    if (it == flows_.end() &&
        key.protocol == static_cast<uint8_t>(Protocol::Udp) &&
        !is_multicast_or_broadcast(key.remote_addr)) {
        const auto bit = udp_port_bindings_.find(key.local_port);
        if (bit != udp_port_bindings_.end() && !bit->second.empty()) {
            const UdpPortOwner* sole_discord = nullptr;
            bool any_non_discord = false;
            for (const auto& owner : bit->second) {
                if (!owner.local_addr.is_wildcard() && owner.local_addr != key.local_addr) {
                    continue;
                }
                if (owner.classification == FlowClassification::Discord) {
                    sole_discord = &owner;
                } else {
                    any_non_discord = true;
                }
            }
            if (sole_discord != nullptr && !any_non_discord) {
                upsert_flow_locked(
                    key,
                    sole_discord->pid,
                    sole_discord->process_creation_time,
                    sole_discord->endpoint_id,
                    FlowClassification::Discord,
                    FlowSource::UdpPortBinding,
                    now);
                it = flows_.find(key);
            } else if (any_non_discord && sole_discord == nullptr) {
                packets_non_discord_passthrough_.fetch_add(1, std::memory_order_relaxed);
                return FlowClassification::NonDiscord;
            }
        }
    }

    if (it == flows_.end()) {
        return FlowClassification::Unknown;
    }

    it->second.last_seen = now;
    if (outbound) {
        ++it->second.packets_out;
        it->second.bytes_out += packet_bytes_len;
    } else {
        ++it->second.packets_in;
        it->second.bytes_in += packet_bytes_len;
    }

    if (it->second.classification == FlowClassification::Discord) {
        packets_discord_seen_.fetch_add(1, std::memory_order_relaxed);
        if (outbound) {
            bytes_discord_out_.fetch_add(packet_bytes_len, std::memory_order_relaxed);
        } else {
            bytes_discord_in_.fetch_add(packet_bytes_len, std::memory_order_relaxed);
        }
        return FlowClassification::Discord;
    }

    packets_non_discord_passthrough_.fetch_add(1, std::memory_order_relaxed);
    return FlowClassification::NonDiscord;
}

bool FlowTracker::enqueue_pending_packet(PendingPacket&& pkt) {
    std::lock_guard lock(pending_mutex_);
    if (!pending_running_ || !pending_callback_) {
        return false;
    }
    if (pending_queue_.size() >= config_.pending_max_packets) {
        pending_overflow_passthrough_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const TimePoint now = SteadyClock::now();
    pkt.enqueue_time = now;
    pkt.deadline = now + config_.pending_timeout;
    pending_queue_.push_back(std::move(pkt));
    pending_enqueued_.fetch_add(1, std::memory_order_relaxed);
    pending_cv_.notify_one();
    return true;
}

void FlowTracker::notify_pending_for_flow() {
    pending_cv_.notify_all();
}

void FlowTracker::pending_worker_loop() {
    struct ReadyItem {
        PendingPacket pkt;
        FlowClassification classification;
        bool timed_out;
    };
    std::vector<ReadyItem> ready;
    ready.reserve(32);

    while (true) {
        ready.clear();
        PacketDecisionCallback cb;

        {
            std::unique_lock qlock(pending_mutex_);
            if (!pending_running_) {
                break;
            }
            if (pending_queue_.empty()) {
                pending_cv_.wait(qlock, [this] {
                    return !pending_running_ || !pending_queue_.empty();
                });
                if (!pending_running_) {
                    break;
                }
            }

            cb = pending_callback_;
            const TimePoint now = SteadyClock::now();
            TimePoint next_deadline = now + config_.pending_timeout;
            bool any_ready = false;

            {
                std::shared_lock flock(flow_mutex_);
                for (auto it = pending_queue_.begin(); it != pending_queue_.end();) {
                    auto cls_opt = lookup_classification_locked(it->key, now);
                    if (cls_opt.has_value()) {
                        ready.push_back(ReadyItem{std::move(*it), *cls_opt, false});
                        it = pending_queue_.erase(it);
                        any_ready = true;
                    } else if (now >= it->deadline) {
                        ready.push_back(ReadyItem{
                            std::move(*it), FlowClassification::Unknown, true});
                        it = pending_queue_.erase(it);
                        any_ready = true;
                    } else {
                        if (it->deadline < next_deadline) {
                            next_deadline = it->deadline;
                        }
                        ++it;
                    }
                }
            }

            if (!any_ready && pending_running_) {
                pending_cv_.wait_until(qlock, next_deadline);
                continue;
            }
        }

        for (auto& item : ready) {
            if (item.timed_out) {
                pending_timeout_passthrough_.fetch_add(1, std::memory_order_relaxed);
                if (cb) {
                    cb(std::move(item.pkt), FlowClassification::Unknown);
                }
            } else {
                const FlowClassification final_cls = classify_and_account_packet(
                    item.pkt.key,
                    item.pkt.outbound,
                    static_cast<uint32_t>(item.pkt.packet_bytes.size()));
                if (final_cls == FlowClassification::Discord) {
                    pending_hit_discord_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    pending_hit_non_discord_.fetch_add(1, std::memory_order_relaxed);
                }
                if (cb) {
                    cb(std::move(item.pkt), final_cls);
                }
            }
        }
    }
}

std::size_t FlowTracker::purge_process_flows(uint32_t pid) {
    std::size_t removed = 0;
    std::unique_lock lock(flow_mutex_);

    for (auto it = flows_.begin(); it != flows_.end();) {
        if (it->second.pid == pid) {
            it = flows_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    for (auto it = partial_connects_.begin(); it != partial_connects_.end();) {
        if (it->second.pid == pid) {
            it = partial_connects_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = udp_port_bindings_.begin(); it != udp_port_bindings_.end();) {
        auto& owners = it->second;
        owners.erase(
            std::remove_if(owners.begin(), owners.end(), [pid](const UdpPortOwner& o) {
                return o.pid == pid;
            }),
            owners.end());
        if (owners.empty()) {
            it = udp_port_bindings_.erase(it);
        } else {
            ++it;
        }
    }

    return removed;
}

std::size_t FlowTracker::cleanup_expired_flows(TimePoint now) {
    std::size_t removed = 0;
    std::unique_lock lock(flow_mutex_);

    for (auto it = flows_.begin(); it != flows_.end();) {
        const auto timeout = (it->second.classification == FlowClassification::Discord)
                                 ? config_.flow_idle_timeout
                                 : config_.non_discord_flow_ttl;
        if ((now - it->second.last_seen) > timeout) {
            it = flows_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    for (auto it = partial_connects_.begin(); it != partial_connects_.end();) {
        if ((now - it->second.created_at) > std::chrono::seconds(10)) {
            it = partial_connects_.erase(it);
        } else {
            ++it;
        }
    }

    return removed;
}

bool FlowTracker::allow_discord_tls_processing(const FlowKey& key) const {
    std::shared_lock lock(flow_mutex_);
    const auto it = flows_.find(key);
    if (it == flows_.end()) {
        return false;
    }
    if (it->second.classification != FlowClassification::Discord) {
        return false;
    }
    if (it->second.tls_established || it->second.tls_hellos_processed >= 4) {
        return false;
    }
    return true;
}

void FlowTracker::record_discord_tls_hello(const FlowKey& key) {
    std::unique_lock lock(flow_mutex_);
    auto it = flows_.find(key);
    if (it != flows_.end() && it->second.classification == FlowClassification::Discord) {
        ++it->second.tls_hellos_processed;
    }
}

void FlowTracker::seed_existing_connections() {
    const TimePoint now = SteadyClock::now();

    // 1. IPv4 TCP table
    {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        for (int attempt = 0; attempt < 3 && size > 0; ++attempt) {
            std::vector<uint8_t> buf(size);
            const DWORD err = GetExtendedTcpTable(
                buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (err == NO_ERROR) {
                const auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    const auto& row = tbl->table[i];
                    if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwRemotePort == 0) {
                        continue;
                    }
                    uint64_t ctime = 0;
                    const FlowClassification cls =
                        resolve_pid_classification(row.dwOwningPid, ctime);

                    FlowKey key{};
                    key.local_addr = IpAddress128::from_ipv4_host(
                        WinDivertHelperNtohl(row.dwLocalAddr));
                    key.remote_addr = IpAddress128::from_ipv4_host(
                        WinDivertHelperNtohl(row.dwRemoteAddr));
                    key.local_port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwLocalPort));
                    key.remote_port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwRemotePort));
                    key.protocol = static_cast<uint8_t>(Protocol::Tcp);

                    std::unique_lock lock(flow_mutex_);
                    upsert_flow_locked(
                        key, row.dwOwningPid, ctime, 0, cls, FlowSource::IpHelperSeed, now);
                }
                break;
            }
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                break;
            }
        }
    }

    // 2. IPv6 TCP table
    {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        for (int attempt = 0; attempt < 3 && size > 0; ++attempt) {
            std::vector<uint8_t> buf(size);
            const DWORD err = GetExtendedTcpTable(
                buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (err == NO_ERROR) {
                const auto* tbl = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    const auto& row = tbl->table[i];
                    if (row.dwState == MIB_TCP_STATE_LISTEN || row.dwRemotePort == 0) {
                        continue;
                    }
                    uint64_t ctime = 0;
                    const FlowClassification cls =
                        resolve_pid_classification(row.dwOwningPid, ctime);

                    UINT local_w[4]{};
                    UINT remote_w[4]{};
                    WinDivertHelperNtohIPv6Address(
                        reinterpret_cast<const UINT*>(row.ucLocalAddr), local_w);
                    WinDivertHelperNtohIPv6Address(
                        reinterpret_cast<const UINT*>(row.ucRemoteAddr), remote_w);

                    FlowKey key{};
                    key.local_addr = IpAddress128::from_windivert_words(local_w);
                    key.remote_addr = IpAddress128::from_windivert_words(remote_w);
                    key.local_port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwLocalPort));
                    key.remote_port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwRemotePort));
                    key.protocol = static_cast<uint8_t>(Protocol::Tcp);

                    std::unique_lock lock(flow_mutex_);
                    upsert_flow_locked(
                        key, row.dwOwningPid, ctime, 0, cls, FlowSource::IpHelperSeed, now);
                }
                break;
            }
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                break;
            }
        }
    }

    // 3. IPv4 UDP endpoints
    {
        DWORD size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        for (int attempt = 0; attempt < 3 && size > 0; ++attempt) {
            std::vector<uint8_t> buf(size);
            const DWORD err = GetExtendedUdpTable(
                buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (err == NO_ERROR) {
                const auto* tbl = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    const auto& row = tbl->table[i];
                    const uint16_t port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwLocalPort));
                    if (port == 0) {
                        continue;
                    }
                    const IpAddress128 laddr = IpAddress128::from_ipv4_host(
                        WinDivertHelperNtohl(row.dwLocalAddr));
                    on_socket_bind(
                        laddr,
                        port,
                        static_cast<uint8_t>(Protocol::Udp),
                        row.dwOwningPid,
                        0);
                }
                break;
            }
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                break;
            }
        }
    }

    // 4. IPv6 UDP endpoints
    {
        DWORD size = 0;
        GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        for (int attempt = 0; attempt < 3 && size > 0; ++attempt) {
            std::vector<uint8_t> buf(size);
            const DWORD err = GetExtendedUdpTable(
                buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (err == NO_ERROR) {
                const auto* tbl = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    const auto& row = tbl->table[i];
                    const uint16_t port =
                        WinDivertHelperNtohs(static_cast<UINT16>(row.dwLocalPort));
                    if (port == 0) {
                        continue;
                    }
                    UINT local_w[4]{};
                    WinDivertHelperNtohIPv6Address(
                        reinterpret_cast<const UINT*>(row.ucLocalAddr), local_w);
                    const IpAddress128 laddr = IpAddress128::from_windivert_words(local_w);
                    on_socket_bind(
                        laddr,
                        port,
                        static_cast<uint8_t>(Protocol::Udp),
                        row.dwOwningPid,
                        0);
                }
                break;
            }
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                break;
            }
        }
    }
}

std::vector<FlowRecord> FlowTracker::active_discord_flows() const {
    std::vector<FlowRecord> out;
    std::shared_lock lock(flow_mutex_);
    for (const auto& [key, rec] : flows_) {
        if (rec.classification == FlowClassification::Discord) {
            out.push_back(rec);
        }
    }
    return out;
}

void FlowTracker::populate_stats(EngineStatsSnapshot& out_stats) const {
    out_stats.active_discord_processes = process_tracker_.active_discord_count();

    uint32_t discord_flows = 0;
    uint32_t discord_tcp = 0;
    uint32_t discord_udp = 0;
    uint32_t discord_v4 = 0;
    uint32_t discord_v6 = 0;
    uint32_t non_discord_flows = 0;

    {
        std::shared_lock lock(flow_mutex_);
        for (const auto& [key, rec] : flows_) {
            if (rec.classification == FlowClassification::Discord) {
                ++discord_flows;
                if (key.protocol == static_cast<uint8_t>(Protocol::Tcp)) {
                    ++discord_tcp;
                } else if (key.protocol == static_cast<uint8_t>(Protocol::Udp)) {
                    ++discord_udp;
                }
                if (key.is_ipv6()) {
                    ++discord_v6;
                } else {
                    ++discord_v4;
                }
            } else if (rec.classification == FlowClassification::NonDiscord) {
                ++non_discord_flows;
            }
        }
    }

    out_stats.active_discord_flows = discord_flows;
    out_stats.active_discord_tcp_flows = discord_tcp;
    out_stats.active_discord_udp_flows = discord_udp;
    out_stats.active_discord_ipv4_flows = discord_v4;
    out_stats.active_discord_ipv6_flows = discord_v6;
    out_stats.active_non_discord_flows = non_discord_flows;

    out_stats.socket_events_total = socket_events_total_.load(std::memory_order_relaxed);
    out_stats.flow_events_total = flow_events_total_.load(std::memory_order_relaxed);
    out_stats.packets_discord_seen = packets_discord_seen_.load(std::memory_order_relaxed);
    out_stats.packets_non_discord_passthrough =
        packets_non_discord_passthrough_.load(std::memory_order_relaxed);

    out_stats.bytes_discord_out = bytes_discord_out_.load(std::memory_order_relaxed);
    out_stats.bytes_discord_in = bytes_discord_in_.load(std::memory_order_relaxed);

    out_stats.pending_enqueued = pending_enqueued_.load(std::memory_order_relaxed);
    out_stats.pending_hit_discord = pending_hit_discord_.load(std::memory_order_relaxed);
    out_stats.pending_hit_non_discord = pending_hit_non_discord_.load(std::memory_order_relaxed);
    out_stats.pending_timeout_passthrough =
        pending_timeout_passthrough_.load(std::memory_order_relaxed);
    out_stats.pending_overflow_passthrough =
        pending_overflow_passthrough_.load(std::memory_order_relaxed);
}

} // namespace discorddpi
