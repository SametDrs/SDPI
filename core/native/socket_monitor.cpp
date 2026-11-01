#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include "windivert.h"

#include "discorddpi/socket_monitor.hpp"

namespace discorddpi {

namespace {

std::string describe_windivert_error(const char* layer_name, DWORD err) {
    std::string msg = std::string(layer_name) + " acilamadi (Win32 hata kodu " +
                      std::to_string(err) + "): ";
    switch (err) {
        case ERROR_ACCESS_DENIED:
            msg += "Yonetici (Administrator) yetkisi gerekiyor.";
            break;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
            msg += "WinDivert64.sys surucu dosyasi bulunamadi.";
            break;
        case ERROR_INVALID_PARAMETER:
            msg += "Gecersiz WinDivert filtre ifadesi veya bayrak.";
            break;
        case ERROR_INVALID_IMAGE_HASH:
            msg += "WinDivert64.sys dijital imza dogrulamasi Windows/AV tarafindan reddedildi.";
            break;
        case ERROR_DRIVER_BLOCKED:
            msg += "Surucu yuklemesi sistem politikasi veya antivirus tarafindan engellendi.";
            break;
        default:
            msg += "Beklenmeyen sistem hatasi.";
            break;
    }
    return msg;
}

FlowKey make_flow_key_from_socket_data(const WINDIVERT_DATA_SOCKET& s) noexcept {
    FlowKey key{};
    key.local_addr = IpAddress128::from_windivert_words(s.LocalAddr);
    key.remote_addr = IpAddress128::from_windivert_words(s.RemoteAddr);
    key.local_port = s.LocalPort;
    key.remote_port = s.RemotePort;
    key.protocol = s.Protocol;
    return key;
}

FlowKey make_flow_key_from_flow_data(const WINDIVERT_DATA_FLOW& f) noexcept {
    FlowKey key{};
    key.local_addr = IpAddress128::from_windivert_words(f.LocalAddr);
    key.remote_addr = IpAddress128::from_windivert_words(f.RemoteAddr);
    key.local_port = f.LocalPort;
    key.remote_port = f.RemotePort;
    key.protocol = f.Protocol;
    return key;
}

} // namespace

SocketMonitor::SocketMonitor(FlowTracker& flow_tracker, bool enable_ipv6)
    : flow_tracker_(flow_tracker),
      enable_ipv6_(enable_ipv6) {}

SocketMonitor::~SocketMonitor() {
    stop();
}

SocketMonitorStartResult SocketMonitor::start() {
    if (running_.load(std::memory_order_acquire)) {
        return SocketMonitorStartResult{true, 0, "Zaten calisiyor."};
    }

    const char* filter = enable_ipv6_
                             ? "(tcp or udp) and !loopback"
                             : "ip and (tcp or udp) and !loopback";

    // CRITICAL: WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY ensures passive
    // observation so socket operations are NEVER blocked.
    HANDLE sh = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_SOCKET,
        1000,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (sh == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        return SocketMonitorStartResult{
            false, err, describe_windivert_error("WINDIVERT_LAYER_SOCKET", err)};
    }
    WinDivertSetParam(sh, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);

    HANDLE fh = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_FLOW,
        1000,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (fh == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        WinDivertClose(sh);
        return SocketMonitorStartResult{
            false, err, describe_windivert_error("WINDIVERT_LAYER_FLOW", err)};
    }
    WinDivertSetParam(fh, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);

    socket_handle_ = sh;
    flow_handle_ = fh;
    running_.store(true, std::memory_order_release);

    socket_thread_ = std::thread(&SocketMonitor::socket_thread_loop, this);
    flow_thread_ = std::thread(&SocketMonitor::flow_thread_loop, this);

    return SocketMonitorStartResult{true, 0, "SOCKET ve FLOW dinleyicileri baslatildi."};
}

void SocketMonitor::stop() {
    const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (!was_running && socket_handle_ == nullptr && flow_handle_ == nullptr) {
        return;
    }

    if (socket_handle_ != nullptr) {
        WinDivertShutdown(static_cast<HANDLE>(socket_handle_), WINDIVERT_SHUTDOWN_BOTH);
    }
    if (flow_handle_ != nullptr) {
        WinDivertShutdown(static_cast<HANDLE>(flow_handle_), WINDIVERT_SHUTDOWN_BOTH);
    }

    if (socket_thread_.joinable()) {
        socket_thread_.join();
    }
    if (flow_thread_.joinable()) {
        flow_thread_.join();
    }

    if (socket_handle_ != nullptr) {
        WinDivertClose(static_cast<HANDLE>(socket_handle_));
        socket_handle_ = nullptr;
    }
    if (flow_handle_ != nullptr) {
        WinDivertClose(static_cast<HANDLE>(flow_handle_));
        flow_handle_ = nullptr;
    }
}

void SocketMonitor::socket_thread_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    HANDLE h = static_cast<HANDLE>(socket_handle_);

    WINDIVERT_ADDRESS addr{};
    while (running_.load(std::memory_order_acquire)) {
        if (!WinDivertRecv(h, nullptr, 0, nullptr, &addr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || !running_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        const auto& s = addr.Socket;
        switch (addr.Event) {
            case WINDIVERT_EVENT_SOCKET_CONNECT:
            case WINDIVERT_EVENT_SOCKET_ACCEPT: {
                const FlowKey key = make_flow_key_from_socket_data(s);
                flow_tracker_.on_socket_connect_or_accept(key, s.ProcessId, s.EndpointId);
                break;
            }
            case WINDIVERT_EVENT_SOCKET_BIND: {
                const IpAddress128 local_addr = IpAddress128::from_windivert_words(s.LocalAddr);
                flow_tracker_.on_socket_bind(
                    local_addr, s.LocalPort, s.Protocol, s.ProcessId, s.EndpointId);
                break;
            }
            case WINDIVERT_EVENT_SOCKET_CLOSE: {
                const FlowKey key = make_flow_key_from_socket_data(s);
                flow_tracker_.on_socket_close(key, s.ProcessId, s.EndpointId);
                break;
            }
            default:
                break;
        }
    }
}

void SocketMonitor::flow_thread_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    HANDLE h = static_cast<HANDLE>(flow_handle_);

    WINDIVERT_ADDRESS addr{};
    while (running_.load(std::memory_order_acquire)) {
        if (!WinDivertRecv(h, nullptr, 0, nullptr, &addr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || !running_.load(std::memory_order_acquire)) {
                break;
            }
            continue;
        }

        const auto& f = addr.Flow;
        const FlowKey key = make_flow_key_from_flow_data(f);
        if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
            flow_tracker_.on_flow_established(key, f.ProcessId, f.EndpointId);
        } else if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED) {
            flow_tracker_.on_flow_deleted(key, f.ProcessId, f.EndpointId);
        }
    }
}

} // namespace discorddpi
