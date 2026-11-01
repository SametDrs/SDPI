#pragma once

#include "discorddpi/flow_tracker.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace discorddpi {

struct SocketMonitorStartResult {
    bool ok{false};
    uint32_t win32_error{0};
    std::string message{};
};

class SocketMonitor {
public:
    explicit SocketMonitor(FlowTracker& flow_tracker, bool enable_ipv6 = true);
    ~SocketMonitor();

    SocketMonitor(const SocketMonitor&) = delete;
    SocketMonitor& operator=(const SocketMonitor&) = delete;

    [[nodiscard]] SocketMonitorStartResult start();
    void stop();

    [[nodiscard]] bool is_running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

private:
    void socket_thread_loop();
    void flow_thread_loop();

    FlowTracker& flow_tracker_;
    bool enable_ipv6_{true};

    void* socket_handle_{nullptr};
    void* flow_handle_{nullptr};

    std::atomic<bool> running_{false};
    std::thread socket_thread_;
    std::thread flow_thread_;
};

} // namespace discorddpi
