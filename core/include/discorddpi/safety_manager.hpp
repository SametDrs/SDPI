#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace discorddpi {

class SafetyManager {
public:
    SafetyManager();
    ~SafetyManager();

    SafetyManager(const SafetyManager&) = delete;
    SafetyManager& operator=(const SafetyManager&) = delete;

    // Acquires single-instance named mutex. Returns false if another engine
    // instance is already active on this machine.
    [[nodiscard]] bool acquire_single_instance(std::string& out_error);
    void release_single_instance() noexcept;

    // Installs console control handler (Ctrl+C, console close, shutdown).
    void install_signal_handlers(std::function<void()> on_stop_requested);

    // Optional parent/GUI process watchdog: triggers stop if `parent_pid` exits.
    [[nodiscard]] bool start_parent_watchdog(uint32_t parent_pid);
    void stop_parent_watchdog() noexcept;

    void request_stop() noexcept;
    [[nodiscard]] bool stop_requested() const noexcept;

    [[nodiscard]] static bool is_process_elevated() noexcept;

private:
    void watchdog_loop(void* parent_handle);

    void* instance_mutex_{nullptr};
    void* watchdog_stop_event_{nullptr};
    std::thread watchdog_thread_;
    std::atomic<bool> stop_flag_{false};
};

} // namespace discorddpi
