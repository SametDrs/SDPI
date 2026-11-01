#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "discorddpi/safety_manager.hpp"

#include <mutex>

namespace discorddpi {

namespace {

std::mutex g_handler_mutex;
SafetyManager* g_active_instance = nullptr;
std::function<void()> g_stop_callback;

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT: {
            std::function<void()> cb;
            {
                std::lock_guard lock(g_handler_mutex);
                if (g_active_instance != nullptr) {
                    g_active_instance->request_stop();
                }
                cb = g_stop_callback;
            }
            if (cb) {
                cb();
            }
            return TRUE;
        }
        default:
            return FALSE;
    }
}

} // namespace

SafetyManager::SafetyManager() = default;

SafetyManager::~SafetyManager() {
    {
        std::lock_guard lock(g_handler_mutex);
        if (g_active_instance == this) {
            SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
            g_active_instance = nullptr;
            g_stop_callback = nullptr;
        }
    }
    stop_parent_watchdog();
    release_single_instance();
}

bool SafetyManager::acquire_single_instance(std::string& out_error) {
    if (instance_mutex_ != nullptr) {
        return true;
    }

    HANDLE m = CreateMutexW(nullptr, TRUE, L"Global\\SDPI.Engine.SingleInstance");
    DWORD err = GetLastError();

    if (m == nullptr && err == ERROR_ACCESS_DENIED) {
        // Either another elevated instance already created the Global mutex, or we
        // lack Global\ creation rights. Check if it already exists via OpenMutexW:
        HANDLE existing = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\SDPI.Engine.SingleInstance");
        if (existing != nullptr) {
            CloseHandle(existing);
            out_error = "Baska bir SDPI motor ornegi zaten calisiyor.";
            return false;
        }
        m = CreateMutexW(nullptr, TRUE, L"Local\\SDPI.Engine.SingleInstance");
        err = GetLastError();
    }

    if (m == nullptr) {
        out_error = "Tekil ornek kilidi olusturulamadi (Win32 hata kodu " +
                    std::to_string(err) + ").";
        return false;
    }

    if (err == ERROR_ALREADY_EXISTS) {
        CloseHandle(m);
        out_error = "Baska bir SDPI motor ornegi zaten calisiyor.";
        return false;
    }

    instance_mutex_ = m;
    out_error.clear();
    return true;
}

void SafetyManager::release_single_instance() noexcept {
    if (instance_mutex_ != nullptr) {
        ReleaseMutex(static_cast<HANDLE>(instance_mutex_));
        CloseHandle(static_cast<HANDLE>(instance_mutex_));
        instance_mutex_ = nullptr;
    }
}

void SafetyManager::install_signal_handlers(std::function<void()> on_stop_requested) {
    std::lock_guard lock(g_handler_mutex);
    g_active_instance = this;
    g_stop_callback = std::move(on_stop_requested);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
}

bool SafetyManager::start_parent_watchdog(uint32_t parent_pid) {
    stop_parent_watchdog();
    if (parent_pid == 0) {
        return false;
    }

    HANDLE parent_h = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(parent_pid));
    if (parent_h == nullptr) {
        return false;
    }

    HANDLE stop_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stop_ev == nullptr) {
        CloseHandle(parent_h);
        return false;
    }

    watchdog_stop_event_ = stop_ev;
    watchdog_thread_ = std::thread(&SafetyManager::watchdog_loop, this, parent_h);
    return true;
}

void SafetyManager::stop_parent_watchdog() noexcept {
    if (watchdog_stop_event_ != nullptr) {
        SetEvent(static_cast<HANDLE>(watchdog_stop_event_));
    }
    if (watchdog_thread_.joinable()) {
        watchdog_thread_.join();
    }
    if (watchdog_stop_event_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(watchdog_stop_event_));
        watchdog_stop_event_ = nullptr;
    }
}

void SafetyManager::watchdog_loop(void* parent_handle) {
    HANDLE handles[2] = {
        static_cast<HANDLE>(parent_handle),
        static_cast<HANDLE>(watchdog_stop_event_)};

    const DWORD res = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    CloseHandle(static_cast<HANDLE>(parent_handle));

    if (res == WAIT_OBJECT_0) {
        // Parent GUI process exited unexpectedly; trigger clean engine shutdown.
        request_stop();
        std::function<void()> cb;
        {
            std::lock_guard lock(g_handler_mutex);
            cb = g_stop_callback;
        }
        if (cb) {
            cb();
        }
    }
}

void SafetyManager::request_stop() noexcept {
    stop_flag_.store(true, std::memory_order_release);
}

bool SafetyManager::stop_requested() const noexcept {
    return stop_flag_.load(std::memory_order_acquire);
}

bool SafetyManager::is_process_elevated() noexcept {
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    BOOL is_member = FALSE;
    if (AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &admin_group)) {
        if (!CheckTokenMembership(nullptr, admin_group, &is_member)) {
            is_member = FALSE;
        }
        FreeSid(admin_group);
    }
    return is_member != FALSE;
}

} // namespace discorddpi
