#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

fs::path find_pythonw() {
    wchar_t buf[MAX_PATH] = {};
    if (SearchPathW(nullptr, L"pythonw.exe", nullptr, MAX_PATH, buf, nullptr) > 0) {
        return fs::path(buf);
    }
    if (SearchPathW(nullptr, L"python.exe", nullptr, MAX_PATH, buf, nullptr) > 0) {
        fs::path p(buf);
        fs::path pw = p.parent_path() / L"pythonw.exe";
        if (fs::is_regular_file(pw)) {
            return pw;
        }
        return p;
    }

    wchar_t local_app[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app, MAX_PATH) > 0) {
        fs::path py_root = fs::path(local_app) / L"Programs" / L"Python";
        std::error_code ec;
        if (fs::is_directory(py_root, ec)) {
            for (const auto& entry : fs::directory_iterator(py_root, ec)) {
                fs::path candidate = entry.path() / L"pythonw.exe";
                if (fs::is_regular_file(candidate, ec)) {
                    return candidate;
                }
            }
        }
    }
    return {};
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR lpCmdLine, int) {
    SetCurrentProcessExplicitAppUserModelID(L"SametDrs.SDPI.Desktop.1.0");

    wchar_t exe_buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe_buf, MAX_PATH);
    fs::path exe_dir = fs::path(exe_buf).parent_path();

    fs::path main_py = exe_dir / L"app" / L"main.py";
    if (!fs::is_regular_file(main_py)) {
        main_py = exe_dir.parent_path() / L"app" / L"main.py";
        if (fs::is_regular_file(main_py)) {
            exe_dir = exe_dir.parent_path();
        }
    }

    fs::path py_exe = find_pythonw();
    if (py_exe.empty() || !fs::is_regular_file(main_py)) {
        MessageBoxW(
            nullptr,
            L"SDPI baslatilamadi: Python calisma ortami veya app/main.py bulunamadi.",
            L"SDPI",
            MB_ICONERROR | MB_OK);
        return 1;
    }

    std::wstring cmd = L"\"" + py_exe.wstring() + L"\" \"" + main_py.wstring() + L"\"";
    if (lpCmdLine != nullptr && lpCmdLine[0] != L'\0') {
        cmd += L" ";
        cmd += lpCmdLine;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back(L'\0');

    const BOOL ok = CreateProcessW(
        nullptr,
        mutable_cmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        exe_dir.wstring().c_str(),
        &si,
        &pi);

    if (!ok) {
        MessageBoxW(
            nullptr,
            L"SDPI masaustu arayuzu baslatilamadi.",
            L"SDPI",
            MB_ICONERROR | MB_OK);
        return 1;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
