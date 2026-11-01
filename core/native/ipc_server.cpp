#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <sddl.h>

#include "sdpi/ipc_server.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <unordered_map>

namespace discorddpi {

namespace {

constexpr std::size_t kMaxRequestLineBytes = 8192;

std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(std::string_view s) {
    if (s.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const unsigned char ch : s) {
        switch (ch) {
            case '\"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (ch < 0x20u) {
                    char hex[7]{};
                    std::snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned int>(ch));
                    out += hex;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return out;
}

std::string make_error_json(std::string_view message) {
    return std::string("{\"ok\":false,\"error\":\"") + json_escape(message) + "\"}";
}

enum class JsonValKind : uint8_t {
    String,
    Bool,
    Number,
    Null,
};

struct JsonVal {
    JsonValKind kind{JsonValKind::Null};
    std::string str{};
    bool boolean{false};
};

void skip_ws(std::string_view sv, std::size_t& pos) noexcept {
    while (pos < sv.size() &&
           (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == '\r' || sv[pos] == '\n')) {
        ++pos;
    }
}

bool parse_json_string(std::string_view sv, std::size_t& pos, std::string& out) {
    out.clear();
    if (pos >= sv.size() || sv[pos] != '\"') {
        return false;
    }
    ++pos;
    while (pos < sv.size()) {
        const char c = sv[pos++];
        if (c == '\"') {
            return true;
        }
        if (static_cast<unsigned char>(c) < 0x20u) {
            return false;
        }
        if (c == '\\') {
            if (pos >= sv.size()) {
                return false;
            }
            const char esc = sv[pos++];
            switch (esc) {
                case '\"':
                    out.push_back('\"');
                    break;
                case '\\':
                    out.push_back('\\');
                    break;
                case '/':
                    out.push_back('/');
                    break;
                case 'b':
                    out.push_back('\b');
                    break;
                case 'f':
                    out.push_back('\f');
                    break;
                case 'n':
                    out.push_back('\n');
                    break;
                case 'r':
                    out.push_back('\r');
                    break;
                case 't':
                    out.push_back('\t');
                    break;
                case 'u': {
                    if (pos + 4 > sv.size()) {
                        return false;
                    }
                    uint32_t code = 0;
                    for (int i = 0; i < 4; ++i) {
                        const char hc = sv[pos++];
                        code <<= 4;
                        if (hc >= '0' && hc <= '9') {
                            code |= static_cast<uint32_t>(hc - '0');
                        } else if (hc >= 'a' && hc <= 'f') {
                            code |= static_cast<uint32_t>(10 + (hc - 'a'));
                        } else if (hc >= 'A' && hc <= 'F') {
                            code |= static_cast<uint32_t>(10 + (hc - 'A'));
                        } else {
                            return false;
                        }
                    }
                    if (code < 0x80u) {
                        out.push_back(static_cast<char>(code));
                    } else {
                        out.push_back('?');
                    }
                    break;
                }
                default:
                    return false;
            }
        } else {
            out.push_back(c);
        }
    }
    return false;
}

bool parse_flat_json_object(
    std::string_view sv,
    std::unordered_map<std::string, JsonVal>& out_fields) {
    out_fields.clear();
    std::size_t pos = 0;
    skip_ws(sv, pos);
    if (pos >= sv.size() || sv[pos] != '{') {
        return false;
    }
    ++pos;
    skip_ws(sv, pos);
    if (pos < sv.size() && sv[pos] == '}') {
        ++pos;
        skip_ws(sv, pos);
        return pos == sv.size();
    }

    while (pos < sv.size()) {
        skip_ws(sv, pos);
        std::string key;
        if (!parse_json_string(sv, pos, key)) {
            return false;
        }
        skip_ws(sv, pos);
        if (pos >= sv.size() || sv[pos] != ':') {
            return false;
        }
        ++pos;
        skip_ws(sv, pos);
        if (pos >= sv.size()) {
            return false;
        }

        JsonVal val{};
        if (sv[pos] == '\"') {
            val.kind = JsonValKind::String;
            if (!parse_json_string(sv, pos, val.str)) {
                return false;
            }
        } else if (sv.substr(pos, 4) == "true") {
            val.kind = JsonValKind::Bool;
            val.boolean = true;
            pos += 4;
        } else if (sv.substr(pos, 5) == "false") {
            val.kind = JsonValKind::Bool;
            val.boolean = false;
            pos += 5;
        } else if (sv.substr(pos, 4) == "null") {
            val.kind = JsonValKind::Null;
            pos += 4;
        } else if (sv[pos] == '-' || (sv[pos] >= '0' && sv[pos] <= '9')) {
            val.kind = JsonValKind::Number;
            const std::size_t start = pos;
            if (sv[pos] == '-') {
                ++pos;
            }
            if (pos >= sv.size() || sv[pos] < '0' || sv[pos] > '9') {
                return false;
            }
            while (pos < sv.size() &&
                   ((sv[pos] >= '0' && sv[pos] <= '9') || sv[pos] == '.' ||
                    sv[pos] == 'e' || sv[pos] == 'E' || sv[pos] == '+' || sv[pos] == '-')) {
                ++pos;
            }
            val.str = std::string(sv.substr(start, pos - start));
        } else {
            return false;
        }

        out_fields[std::move(key)] = std::move(val);

        skip_ws(sv, pos);
        if (pos >= sv.size()) {
            return false;
        }
        if (sv[pos] == ',') {
            ++pos;
            continue;
        }
        if (sv[pos] == '}') {
            ++pos;
            skip_ws(sv, pos);
            return pos == sv.size();
        }
        return false;
    }
    return false;
}

std::string serialize_status_json(const IpcStatusPayload& p) {
    std::ostringstream oss;
    oss << "{\"ok\":true,\"cmd\":\"get_status\""
        << ",\"engine_version\":\"" << json_escape(p.engine_version) << "\""
        << ",\"running\":" << (p.running ? "true" : "false")
        << ",\"mode\":\"" << json_escape(p.mode) << "\""
        << ",\"ipv6\":" << (p.enable_ipv6 ? "true" : "false")
        << ",\"network_filter\":\"" << json_escape(p.network_filter) << "\""
        << ",\"last_warning\":\"" << json_escape(p.last_warning) << "\""
        << ",\"last_error\":\"" << json_escape(p.last_error) << "\"";

    // Active strategy config
    oss << ",\"config\":{"
        << "\"tcp_enabled\":" << (p.dpi_config.tcp.enabled ? "true" : "false")
        << ",\"split_mode\":\"" << to_string(p.dpi_config.tcp.split_mode) << "\""
        << ",\"reverse_order\":" << (p.dpi_config.tcp.reverse_order ? "true" : "false")
        << ",\"quic_strategy\":\"" << to_string(p.dpi_config.udp.quic_strategy) << "\""
        << ",\"target_ports\":[";
    for (std::size_t i = 0; i < p.dpi_config.tcp.target_ports.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << p.dpi_config.tcp.target_ports[i];
    }
    oss << "]}";

    // Full real-time EngineStatsSnapshot
    const auto& s = p.stats;
    oss << ",\"stats\":{"
        << "\"windivert_version_major\":" << s.windivert_version_major
        << ",\"windivert_version_minor\":" << s.windivert_version_minor
        << ",\"uptime_ms\":" << s.uptime_ms
        << ",\"active_discord_processes\":" << s.active_discord_processes
        << ",\"active_discord_flows\":" << s.active_discord_flows
        << ",\"active_discord_tcp_flows\":" << s.active_discord_tcp_flows
        << ",\"active_discord_udp_flows\":" << s.active_discord_udp_flows
        << ",\"active_discord_ipv4_flows\":" << s.active_discord_ipv4_flows
        << ",\"active_discord_ipv6_flows\":" << s.active_discord_ipv6_flows
        << ",\"active_non_discord_flows\":" << s.active_non_discord_flows
        << ",\"socket_events_total\":" << s.socket_events_total
        << ",\"flow_events_total\":" << s.flow_events_total
        << ",\"packets_seen_total\":" << s.packets_seen_total
        << ",\"packets_discord_seen\":" << s.packets_discord_seen
        << ",\"packets_non_discord_passthrough\":" << s.packets_non_discord_passthrough
        << ",\"packets_unknown_passthrough\":" << s.packets_unknown_passthrough
        << ",\"packets_invalid_passthrough\":" << s.packets_invalid_passthrough
        << ",\"packets_modified\":" << s.packets_modified
        << ",\"packets_non_discord_modified\":" << s.packets_non_discord_modified
        << ",\"tls_client_hellos_detected\":" << s.tls_client_hellos_detected
        << ",\"tcp_packets_segmented\":" << s.tcp_packets_segmented
        << ",\"tcp_segments_injected\":" << s.tcp_segments_injected
        << ",\"quic_packets_dropped_discord\":" << s.quic_packets_dropped_discord
        << ",\"bytes_discord_out\":" << s.bytes_discord_out
        << ",\"bytes_discord_in\":" << s.bytes_discord_in
        << ",\"pending_enqueued\":" << s.pending_enqueued
        << ",\"pending_hit_discord\":" << s.pending_hit_discord
        << ",\"pending_hit_non_discord\":" << s.pending_hit_non_discord
        << ",\"pending_timeout_passthrough\":" << s.pending_timeout_passthrough
        << ",\"pending_overflow_passthrough\":" << s.pending_overflow_passthrough
        << "}";

    // Active verified Discord processes (capped at 32)
    oss << ",\"processes\":[";
    const std::size_t proc_limit = std::min<std::size_t>(p.processes.size(), 32);
    for (std::size_t i = 0; i < proc_limit; ++i) {
        const auto& pr = p.processes[i];
        if (i > 0) {
            oss << ",";
        }
        oss << "{\"pid\":" << pr.pid
            << ",\"parent_pid\":" << pr.parent_pid
            << ",\"role\":\"" << to_string(pr.role) << "\""
            << ",\"signature_valid\":" << (pr.signature_valid ? "true" : "false")
            << ",\"signer_name\":\"" << json_escape(wide_to_utf8(pr.signer_name)) << "\""
            << ",\"exe_path\":\"" << json_escape(wide_to_utf8(pr.exe_path)) << "\"}";
    }
    oss << "]";

    // Active verified Discord flows (capped at 64)
    oss << ",\"flows\":[";
    const std::size_t flow_limit = std::min<std::size_t>(p.flows.size(), 64);
    for (std::size_t i = 0; i < flow_limit; ++i) {
        const auto& fl = p.flows[i];
        if (i > 0) {
            oss << ",";
        }
        const char* proto_str =
            (fl.key.protocol == static_cast<uint8_t>(Protocol::Tcp)) ? "TCP" : "UDP";
        const char* ipver_str = fl.key.is_ipv6() ? "IPv6" : "IPv4";
        oss << "{\"pid\":" << fl.pid
            << ",\"ip_version\":\"" << ipver_str << "\""
            << ",\"protocol\":\"" << proto_str << "\""
            << ",\"local_addr\":\"" << json_escape(fl.key.local_addr.to_string()) << "\""
            << ",\"local_port\":" << fl.key.local_port
            << ",\"remote_addr\":\"" << json_escape(fl.key.remote_addr.to_string()) << "\""
            << ",\"remote_port\":" << fl.key.remote_port
            << ",\"source\":\"" << to_string(fl.source) << "\""
            << ",\"tls_hellos\":" << fl.tls_hellos_processed
            << ",\"packets_out\":" << fl.packets_out
            << ",\"packets_in\":" << fl.packets_in
            << ",\"bytes_out\":" << fl.bytes_out
            << ",\"bytes_in\":" << fl.bytes_in << "}";
    }
    oss << "]}";
    return oss.str();
}

bool wait_overlapped_or_stop(
    HANDLE pipe,
    HANDLE stop_event,
    OVERLAPPED& ov,
    DWORD& out_bytes) noexcept {
    out_bytes = 0;
    HANDLE waits[2] = {stop_event, ov.hEvent};
    const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (w == WAIT_OBJECT_0) {
        // Stop requested: cancel pending I/O and wait for kernel completion so stack
        // OVERLAPPED is safely released before returning.
        CancelIoEx(pipe, &ov);
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &ov, &ignored, TRUE);
        return false;
    }
    if (w == WAIT_OBJECT_0 + 1) {
        return GetOverlappedResult(pipe, &ov, &out_bytes, FALSE) == TRUE;
    }
    CancelIoEx(pipe, &ov);
    DWORD ignored = 0;
    GetOverlappedResult(pipe, &ov, &ignored, TRUE);
    return false;
}

bool write_all_overlapped(
    HANDLE pipe,
    HANDLE stop_event,
    HANDLE io_event,
    std::string_view data) noexcept {
    std::size_t offset = 0;
    while (offset < data.size()) {
        ResetEvent(io_event);
        OVERLAPPED ov{};
        ov.hEvent = io_event;

        const DWORD chunk = static_cast<DWORD>(
            std::min<std::size_t>(data.size() - offset, 65536));
        DWORD written = 0;
        const BOOL ok = WriteFile(pipe, data.data() + offset, chunk, &written, &ov);
        if (!ok) {
            const DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                return false;
            }
            if (!wait_overlapped_or_stop(pipe, stop_event, ov, written)) {
                return false;
            }
        }
        if (written == 0) {
            return false;
        }
        offset += written;
    }
    return true;
}

} // namespace

IpcServer::IpcServer(
    IpcServerConfig config,
    StatusCallback on_status,
    ConfigUpdateCallback on_update_config,
    ShutdownCallback on_shutdown)
    : config_(std::move(config)),
      on_status_(std::move(on_status)),
      on_update_config_(std::move(on_update_config)),
      on_shutdown_(std::move(on_shutdown)) {}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::is_valid_pipe_token(std::string_view token) noexcept {
    if (token.empty() || token.size() > 64) {
        return false;
    }
    for (const unsigned char ch : token) {
        const bool ok =
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '.' || ch == '_' || ch == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool IpcServer::query_current_user_sid(std::wstring& out_sid) {
    out_sid.clear();
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        return false;
    }

    DWORD needed = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(tok);
        return false;
    }

    std::vector<uint8_t> buf(needed);
    if (!GetTokenInformation(tok, TokenUser, buf.data(), needed, &needed)) {
        CloseHandle(tok);
        return false;
    }
    CloseHandle(tok);

    const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
    LPWSTR sid_str = nullptr;
    if (!ConvertSidToStringSidW(tu->User.Sid, &sid_str) || sid_str == nullptr) {
        return false;
    }
    out_sid.assign(sid_str);
    LocalFree(sid_str);
    return !out_sid.empty();
}

IpcStartResult IpcServer::start() {
    if (running_.load(std::memory_order_acquire)) {
        return IpcStartResult{true, 0, pipe_path_, "IPC sunucusu zaten aktif."};
    }

    if (!is_valid_pipe_token(config_.pipe_token)) {
        return IpcStartResult{
            false,
            ERROR_INVALID_NAME,
            {},
            "Gecersiz Named Pipe adi (yalnizca [A-Za-z0-9._-] izinli)."};
    }

    std::wstring client_sid = config_.allowed_client_sid;
    if (!client_sid.empty()) {
        PSID validated_sid = nullptr;
        if (!ConvertStringSidToSidW(client_sid.c_str(), &validated_sid) ||
            validated_sid == nullptr) {
            return IpcStartResult{
                false,
                ERROR_INVALID_SID,
                {},
                "Gecersiz --client-sid formati."};
        }
        LocalFree(validated_sid);
    } else {
        if (!query_current_user_sid(client_sid)) {
            return IpcStartResult{
                false,
                GetLastError(),
                {},
                "Mevcut kullanici SID bilgisi okunamadi."};
        }
    }

    // Protected DACL: grant access ONLY to LocalSystem (SY), Builtin Administrators (BA),
    // and the exact launching desktop user SID. Remote SMB clients are rejected.
    const std::wstring sddl =
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + client_sid + L")";

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) ||
        sd == nullptr) {
        const DWORD err = GetLastError();
        return IpcStartResult{
            false,
            err,
            {},
            "Named Pipe DACL guvenlik tanimlayicisi olusturulamadi (hata " +
                std::to_string(err) + ")."};
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    pipe_path_ = "\\\\.\\pipe\\" + config_.pipe_token;
    const std::wstring wide_pipe_path = utf8_to_wide(pipe_path_);

    HANDLE ph = CreateNamedPipeW(
        wide_pipe_path.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,     // Single authoritative pipe instance
        65536, // Outbound buffer
        16384, // Inbound buffer
        0,
        &sa);
    const DWORD create_err = GetLastError();
    LocalFree(sd);

    if (ph == INVALID_HANDLE_VALUE) {
        return IpcStartResult{
            false,
            create_err,
            pipe_path_,
            "Named Pipe olusturulamadi (Win32 hata kodu " + std::to_string(create_err) + ")."};
    }

    HANDLE stop_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stop_ev == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(ph);
        return IpcStartResult{
            false,
            err,
            pipe_path_,
            "IPC durdurma olayi olusturulamadi."};
    }

    pipe_handle_ = ph;
    stop_event_ = stop_ev;
    running_.store(true, std::memory_order_release);
    server_thread_ = std::thread(&IpcServer::server_thread_loop, this);

    return IpcStartResult{true, 0, pipe_path_, "IPC sunucusu aktif."};
}

void IpcServer::stop() {
    const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (stop_event_ != nullptr) {
        SetEvent(static_cast<HANDLE>(stop_event_));
    }
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    if (pipe_handle_ != nullptr) {
        DisconnectNamedPipe(static_cast<HANDLE>(pipe_handle_));
        CloseHandle(static_cast<HANDLE>(pipe_handle_));
        pipe_handle_ = nullptr;
    }
    if (stop_event_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
    (void)was_running;
}

std::string IpcServer::handle_json_line(
    std::string_view line,
    bool& out_request_shutdown) {
    std::optional<bool> ignored_reset_override{};
    return handle_json_line(line, out_request_shutdown, ignored_reset_override);
}

std::string IpcServer::handle_json_line(
    std::string_view line,
    bool& out_request_shutdown,
    std::optional<bool>& out_reset_discord_override) {
    out_request_shutdown = false;
    out_reset_discord_override.reset();

    if (line.empty()) {
        return make_error_json("Bos IPC istegi.");
    }
    if (line.size() > kMaxRequestLineBytes) {
        return make_error_json("IPC istek boyutu siniri asildi (max 8192 bayt).");
    }

    std::unordered_map<std::string, JsonVal> fields;
    if (!parse_flat_json_object(line, fields)) {
        return make_error_json("Gecersiz JSON nesnesi.");
    }

    const auto cmd_it = fields.find("cmd");
    if (cmd_it == fields.end() || cmd_it->second.kind != JsonValKind::String) {
        return make_error_json("Eksik veya gecersiz 'cmd' alani.");
    }

    const std::string& cmd = cmd_it->second.str;
    if (cmd == "ping") {
        return "{\"ok\":true,\"cmd\":\"ping\",\"engine_version\":\"1.0.0\",\"running\":true}";
    }

    if (cmd == "get_status") {
        if (!on_status_) {
            return make_error_json("Durum saglayicisi yapilandirilmamis.");
        }
        return serialize_status_json(on_status_());
    }

    if (cmd == "update_config") {
        if (!on_update_config_) {
            return make_error_json("Yapilandirma guncelleyicisi mevcut degil.");
        }
        IpcConfigUpdate upd{};

        if (const auto it = fields.find("tcp_enabled"); it != fields.end()) {
            if (it->second.kind != JsonValKind::Bool) {
                return make_error_json("'tcp_enabled' boolean olmalidir.");
            }
            upd.tcp_enabled = it->second.boolean;
        }

        if (const auto it = fields.find("reverse_order"); it != fields.end()) {
            if (it->second.kind != JsonValKind::Bool) {
                return make_error_json("'reverse_order' boolean olmalidir.");
            }
            upd.reverse_order = it->second.boolean;
        }

        if (const auto it = fields.find("split_mode"); it != fields.end()) {
            if (it->second.kind != JsonValKind::String) {
                return make_error_json("'split_mode' string olmalidir.");
            }
            const std::string& m = it->second.str;
            if (m == "record_and_sni" || m == "record-sni") {
                upd.split_mode = TcpSplitMode::RecordAndSni;
            } else if (m == "sni_middle" || m == "sni") {
                upd.split_mode = TcpSplitMode::SniMiddle;
            } else if (m == "first_byte" || m == "first") {
                upd.split_mode = TcpSplitMode::FirstByte;
            } else if (m == "none") {
                upd.split_mode = TcpSplitMode::None;
            } else {
                return make_error_json("Bilinmeyen 'split_mode' degeri.");
            }
        }

        if (const auto it = fields.find("quic_strategy"); it != fields.end()) {
            if (it->second.kind != JsonValKind::String) {
                return make_error_json("'quic_strategy' string olmalidir.");
            }
            const std::string& q = it->second.str;
            if (q == "drop_discord_quic_443" || q == "disable") {
                upd.quic_strategy = QuicStrategy::DropDiscordQuic443;
            } else if (q == "observe") {
                upd.quic_strategy = QuicStrategy::Observe;
            } else {
                return make_error_json("Bilinmeyen 'quic_strategy' degeri.");
            }
        }

        if (const auto it = fields.find("reset_discord_on_stop"); it != fields.end()) {
            if (it->second.kind != JsonValKind::Bool) {
                return make_error_json("'reset_discord_on_stop' boolean olmalidir.");
            }
            upd.reset_discord_on_stop = it->second.boolean;
        }

        std::string err_msg;
        if (!on_update_config_(upd, err_msg)) {
            return make_error_json(err_msg.empty() ? "Yapilandirma guncellenemedi." : err_msg);
        }
        return "{\"ok\":true,\"cmd\":\"update_config\"}";
    }

    if (cmd == "shutdown") {
        if (const auto it = fields.find("reset_discord_connections"); it != fields.end()) {
            if (it->second.kind != JsonValKind::Bool) {
                return make_error_json("'reset_discord_connections' boolean olmalidir.");
            }
            out_reset_discord_override = it->second.boolean;
        }
        out_request_shutdown = true;
        return "{\"ok\":true,\"cmd\":\"shutdown\"}";
    }

    return make_error_json("Bilinmeyen komut: " + cmd);
}

void IpcServer::server_thread_loop() {
    HANDLE pipe = static_cast<HANDLE>(pipe_handle_);
    HANDLE stop_ev = static_cast<HANDLE>(stop_event_);
    HANDLE io_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (io_ev == nullptr) {
        return;
    }

    std::string recv_acc;
    recv_acc.reserve(2048);
    char read_buf[2048]{};

    while (running_.load(std::memory_order_acquire)) {
        ResetEvent(io_ev);
        OVERLAPPED connect_ov{};
        connect_ov.hEvent = io_ev;

        BOOL connected = ConnectNamedPipe(pipe, &connect_ov);
        if (!connected) {
            const DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else if (err == ERROR_IO_PENDING) {
                DWORD dummy = 0;
                connected = wait_overlapped_or_stop(pipe, stop_ev, connect_ov, dummy) ? TRUE : FALSE;
            } else {
                Sleep(25);
                continue;
            }
        }

        if (!connected || !running_.load(std::memory_order_acquire)) {
            break;
        }

        recv_acc.clear();
        bool client_alive = true;
        bool trigger_shutdown = false;
        std::optional<bool> shutdown_reset_override{};

        while (client_alive && running_.load(std::memory_order_acquire)) {
            ResetEvent(io_ev);
            OVERLAPPED read_ov{};
            read_ov.hEvent = io_ev;
            DWORD bytes_read = 0;

            const BOOL rok = ReadFile(pipe, read_buf, sizeof(read_buf), &bytes_read, &read_ov);
            if (!rok) {
                const DWORD rerr = GetLastError();
                if (rerr != ERROR_IO_PENDING) {
                    break;
                }
                if (!wait_overlapped_or_stop(pipe, stop_ev, read_ov, bytes_read)) {
                    break;
                }
            }

            if (bytes_read == 0) {
                break;
            }

            recv_acc.append(read_buf, bytes_read);

            // Process every newline-delimited JSON command in recv_acc.
            while (true) {
                const std::size_t nl = recv_acc.find('\n');
                if (nl == std::string::npos) {
                    if (recv_acc.size() > kMaxRequestLineBytes) {
                        const std::string err_resp =
                            make_error_json("IPC satir boyutu siniri asildi (max 8192 bayt).") + "\n";
                        (void)write_all_overlapped(pipe, stop_ev, io_ev, err_resp);
                        client_alive = false;
                    }
                    break;
                }

                std::string line = recv_acc.substr(0, nl);
                recv_acc.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                bool req_shutdown = false;
                std::optional<bool> req_reset_override{};
                std::string resp = handle_json_line(line, req_shutdown, req_reset_override);
                resp.push_back('\n');

                if (!write_all_overlapped(pipe, stop_ev, io_ev, resp)) {
                    client_alive = false;
                    break;
                }

                if (req_shutdown) {
                    FlushFileBuffers(pipe);
                    trigger_shutdown = true;
                    shutdown_reset_override = req_reset_override;
                    client_alive = false;
                    break;
                }
            }
        }

        DisconnectNamedPipe(pipe);

        if (trigger_shutdown) {
            running_.store(false, std::memory_order_release);
            if (on_shutdown_) {
                on_shutdown_(shutdown_reset_override);
            }
            break;
        }
    }

    CloseHandle(io_ev);
}

} // namespace discorddpi
