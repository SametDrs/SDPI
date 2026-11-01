#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "sdpi/flow_tracker.hpp"
#include "sdpi/ipc_server.hpp"
#include "sdpi/process_tracker.hpp"
#include "sdpi/safety_manager.hpp"
#include "sdpi/windivert_manager.hpp"

#include <atomic>
#include <charconv>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace {

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

std::wstring utf8_to_wide(std::string_view sv) {
    if (sv.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, 0, sv.data(), static_cast<int>(sv.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, sv.data(), static_cast<int>(sv.size()), out.data(), needed);
    return out;
}

bool parse_uint32_bounded(
    std::string_view sv,
    uint32_t min_val,
    uint32_t max_val,
    uint32_t& out_val) noexcept {
    if (sv.empty()) {
        return false;
    }
    uint32_t val = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return false;
    }
    if (val < min_val || val > max_val) {
        return false;
    }
    out_val = val;
    return true;
}

void print_usage() {
    std::cout
        << "SDPI Native Engine v1.0.0 (Surec Bazli Trafik Motoru)\n"
        << "Kullanim:\n"
        << "  sdpi-engine.exe --check-processes\n"
        << "      Yonetici izni gerektirmeden Discord sureclerini ve imzalarini tarar.\n\n"
        << "  sdpi-engine.exe --observe-sniff [--duration <0..3600>]\n"
        << "      Pasif gozlem modu (SNIFF | RECV_ONLY). Hicbir paketi degistirmez.\n\n"
        << "  sdpi-engine.exe --observe-divert [--duration <0..3600>]\n"
        << "      Dar aday filtresi + ertelenmis kuyruk testi (0 degisiklik).\n\n"
        << "  sdpi-engine.exe --active [secenekler]\n"
        << "      Yalnizca dogrulanmis Discord akislari icin aktif paket isleme motoru.\n"
        << "      Secenekler:\n"
        << "        --ipc                           Named Pipe IPC sunucusunu baslat (GUI modu)\n"
        << "        --pipe-name <token>             Named Pipe belirteci (varsayilan: SDPI.Engine)\n"
        << "        --client-sid <SID>              Named Pipe DACL istemci kullanici SID'i\n"
        << "        --gui-pid <pid>                 Ebeveyn GUI surec watchdog'u\n"
        << "        --quiet                         Periyodik konsol ciktisini kapat\n"
        << "        --duration <0..86400>           Calisma suresi sn (0 = surekli)\n"
        << "        --split-mode <record-sni|sni|first>  TCP bolme stratejisi (varsayilan: record-sni)\n"
        << "        --reverse-frag / --no-reverse-frag   Segmentleri ters sirada gonder (varsayilan: acik)\n"
        << "        --discord-quic <disable|observe>     Discord UDP 443 QUIC politikasi (varsayilan: disable)\n"
        << "        --reset-discord-on-stop              Durduruldugunda acik Discord baglantilarini sifirla\n"
        << "        --no-ipv6                            IPv6 kapsamini kapat\n";
}

void print_processes_and_flows(
    const std::vector<discorddpi::ProcessIdentity>& procs,
    const std::vector<discorddpi::FlowRecord>& flows) {
    std::cout << "\n--- Algilanan Discord Surecleri (" << procs.size() << ") ---\n";
    for (const auto& p : procs) {
        std::cout << "  PID=" << std::setw(6) << p.pid
                  << " | PPID=" << std::setw(6) << p.parent_pid
                  << " | Rol=" << std::setw(7) << discorddpi::to_string(p.role)
                  << " | Imza=" << (p.signature_valid ? "Valid (" + wide_to_utf8(p.signer_name) + ")" : "Invalid")
                  << " | Yol=" << wide_to_utf8(p.exe_path) << "\n";
    }

    std::cout << "\n--- Algilanan Aktif Discord Akislari (" << flows.size() << ") ---\n";
    for (const auto& f : flows) {
        const char* proto_str =
            (f.key.protocol == static_cast<uint8_t>(discorddpi::Protocol::Tcp)) ? "TCP" : "UDP";
        const char* ipver_str = f.key.is_ipv6() ? "IPv6" : "IPv4";
        std::cout << "  PID=" << std::setw(6) << f.pid
                  << " | " << ipver_str << "/" << proto_str
                  << " | " << f.key.local_addr.to_string() << ":" << f.key.local_port
                  << " <-> " << f.key.remote_addr.to_string() << ":" << f.key.remote_port
                  << " | Kaynak=" << discorddpi::to_string(f.source)
                  << " | TLS_CH=" << f.tls_hellos_processed
                  << " | Pkt(Giden/Gelen)=" << f.packets_out << "/" << f.packets_in
                  << "\n";
    }
}

int run_check_processes() {
    discorddpi::ProcessTracker pt;
    pt.prewarm_signatures();
    pt.scan_and_reap();

    std::cout << "Izlenen kurulum kokleri (" << pt.normalized_roots().size() << "):\n";
    for (const auto& root : pt.normalized_roots()) {
        std::cout << "  - " << wide_to_utf8(root) << "\n";
    }

    discorddpi::FlowTracker ft(pt);
    ft.seed_existing_connections();

    discorddpi::EngineStatsSnapshot stats{};
    ft.populate_stats(stats);

    print_processes_and_flows(pt.active_discord_processes(), ft.active_discord_flows());

    std::cout << "\n--- Sistem Soket Ozeti (IP Helper) ---\n"
              << "  Discord surec sayisi       : " << stats.active_discord_processes << "\n"
              << "  Discord aktif akis         : " << stats.active_discord_flows
              << " (TCP=" << stats.active_discord_tcp_flows
              << ", UDP=" << stats.active_discord_udp_flows
              << ", IPv4=" << stats.active_discord_ipv4_flows
              << ", IPv6=" << stats.active_discord_ipv6_flows << ")\n"
              << "  Discord disi aktif akis    : " << stats.active_non_discord_flows
              << " (izole / kapsam disi)\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    enum class CliCommand { None, Help, CheckProcesses, ObserveSniff, ObserveDivert, ActiveDpi };
    CliCommand cmd = CliCommand::None;
    uint32_t duration_sec = 0;
    bool duration_specified = false;
    uint32_t gui_pid = 0;
    bool enable_ipv6 = true;
    bool enable_ipc = false;
    bool quiet_console = false;
    bool cli_reset_discord_on_stop = false;
    std::string pipe_token = "SDPI.Engine";
    std::wstring client_sid;

    discorddpi::DpiEngineConfig dpi_cfg{};
    dpi_cfg.tcp.enabled = true;
    dpi_cfg.tcp.target_ports = {443, 2053, 2083, 2087, 2096, 8443};
    dpi_cfg.tcp.split_mode = discorddpi::TcpSplitMode::RecordAndSni;
    dpi_cfg.tcp.reverse_order = true;
    dpi_cfg.udp.quic_strategy = discorddpi::QuicStrategy::DropDiscordQuic443;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            cmd = CliCommand::Help;
            break;
        } else if (arg == "--check-processes") {
            if (cmd != CliCommand::None) {
                std::cerr << "HATA: Birden fazla mod bayragi belirtildi.\n";
                return 2;
            }
            cmd = CliCommand::CheckProcesses;
        } else if (arg == "--observe-sniff") {
            if (cmd != CliCommand::None) {
                std::cerr << "HATA: Birden fazla mod bayragi belirtildi.\n";
                return 2;
            }
            cmd = CliCommand::ObserveSniff;
        } else if (arg == "--observe-divert") {
            if (cmd != CliCommand::None) {
                std::cerr << "HATA: Birden fazla mod bayragi belirtildi.\n";
                return 2;
            }
            cmd = CliCommand::ObserveDivert;
        } else if (arg == "--active") {
            if (cmd != CliCommand::None) {
                std::cerr << "HATA: Birden fazla mod bayragi belirtildi.\n";
                return 2;
            }
            cmd = CliCommand::ActiveDpi;
        } else if (arg == "--ipc") {
            enable_ipc = true;
            if (cmd == CliCommand::None) {
                cmd = CliCommand::ActiveDpi;
            }
        } else if (arg == "--quiet") {
            quiet_console = true;
        } else if (arg == "--pipe-name") {
            if (i + 1 >= argc) {
                std::cerr << "HATA: --pipe-name bir belirtec bekliyor.\n";
                return 2;
            }
            pipe_token = argv[++i];
            if (!discorddpi::IpcServer::is_valid_pipe_token(pipe_token)) {
                std::cerr << "HATA: Gecersiz --pipe-name karakteri.\n";
                return 2;
            }
        } else if (arg == "--client-sid") {
            if (i + 1 >= argc) {
                std::cerr << "HATA: --client-sid bir SID degeri bekliyor.\n";
                return 2;
            }
            client_sid = utf8_to_wide(argv[++i]);
        } else if (arg == "--no-ipv6") {
            enable_ipv6 = false;
        } else if (arg == "--reset-discord-on-stop") {
            cli_reset_discord_on_stop = true;
        } else if (arg == "--no-reset-discord-on-stop") {
            cli_reset_discord_on_stop = false;
        } else if (arg == "--reverse-frag") {
            dpi_cfg.tcp.reverse_order = true;
        } else if (arg == "--no-reverse-frag") {
            dpi_cfg.tcp.reverse_order = false;
        } else if (arg == "--split-mode") {
            if (i + 1 >= argc) {
                std::cerr << "HATA: --split-mode deger bekliyor (record-sni | sni | first).\n";
                return 2;
            }
            const std::string_view m(argv[++i]);
            if (m == "record-sni" || m == "record_and_sni") {
                dpi_cfg.tcp.split_mode = discorddpi::TcpSplitMode::RecordAndSni;
            } else if (m == "sni" || m == "sni_middle") {
                dpi_cfg.tcp.split_mode = discorddpi::TcpSplitMode::SniMiddle;
            } else if (m == "first" || m == "first_byte") {
                dpi_cfg.tcp.split_mode = discorddpi::TcpSplitMode::FirstByte;
            } else {
                std::cerr << "HATA: Gecersiz --split-mode: " << m << "\n";
                return 2;
            }
        } else if (arg == "--discord-quic") {
            if (i + 1 >= argc) {
                std::cerr << "HATA: --discord-quic deger bekliyor (disable | observe).\n";
                return 2;
            }
            const std::string_view q(argv[++i]);
            if (q == "disable" || q == "drop_discord_quic_443") {
                dpi_cfg.udp.quic_strategy = discorddpi::QuicStrategy::DropDiscordQuic443;
            } else if (q == "observe") {
                dpi_cfg.udp.quic_strategy = discorddpi::QuicStrategy::Observe;
            } else {
                std::cerr << "HATA: Gecersiz --discord-quic: " << q << "\n";
                return 2;
            }
        } else if (arg == "--duration") {
            if (i + 1 >= argc || !parse_uint32_bounded(argv[++i], 0, 86400, duration_sec)) {
                std::cerr << "HATA: --duration icin 0..86400 araliginda tam sayi gerekli.\n";
                return 2;
            }
            duration_specified = true;
        } else if (arg == "--gui-pid") {
            if (i + 1 >= argc || !parse_uint32_bounded(argv[++i], 1, 0xFFFFFFFFu, gui_pid)) {
                std::cerr << "HATA: --gui-pid icin gecerli bir PID gerekli.\n";
                return 2;
            }
        } else {
            std::cerr << "HATA: Bilinmeyen arguman: " << arg << "\n\n";
            print_usage();
            return 2;
        }
    }

    if (cmd == CliCommand::None || cmd == CliCommand::Help) {
        print_usage();
        return (cmd == CliCommand::Help) ? 0 : 2;
    }

    if (cmd == CliCommand::CheckProcesses) {
        return run_check_processes();
    }

    if (!duration_specified) {
        if (enable_ipc) {
            duration_sec = 0; // Run continuously until GUI shutdown or watchdog exit
        } else {
            duration_sec = (cmd == CliCommand::ActiveDpi) ? 60 : 15;
        }
    }

    if (!discorddpi::SafetyManager::is_process_elevated()) {
        std::cerr << "HATA: WinDivert motoru Yonetici (Administrator) yetkisi gerektirir.\n"
                  << "Lutfen PowerShell'i 'Yonetici olarak calistir' ile acip tekrar deneyin.\n";
        return 5;
    }

    discorddpi::SafetyManager safety;
    std::string mutex_err;
    if (!safety.acquire_single_instance(mutex_err)) {
        std::cerr << "HATA: " << mutex_err << "\n";
        return 3;
    }

    discorddpi::EngineConfig cfg{};
    if (cmd == CliCommand::ActiveDpi) {
        cfg.mode = discorddpi::NetworkMode::ActiveDpi;
    } else if (cmd == CliCommand::ObserveDivert) {
        cfg.mode = discorddpi::NetworkMode::ObserveDivert;
    } else {
        cfg.mode = discorddpi::NetworkMode::ObserveSniff;
    }
    cfg.enable_ipv6 = enable_ipv6;
    cfg.dpi_config = dpi_cfg;

    discorddpi::WinDivertManager engine(cfg);
    std::string watchdog_warning;

    safety.install_signal_handlers([&]() {
        safety.request_stop();
    });
    if (gui_pid != 0) {
        if (!safety.start_parent_watchdog(gui_pid)) {
            watchdog_warning =
                "GUI surec watchdog'u baslatilamadi (PID " + std::to_string(gui_pid) + ").";
            if (!quiet_console) {
                std::cerr << "UYARI: " << watchdog_warning << "\n";
            }
        }
    }

    const char* mode_label =
        (cfg.mode == discorddpi::NetworkMode::ActiveDpi) ? "active" :
        (cfg.mode == discorddpi::NetworkMode::ObserveDivert) ? "observe_divert" : "observe_sniff";

    if (!quiet_console) {
        std::cout << "SDPI Motoru baslatiliyor (mod=" << mode_label
                  << ", sure=" << (duration_sec == 0 ? "surekli" : std::to_string(duration_sec) + " sn")
                  << ", split=" << discorddpi::to_string(dpi_cfg.tcp.split_mode)
                  << ", reverse=" << (dpi_cfg.tcp.reverse_order ? "evet" : "hayir")
                  << ", quic=" << discorddpi::to_string(dpi_cfg.udp.quic_strategy)
                  << ")...\n";
    }

    const auto start_res = engine.start();
    if (!start_res.ok) {
        std::cerr << "MOTOR BASLATMA HATASI: " << start_res.message << "\n";
        return 4;
    }

    std::atomic<bool> reset_discord_on_stop{cli_reset_discord_on_stop};

    std::unique_ptr<discorddpi::IpcServer> ipc_server;
    if (enable_ipc) {
        discorddpi::IpcServerConfig icfg{};
        icfg.pipe_token = pipe_token;
        icfg.allowed_client_sid = client_sid;

        ipc_server = std::make_unique<discorddpi::IpcServer>(
            std::move(icfg),
            [&]() -> discorddpi::IpcStatusPayload {
                discorddpi::IpcStatusPayload p{};
                p.engine_version = "1.0.0";
                p.running = engine.is_running();
                p.mode = mode_label;
                p.enable_ipv6 = enable_ipv6;
                p.network_filter = engine.build_network_filter();
                p.dpi_config = engine.current_dpi_config();
                p.stats = engine.snapshot_stats();
                p.processes = engine.active_discord_processes();
                p.flows = engine.active_discord_flows();
                p.last_warning = watchdog_warning;
                return p;
            },
            [&](const discorddpi::IpcConfigUpdate& upd, std::string& /*out_err*/) -> bool {
                auto current = engine.current_dpi_config();
                if (upd.tcp_enabled.has_value()) {
                    current.tcp.enabled = *upd.tcp_enabled;
                }
                if (upd.split_mode.has_value()) {
                    current.tcp.split_mode = *upd.split_mode;
                }
                if (upd.reverse_order.has_value()) {
                    current.tcp.reverse_order = *upd.reverse_order;
                }
                if (upd.quic_strategy.has_value()) {
                    current.udp.quic_strategy = *upd.quic_strategy;
                }
                if (upd.reset_discord_on_stop.has_value()) {
                    reset_discord_on_stop.store(
                        *upd.reset_discord_on_stop, std::memory_order_release);
                }
                engine.update_dpi_config(std::move(current));
                return true;
            },
            [&](std::optional<bool> reset_override) {
                if (reset_override.has_value()) {
                    reset_discord_on_stop.store(*reset_override, std::memory_order_release);
                }
                safety.request_stop();
            });

        const auto ipc_res = ipc_server->start();
        if (!ipc_res.ok) {
            std::cerr << "IPC SUNUCU HATASI: " << ipc_res.message << "\n";
            engine.stop();
            return 6;
        }
        if (!quiet_console) {
            std::cout << "Named Pipe IPC sunucusu hazir: " << ipc_res.pipe_path << "\n";
        }
    }

    if (!quiet_console) {
        const auto initial_stats = engine.snapshot_stats();
        std::cout << "WinDivert surucusu aktif: v"
                  << initial_stats.windivert_version_major << "."
                  << initial_stats.windivert_version_minor
                  << " | Filtre: " << engine.build_network_filter() << "\n"
                  << "Durdurmak icin Ctrl+C tuslayin.\n\n";
    }

    for (uint32_t elapsed = 0;
         (duration_sec == 0 || elapsed < duration_sec) && !safety.stop_requested();
         ++elapsed) {
        for (int tick = 0; tick < 10 && !safety.stop_requested(); ++tick) {
            Sleep(100);
        }
        if (!quiet_console && !safety.stop_requested()) {
            const auto s = engine.snapshot_stats();
            std::cout << "[" << std::setw(3) << (elapsed + 1) << "s]"
                      << " PID=" << s.active_discord_processes
                      << " | DiscordAkis=" << s.active_discord_flows
                      << " (T=" << s.active_discord_tcp_flows
                      << ",U=" << s.active_discord_udp_flows << ")"
                      << " | TLS_CH=" << s.tls_client_hellos_detected
                      << " | TCP_Bolunen=" << s.tcp_packets_segmented
                      << " (Seg=" << s.tcp_segments_injected << ")"
                      << " | QUIC_Drop=" << s.quic_packets_dropped_discord
                      << " | DigerPkt=" << s.packets_non_discord_passthrough
                      << " | DigerDegisen=" << s.packets_non_discord_modified
                      << "\n";
        }
    }

    if (ipc_server) {
        ipc_server->stop();
    }

    const auto final_stats = engine.snapshot_stats();
    const auto final_procs = engine.active_discord_processes();
    const auto final_flows = engine.active_discord_flows();

    if (!quiet_console) {
        std::cout << "\nMotor guvenli sekilde durduruluyor...\n";
    }
    engine.stop();

    if (reset_discord_on_stop.load(std::memory_order_acquire)) {
        const uint32_t reset_items = engine.reset_discord_connections();
        if (!quiet_console) {
            std::cout << "Acik Discord baglantilari sifirlandi (sifirlanan oge: "
                      << reset_items << ").\n";
        }
    }

    if (!quiet_console) {
        print_processes_and_flows(final_procs, final_flows);

        std::cout << "\n=== MOTOR OTURUM RAPORU ===\n"
                  << "  WinDivert surumu              : " << final_stats.windivert_version_major << "."
                  << final_stats.windivert_version_minor << "\n"
                  << "  Calisma suresi (ms)           : " << final_stats.uptime_ms << "\n"
                  << "  SOCKET / FLOW olay sayisi     : " << final_stats.socket_events_total
                  << " / " << final_stats.flow_events_total << "\n"
                  << "  Toplam aday paket             : " << final_stats.packets_seen_total << "\n"
                  << "  Discord aday paketleri        : " << final_stats.packets_discord_seen << "\n"
                  << "  Tespit edilen TLS ClientHello : " << final_stats.tls_client_hellos_detected << "\n"
                  << "  Bolunen Discord TCP paketi    : " << final_stats.tcp_packets_segmented
                  << " (Gonderilen toplam segment: " << final_stats.tcp_segments_injected << ")\n"
                  << "  Engellenen Discord QUIC(443)  : " << final_stats.quic_packets_dropped_discord << "\n"
                  << "  Discord disi aday (dokunulmaz): " << final_stats.packets_non_discord_passthrough << "\n"
                  << "  Bilinmeyen / gecersiz paket   : " << final_stats.packets_unknown_passthrough
                  << " / " << final_stats.packets_invalid_passthrough << "\n"
                  << "  Ertelenmis kuyruk (enq/hitD/hitN/timeout/ovf): "
                  << final_stats.pending_enqueued << " / "
                  << final_stats.pending_hit_discord << " / "
                  << final_stats.pending_hit_non_discord << " / "
                  << final_stats.pending_timeout_passthrough << " / "
                  << final_stats.pending_overflow_passthrough << "\n"
                  << "  Islenen Discord paketi        : " << final_stats.packets_modified << "\n"
                  << "  Degistirilen Discord disi pkt : " << final_stats.packets_non_discord_modified << "\n";
    }

    return 0;
}
