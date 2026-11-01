"""SDPI merkezi sabitler, yol tanımları ve varsayılan yapılandırma şeması."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

APP_NAME = "SDPI"
APP_VERSION = "1.0.0"
APP_ORG = "SDPI"

# Görsel renk paleti (Koyu mod — Bölüm 8 tasarım sistemi)
PALETTE = {
    "bg_main": "#101114",
    "bg_sidebar": "#14161B",
    "bg_card": "#191B22",
    "bg_card_hover": "#1F222B",
    "bg_input": "#12141A",
    "border": "#292C36",
    "accent": "#756BFA",
    "accent_hover": "#867DFB",
    "accent_pressed": "#6157E8",
    "success": "#27C58A",
    "success_bg": "#142922",
    "warning": "#F0B44D",
    "warning_bg": "#2B2315",
    "error": "#E45D67",
    "error_bg": "#2B171B",
    "text_primary": "#F4F4F7",
    "text_secondary": "#9BA1B0",
    "text_muted": "#6C7282",
}


def get_runtime_root() -> Path:
    """Kaynak koddan veya paketlenmiş (PyInstaller) ortamdan çalışma kök dizinini döndürür."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


PROJECT_ROOT = get_runtime_root()
CONFIG_DIR = PROJECT_ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "settings.json"
LOGS_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOGS_DIR / "sdpi.log"
def _resolve_icon_path() -> Path:
    direct = PROJECT_ROOT / "assets" / "app_icon.ico"
    if direct.is_file():
        return direct
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bundled = Path(meipass) / "assets" / "app_icon.ico"
        if bundled.is_file():
            return bundled
    return direct


ASSETS_DIR = PROJECT_ROOT / "assets"
APP_ICON_PATH = _resolve_icon_path()

DEFAULT_PIPE_TOKEN_PREFIX = "SDPI.Engine"

ALLOWED_DISCORD_EXE_NAMES = frozenset(
    {
        "discord.exe",
        "discordptb.exe",
        "discordcanary.exe",
        "update.exe",
        "updater_launcher.exe",
        "discordsystemhelper.exe",
        "discordhookhelper.exe",
        "discordhookhelper64.exe",
        "audio_effects_helper.exe",
        "gpu_encoder_helper.exe",
    }
)

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
VALID_ON_STOP_ACTIONS = ("reset_connections", "keep", "close_discord")
VALID_ENGINE_MODES = ("active", "observe_divert", "observe_sniff")
VALID_SPLIT_MODES = ("record_and_sni", "sni_middle", "first_byte")
VALID_QUIC_MODES = ("drop_discord_quic_443", "observe")

DEFAULT_SETTINGS: dict[str, Any] = {
    "schema_version": 1,
    "general": {
        "start_with_windows": False,
        "start_minimized": False,
        "auto_connect_on_start": False,
        "minimize_to_tray": False,
        "auto_fallback": True,
        "auto_detect_discord": True,
        "launch_discord_on_start": False,
        "on_stop_discord_action": "reset_connections",
        "log_level": "INFO",
        "auto_health_check": True,
        "diagnostics_mode": False,
    },
    "process_match": {
        "install_roots": [
            "%LOCALAPPDATA%\\Discord",
            "%LOCALAPPDATA%\\DiscordPTB",
            "%LOCALAPPDATA%\\DiscordCanary",
        ],
        "required_signer": "Discord Inc.",
        "verify_signature": True,
    },
    "engine": {
        "mode": "active",
        "pending_queue_timeout_ms": 75,
        "pending_queue_max_packets": 256,
        "flow_idle_timeout_s": 120,
        "ipv6": True,
    },
    "tcp_strategy": {
        "enabled": True,
        "target_ports": [443, 2053, 2083, 2087, 2096, 8443],
        "split_mode": "record_and_sni",
        "reverse_order": True,
    },
    "udp_strategy": {
        "mode": "observe",
    },
    "quic_strategy": {
        "mode": "drop_discord_quic_443",
    },
}


def resolve_engine_executable() -> Path | None:
    """Derlenmiş C++ motor yürütülebilir dosyasının (`sdpi-engine.exe` / `discorddpi-engine.exe`) yolunu bulur."""
    candidates = [
        PROJECT_ROOT / "engine" / "sdpi-engine.exe",
        PROJECT_ROOT / "sdpi-engine.exe",
        PROJECT_ROOT / "core" / "build" / "Release" / "sdpi-engine.exe",
        PROJECT_ROOT / "core" / "build" / "Debug" / "sdpi-engine.exe",
        PROJECT_ROOT / "engine" / "discorddpi-engine.exe",
        PROJECT_ROOT / "discorddpi-engine.exe",
        PROJECT_ROOT / "core" / "build" / "Release" / "discorddpi-engine.exe",
        PROJECT_ROOT / "core" / "build" / "Debug" / "discorddpi-engine.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
