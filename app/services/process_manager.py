"""Yönetici izni gerektirmeyen Discord süreç tespiti, başlatma ve Windows entegrasyonu."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import winreg

import psutil

from app.constants import ALLOWED_DISCORD_EXE_NAMES, APP_NAME, PROJECT_ROOT

logger = logging.getLogger("sdpi.process")

TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1
RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [
        ("User", _SID_AND_ATTRIBUTES),
    ]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)

_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.argtypes = []
_GetCurrentProcess.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL

_OpenProcessToken = _advapi32.OpenProcessToken
_OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
_OpenProcessToken.restype = wintypes.BOOL

_GetTokenInformation = _advapi32.GetTokenInformation
_GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_GetTokenInformation.restype = wintypes.BOOL

_ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
_ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.LPWSTR),
]
_ConvertSidToStringSidW.restype = wintypes.BOOL


@dataclass(frozen=True)
class DiscordProcessInfo:
    pid: int
    parent_pid: int
    role: str
    signature_valid: bool | None  # None = motor kapalıyken yerel tespit (C++ motorunda doğrulanır)
    signer_name: str
    exe_path: str


class ProcessManager:
    """GUI katmanı için Discord algılama, otomatik başlatma ve başlangıç kaydı servisi."""

    @staticmethod
    def is_process_elevated() -> bool:
        try:
            return bool(_shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def query_current_user_sid() -> str:
        """Mevcut masaüstü kullanıcısının Windows SID dizesini (`S-1-5-21-...`) döndürür."""
        tok = wintypes.HANDLE()
        if not _OpenProcessToken(_GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)):
            return ""
        try:
            needed = wintypes.DWORD(0)
            _GetTokenInformation(tok, TOKEN_USER_CLASS, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                return ""
            buf = ctypes.create_string_buffer(needed.value)
            if not _GetTokenInformation(
                tok, TOKEN_USER_CLASS, buf, needed.value, ctypes.byref(needed)
            ):
                return ""
            tu = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
            sid_str = wintypes.LPWSTR()
            if not _ConvertSidToStringSidW(tu.User.Sid, ctypes.byref(sid_str)):
                return ""
            try:
                return sid_str.value or ""
            finally:
                if sid_str:
                    _LocalFree(sid_str)
        finally:
            _CloseHandle(tok)

    @staticmethod
    def normalize_install_roots(raw_roots: list[str] | None = None) -> list[str]:
        roots = raw_roots or [
            r"%LOCALAPPDATA%\Discord",
            r"%LOCALAPPDATA%\DiscordPTB",
            r"%LOCALAPPDATA%\DiscordCanary",
        ]
        normalized: list[str] = []
        for item in roots:
            expanded = os.path.expandvars(item).strip()
            if not expanded:
                continue
            norm = os.path.normcase(os.path.normpath(expanded))
            if not norm.endswith("\\"):
                norm += "\\"
            if norm not in normalized:
                normalized.append(norm)
        return normalized

    @classmethod
    def is_discord_executable_path(
        cls, exe_path: str, normalized_roots: list[str] | None = None
    ) -> bool:
        if not exe_path:
            return False
        roots = (
            normalized_roots
            if normalized_roots is not None
            else cls.normalize_install_roots()
        )
        norm_exe = os.path.normcase(os.path.normpath(exe_path))
        filename = os.path.basename(norm_exe)
        if filename not in ALLOWED_DISCORD_EXE_NAMES:
            return False
        return any(
            len(norm_exe) > len(r) and norm_exe.startswith(r) for r in roots
        )

    @classmethod
    def detect_discord_processes(
        cls, install_roots: list[str] | None = None
    ) -> list[DiscordProcessInfo]:
        """Yönetici yetkisi gerekmeden çalışan Discord süreçlerini tespit eder."""
        roots = cls.normalize_install_roots(install_roots)
        raw_matches: dict[int, tuple[int, str]] = {}

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
            try:
                info = proc.info
                pid = int(info.get("pid") or 0)
                if pid <= 4:
                    continue
                exe_path = str(info.get("exe") or "")
                if not cls.is_discord_executable_path(exe_path, roots):
                    continue
                ppid = int(info.get("ppid") or 0)
                raw_matches[pid] = (ppid, exe_path)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        results: list[DiscordProcessInfo] = []
        for pid, (ppid, exe_path) in sorted(raw_matches.items()):
            fname = os.path.basename(exe_path).lower()
            if fname in ("update.exe", "updater_launcher.exe"):
                role = "Updater"
            elif ppid in raw_matches:
                role = "Child"
            else:
                role = "Main"

            results.append(
                DiscordProcessInfo(
                    pid=pid,
                    parent_pid=ppid,
                    role=role,
                    signature_valid=None,
                    signer_name="Yerel Tespit (Motor Kapalı)",
                    exe_path=exe_path,
                )
            )
        return results

    @staticmethod
    def find_discord_launcher() -> tuple[Path, list[str]] | None:
        """Kurulu Discord başlatıcısını (`Update.exe --processStart Discord.exe`) bulur."""
        variants = [
            (r"%LOCALAPPDATA%\Discord", "Discord.exe"),
            (r"%LOCALAPPDATA%\DiscordPTB", "DiscordPTB.exe"),
            (r"%LOCALAPPDATA%\DiscordCanary", "DiscordCanary.exe"),
        ]
        for root_expr, exe_name in variants:
            root_dir = Path(os.path.expandvars(root_expr))
            update_exe = root_dir / "Update.exe"
            if update_exe.is_file():
                return update_exe, ["--processStart", exe_name]
            direct_exe = root_dir / exe_name
            if direct_exe.is_file():
                return direct_exe, []
        return None

    @classmethod
    def launch_discord(cls) -> tuple[bool, str]:
        launcher = cls.find_discord_launcher()
        if launcher is None:
            return False, "Sistemde kurulu Discord masaüstü istemcisi bulunamadı."

        exe_path, args = launcher
        try:
            creation_flags = (
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            )
            subprocess.Popen(
                [str(exe_path), *args],
                cwd=str(exe_path.parent),
                creationflags=creation_flags,
                close_fds=True,
            )
            logger.info("Discord istemcisi baslatildi: %s %s", exe_path, " ".join(args))
            return True, "Discord masaüstü uygulaması başlatıldı."
        except OSError as exc:
            logger.error("Discord baslatma hatasi: %s", exc)
            return False, f"Discord başlatılamadı: {exc}"

    @classmethod
    def close_discord_processes(
        cls, install_roots: list[str] | None = None
    ) -> int:
        """Yalnızca doğrulanmış kurulum dizinlerindeki Discord süreçlerini sonlandırır."""
        roots = cls.normalize_install_roots(install_roots)
        self_pid = os.getpid()
        targets: list[psutil.Process] = []

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = int(info.get("pid") or 0)
                if pid <= 4 or pid == self_pid:
                    continue
                exe_path = str(info.get("exe") or "")
                if not cls.is_discord_executable_path(exe_path, roots):
                    continue
                targets.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if not targets:
            return 0

        closed_count = 0
        for proc in targets:
            try:
                proc.terminate()
                closed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        _, alive = psutil.wait_procs(targets, timeout=2.5)
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if closed_count > 0:
            logger.info(
                "Motor durdurma tercihi geregi %d Discord sureci kapatildi.",
                closed_count,
            )
        return closed_count

    @staticmethod
    def build_autorun_command(*, minimized: bool = False) -> str:
        suffix = " --minimized" if minimized else ""
        if getattr(sys, "frozen", False):
            return f'"{Path(sys.executable).resolve()}"{suffix}'
        launcher_exe = PROJECT_ROOT / "SDPI.exe"
        if launcher_exe.is_file():
            return f'"{launcher_exe.resolve()}"{suffix}'
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        interpreter = pythonw if pythonw.is_file() else Path(sys.executable)
        main_script = (PROJECT_ROOT / "app" / "main.py").resolve()
        return f'"{interpreter}" "{main_script}"{suffix}'

    @staticmethod
    def is_start_with_windows_enabled() -> bool:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ
            ) as key:
                val, _ = winreg.QueryValueEx(key, APP_NAME)
                return bool(isinstance(val, str) and val.strip())
        except OSError:
            return False

    @classmethod
    def build_scheduled_task_args(
        cls, enabled: bool, *, minimized: bool = False
    ) -> list[str]:
        """UAC onaysız başlangıç için Windows Görev Zamanlayıcısı (schtasks) argümanlarını üretir."""
        task_name = f"{APP_NAME}_AutoStart"
        if not enabled:
            return ["schtasks", "/Delete", "/TN", task_name, "/F"]
        cmd = cls.build_autorun_command(minimized=minimized)
        return [
            "schtasks",
            "/Create",
            "/TN",
            task_name,
            "/TR",
            cmd,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/F",
        ]

    @classmethod
    def set_start_with_windows(
        cls, enabled: bool, *, minimized: bool = False
    ) -> tuple[bool, str]:
        try:
            if cls.is_process_elevated():
                try:
                    subprocess.run(
                        cls.build_scheduled_task_args(enabled, minimized=minimized),
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=3.0,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError):
                    pass

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_SET_VALUE
            ) as key:
                if enabled:
                    cmd = cls.build_autorun_command(minimized=minimized)
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
                    logger.info("Windows baslangic kaydi eklendi: %s", cmd)
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                        logger.info("Windows baslangic kaydi kaldirildi.")
                    except FileNotFoundError:
                        pass
            return True, ""
        except OSError as exc:
            logger.warning("Windows baslangic kaydi guncellenemedi: %s", exc)
            return False, f"Windows başlangıç ayarı güncellenemedi: {exc}"

    @staticmethod
    def measure_discord_ping_ms(timeout_sec: float = 0.6) -> int | None:
        """Discord kenar geçidine (162.159.128.233:443) TCP el sıkışma gecikmesini (ms) ölçer."""
        targets = (("162.159.128.233", 443), ("162.159.135.232", 443))
        for host, port in targets:
            t0 = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=timeout_sec):
                    elapsed_ms = int(round((time.perf_counter() - t0) * 1000.0))
                    return max(1, elapsed_ms)
            except OSError:
                continue
        return None

    @classmethod
    def repair_discord_connection(
        cls, install_roots: list[str] | None = None
    ) -> tuple[bool, str]:
        """Windows DNS önbelleğini temizler ve açık Discord ağ alt sürecini (NetworkService) yeniler."""
        dns_flushed = False
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                check=False,
            )
            dns_flushed = True
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("DNS onbellegi temizlenemedi: %s", exc)

        roots = cls.normalize_install_roots(install_roots)
        self_pid = os.getpid()
        recycled_net = 0

        for proc in psutil.process_iter(["pid", "exe", "cmdline"]):
            try:
                info = proc.info
                pid = int(info.get("pid") or 0)
                if pid <= 4 or pid == self_pid:
                    continue
                exe_path = str(info.get("exe") or "")
                if not cls.is_discord_executable_path(exe_path, roots):
                    continue
                cmdline_list = info.get("cmdline") or []
                cmdline_str = " ".join(str(x) for x in cmdline_list).lower()
                if "network.mojom.networkservice" in cmdline_str:
                    proc.terminate()
                    recycled_net += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        logger.info(
            "Baglanti onarimi tamamlandi (dns_flush=%s, yenilenen_ag_servisi=%d).",
            dns_flushed,
            recycled_net,
        )
        return True, "Bağlantı onarıldı"
