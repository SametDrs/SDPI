"""Yükseltilmiş (UAC) C++ DPI motorunun yaşam döngüsü ve IPC köprüsü yöneticisi."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
import logging
import os
from pathlib import Path
import subprocess
import threading
import time
from typing import Any

from app.constants import DEFAULT_PIPE_TOKEN_PREFIX, resolve_engine_executable
from app.services.ipc_client import IpcClient, IpcError
from app.services.process_manager import ProcessManager

logger = logging.getLogger("sdpi.backend")

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
ERROR_CANCELLED = 1223
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)

_ShellExecuteExW = _shell32.ShellExecuteExW
_ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
_ShellExecuteExW.restype = wintypes.BOOL

_WaitForSingleObject = _kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_WaitForSingleObject.restype = wintypes.DWORD

_GetExitCodeProcess = _kernel32.GetExitCodeProcess
_GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_GetExitCodeProcess.restype = wintypes.BOOL

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL


class EngineState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class BackendActionResult:
    ok: bool
    state: EngineState
    message: str
    uac_cancelled: bool = False


class BackendManager:
    """`discorddpi-engine.exe` sürecini UAC ile başlatır, izler ve temizce durdurur."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = EngineState.STOPPED
        self._proc_handle: int | None = None
        self._popen: subprocess.Popen[bytes] | None = None
        self._ipc: IpcClient | None = None
        self._pipe_token = f"{DEFAULT_PIPE_TOKEN_PREFIX}.{os.getpid()}"
        self._last_error = ""
        self._last_warning = ""

    @property
    def state(self) -> EngineState:
        with self._lock:
            return self._state

    @property
    def last_error(self) -> str:
        with self._lock:
            return self._last_error

    @property
    def last_warning(self) -> str:
        with self._lock:
            return self._last_warning

    @staticmethod
    def check_engine_prerequisites() -> tuple[bool, Path | None, str]:
        exe = resolve_engine_executable()
        if exe is None:
            return (
                False,
                None,
                "Bağlantı servisi dosyası bulunamadı. Lütfen kurulum dosyalarını kontrol edin.",
            )
        engine_dir = exe.parent
        dll_path = engine_dir / "WinDivert.dll"
        sys_path = engine_dir / "WinDivert64.sys"
        if not dll_path.is_file() or not sys_path.is_file():
            return (
                False,
                exe,
                "Gerekli ağ sürücüsü dosyaları bulunamadı. Antivirüs programınız dosyaları karantinaya almış olabilir.",
            )
        return True, exe, ""

    def build_engine_arguments(self, settings: dict[str, Any]) -> list[str]:
        gen = settings.get("general", {})
        eng = settings.get("engine", {})
        tcp = settings.get("tcp_strategy", {})
        quic = settings.get("quic_strategy", {})

        mode = eng.get("mode", "active")
        if mode == "observe_sniff":
            args = ["--observe-sniff"]
        elif mode == "observe_divert":
            args = ["--observe-divert"]
        else:
            args = ["--active"]

        args.extend(
            [
                "--ipc",
                "--quiet",
                "--pipe-name",
                self._pipe_token,
                "--gui-pid",
                str(os.getpid()),
            ]
        )

        sid = ProcessManager.query_current_user_sid()
        if sid:
            args.extend(["--client-sid", sid])

        if not eng.get("ipv6", True):
            args.append("--no-ipv6")

        if str(gen.get("on_stop_discord_action", "reset_connections")) == "reset_connections":
            args.append("--reset-discord-on-stop")

        if mode == "active":
            split_mode = str(tcp.get("split_mode", "record_and_sni"))
            args.extend(["--split-mode", split_mode])
            if tcp.get("reverse_order", True):
                args.append("--reverse-frag")
            else:
                args.append("--no-reverse-frag")

            quic_mode = str(quic.get("mode", "drop_discord_quic_443"))
            args.extend(["--discord-quic", quic_mode])

        return args

    def start_engine(self, settings: dict[str, Any]) -> BackendActionResult:
        with self._lock:
            if self._state in (EngineState.RUNNING, EngineState.STARTING):
                return BackendActionResult(
                    ok=True, state=self._state, message="Motor zaten çalışıyor."
                )
            self._state = EngineState.STARTING
            self._last_error = ""
            self._last_warning = ""

        ok_pre, exe_path, pre_msg = self.check_engine_prerequisites()
        if not ok_pre or exe_path is None:
            with self._lock:
                self._state = EngineState.ERROR
                self._last_error = pre_msg
            logger.error("Motor on kosul hatasi: %s", pre_msg)
            return BackendActionResult(
                ok=False, state=EngineState.ERROR, message=pre_msg
            )

        args = self.build_engine_arguments(settings)
        ipc = IpcClient(self._pipe_token, connect_timeout_ms=600)

        launch_ok, uac_cancelled, launch_msg = self._spawn_engine_process(
            exe_path, args
        )
        if not launch_ok:
            with self._lock:
                if uac_cancelled:
                    self._state = EngineState.STOPPED
                    self._last_warning = launch_msg
                else:
                    self._state = EngineState.ERROR
                    self._last_error = launch_msg
            return BackendActionResult(
                ok=False,
                state=EngineState.STOPPED if uac_cancelled else EngineState.ERROR,
                message=launch_msg,
                uac_cancelled=uac_cancelled,
            )

        # Named Pipe hazır olana kadar en fazla 8 saniye bekle; erken çıkışı anında yakala.
        deadline = time.monotonic() + 8.0
        connected = False
        early_exit_code: int | None = None

        while time.monotonic() < deadline:
            exit_code = self._poll_process_exit_code()
            if exit_code is not None:
                early_exit_code = exit_code
                break
            try:
                if ipc.ping():
                    connected = True
                    break
            except IpcError:
                pass
            time.sleep(0.12)

        if not connected:
            ipc.close()
            self._cleanup_process_handles()
            err_msg = self._describe_startup_failure(early_exit_code)
            with self._lock:
                self._state = EngineState.ERROR
                self._last_error = err_msg
            logger.error("Motor baslatma basarisiz: %s", err_msg)
            return BackendActionResult(
                ok=False, state=EngineState.ERROR, message=err_msg
            )

        with self._lock:
            self._ipc = ipc
            self._state = EngineState.RUNNING
            self._last_error = ""

        logger.info("C++ DPI motoru basariyla baslatildi (pipe=%s).", ipc.pipe_path)

        # Kullanıcı ayarlarında "Discord kapalıysa otomatik başlat" açıksa kontrol et.
        if settings.get("general", {}).get("launch_discord_on_start", False):
            if not ProcessManager.detect_discord_processes(
                settings.get("process_match", {}).get("install_roots")
            ):
                ProcessManager.launch_discord()

        return BackendActionResult(
            ok=True,
            state=EngineState.RUNNING,
            message="DPI motoru ve süreç bazlı filtreleme aktif.",
        )

    def stop_engine(
        self, settings: dict[str, Any] | None = None
    ) -> BackendActionResult:
        with self._lock:
            if self._state == EngineState.STOPPED:
                return BackendActionResult(
                    ok=True, state=EngineState.STOPPED, message="Motor zaten durduruldu."
                )
            self._state = EngineState.STOPPING
            ipc = self._ipc

        on_stop_action: str | None = None
        reset_override: bool | None = None
        if settings is not None:
            on_stop_action = str(
                settings.get("general", {}).get(
                    "on_stop_discord_action", "reset_connections"
                )
            )
            reset_override = on_stop_action == "reset_connections"

        if ipc is not None:
            try:
                ipc.shutdown(reset_discord_connections=reset_override)
            except IpcError as exc:
                logger.debug("IPC shutdown yaniti alinamadi (normal kapanis olabilir): %s", exc)
            finally:
                ipc.close()

        # Sürecin temizce WinDivert tutamaçlarını kapatması için en fazla 3.5 sn bekle.
        deadline = time.monotonic() + 3.5
        while time.monotonic() < deadline:
            if self._poll_process_exit_code() is not None:
                break
            time.sleep(0.1)

        self._cleanup_process_handles()
        with self._lock:
            self._ipc = None
            self._state = EngineState.STOPPED
            self._last_warning = ""

        if on_stop_action == "close_discord":
            install_roots = (settings or {}).get("process_match", {}).get("install_roots")
            closed_count = ProcessManager.close_discord_processes(install_roots)
            logger.info(
                "C++ DPI motoru durduruldu ve Discord kapatma tercihi uygulandi (kapatilan=%d).",
                closed_count,
            )
            return BackendActionResult(
                ok=True,
                state=EngineState.STOPPED,
                message="Motor güvenli şekilde durduruldu ve Discord masaüstü uygulaması kapatıldı.",
            )

        if on_stop_action == "reset_connections":
            logger.info(
                "C++ DPI motoru durduruldu ve acik Discord baglantilari sifirlandi."
            )
            return BackendActionResult(
                ok=True,
                state=EngineState.STOPPED,
                message="Motor durduruldu ve açık Discord bağlantıları sıfırlandı (diğer uygulamalar etkilenmedi).",
            )

        logger.info("C++ DPI motoru temiz sekilde durduruldu.")
        return BackendActionResult(
            ok=True,
            state=EngineState.STOPPED,
            message="Motor güvenli şekilde durduruldu. Normal ağ bağlantısı korunuyor.",
        )

    def apply_live_strategy(self, settings: dict[str, Any]) -> tuple[bool, str]:
        """Motor çalışırken bölme, QUIC ve durdurma tercihini Named Pipe üzerinden canlı günceller."""
        with self._lock:
            if self._state != EngineState.RUNNING or self._ipc is None:
                return True, "Ayarlar kaydedildi."
            ipc = self._ipc

        gen = settings.get("general", {})
        tcp = settings.get("tcp_strategy", {})
        quic = settings.get("quic_strategy", {})
        reset_on_stop = (
            str(gen.get("on_stop_discord_action", "reset_connections"))
            == "reset_connections"
        )
        try:
            ipc.update_config(
                tcp_enabled=bool(tcp.get("enabled", True)),
                split_mode=str(tcp.get("split_mode", "record_and_sni")),
                reverse_order=bool(tcp.get("reverse_order", True)),
                quic_strategy=str(quic.get("mode", "drop_discord_quic_443")),
                reset_discord_on_stop=reset_on_stop,
            )
            logger.info("Canli DPI stratejisi IPC uzerinden guncellendi.")
            return True, "Ayarlar kaydedildi ve uygulandı."
        except IpcError as exc:
            logger.warning("Canli strateji guncelleme hatasi: %s", exc)
            return False, "Ayarlar kaydedildi (yeniden başlatıldığında uygulanacak)."

    def query_live_status(self) -> dict[str, Any] | None:
        """Çalışan motordan gerçek zamanlı telemetri anlık görüntüsünü alır."""
        with self._lock:
            if self._state != EngineState.RUNNING or self._ipc is None:
                return None
            ipc = self._ipc

        exit_code = self._poll_process_exit_code()
        if exit_code is not None:
            ipc.close()
            self._cleanup_process_handles()
            msg = f"Motor beklenmedik şekilde sonlandı (çıkış kodu: {exit_code})."
            with self._lock:
                self._ipc = None
                self._state = EngineState.ERROR
                self._last_error = msg
            logger.error(msg)
            return None

        try:
            return ipc.get_status()
        except IpcError as exc:
            # Sınır durumu: kapanış sırasında tek seferlik hata olabilir; süreç hâlâ yaşıyor mu kontrol et.
            exit_after = self._poll_process_exit_code()
            if exit_after is not None:
                self._cleanup_process_handles()
                msg = f"Motor bağlantısı kesildi (çıkış kodu: {exit_after})."
                with self._lock:
                    self._ipc = None
                    self._state = EngineState.ERROR
                    self._last_error = msg
                logger.error(msg)
            else:
                logger.warning("Gecici IPC durum sorgusu hatasi: %s", exc)
            return None

    def _spawn_engine_process(
        self, exe_path: Path, args: list[str]
    ) -> tuple[bool, bool, str]:
        param_str = subprocess.list2cmdline(args)
        work_dir = str(exe_path.parent)

        if ProcessManager.is_process_elevated():
            try:
                proc = subprocess.Popen(
                    [str(exe_path), *args],
                    cwd=work_dir,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                with self._lock:
                    self._popen = proc
                return True, False, ""
            except OSError as exc:
                return False, False, f"Motor başlatılamadı: {exc}"

        sei = _SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = str(exe_path)
        sei.lpParameters = param_str
        sei.lpDirectory = work_dir
        sei.nShow = SW_HIDE

        ok = _ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            err = ctypes.get_last_error()
            if err == ERROR_CANCELLED:
                logger.info("Kullanici UAC yukseltme istemini iptal etti.")
                return (
                    False,
                    True,
                    "Bağlantıyı başlatmak için yönetici iznini onaylamanız gerekir.",
                )
            return (
                False,
                False,
                "Bağlantı servisi yönetici izniyle başlatılamadı.",
            )

        if not sei.hProcess:
            return (
                False,
                False,
                "Motor süreci başlatıldı ancak süreç tutamacı alınamadı.",
            )

        with self._lock:
            self._proc_handle = int(sei.hProcess)
        return True, False, ""

    def _poll_process_exit_code(self) -> int | None:
        with self._lock:
            popen = self._popen
            handle = self._proc_handle

        if popen is not None:
            rc = popen.poll()
            return int(rc) if rc is not None else None

        if handle is not None:
            wait_res = _WaitForSingleObject(wintypes.HANDLE(handle), 0)
            if wait_res == WAIT_TIMEOUT:
                return None
            code = wintypes.DWORD(0)
            if _GetExitCodeProcess(wintypes.HANDLE(handle), ctypes.byref(code)):
                if code.value == STILL_ACTIVE and wait_res != WAIT_OBJECT_0:
                    return None
                return int(code.value)
            return -1
        return 0

    def _cleanup_process_handles(self) -> None:
        with self._lock:
            handle = self._proc_handle
            self._proc_handle = None
            self._popen = None
        if handle is not None:
            _CloseHandle(wintypes.HANDLE(handle))

    @staticmethod
    def _describe_startup_failure(exit_code: int | None) -> str:
        if exit_code == 3:
            return "SDPI arka planda zaten çalışıyor."
        if exit_code == 4:
            return (
                "Ağ sürücüsü başlatılamadı. Antivirüs programınız engelliyor olabilir; "
                "lütfen SDPI klasörünü istisnalara ekleyin."
            )
        if exit_code == 5:
            return "Bağlantıyı başlatmak için yönetici izni gereklidir."
        return "Bağlantı servisi başlatılamadı. Lütfen tekrar deneyin."
