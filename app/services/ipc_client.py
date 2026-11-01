"""Win32 Named Pipe üzerinden C++ motoru ile konuşan kalıcı bağlantılı JSON-line IPC istemcisi."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import re
import threading
import time
from typing import Any

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_PIPE_BUSY = 231

MAX_RESPONSE_BYTES = 131072
_PIPE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CreateFileW = _kernel32.CreateFileW
_CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_CreateFileW.restype = wintypes.HANDLE

_WaitNamedPipeW = _kernel32.WaitNamedPipeW
_WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
_WaitNamedPipeW.restype = wintypes.BOOL

_WriteFile = _kernel32.WriteFile
_WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_WriteFile.restype = wintypes.BOOL

_ReadFile = _kernel32.ReadFile
_ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_ReadFile.restype = wintypes.BOOL

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL


class IpcError(RuntimeError):
    """Named Pipe iletişim veya protokol hatası."""


def validate_pipe_token(token: str) -> str:
    if not isinstance(token, str) or not _PIPE_TOKEN_RE.match(token):
        raise ValueError(f"Gecersiz Named Pipe belirteci: {token!r}")
    return token


class IpcClient:
    """`\\\\.\\pipe\\<pipe_token>` üzerinden C++ `IpcServer` ile konuşur."""

    def __init__(self, pipe_token: str, connect_timeout_ms: int = 800) -> None:
        self._pipe_token = validate_pipe_token(pipe_token)
        self._pipe_path = f"\\\\.\\pipe\\{self._pipe_token}"
        self._connect_timeout_ms = max(50, connect_timeout_ms)
        self._lock = threading.Lock()
        self._handle: int | None = None

    @property
    def pipe_token(self) -> str:
        return self._pipe_token

    @property
    def pipe_path(self) -> str:
        return self._pipe_path

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        if self._handle is not None:
            _CloseHandle(wintypes.HANDLE(self._handle))
            self._handle = None

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Tek satırlık JSON komutu gönderir ve JSON yanıtını döndürür."""
        encoded = (
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("utf-8")
        is_shutdown = payload.get("cmd") == "shutdown"

        with self._lock:
            last_exc: IpcError | None = None
            raw_line = ""
            for attempt in range(2):
                had_cached_handle = self._handle is not None
                try:
                    if self._handle is None:
                        self._handle = self._open_pipe()
                    self._write_all(self._handle, encoded)
                    raw_line = self._read_line(self._handle)
                    if is_shutdown:
                        self._close_unlocked()
                    last_exc = None
                    break
                except IpcError as exc:
                    self._close_unlocked()
                    last_exc = exc
                    if not had_cached_handle or attempt == 1:
                        raise
                    time.sleep(0.02)

            if last_exc is not None:
                raise last_exc

        try:
            parsed = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise IpcError(f"Motordan gecersiz JSON yaniti alindi: {exc}") from exc

        if not isinstance(parsed, dict):
            raise IpcError("Motor IPC yaniti JSON nesnesi degil.")
        return parsed

    def ping(self) -> bool:
        resp = self.request({"cmd": "ping"})
        return bool(resp.get("ok") is True and resp.get("cmd") == "ping")

    def get_status(self) -> dict[str, Any]:
        resp = self.request({"cmd": "get_status"})
        if not resp.get("ok"):
            raise IpcError(str(resp.get("error") or "Durum sorgusu basarisiz."))
        return resp

    def update_config(
        self,
        *,
        tcp_enabled: bool | None = None,
        split_mode: str | None = None,
        reverse_order: bool | None = None,
        quic_strategy: str | None = None,
        reset_discord_on_stop: bool | None = None,
    ) -> dict[str, Any]:
        cmd: dict[str, Any] = {"cmd": "update_config"}
        if tcp_enabled is not None:
            cmd["tcp_enabled"] = bool(tcp_enabled)
        if split_mode is not None:
            cmd["split_mode"] = str(split_mode)
        if reverse_order is not None:
            cmd["reverse_order"] = bool(reverse_order)
        if quic_strategy is not None:
            cmd["quic_strategy"] = str(quic_strategy)
        if reset_discord_on_stop is not None:
            cmd["reset_discord_on_stop"] = bool(reset_discord_on_stop)

        resp = self.request(cmd)
        if not resp.get("ok"):
            raise IpcError(str(resp.get("error") or "Yapilandirma guncellenemedi."))
        return resp

    def shutdown(self, *, reset_discord_connections: bool | None = None) -> bool:
        cmd: dict[str, Any] = {"cmd": "shutdown"}
        if reset_discord_connections is not None:
            cmd["reset_discord_connections"] = bool(reset_discord_connections)
        resp = self.request(cmd)
        return bool(resp.get("ok") is True)

    def _open_pipe(self) -> int:
        for _ in range(5):
            handle = _CreateFileW(
                self._pipe_path,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle and handle != INVALID_HANDLE_VALUE:
                return int(handle)

            err = ctypes.get_last_error()
            if err == ERROR_PIPE_BUSY:
                if _WaitNamedPipeW(self._pipe_path, self._connect_timeout_ms):
                    continue
                time.sleep(0.02)
                continue
            raise IpcError(f"Named Pipe acilamadi ({self._pipe_path}, Win32 hata={err}).")

        raise IpcError(f"Named Pipe mesgul ({self._pipe_path}).")

    @staticmethod
    def _write_all(handle: int, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(data):
            chunk = bytes(view[offset:])
            written = wintypes.DWORD(0)
            ok = _WriteFile(
                wintypes.HANDLE(handle),
                chunk,
                len(chunk),
                ctypes.byref(written),
                None,
            )
            if not ok or written.value == 0:
                err = ctypes.get_last_error()
                raise IpcError(f"Named Pipe yazma hatasi (Win32 hata={err}).")
            offset += written.value

    @staticmethod
    def _read_line(handle: int) -> str:
        buf = bytearray()
        chunk_buf = ctypes.create_string_buffer(4096)
        read_bytes = wintypes.DWORD(0)

        while len(buf) < MAX_RESPONSE_BYTES:
            ok = _ReadFile(
                wintypes.HANDLE(handle),
                chunk_buf,
                len(chunk_buf),
                ctypes.byref(read_bytes),
                None,
            )
            if not ok or read_bytes.value == 0:
                if buf:
                    break
                err = ctypes.get_last_error()
                raise IpcError(f"Named Pipe okuma hatasi (Win32 hata={err}).")

            piece = chunk_buf.raw[: read_bytes.value]
            nl_idx = piece.find(b"\n")
            if nl_idx != -1:
                buf.extend(piece[:nl_idx])
                break
            buf.extend(piece)
        else:
            raise IpcError("Motor IPC yaniti izin verilen maksimum boyutu asti.")

        if buf.endswith(b"\r"):
            del buf[-1]
        return buf.decode("utf-8", errors="replace")
