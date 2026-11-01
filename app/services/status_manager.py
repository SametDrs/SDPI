"""Asenkron motor ve süreç durumu izleyicisi (UI iş parçacığını asla bloklamaz)."""

from __future__ import annotations

from dataclasses import asdict
import threading
import time
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from app.services.backend_manager import BackendActionResult, BackendManager, EngineState
from app.services.config_manager import ConfigManager
from app.services.process_manager import ProcessManager


class _StartStopWorker(QThread):
    """UAC onayı veya motor kapanışı sırasında GUI donmasını önleyen arka plan işçisi."""

    completed = Signal(object)  # BackendActionResult

    def __init__(
        self,
        backend: BackendManager,
        action: str,
        settings: dict[str, Any] | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._backend = backend
        self._action = action
        self._settings = settings or {}

    def run(self) -> None:
        if self._action == "start":
            res = self._backend.start_engine(self._settings)
        else:
            res = self._backend.stop_engine(self._settings)
        self.completed.emit(res)


class _TelemetryPollerThread(QThread):
    """1 saniyelik aralıklarla C++ IPC veya yerel Discord süreç durumunu okur."""

    snapshot_ready = Signal(dict)

    def __init__(
        self,
        backend: BackendManager,
        config: ConfigManager,
        interval_sec: float = 1.0,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._backend = backend
        self._config = config
        self._interval_sec = max(0.3, interval_sec)
        self._stop_event = threading.Event()
        self._tick_counter = 0
        self._cached_ping_ms: int | None = None

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            payload = self._collect_once()
            self.snapshot_ready.emit(payload)
            self._stop_event.wait(self._interval_sec)

    def _collect_once(self) -> dict[str, Any]:
        settings = self._config.get_all()
        state = self._backend.state

        if state == EngineState.RUNNING:
            live = self._backend.query_live_status()
            if live is not None:
                if self._tick_counter % 3 == 0 or self._cached_ping_ms is None:
                    self._cached_ping_ms = ProcessManager.measure_discord_ping_ms()
                self._tick_counter += 1
                if isinstance(live.get("stats"), dict) and self._cached_ping_ms is not None:
                    live["stats"]["ping_ms"] = self._cached_ping_ms
                live["engine_state"] = self._backend.state.value
                live["ui_error"] = self._backend.last_error
                live["ui_warning"] = self._backend.last_warning or live.get(
                    "last_warning", ""
                )
                live["timestamp_epoch"] = time.time()
                return live
            # Motor bu sorgu sırasında hata durumuna geçtiyse güncel durumu yansıt.
            state = self._backend.state

        self._tick_counter = 0
        self._cached_ping_ms = None

        auto_detect = settings.get("general", {}).get("auto_detect_discord", True)
        install_roots = settings.get("process_match", {}).get("install_roots")
        local_procs = (
            [asdict(p) for p in ProcessManager.detect_discord_processes(install_roots)]
            if auto_detect
            else []
        )

        return {
            "ok": True,
            "engine_state": state.value,
            "running": False,
            "engine_version": "1.0.0",
            "mode": settings.get("engine", {}).get("mode", "active"),
            "ipv6": settings.get("engine", {}).get("ipv6", True),
            "network_filter": "",
            "ui_error": self._backend.last_error,
            "ui_warning": self._backend.last_warning,
            "config": {
                "tcp_enabled": settings.get("tcp_strategy", {}).get("enabled", True),
                "split_mode": settings.get("tcp_strategy", {}).get(
                    "split_mode", "record_and_sni"
                ),
                "reverse_order": settings.get("tcp_strategy", {}).get(
                    "reverse_order", True
                ),
                "quic_strategy": settings.get("quic_strategy", {}).get(
                    "mode", "drop_discord_quic_443"
                ),
                "target_ports": settings.get("tcp_strategy", {}).get(
                    "target_ports", [443, 8443]
                ),
            },
            "stats": {
                "windivert_version_major": 0,
                "windivert_version_minor": 0,
                "uptime_ms": 0,
                "active_discord_processes": len(local_procs),
                "active_discord_flows": 0,
                "active_discord_tcp_flows": 0,
                "active_discord_udp_flows": 0,
                "active_discord_ipv4_flows": 0,
                "active_discord_ipv6_flows": 0,
                "active_non_discord_flows": 0,
                "socket_events_total": 0,
                "flow_events_total": 0,
                "packets_seen_total": 0,
                "packets_discord_seen": 0,
                "packets_non_discord_passthrough": 0,
                "packets_unknown_passthrough": 0,
                "packets_invalid_passthrough": 0,
                "packets_modified": 0,
                "packets_non_discord_modified": 0,
                "tls_client_hellos_detected": 0,
                "tcp_packets_segmented": 0,
                "tcp_segments_injected": 0,
                "quic_packets_dropped_discord": 0,
                "bytes_discord_out": 0,
                "bytes_discord_in": 0,
                "pending_enqueued": 0,
                "pending_hit_discord": 0,
                "pending_hit_non_discord": 0,
                "pending_timeout_passthrough": 0,
                "pending_overflow_passthrough": 0,
            },
            "processes": local_procs,
            "flows": [],
            "timestamp_epoch": time.time(),
        }


FALLBACK_PRESETS: tuple[tuple[str, str, bool, str], ...] = (
    ("standard", "record_and_sni", True, "Standart Mod"),
    ("alt_1", "sni_middle", True, "Alternatif Mod 1"),
    ("alt_2", "first_byte", False, "Alternatif Mod 2"),
)


class StatusManager(QObject):
    """Motor durum geçişlerini ve periyodik gerçek zamanlı telemetri sinyallerini yönetir."""

    telemetry_updated = Signal(dict)
    action_started = Signal(str)  # "start" | "stop"
    action_finished = Signal(object)  # BackendActionResult
    fallback_switched = Signal(str)  # Geçilen mod açıklaması

    def __init__(
        self,
        backend: BackendManager,
        config: ConfigManager,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._backend = backend
        self._config = config
        self._poller: _TelemetryPollerThread | None = None
        self._active_worker: _StartStopWorker | None = None
        self._latest_snapshot: dict[str, Any] = {}
        self._fallback_stalled_ticks = 0
        self._fallback_switches_done = 0
        self._baseline_hellos = 0
        self._baseline_bytes_in = 0

    @property
    def latest_snapshot(self) -> dict[str, Any]:
        return self._latest_snapshot

    @property
    def is_busy(self) -> bool:
        return self._active_worker is not None and self._active_worker.isRunning()

    def start_monitoring(self) -> None:
        if self._poller is not None and self._poller.isRunning():
            return
        self._poller = _TelemetryPollerThread(
            self._backend, self._config, interval_sec=1.0, parent=self
        )
        self._poller.snapshot_ready.connect(self._on_snapshot)
        self._poller.start()

    def stop_monitoring(self) -> None:
        if self._poller is not None:
            self._poller.request_stop()
            self._poller.wait(2500)
            self._poller = None
        if self._active_worker is not None and self._active_worker.isRunning():
            self._active_worker.wait(4000)

    def request_start_engine(self) -> None:
        if self.is_busy:
            return
        settings = self._config.get_all()
        self.action_started.emit("start")
        worker = _StartStopWorker(self._backend, "start", settings=settings, parent=self)
        worker.completed.connect(self._on_worker_completed)
        self._active_worker = worker
        worker.start()

    def request_stop_engine(self) -> None:
        if self.is_busy:
            return
        settings = self._config.get_all()
        self.action_started.emit("stop")
        worker = _StartStopWorker(self._backend, "stop", settings=settings, parent=self)
        worker.completed.connect(self._on_worker_completed)
        self._active_worker = worker
        worker.start()

    def toggle_engine(self) -> None:
        if self._backend.state == EngineState.RUNNING:
            self.request_stop_engine()
        elif self._backend.state in (EngineState.STOPPED, EngineState.ERROR):
            self.request_start_engine()

    def evaluate_auto_fallback(self, payload: dict[str, Any]) -> str | None:
        """Mevcut modda TLS el sıkışmaları yanıt alamıyorsa sıradaki uyumluluk moduna geçer."""
        if not bool(payload.get("running", False)):
            self._fallback_stalled_ticks = 0
            self._fallback_switches_done = 0
            self._baseline_hellos = 0
            self._baseline_bytes_in = 0
            return None

        settings = self._config.get_all()
        if not bool(settings.get("general", {}).get("auto_fallback", True)):
            return None
        if self._fallback_switches_done >= len(FALLBACK_PRESETS) - 1:
            return None

        stats = payload.get("stats", {})
        if not isinstance(stats, dict):
            return None

        procs = int(stats.get("active_discord_processes", 0))
        if procs <= 0:
            self._fallback_stalled_ticks = 0
            return None

        hellos = int(stats.get("tls_client_hellos_detected", 0))
        bytes_in = int(stats.get("bytes_discord_in", 0))
        delta_hellos = max(0, hellos - self._baseline_hellos)
        delta_bytes_in = max(0, bytes_in - self._baseline_bytes_in)

        if delta_bytes_in > 0:
            # Gelen Discord verisi akıyor, bağlantı sağlıklı
            self._fallback_stalled_ticks = 0
            return None

        if delta_hellos > 0:
            self._fallback_stalled_ticks += 1

        if self._fallback_stalled_ticks < 8 or delta_hellos < 4:
            return None

        cur_split = str(settings.get("tcp_strategy", {}).get("split_mode", "record_and_sni"))
        cur_rev = bool(settings.get("tcp_strategy", {}).get("reverse_order", True))

        cur_idx = 0
        for idx, (_key, sm, rev, _label) in enumerate(FALLBACK_PRESETS):
            if sm == cur_split and rev == cur_rev:
                cur_idx = idx
                break

        next_idx = (cur_idx + 1) % len(FALLBACK_PRESETS)
        _next_key, next_split, next_rev, next_label = FALLBACK_PRESETS[next_idx]

        settings["tcp_strategy"]["split_mode"] = next_split
        settings["tcp_strategy"]["reverse_order"] = next_rev
        saved = self._config.save(settings)
        self._backend.apply_live_strategy(saved)

        self._fallback_stalled_ticks = 0
        self._fallback_switches_done += 1
        self._baseline_hellos = hellos
        self._baseline_bytes_in = bytes_in

        msg = f"{next_label} otomatik devreye alındı"
        self.fallback_switched.emit(msg)
        return msg

    def _on_snapshot(self, payload: dict[str, Any]) -> None:
        self._latest_snapshot = payload
        self.evaluate_auto_fallback(payload)
        self.telemetry_updated.emit(payload)

    def _on_worker_completed(self, result: BackendActionResult) -> None:
        self.action_finished.emit(result)
