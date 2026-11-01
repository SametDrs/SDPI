"""JSON yapılandırma yöneticisi: şema doğrulama, güvenli varsayılanlar ve atomik yazma."""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from app.constants import (
    CONFIG_FILE,
    DEFAULT_SETTINGS,
    VALID_ENGINE_MODES,
    VALID_LOG_LEVELS,
    VALID_ON_STOP_ACTIONS,
    VALID_QUIC_MODES,
    VALID_SPLIT_MODES,
)

logger = logging.getLogger("sdpi.config")


def _clamp_int(value: Any, default: int, min_val: int, max_val: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(min_val, min(max_val, value))


def _as_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


class ConfigManager:
    """`config/settings.json` dosyasını doğrular, okur ve atomik olarak kaydeder."""

    def __init__(self, config_path: Path = CONFIG_FILE) -> None:
        self._path = config_path
        self._lock = threading.RLock()
        self._data: dict[str, Any] = copy.deepcopy(DEFAULT_SETTINGS)
        self.load()

    @property
    def path(self) -> Path:
        return self._path

    def get_all(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self._path.is_file():
                self._data = copy.deepcopy(DEFAULT_SETTINGS)
                self.save(self._data)
                return copy.deepcopy(self._data)

            try:
                raw_text = self._path.read_text(encoding="utf-8")
                parsed = json.loads(raw_text)
                if not isinstance(parsed, dict):
                    raise ValueError("Kok JSON nesnesi bir sozluk (object) degil.")
                self._data = self.validate_and_normalize(parsed)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                logger.warning(
                    "Yapilandirma okunamadi (%s), varsayilan ayarlar kullaniliyor: %s",
                    self._path,
                    exc,
                )
                self._data = copy.deepcopy(DEFAULT_SETTINGS)
            return copy.deepcopy(self._data)

    def save(self, new_settings: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_and_normalize(new_settings)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(".json.tmp")
            payload = json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"
            tmp_path.write_text(payload, encoding="utf-8")
            os.replace(tmp_path, self._path)
            self._data = copy.deepcopy(normalized)
            return copy.deepcopy(self._data)

    def reset_to_defaults(self) -> dict[str, Any]:
        return self.save(copy.deepcopy(DEFAULT_SETTINGS))

    @staticmethod
    def validate_and_normalize(raw: dict[str, Any]) -> dict[str, Any]:
        out = copy.deepcopy(DEFAULT_SETTINGS)
        if not isinstance(raw, dict):
            return out

        # 1. General
        gen = raw.get("general")
        if isinstance(gen, dict):
            dg = out["general"]
            dg["start_with_windows"] = _as_bool(
                gen.get("start_with_windows"), dg["start_with_windows"]
            )
            dg["start_minimized"] = _as_bool(
                gen.get("start_minimized"), dg["start_minimized"]
            )
            dg["auto_connect_on_start"] = _as_bool(
                gen.get("auto_connect_on_start"), dg["auto_connect_on_start"]
            )
            dg["minimize_to_tray"] = _as_bool(
                gen.get("minimize_to_tray"), dg["minimize_to_tray"]
            )
            dg["auto_fallback"] = _as_bool(
                gen.get("auto_fallback"), dg["auto_fallback"]
            )
            dg["auto_detect_discord"] = _as_bool(
                gen.get("auto_detect_discord"), dg["auto_detect_discord"]
            )
            dg["launch_discord_on_start"] = _as_bool(
                gen.get("launch_discord_on_start"), dg["launch_discord_on_start"]
            )
            stop_act = gen.get("on_stop_discord_action")
            if isinstance(stop_act, str) and stop_act in VALID_ON_STOP_ACTIONS:
                dg["on_stop_discord_action"] = stop_act
            lvl = gen.get("log_level")
            if isinstance(lvl, str) and lvl.upper() in VALID_LOG_LEVELS:
                dg["log_level"] = lvl.upper()
            dg["auto_health_check"] = _as_bool(
                gen.get("auto_health_check"), dg["auto_health_check"]
            )
            dg["diagnostics_mode"] = _as_bool(
                gen.get("diagnostics_mode"), dg["diagnostics_mode"]
            )

        # 2. Process match
        pm = raw.get("process_match")
        if isinstance(pm, dict):
            dp = out["process_match"]
            roots = pm.get("install_roots")
            if isinstance(roots, list):
                clean_roots = [
                    r.strip() for r in roots if isinstance(r, str) and r.strip()
                ]
                if clean_roots:
                    dp["install_roots"] = clean_roots[:16]
            signer = pm.get("required_signer")
            if isinstance(signer, str) and signer.strip():
                dp["required_signer"] = signer.strip()
            dp["verify_signature"] = _as_bool(
                pm.get("verify_signature"), dp["verify_signature"]
            )

        # 3. Engine
        eng = raw.get("engine")
        if isinstance(eng, dict):
            de = out["engine"]
            mode = eng.get("mode")
            if isinstance(mode, str):
                mode_map = {
                    "active": "active",
                    "observe": "observe_divert",
                    "observe_divert": "observe_divert",
                    "observe_sniff": "observe_sniff",
                }
                if mode in mode_map:
                    de["mode"] = mode_map[mode]
                elif mode in VALID_ENGINE_MODES:
                    de["mode"] = mode
            de["pending_queue_timeout_ms"] = _clamp_int(
                eng.get("pending_queue_timeout_ms"),
                de["pending_queue_timeout_ms"],
                10,
                500,
            )
            de["pending_queue_max_packets"] = _clamp_int(
                eng.get("pending_queue_max_packets"),
                de["pending_queue_max_packets"],
                16,
                4096,
            )
            de["flow_idle_timeout_s"] = _clamp_int(
                eng.get("flow_idle_timeout_s"),
                de["flow_idle_timeout_s"],
                15,
                3600,
            )
            de["ipv6"] = _as_bool(eng.get("ipv6"), de["ipv6"])

        # 4. TCP strategy
        tcp = raw.get("tcp_strategy")
        if isinstance(tcp, dict):
            dt = out["tcp_strategy"]
            dt["enabled"] = _as_bool(tcp.get("enabled"), dt["enabled"])
            ports = tcp.get("target_ports")
            if isinstance(ports, list):
                valid_ports = sorted(
                    {
                        p
                        for p in ports
                        if not isinstance(p, bool)
                        and isinstance(p, int)
                        and 1 <= p <= 65535
                    }
                )
                if valid_ports:
                    dt["target_ports"] = valid_ports[:16]
            sm = tcp.get("split_mode")
            if isinstance(sm, str):
                sm_alias = {
                    "record-sni": "record_and_sni",
                    "sni": "sni_middle",
                    "first": "first_byte",
                }.get(sm, sm)
                if sm_alias in VALID_SPLIT_MODES:
                    dt["split_mode"] = sm_alias
            dt["reverse_order"] = _as_bool(tcp.get("reverse_order"), dt["reverse_order"])

        # 5. QUIC strategy
        quic = raw.get("quic_strategy")
        if isinstance(quic, dict):
            dq = out["quic_strategy"]
            qm = quic.get("mode")
            if isinstance(qm, str):
                qm_alias = {"disable": "drop_discord_quic_443"}.get(qm, qm)
                if qm_alias in VALID_QUIC_MODES:
                    dq["mode"] = qm_alias

        return out
