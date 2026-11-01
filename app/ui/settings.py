"""Sadeleştirilmiş Ayarlar ekranı: yalnızca son kullanıcının ihtiyaç duyduğu tercihler."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.constants import PALETTE

# Uyumluluk profilleri -> arka plandaki C++ motor parametreleri
_PRESET_MAP: dict[str, tuple[str, bool]] = {
    "standard": ("record_and_sni", True),
    "alt_1": ("sni_middle", True),
    "alt_2": ("first_byte", False),
}


class SettingsPage(QWidget):
    """Son kullanıcı odaklı sade uygulama ayarları ekranı."""

    save_requested = Signal(dict)
    reset_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("PageContainer")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 8, 22, 6)
        outer.setSpacing(8)

        # Kart 1: Uygulama Tercihleri
        gen_card = QFrame()
        gen_card.setObjectName("Card")
        gen_layout = QVBoxLayout(gen_card)
        gen_layout.setContentsMargins(16, 10, 16, 10)
        gen_layout.setSpacing(5)

        gen_title = QLabel("Uygulama Tercihleri")
        gen_title.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {PALETTE['text_primary']}; background: transparent;"
        )
        gen_layout.addWidget(gen_title)

        self.chk_start_windows = QCheckBox("Windows açıldığında otomatik başlat")
        self.chk_start_minimized = QCheckBox(
            "Uygulamayı sistem tepsisinde küçültülmüş başlat"
        )
        self.chk_auto_connect = QCheckBox("Uygulama açıldığında otomatik bağlan")
        self.chk_minimize_to_tray = QCheckBox(
            "Uygulama kapatıldığında sistem tepsisine küçült"
        )
        self.chk_launch_discord = QCheckBox(
            "Bağlantı başlatıldığında Discord kapalıysa otomatik aç"
        )
        gen_layout.addWidget(self.chk_start_windows)
        gen_layout.addWidget(self.chk_start_minimized)
        gen_layout.addWidget(self.chk_auto_connect)
        gen_layout.addWidget(self.chk_minimize_to_tray)
        gen_layout.addWidget(self.chk_launch_discord)

        stop_form = QFormLayout()
        stop_form.setSpacing(6)
        self.cmb_on_stop_action = QComboBox()
        self.cmb_on_stop_action.addItem(
            "Discord bağlantısını kes (pencere açık kalır)",
            "reset_connections",
        )
        self.cmb_on_stop_action.addItem(
            "Discord'u tamamen kapat",
            "close_discord",
        )
        self.cmb_on_stop_action.addItem(
            "Açık bağlantılara dokunma",
            "keep",
        )
        stop_form.addRow("Durdurulduğunda:", self.cmb_on_stop_action)
        gen_layout.addLayout(stop_form)
        outer.addWidget(gen_card)

        # Kart 2: Bağlantı Yöntemi
        net_card = QFrame()
        net_card.setObjectName("Card")
        net_layout = QVBoxLayout(net_card)
        net_layout.setContentsMargins(16, 10, 16, 10)
        net_layout.setSpacing(6)

        net_title = QLabel("Bağlantı Yöntemi")
        net_title.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {PALETTE['text_primary']}; background: transparent;"
        )
        net_layout.addWidget(net_title)

        net_form = QFormLayout()
        net_form.setSpacing(6)
        self.cmb_connection_preset = QComboBox()
        self.cmb_connection_preset.addItem("Standart Mod (Önerilen)", "standard")
        self.cmb_connection_preset.addItem("Alternatif Mod 1", "alt_1")
        self.cmb_connection_preset.addItem("Alternatif Mod 2", "alt_2")
        net_form.addRow("Uyumluluk Modu:", self.cmb_connection_preset)
        net_layout.addLayout(net_form)

        self.chk_auto_fallback = QCheckBox(
            "Bağlantı kurulamazsa alternatif modları otomatik dene"
        )
        net_layout.addWidget(self.chk_auto_fallback)

        net_hint = QLabel(
            "Standart mod çoğu internet bağlantısında sorunsuz çalışır. "
            "Discord'a bağlanırken sorun yaşarsanız alternatif modları deneyebilirsiniz."
        )
        net_hint.setWordWrap(True)
        net_hint.setStyleSheet(
            f"font-size: 11px; color: {PALETTE['text_muted']}; background: transparent;"
        )
        net_layout.addWidget(net_hint)
        outer.addWidget(net_card)

        outer.addStretch(1)

        # Alt kayıt çubuğu
        action_bar = QHBoxLayout()
        action_bar.setSpacing(10)

        self.feedback_lbl = QLabel("")
        self.feedback_lbl.setStyleSheet(
            f"font-size: 12px; font-weight: 600; color: {PALETTE['success']};"
        )

        self.reset_btn = QPushButton("Varsayılanlar")
        self.reset_btn.setObjectName("SecondaryButton")
        self.reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_btn.clicked.connect(self.reset_requested.emit)

        self.save_btn = QPushButton("Kaydet")
        self.save_btn.setObjectName("PrimaryButton")
        self.save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_btn.clicked.connect(self._emit_save)

        action_bar.addWidget(self.feedback_lbl, 1)
        action_bar.addWidget(self.reset_btn)
        action_bar.addWidget(self.save_btn)
        outer.addLayout(action_bar)

        self._base_settings: dict[str, Any] = {}

    def load_settings(self, settings: dict[str, Any]) -> None:
        self._base_settings = settings
        gen = settings.get("general", {})
        tcp = settings.get("tcp_strategy", {})

        self.chk_start_windows.setChecked(bool(gen.get("start_with_windows", False)))
        self.chk_start_minimized.setChecked(bool(gen.get("start_minimized", False)))
        self.chk_auto_connect.setChecked(bool(gen.get("auto_connect_on_start", False)))
        self.chk_minimize_to_tray.setChecked(bool(gen.get("minimize_to_tray", False)))
        self.chk_auto_fallback.setChecked(bool(gen.get("auto_fallback", True)))
        self.chk_launch_discord.setChecked(
            bool(gen.get("launch_discord_on_start", False))
        )
        self._select_combo_data(
            self.cmb_on_stop_action,
            str(gen.get("on_stop_discord_action", "reset_connections")),
        )

        split_mode = str(tcp.get("split_mode", "record_and_sni"))
        reverse_order = bool(tcp.get("reverse_order", True))
        if split_mode == "sni_middle":
            preset = "alt_1"
        elif split_mode == "first_byte" or not reverse_order:
            preset = "alt_2"
        else:
            preset = "standard"
        self._select_combo_data(self.cmb_connection_preset, preset)

    def collect_settings(self) -> dict[str, Any]:
        base_gen = dict(self._base_settings.get("general", {}))
        base_eng = dict(self._base_settings.get("engine", {}))
        base_tcp = dict(self._base_settings.get("tcp_strategy", {}))

        preset = str(self.cmb_connection_preset.currentData() or "standard")
        split_mode, reverse_order = _PRESET_MAP.get(preset, ("record_and_sni", True))

        return {
            "schema_version": 1,
            "general": {
                **base_gen,
                "start_with_windows": self.chk_start_windows.isChecked(),
                "start_minimized": self.chk_start_minimized.isChecked(),
                "auto_connect_on_start": self.chk_auto_connect.isChecked(),
                "minimize_to_tray": self.chk_minimize_to_tray.isChecked(),
                "auto_fallback": self.chk_auto_fallback.isChecked(),
                "auto_detect_discord": True,
                "launch_discord_on_start": self.chk_launch_discord.isChecked(),
                "on_stop_discord_action": str(
                    self.cmb_on_stop_action.currentData() or "reset_connections"
                ),
                "auto_health_check": True,
            },
            "process_match": dict(self._base_settings.get("process_match", {})),
            "engine": {
                **base_eng,
                "mode": "active",
                "ipv6": True,
            },
            "tcp_strategy": {
                **base_tcp,
                "enabled": True,
                "split_mode": split_mode,
                "reverse_order": reverse_order,
            },
            "udp_strategy": {"mode": "observe"},
            "quic_strategy": {"mode": "drop_discord_quic_443"},
        }

    def show_feedback(self, message: str, ok: bool = True) -> None:
        color = PALETTE["success"] if ok else PALETTE["warning"]
        self.feedback_lbl.setStyleSheet(
            f"font-size: 12px; font-weight: 600; color: {color};"
        )
        self.feedback_lbl.setText(message)

    def _emit_save(self) -> None:
        self.save_requested.emit(self.collect_settings())

    @staticmethod
    def _select_combo_data(combo: QComboBox, target: str) -> None:
        idx = combo.findData(target)
        if idx >= 0:
            combo.setCurrentIndex(idx)
