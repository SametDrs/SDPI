"""Sadeleştirilmiş son kullanıcı Ana Ekranı: tek tuşla Discord bağlantısı ve durum özeti."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.constants import PALETTE
from app.ui.components.widgets import (
    BannerAlert,
    LoadingSpinner,
    StatusBadge,
    format_uptime,
)


class DashboardPage(QWidget):
    """Son kullanıcı odaklı sade ana kontrol ekranı."""

    toggle_engine_requested = Signal()
    launch_discord_requested = Signal()
    repair_discord_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("PageContainer")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 18, 22, 6)
        root.setSpacing(13)

        # Uyarı / hata bildirim bandı (yalnızca gerektiğinde görünür)
        self.banner = BannerAlert()
        root.addWidget(self.banner)

        # Merkez Bağlantı Kartı (Hero)
        hero = QFrame()
        hero.setObjectName("HeroCard")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 24, 24, 24)
        hero_layout.setSpacing(10)

        badge_container = QWidget()
        badge_container.setFixedHeight(32)
        badge_container.setStyleSheet("background: transparent;")
        badge_row = QHBoxLayout(badge_container)
        badge_row.setContentsMargins(0, 0, 0, 0)
        badge_row.addStretch(1)
        self.engine_badge = StatusBadge("Kapalı", "neutral")
        self.loading_spinner = LoadingSpinner(size=30, color=PALETTE["accent"])
        badge_row.addWidget(self.engine_badge, 0, Qt.AlignmentFlag.AlignCenter)
        badge_row.addWidget(self.loading_spinner, 0, Qt.AlignmentFlag.AlignCenter)
        badge_row.addStretch(1)

        self.hero_title_lbl = QLabel("Discord Bağlantısı Kapalı")
        self.hero_title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hero_title_lbl.setStyleSheet(
            f"font-size: 21px; font-weight: 700; color: {PALETTE['text_primary']}; background: transparent;"
        )

        self.hero_desc_lbl = QLabel(
            "Discord masaüstü uygulamasına erişmek için bağlantıyı başlatın."
        )
        self.hero_desc_lbl.setWordWrap(True)
        self.hero_desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hero_desc_lbl.setStyleSheet(
            f"font-size: 13px; color: {PALETTE['text_secondary']}; background: transparent;"
        )

        self.hero_uptime_lbl = QLabel("")
        self.hero_uptime_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hero_uptime_lbl.setStyleSheet(
            f"font-size: 12px; font-weight: 600; color: {PALETTE['success']}; background: transparent;"
        )
        self.hero_uptime_lbl.hide()

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.toggle_btn = QPushButton("Bağlantıyı Başlat")
        self.toggle_btn.setObjectName("EngineStartButton")
        self.toggle_btn.setProperty("running", "false")
        self.toggle_btn.setProperty("loading", "false")
        self.toggle_btn.setMinimumSize(230, 46)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self.toggle_engine_requested.emit)
        btn_row.addWidget(self.toggle_btn)
        btn_row.addStretch(1)

        hero_layout.addWidget(badge_container)
        hero_layout.addWidget(self.hero_title_lbl)
        hero_layout.addWidget(self.hero_desc_lbl)
        hero_layout.addWidget(self.hero_uptime_lbl)
        hero_layout.addSpacing(6)
        hero_layout.addLayout(btn_row)
        root.addWidget(hero)

        # Kart 2: Discord Uygulama Durumu
        discord_card = QFrame()
        discord_card.setObjectName("Card")
        dc_layout = QHBoxLayout(discord_card)
        dc_layout.setContentsMargins(18, 14, 18, 14)
        dc_layout.setSpacing(12)

        dc_text = QVBoxLayout()
        dc_text.setSpacing(3)
        dc_title = QLabel("Discord Uygulaması")
        dc_title.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {PALETTE['text_primary']}; background: transparent;"
        )
        self.discord_detail_lbl = QLabel("Durum kontrol ediliyor...")
        self.discord_detail_lbl.setStyleSheet(
            f"font-size: 12px; color: {PALETTE['text_secondary']}; background: transparent;"
        )
        dc_text.addWidget(dc_title)
        dc_text.addWidget(self.discord_detail_lbl)

        self.discord_badge = StatusBadge("Kapalı", "neutral")

        self.repair_discord_btn = QPushButton("Onar")
        self.repair_discord_btn.setObjectName("SecondaryButton")
        self.repair_discord_btn.setToolTip(
            "DNS önbelleğini temizler ve Discord ağ oturumunu yeniler"
        )
        self.repair_discord_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.repair_discord_btn.clicked.connect(self.repair_discord_requested.emit)

        self.launch_discord_btn = QPushButton("Discord'u Aç")
        self.launch_discord_btn.setObjectName("SecondaryButton")
        self.launch_discord_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.launch_discord_btn.clicked.connect(self.launch_discord_requested.emit)

        dc_layout.addLayout(dc_text, 1)
        dc_layout.addWidget(self.repair_discord_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        dc_layout.addWidget(self.launch_discord_btn, 0, Qt.AlignmentFlag.AlignVCenter)
        dc_layout.addWidget(self.discord_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(discord_card)

        # Kart 3: Diğer Uygulamaların Korunması
        iso_card = QFrame()
        iso_card.setObjectName("Card")
        ic_layout = QHBoxLayout(iso_card)
        ic_layout.setContentsMargins(18, 14, 18, 14)
        ic_layout.setSpacing(12)

        ic_text = QVBoxLayout()
        ic_text.setSpacing(3)
        ic_title = QLabel("Diğer Uygulamalar ve Oyunlar")
        ic_title.setStyleSheet(
            f"font-size: 14px; font-weight: 700; color: {PALETTE['text_primary']}; background: transparent;"
        )
        self.iso_detail_lbl = QLabel(
            "Tarayıcılar, oyunlar ve indirmeler normal internet bağlantınızı kullanır."
        )
        self.iso_detail_lbl.setWordWrap(True)
        self.iso_detail_lbl.setStyleSheet(
            f"font-size: 12px; color: {PALETTE['text_secondary']}; background: transparent;"
        )
        ic_text.addWidget(ic_title)
        ic_text.addWidget(self.iso_detail_lbl)

        self.iso_badge = StatusBadge("Etkilenmez", "success")

        ic_layout.addLayout(ic_text, 1)
        ic_layout.addWidget(self.iso_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        root.addWidget(iso_card)

        root.addStretch(1)

    def set_busy_transition(self, action: str) -> None:
        self.toggle_btn.setEnabled(False)
        self._set_button_loading_style(True)
        self.hero_uptime_lbl.hide()
        self.engine_badge.hide()
        self.loading_spinner.start()
        if action == "start":
            self.toggle_btn.setText("Bağlantı Kuruluyor...")
            self.hero_title_lbl.setText("Bağlantı Kuruluyor...")
            self.hero_desc_lbl.setText(
                "Açılan pencerede yönetici iznini onaylayın."
            )
        else:
            self.toggle_btn.setText("Durduruluyor...")
            self.hero_title_lbl.setText("Bağlantı Durduruluyor...")
            self.hero_desc_lbl.setText(
                "Discord bağlantısı güvenli şekilde kapatılıyor."
            )

    def update_from_snapshot(self, snap: dict[str, Any]) -> None:
        state = str(snap.get("engine_state", "stopped"))
        running = bool(snap.get("running", False))
        stats = snap.get("stats", {})

        # 1. Hata / uyarı bildirimi
        ui_err = str(snap.get("ui_error") or snap.get("last_error") or "")
        ui_warn = str(snap.get("ui_warning") or snap.get("last_warning") or "")
        if ui_err:
            self.banner.show_message(ui_err, "error")
        elif ui_warn:
            self.banner.show_message(ui_warn, "warning")
        else:
            self.banner.hide()

        # 2. Ana bağlantı durumu
        if state == "starting":
            self.set_busy_transition("start")
        elif state == "stopping":
            self.set_busy_transition("stop")
        elif running and state == "running":
            uptime_str = format_uptime(int(stats.get("uptime_ms", 0)))
            self.loading_spinner.stop()
            self.engine_badge.show()
            self._set_button_loading_style(False)
            self.toggle_btn.setEnabled(True)
            self.toggle_btn.setText("Bağlantıyı Durdur")
            self._set_button_running_style(True)
            self.engine_badge.set_status("Bağlantı Aktif", "success")
            self.hero_title_lbl.setText("Discord Bağlantısı Aktif")
            self.hero_desc_lbl.setText(
                "Mesajlaşma, sesli sohbet ve medya erişimi açık"
            )
            ping_ms = stats.get("ping_ms")
            if isinstance(ping_ms, int) and ping_ms > 0:
                self.hero_uptime_lbl.setText(f"{uptime_str}  •  {ping_ms} ms")
            else:
                self.hero_uptime_lbl.setText(uptime_str)
            self.hero_uptime_lbl.show()
        elif state == "error":
            self.loading_spinner.stop()
            self.engine_badge.show()
            self._set_button_loading_style(False)
            self.toggle_btn.setEnabled(True)
            self.toggle_btn.setText("Tekrar Dene")
            self._set_button_running_style(False)
            self.engine_badge.set_status("Hata", "error")
            self.hero_title_lbl.setText("Bağlantı Başlatılamadı")
            self.hero_desc_lbl.setText(
                "Lütfen üstteki uyarıyı kontrol edip tekrar deneyin."
            )
            self.hero_uptime_lbl.hide()
        else:
            self.loading_spinner.stop()
            self.engine_badge.show()
            self._set_button_loading_style(False)
            self.toggle_btn.setEnabled(True)
            self.toggle_btn.setText("Bağlantıyı Başlat")
            self._set_button_running_style(False)
            self.engine_badge.set_status("Kapalı", "neutral")
            self.hero_title_lbl.setText("Discord Bağlantısı Kapalı")
            self.hero_desc_lbl.setText(
                "Discord masaüstü uygulamasına erişmek için bağlantıyı başlatın."
            )
            self.hero_uptime_lbl.hide()

        # 3. Discord uygulama durumu
        proc_count = int(stats.get("active_discord_processes", 0))
        if proc_count > 0:
            self.discord_badge.set_status("Açık", "success")
            if running:
                self.discord_detail_lbl.setText("Discord çalışıyor ve bağlantısı korunuyor.")
            else:
                self.discord_detail_lbl.setText("Discord açık — erişim için bağlantıyı başlatın.")
            self.launch_discord_btn.hide()
        else:
            self.discord_badge.set_status("Kapalı", "neutral")
            self.discord_detail_lbl.setText("Discord şu anda kapalı.")
            self.launch_discord_btn.show()

    def _set_button_running_style(self, is_running: bool) -> None:
        desired = "true" if is_running else "false"
        if self.toggle_btn.property("running") != desired:
            self.toggle_btn.setProperty("running", desired)
            self.toggle_btn.style().unpolish(self.toggle_btn)
            self.toggle_btn.style().polish(self.toggle_btn)

    def _set_button_loading_style(self, is_loading: bool) -> None:
        desired = "true" if is_loading else "false"
        if self.toggle_btn.property("loading") != desired:
            self.toggle_btn.setProperty("loading", desired)
            self.toggle_btn.style().unpolish(self.toggle_btn)
            self.toggle_btn.style().polish(self.toggle_btn)
