"""Ana pencere: sabit boyutlu kompakt tasarım, üst sekme çubuğu, GitHub alt bilgisi ve sistem tepsisi."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from app.constants import APP_NAME, PALETTE
from app.services.backend_manager import BackendActionResult, BackendManager, EngineState
from app.services.config_manager import ConfigManager
from app.services.log_manager import LogManager
from app.services.process_manager import ProcessManager
from app.services.status_manager import StatusManager
from app.ui.components.widgets import PopupNotification
from app.ui.dashboard import DashboardPage
from app.ui.settings import SettingsPage
from app.ui.theme import build_app_icon, build_github_icon

GITHUB_PROFILE_NAME = "SametDrs"
GITHUB_PROFILE_URL = "https://github.com/SametDrs"


class MainWindow(QMainWindow):
    """Sabit boyutlu, son kullanıcı odaklı SDPI masaüstü penceresi."""

    def __init__(
        self,
        *,
        config_manager: ConfigManager,
        log_manager: LogManager,
        backend_manager: BackendManager,
        status_manager: StatusManager,
        enable_tray: bool = True,
    ) -> None:
        super().__init__()
        self._config = config_manager
        self._logs = log_manager
        self._backend = backend_manager
        self._status = status_manager
        self._shutting_down = False
        self._force_quit = False
        self._tray_notified_once = False
        self.last_tray_notification = ""
        self._last_running_icon_state: bool | None = None

        self.setWindowTitle(APP_NAME)
        self.setFixedSize(520, 560)

        self._icon_idle = build_app_icon(active=False)
        self._icon_active = build_app_icon(active=True)
        self.setWindowIcon(self._icon_idle)

        # Kök yerleşim: Üst Başlık Çubuğu + Sayfa Yığını + Alt Bilgi Çubuğu
        root_widget = QWidget()
        root_widget.setObjectName("RootContainer")
        root_widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        top_header = QFrame()
        top_header.setObjectName("TopHeader")
        header_layout = QHBoxLayout(top_header)
        header_layout.setContentsMargins(22, 14, 22, 14)
        header_layout.setSpacing(12)

        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(0, 0, 0, 0)
        brand_row.setSpacing(9)

        self.brand_icon_lbl = QLabel()
        self.brand_icon_lbl.setObjectName("BrandIcon")
        self.brand_icon_lbl.setStyleSheet("background: transparent;")
        icon_pixmap = self._icon_idle.pixmap(24, 24)
        self.brand_icon_lbl.setPixmap(icon_pixmap)
        self.brand_icon_lbl.setFixedSize(24, 24)
        self.brand_icon_lbl.setScaledContents(True)

        self.brand_title = QLabel(APP_NAME)
        self.brand_title.setStyleSheet(
            f"font-size: 19px; font-weight: 800; color: {PALETTE['text_primary']}; background: transparent;"
        )

        brand_row.addWidget(self.brand_icon_lbl)
        brand_row.addWidget(self.brand_title)

        segment_bar = QFrame()
        segment_bar.setObjectName("SegmentBar")
        seg_layout = QHBoxLayout(segment_bar)
        seg_layout.setContentsMargins(4, 4, 4, 4)
        seg_layout.setSpacing(4)

        self.nav_dashboard_btn = self._create_nav_button("Ana Ekran", 0)
        self.nav_settings_btn = self._create_nav_button("Ayarlar", 1)
        self._nav_buttons = [
            self.nav_dashboard_btn,
            self.nav_settings_btn,
        ]
        for btn in self._nav_buttons:
            seg_layout.addWidget(btn)

        header_layout.addLayout(brand_row)
        header_layout.addStretch(1)
        header_layout.addWidget(segment_bar)

        self.stack = QStackedWidget()
        self.stack.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.dashboard_page = DashboardPage()
        self.settings_page = SettingsPage()

        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.settings_page)

        # Sol alt GitHub profil bağlantısı
        footer_bar = QFrame()
        footer_bar.setObjectName("FooterBar")
        footer_layout = QHBoxLayout(footer_bar)
        footer_layout.setContentsMargins(16, 2, 22, 10)
        footer_layout.setSpacing(0)

        self.github_btn = QPushButton(f"  {GITHUB_PROFILE_NAME}")
        self.github_btn.setObjectName("GithubFooterButton")
        self.github_btn.setIcon(build_github_icon(PALETTE["text_secondary"]))
        self.github_btn.setIconSize(QSize(15, 15))
        self.github_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.github_btn.setToolTip(GITHUB_PROFILE_URL)
        self.github_btn.clicked.connect(self._open_github_profile)

        footer_layout.addWidget(self.github_btn, 0, Qt.AlignmentFlag.AlignLeft)
        footer_layout.addStretch(1)

        root_layout.addWidget(top_header)
        root_layout.addWidget(self.stack, 1)
        root_layout.addWidget(footer_bar)
        self.setCentralWidget(root_widget)

        self.success_popup = PopupNotification(self)

        # Başlangıç ayarlarını yükle
        initial_settings = self._config.get_all()
        if ProcessManager.is_start_with_windows_enabled():
            initial_settings["general"]["start_with_windows"] = True
        self.settings_page.load_settings(initial_settings)
        self._select_page(0)

        # Sinyal bağlantıları
        self.dashboard_page.toggle_engine_requested.connect(self._status.toggle_engine)
        self.dashboard_page.launch_discord_requested.connect(self._on_launch_discord)
        self.dashboard_page.repair_discord_requested.connect(self._on_repair_discord)
        self.settings_page.save_requested.connect(self._on_save_settings)
        self.settings_page.reset_requested.connect(self._on_reset_settings)

        self._status.action_started.connect(self._on_action_started)
        self._status.action_finished.connect(self._on_action_finished)
        self._status.telemetry_updated.connect(self._on_telemetry_updated)
        self._status.fallback_switched.connect(self._on_fallback_switched)

        # Sistem tepsisi simgesi
        self._tray: QSystemTrayIcon | None = None
        self._tray_toggle_action: QAction | None = None
        platform_name = QGuiApplication.platformName().lower()
        if (
            enable_tray
            and platform_name != "offscreen"
            and QSystemTrayIcon.isSystemTrayAvailable()
        ):
            self._init_system_tray()

    @staticmethod
    def _open_github_profile() -> None:
        QDesktopServices.openUrl(QUrl(GITHUB_PROFILE_URL))

    def _create_nav_button(self, label: str, page_index: int) -> QPushButton:
        btn = QPushButton(label)
        btn.setObjectName("NavButton")
        btn.setProperty("active", "false")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda _checked=False, idx=page_index: self._select_page(idx))
        return btn

    def _select_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            active_str = "true" if i == index else "false"
            if btn.property("active") != active_str:
                btn.setProperty("active", active_str)
                btn.style().unpolish(btn)
                btn.style().polish(btn)

    def _init_system_tray(self) -> None:
        QGuiApplication.setQuitOnLastWindowClosed(False)
        tray = QSystemTrayIcon(self._icon_idle, self)
        tray.setToolTip(f"{APP_NAME} — Kapalı")

        menu = QMenu()
        show_action = QAction("Pencereyi Aç", self)
        show_action.triggered.connect(self._restore_from_tray)

        toggle_action = QAction("Bağlantıyı Başlat", self)
        toggle_action.triggered.connect(self._status.toggle_engine)

        quit_action = QAction("Çıkış", self)
        quit_action.triggered.connect(self.quit_application)

        menu.addAction(show_action)
        menu.addAction(toggle_action)
        menu.addSeparator()
        menu.addAction(quit_action)

        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.show()

        self._tray = tray
        self._tray_toggle_action = toggle_action

    def _restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._restore_from_tray()

    def _on_action_started(self, action: str) -> None:
        self.dashboard_page.set_busy_transition(action)

    def _on_action_finished(self, result: BackendActionResult) -> None:
        prev_stats = dict(self._status.latest_snapshot.get("stats", {}))
        is_running = result.state == EngineState.RUNNING
        instant_snap: dict[str, Any] = {
            "ok": result.ok,
            "engine_state": result.state.value,
            "running": is_running,
            "ui_error": "" if (result.ok or result.uac_cancelled) else result.message,
            "ui_warning": result.message if (not result.ok and result.uac_cancelled) else "",
            "stats": {
                "uptime_ms": prev_stats.get("uptime_ms", 0) if is_running else 0,
                "active_discord_processes": prev_stats.get("active_discord_processes", 0),
            },
        }
        self._on_telemetry_updated(instant_snap)

    def _on_telemetry_updated(self, snap: dict[str, Any]) -> None:
        self.dashboard_page.update_from_snapshot(snap)

        running = bool(snap.get("running", False))
        state = str(snap.get("engine_state", "stopped"))
        state_tr = (
            "Bağlantı Aktif"
            if running
            else ("Hata" if state == "error" else "Kapalı")
        )

        if self._last_running_icon_state != running:
            self._last_running_icon_state = running
            icon = self._icon_active if running else self._icon_idle
            self.setWindowIcon(icon)
            if self._tray is not None:
                self._tray.setIcon(icon)
                self._tray.setToolTip(f"{APP_NAME} — {state_tr}")
            if self._tray_toggle_action is not None:
                self._tray_toggle_action.setText(
                    "Bağlantıyı Durdur" if running else "Bağlantıyı Başlat"
                )

    def _on_launch_discord(self) -> None:
        ok, msg = ProcessManager.launch_discord()
        self.dashboard_page.banner.show_message(
            msg, "success" if ok else "warning"
        )

    def _on_repair_discord(self) -> None:
        roots = self._config.get_all().get("process_match", {}).get("install_roots")
        _ok, msg = ProcessManager.repair_discord_connection(roots)
        self.success_popup.show_popup(msg, duration_ms=2000)

    def _on_fallback_switched(self, msg: str) -> None:
        self.settings_page.load_settings(self._config.get_all())
        self.success_popup.show_popup(msg, duration_ms=2000)

    def _on_save_settings(self, candidate: dict[str, Any]) -> None:
        saved = self._config.save(candidate)
        self._logs.configure(saved["general"]["log_level"])

        reg_ok, reg_msg = ProcessManager.set_start_with_windows(
            bool(saved["general"]["start_with_windows"]),
            minimized=bool(saved["general"].get("start_minimized", False)),
        )
        self._backend.apply_live_strategy(saved)
        self.settings_page.load_settings(saved)

        if not reg_ok:
            self.settings_page.show_feedback(reg_msg, ok=False)
            return

        self.settings_page.show_feedback("")
        self._select_page(0)
        self.success_popup.show_popup("İşlem başarılı", duration_ms=2000)

    def _on_reset_settings(self) -> None:
        defaults = self._config.reset_to_defaults()
        self._logs.configure(defaults["general"]["log_level"])
        ProcessManager.set_start_with_windows(False)
        self._backend.apply_live_strategy(defaults)
        self.settings_page.load_settings(defaults)
        self.settings_page.show_feedback("Varsayılan ayarlar yüklendi.", ok=True)

    def should_start_minimized(self, cli_args: list[str] | None = None) -> bool:
        """Uygulamanın açılışta sistem tepsisinde gizli başlayıp başlamayacağını belirler."""
        args = cli_args or []
        if "--minimized" in args:
            return True
        settings = self._config.get_all()
        return bool(settings.get("general", {}).get("start_minimized", False))

    def trigger_startup_actions(self, *, immediate: bool = False) -> bool:
        """Uygulama açıldığında 'otomatik bağlan' ayarı etkinse bağlantıyı başlatır."""
        settings = self._config.get_all()
        if not bool(settings.get("general", {}).get("auto_connect_on_start", False)):
            return False
        if immediate:
            self._status.request_start_engine()
        else:
            QTimer.singleShot(150, self._status.request_start_engine)
        return True

    def quit_application(self) -> None:
        """Sistem tepsisinden 'Çıkış' seçildiğinde uygulamayı tamamen kapatır."""
        self._force_quit = True
        self.shutdown_cleanly()
        self.close()
        app_inst = QGuiApplication.instance()
        if app_inst is not None:
            app_inst.quit()

    def shutdown_cleanly(self) -> None:
        """Pencere kapanırken izleyiciyi ve arka plan servisini güvenli şekilde kapatır."""
        if self._shutting_down:
            return
        self._shutting_down = True
        if self._tray is not None:
            self._tray.hide()
        self._status.stop_monitoring()
        if self._backend.state != EngineState.STOPPED:
            self._backend.stop_engine(self._config.get_all())

    def closeEvent(self, event: QCloseEvent) -> None:
        minimize_to_tray = bool(
            self._config.get_all().get("general", {}).get("minimize_to_tray", False)
        )
        if not self._force_quit and minimize_to_tray and self._tray is not None:
            event.ignore()
            self.hide()
            if not self._tray_notified_once:
                self._tray_notified_once = True
                msg = "Uygulama sağ alttaki sistem tepsisinde çalışmaya devam ediyor."
                self.last_tray_notification = msg
                self._tray.showMessage(
                    APP_NAME,
                    msg,
                    QSystemTrayIcon.MessageIcon.Information,
                    2500,
                )
            return
        self.shutdown_cleanly()
        event.accept()
        if self._tray is not None:
            app_inst = QGuiApplication.instance()
            if app_inst is not None:
                app_inst.quit()
