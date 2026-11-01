"""QApplication yaşam döngüsü, tek örnek kontrolü ve servis orkestrasyonu."""

from __future__ import annotations

from pathlib import Path
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.constants import APP_NAME, APP_ORG, APP_VERSION, CONFIG_FILE, LOG_FILE
from app.services.backend_manager import BackendManager
from app.services.config_manager import ConfigManager
from app.services.log_manager import LogManager
from app.services.status_manager import StatusManager
from app.ui.main_window import MainWindow
from app.ui.theme import build_app_icon, build_stylesheet


class DiscordDpiApplication:
    """Tüm uygulama servislerini ve ana PySide6 penceresini birbirine bağlar."""

    def __init__(
        self,
        argv: list[str] | None = None,
        *,
        config_path: Path = CONFIG_FILE,
        log_path: Path = LOG_FILE,
        enable_tray: bool = True,
    ) -> None:
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "SametDrs.SDPI.Desktop.1.0"
                )
            except Exception:
                pass

        self._argv = list(argv if argv is not None else sys.argv)
        existing_app = QApplication.instance()
        if existing_app is not None and isinstance(existing_app, QApplication):
            self.qt_app = existing_app
        else:
            QApplication.setHighDpiScaleFactorRoundingPolicy(
                Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
            )
            self.qt_app = QApplication(self._argv)

        self.qt_app.setApplicationName(APP_NAME)
        self.qt_app.setApplicationVersion(APP_VERSION)
        self.qt_app.setOrganizationName(APP_ORG)
        self.qt_app.setWindowIcon(build_app_icon(active=False))
        self.qt_app.setStyleSheet(build_stylesheet())

        self.config_manager = ConfigManager(config_path=config_path)
        initial_cfg = self.config_manager.get_all()

        self.log_manager = LogManager(
            log_file=log_path,
            level=initial_cfg["general"]["log_level"],
        )
        self.log_manager.logger.info(
            "%s v%s baslatildi.", APP_NAME, APP_VERSION
        )

        self.backend_manager = BackendManager()
        self.status_manager = StatusManager(
            backend=self.backend_manager,
            config=self.config_manager,
        )

        self.main_window = MainWindow(
            config_manager=self.config_manager,
            log_manager=self.log_manager,
            backend_manager=self.backend_manager,
            status_manager=self.status_manager,
            enable_tray=enable_tray,
        )
        self.qt_app.aboutToQuit.connect(self.main_window.shutdown_cleanly)

    def run(self) -> int:
        self.status_manager.start_monitoring()
        if (
            self.main_window.should_start_minimized(self._argv)
            and self.main_window._tray is not None
        ):
            self.main_window.hide()
        else:
            self.main_window.show()
        self.main_window.trigger_startup_actions()
        return int(self.qt_app.exec())


SdpiApplication = DiscordDpiApplication
