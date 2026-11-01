"""Durum rozetleri, uyarı bantları ve geçici bildirim pencereleri (popup)."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QWidget,
)

from app.constants import PALETTE


def format_uptime(uptime_ms: int) -> str:
    """Milisaniye cinsinden çalışma süresini `SS:DD:SN` biçimine çevirir."""
    total_sec = max(0, int(uptime_ms) // 1000)
    hours, rem = divmod(total_sec, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class StatusBadge(QLabel):
    """Durum rengine göre biçimlenen yuvarlatılmış rozet."""

    _TONES = {
        "success": (PALETTE["success"], PALETTE["success_bg"]),
        "warning": (PALETTE["warning"], PALETTE["warning_bg"]),
        "error": (PALETTE["error"], PALETTE["error_bg"]),
        "neutral": (PALETTE["text_secondary"], PALETTE["bg_input"]),
        "accent": (PALETTE["accent"], "#1D1B38"),
    }

    def __init__(
        self, text: str = "Kapalı", tone: str = "neutral", parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_status(text, tone)

    def set_status(self, text: str, tone: str = "neutral") -> None:
        fg, bg = self._TONES.get(tone, self._TONES["neutral"])
        self.setText(f"●  {text}")
        self.setStyleSheet(
            f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 11px;
                padding: 4px 12px;
                font-size: 12px;
                font-weight: 700;
            }}
            """
        )


class BannerAlert(QFrame):
    """Kullanıcıya anlaşılır durum veya uyarı mesajlarını gösteren üst bilgi bandı."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        self._label = QLabel("")
        self._label.setWordWrap(True)
        layout.addWidget(self._label, 1)
        self.hide()

    def show_message(self, text: str, level: str = "warning") -> None:
        if not text:
            self.hide()
            return
        if level == "error":
            fg, bg = PALETTE["error"], PALETTE["error_bg"]
        elif level == "success":
            fg, bg = PALETTE["success"], PALETTE["success_bg"]
        else:
            fg, bg = PALETTE["warning"], PALETTE["warning_bg"]

        self._label.setText(text)
        self._label.setStyleSheet(
            f"color: {fg}; font-weight: 600; font-size: 12px; background: transparent;"
        )
        self.setStyleSheet(
            f"""
            QFrame {{
                background-color: {bg};
                border: 1px solid {fg};
                border-radius: 8px;
            }}
            """
        )
        self.show()


class PopupNotification(QFrame):
    """Pencere ortasında beliren ve belirtilen süre sonunda kendiliğinden kapanan modern popup."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SuccessPopup")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedSize(224, 56)

        self.setStyleSheet(
            f"""
            QFrame#SuccessPopup {{
                background-color: #152822;
                border: 1.5px solid {PALETTE["success"]};
                border-radius: 13px;
            }}
            """
        )

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 170))
        self.setGraphicsEffect(shadow)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 12, 20, 12)
        layout.setSpacing(12)

        self.icon_lbl = QLabel("✓")
        self.icon_lbl.setFixedSize(26, 26)
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet(
            f"""
            QLabel {{
                background-color: {PALETTE["success"]};
                color: #0D1714;
                border-radius: 13px;
                font-size: 14px;
                font-weight: 800;
            }}
            """
        )

        self.message_lbl = QLabel("İşlem başarılı")
        self.message_lbl.setStyleSheet(
            f"color: {PALETTE['text_primary']}; font-size: 14px; font-weight: 700; background: transparent;"
        )

        layout.addWidget(self.icon_lbl, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.message_lbl, 1, Qt.AlignmentFlag.AlignVCenter)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

        self.hide()

    @property
    def timer(self) -> QTimer:
        return self._timer

    def show_popup(self, text: str = "İşlem başarılı", duration_ms: int = 2000) -> None:
        self._timer.stop()
        self.message_lbl.setText(text)
        parent = self.parentWidget()
        if parent is not None:
            x = (parent.width() - self.width()) // 2
            y = (parent.height() - self.height()) // 2
            self.move(x, y)
        self.show()
        self.raise_()
        self._timer.start(max(200, int(duration_ms)))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        self._timer.stop()
        self.hide()
        event.accept()


class LoadingSpinner(QWidget):
    """Bağlantı kurulurken çalışan akıcı vektörel yükleme animasyonu (yalnızca görünürken çalışır)."""

    def __init__(
        self,
        size: int = 30,
        color: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._angle_deg = 0
        self._arc_color = QColor(color or PALETTE["accent"])
        self._track_color = QColor(PALETTE["border"])

        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._advance_frame)
        self.hide()

    @property
    def is_spinning(self) -> bool:
        return self._timer.isActive()

    def start(self) -> None:
        self.show()
        if not self._timer.isActive():
            self._timer.start()
        self.update()

    def stop(self) -> None:
        if self._timer.isActive():
            self._timer.stop()
        self.hide()

    def _advance_frame(self) -> None:
        self._angle_deg = (self._angle_deg + 14) % 360
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        pen_width = 3.2
        margin = pen_width / 2.0 + 1.5
        rect = QRectF(
            margin,
            margin,
            float(self.width()) - 2.0 * margin,
            float(self.height()) - 2.0 * margin,
        )

        # Arka plan halka izi
        track_pen = QPen(self._track_color, pen_width)
        painter.setPen(track_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(rect)

        # Dönen parlak yay (Qt açıları 1/16 derece birimindedir, saat yönü negatif)
        arc_pen = QPen(
            self._arc_color,
            pen_width,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
        )
        painter.setPen(arc_pen)
        start_angle_16 = int(-self._angle_deg * 16)
        span_angle_16 = int(-110 * 16)
        painter.drawArc(rect, start_angle_16, span_angle_16)
        painter.end()

