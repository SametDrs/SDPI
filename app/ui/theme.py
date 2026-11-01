"""Koyu mod görsel stil şablonu (QSS) ve vektör ikon üreticileri."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QPointF, QSize, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
)
from PySide6.QtSvg import QSvgRenderer

from app.constants import APP_ICON_PATH, PALETTE

_GITHUB_OCTOCAT_SVG_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">
  <path fill="{color}" fill-rule="evenodd"
    d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
       0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
       -.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66
       .07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15
       -.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0
       1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82
       1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01
       1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
</svg>"""


def build_github_icon(color: str | None = None) -> QIcon:
    """Keskin vektörel GitHub Octocat ikonu üretir."""
    fill = color or PALETTE["text_secondary"]
    svg_bytes = QByteArray(
        _GITHUB_OCTOCAT_SVG_TEMPLATE.format(color=fill).encode("utf-8")
    )
    renderer = QSvgRenderer(svg_bytes)

    icon = QIcon()
    for px in (16, 32):
        pix = QPixmap(px, px)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        renderer.render(painter)
        painter.end()
        if px == 32:
            pix.setDevicePixelRatio(2.0)
        icon.addPixmap(pix)
    return icon


def build_app_icon(active: bool = False) -> QIcon:
    """Uygulama ikonunu döner. Varsa assets/app_icon.ico dosyasını yükler, yoksa geometrik kalkan çizer."""
    if APP_ICON_PATH.is_file():
        base_icon = QIcon(str(APP_ICON_PATH))
        if not base_icon.isNull():
            if not active:
                return base_icon
            # Aktif bağlantı durumu için (özellikle sistem tepsisi ve görev çubuğu) sağ alt köşeye yeşil durum rozeti ekle
            active_icon = QIcon()
            sizes = base_icon.availableSizes() or [
                QSize(16, 16),
                QSize(24, 24),
                QSize(32, 32),
                QSize(48, 48),
                QSize(64, 64),
                QSize(128, 128),
                QSize(256, 256),
            ]
            for sz in sizes:
                w, h = sz.width(), sz.height()
                pix = base_icon.pixmap(w, h)
                painter = QPainter(pix)
                painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
                radius = max(2.5, float(min(w, h)) * 0.17)
                cx = float(w) - radius - 1.0
                cy = float(h) - radius - 1.0
                painter.setPen(QPen(QColor(PALETTE["bg_main"]), max(1.0, radius * 0.35)))
                painter.setBrush(QColor(PALETTE["success"]))
                painter.drawEllipse(QPointF(cx, cy), radius, radius)
                painter.end()
                active_icon.addPixmap(pix)
            return active_icon

    icon = QIcon()
    for size in (16, 24, 32, 48, 64):
        pix = QPixmap(size, size)
        pix.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        s = float(size)
        pad = s * 0.08

        shield = QPainterPath()
        shield.moveTo(s * 0.50, pad)
        shield.lineTo(s - pad, s * 0.24)
        shield.lineTo(s - pad, s * 0.54)
        shield.quadTo(s - pad, s * 0.80, s * 0.50, s - pad)
        shield.quadTo(pad, s * 0.80, pad, s * 0.54)
        shield.lineTo(pad, s * 0.24)
        shield.closeSubpath()

        fill_color = QColor(PALETTE["success"] if active else PALETTE["accent"])
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill_color)
        painter.drawPath(shield)

        pen = QPen(QColor("#FFFFFF"))
        pen.setWidthF(max(1.5, s * 0.085))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        poly = QPolygonF(
            [
                QPointF(s * 0.28, s * 0.52),
                QPointF(s * 0.42, s * 0.52),
                QPointF(s * 0.48, s * 0.36),
                QPointF(s * 0.56, s * 0.66),
                QPointF(s * 0.62, s * 0.50),
                QPointF(s * 0.73, s * 0.50),
            ]
        )
        painter.drawPolyline(poly)
        painter.end()

        icon.addPixmap(pix)
    return icon


def build_stylesheet() -> str:
    """Windows 11 koyu mod tasarım diline uygun sadeleştirilmiş QSS şablonunu üretir."""
    p = PALETTE
    return f"""
    QMainWindow,
    QWidget#RootContainer,
    QStackedWidget,
    QWidget#PageContainer,
    QFrame#FooterBar {{
        background-color: {p["bg_main"]};
        color: {p["text_primary"]};
        font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
        font-size: 13px;
    }}

    QWidget {{
        color: {p["text_primary"]};
        font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
    }}

    QLabel, QCheckBox {{
        background-color: transparent;
    }}

    QFrame#TopHeader {{
        background-color: {p["bg_sidebar"]};
        border-bottom: 1px solid {p["border"]};
    }}

    QFrame#SegmentBar {{
        background-color: {p["bg_input"]};
        border: 1px solid {p["border"]};
        border-radius: 9px;
    }}

    QPushButton#NavButton {{
        background-color: transparent;
        color: {p["text_secondary"]};
        border: none;
        border-radius: 7px;
        padding: 7px 16px;
        font-size: 13px;
        font-weight: 600;
    }}
    QPushButton#NavButton:hover {{
        color: {p["text_primary"]};
    }}
    QPushButton#NavButton[active="true"] {{
        background-color: {p["accent"]};
        color: #FFFFFF;
    }}

    QFrame#Card {{
        background-color: {p["bg_card"]};
        border: 1px solid {p["border"]};
        border-radius: 12px;
    }}

    QFrame#HeroCard {{
        background-color: {p["bg_card"]};
        border: 1px solid {p["border"]};
        border-radius: 14px;
    }}

    QPushButton#PrimaryButton {{
        background-color: {p["accent"]};
        color: #FFFFFF;
        border: none;
        border-radius: 8px;
        padding: 9px 20px;
        font-size: 13px;
        font-weight: 600;
    }}
    QPushButton#PrimaryButton:hover {{
        background-color: {p["accent_hover"]};
    }}
    QPushButton#PrimaryButton:pressed {{
        background-color: {p["accent_pressed"]};
    }}
    QPushButton#PrimaryButton:disabled {{
        background-color: {p["border"]};
        color: {p["text_muted"]};
    }}

    QPushButton#SecondaryButton {{
        background-color: {p["bg_input"]};
        color: {p["text_primary"]};
        border: 1px solid {p["border"]};
        border-radius: 8px;
        padding: 8px 14px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton#SecondaryButton:hover {{
        background-color: {p["bg_card_hover"]};
        border-color: {p["accent"]};
    }}
    QPushButton#SecondaryButton:disabled {{
        color: {p["text_muted"]};
    }}

    QPushButton#EngineStartButton {{
        background-color: {p["accent"]};
        color: #FFFFFF;
        border: none;
        border-radius: 11px;
        padding: 13px 32px;
        font-size: 15px;
        font-weight: 700;
    }}
    QPushButton#EngineStartButton:hover {{
        background-color: {p["accent_hover"]};
    }}
    QPushButton#EngineStartButton[running="true"] {{
        background-color: {p["error"]};
    }}
    QPushButton#EngineStartButton[running="true"]:hover {{
        background-color: #EE6C75;
    }}
    QPushButton#EngineStartButton:disabled {{
        background-color: {p["border"]};
        color: {p["text_secondary"]};
    }}
    QPushButton#EngineStartButton[loading="true"]:disabled {{
        background-color: #1D1F2E;
        color: #C9C5FF;
        border: 1px solid #4B4596;
    }}

    QPushButton#GithubFooterButton {{
        background-color: transparent;
        color: {p["text_secondary"]};
        border: none;
        border-radius: 6px;
        padding: 4px 8px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton#GithubFooterButton:hover {{
        background-color: {p["bg_card"]};
        color: {p["text_primary"]};
    }}

    QComboBox {{
        background-color: {p["bg_input"]};
        color: {p["text_primary"]};
        border: 1px solid {p["border"]};
        border-radius: 8px;
        padding: 7px 10px;
        selection-background-color: {p["accent"]};
    }}
    QComboBox:hover {{
        border-color: {p["accent"]};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {p["bg_card"]};
        color: {p["text_primary"]};
        border: 1px solid {p["border"]};
        selection-background-color: {p["accent"]};
    }}

    QCheckBox {{
        spacing: 10px;
        font-size: 13px;
        color: {p["text_primary"]};
    }}
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border-radius: 5px;
        border: 1px solid {p["border"]};
        background-color: {p["bg_input"]};
    }}
    QCheckBox::indicator:hover {{
        border-color: {p["accent"]};
    }}
    QCheckBox::indicator:checked {{
        background-color: {p["accent"]};
        border-color: {p["accent"]};
    }}
    """
