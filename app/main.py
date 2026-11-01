"""SDPI masaüstü uygulaması giriş noktası (`python -m app.main`)."""

from __future__ import annotations

import os
from pathlib import Path
import sys

# Windows görev çubuğunda Python simgesi yerine uygulamanın kendi ikonunun görünmesini sağla
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SametDrs.SDPI.Desktop.1.0")
    except Exception:
        pass

# Doğrudan `python app/main.py` ile çalıştırıldığında proje kökünü sys.path'e ekle.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.application import SdpiApplication  # noqa: E402


def main() -> int:
    app = SdpiApplication(sys.argv)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
