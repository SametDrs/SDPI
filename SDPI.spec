# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project_root = Path(SPECPATH).resolve()

a = Analysis(
    [str(project_root / "app" / "main.py")],
    pathex=[str(project_root)],
    binaries=[
        (str(project_root / "core" / "build" / "Release" / "sdpi-engine.exe"), "engine"),
        (str(project_root / "drivers" / "WinDivert" / "x64" / "WinDivert.dll"), "engine"),
        (str(project_root / "drivers" / "WinDivert" / "x64" / "WinDivert64.sys"), "engine"),
    ],
    datas=[
        (str(project_root / "assets" / "app_icon.ico"), "assets"),
        (str(project_root / "config" / "settings.json"), "config"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SDPI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(project_root / "assets" / "app_icon.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="SDPI",
)
