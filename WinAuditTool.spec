# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/collector.py', 'src'),
        ('src/report.py', 'src'),
    ],
    hiddenimports=[
        'paramiko',
        'cryptography',
        'paramiko.ed25519key',
        'paramiko.rsa',
        'paramiko.ecdsakey',
        'paramiko.agent',
        'paramiko.ssh_gss',
        'dearpygui',
        'jinja2',
        'MarkupSafe',
    ],
    hookspath=[],
    hooksconfig={},
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=False,
    name='WinAuditTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # GUI 程序，不显示控制台
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='WinAuditTool',
)
