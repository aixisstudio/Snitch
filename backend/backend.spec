# backend.spec — PyInstaller specification for the Snitch backend.
#
# EN: Run from the backend/ directory:
#       pyinstaller backend.spec --distpath ../dist/backend
#     Produces a single-file `snitch-backend` executable that the Electron
#     wrapper spawns as a child process.
#
# FR: À lancer depuis le dossier backend/ :
#       pyinstaller backend.spec --distpath ../dist/backend
#     Produit un exécutable unique `snitch-backend` que le conteneur Electron
#     lance comme processus enfant.

from PyInstaller.utils.hooks import collect_all, collect_submodules

# EN: Pull in ALL of scapy — layers, arch backends, libs and data files.
#     Scapy does a lot of dynamic imports, so a plain Analysis misses them.
# FR: On embarque TOUT scapy — couches, backends arch, libs et fichiers de
#     données. Scapy fait beaucoup d'imports dynamiques, donc une Analysis
#     simple les raterait.
scapy_datas, scapy_binaries, scapy_hiddenimports = collect_all('scapy')

block_cipher = None

a = Analysis(
    ['run_backend.py'],
    pathex=['.'],           # EN: backend/ — so api.*, capture.*, etc. resolve
                          # FR: backend/ — pour que api.*, capture.*, etc. se résolvent
    binaries=scapy_binaries,
    datas=scapy_datas,
    hiddenimports=(
        scapy_hiddenimports

        # ── uvicorn internals / éléments internes d'uvicorn ─────────────
        + collect_submodules('uvicorn')

        # ── FastAPI / Starlette / Pydantic ──────────────────────────────
        + collect_submodules('starlette')
        + collect_submodules('fastapi')
        + collect_submodules('pydantic')
        + collect_submodules('pydantic_core')

        # ── async / HTTP / WebSocket ────────────────────────────────────
        + collect_submodules('anyio')
        + collect_submodules('websockets')
        + [
            'h11',
            'httptools',
            'wsproto',
            'aiofiles',
        ]

        # ── DNS / networking / réseau ───────────────────────────────────
        + collect_submodules('dns')
        + [
            'psutil',
            'psutil._pswindows',
            'psutil._psutil_windows',
        ]

        # ── stdlib extras often missed / modules stdlib souvent oubliés ──
        + [
            'email.mime.text',
            'email.mime.multipart',
            'email.mime.base',
            'logging.handlers',
            'asyncio',
            'asyncio.windows_events',
            'sqlite3',
        ]
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # EN: Exclude heavy unused packages to keep the binary small.
    # FR: Exclure les gros paquets inutilisés pour garder un binaire léger.
    excludes=['tkinter', 'matplotlib', 'numpy', 'PIL', 'PyQt5', 'wx'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='snitch-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # EN: Keep a console for debugging; set to False for release builds.
    # FR: Garder une console pour le débogage ; passer à False en release.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # EN: Elevation is handled by the Electron wrapper (NSIS requireAdministrator).
    # FR: L'élévation est gérée par le conteneur Electron (NSIS requireAdministrator).
    uac_admin=False,
)
