# backend.spec — PyInstaller specification for the Snitch backend.
#
# EN: Run from the backend/ directory:
#       pyinstaller backend.spec --distpath ../dist/backend
#     Produces a `snitch-backend/` ONEDIR bundle the Electron wrapper spawns
#     as a child process. ONEDIR (not onefile) is deliberate: fewer AV false
#     positives, faster startup, no temp-dir self-extraction of a
#     network-sniffing binary.
#
#     UPX is DISABLED — UPX-packed executables that touch the network are a
#     well-known antivirus false-positive trigger.
#
# FR: À lancer depuis le dossier backend/ :
#       pyinstaller backend.spec --distpath ../dist/backend
#     Produit un bundle ONEDIR `snitch-backend/` que le conteneur Electron
#     lance comme processus enfant. ONEDIR (pas onefile) est voulu : moins de
#     faux positifs antivirus, démarrage plus rapide, pas d'auto-extraction
#     en temp d'un binaire qui sniffe le réseau.
#
#     UPX est DÉSACTIVÉ — les exécutables UPX qui touchent au réseau sont un
#     déclencheur connu de faux positifs antivirus.

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

a = Analysis(
    ['run_backend.py'],
    pathex=['.'],           # EN: backend/ — so api.*, capture.*, etc. resolve
                          # FR: backend/ — pour que api.*, capture.*, etc. se résolvent
    binaries=[],
    datas=[],
    hiddenimports=(
        # ── uvicorn internals / éléments internes d'uvicorn ─────────────
        collect_submodules('uvicorn')

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

        # ── mmdb / psutil internals ─────────────────────────────────────
        + collect_submodules('maxminddb')
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
    # EN: Exclude heavy unused packages to keep the bundle small.
    # FR: Exclure les gros paquets inutilisés pour garder un bundle léger.
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
    [],
    exclude_binaries=True,      # EN: ONEDIR mode — binaries go into COLLECT
                                # FR: mode ONEDIR — les binaires vont dans COLLECT
    name='snitch-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                  # EN: UPX off — AV false-positive trigger
                                # FR: UPX désactivé — faux positifs antivirus
    console=False,              # EN: no console window under Electron
                                # FR: pas de fenêtre console sous Electron
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # EN: Elevation is handled by the Electron wrapper (NSIS
    #     requireAdministrator) — the backend does not self-elevate.
    # FR: L'élévation est gérée par le conteneur Electron (NSIS
    #     requireAdministrator) — le backend ne s'élève pas tout seul.
    uac_admin=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='snitch-backend',
)
