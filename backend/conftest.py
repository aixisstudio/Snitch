"""
Snitch — pytest bootstrap.

EN: Guarantees that the `backend/` directory is on sys.path regardless of how
    pytest is invoked, so tests can do `from classifier.traffic import …`.
    Also redirects the data directory to a temp folder BEFORE any storage
    module is imported — tests must never touch the real snitch.db.

FR: Garantit que le dossier `backend/` est dans sys.path quelle que soit la
    façon dont pytest est lancé, pour que les tests puissent faire
    `from classifier.traffic import …`. Redirige aussi le dossier de données
    vers un dossier temporaire AVANT tout import de storage — les tests ne
    doivent jamais toucher la vraie snitch.db.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("SNITCH_DATA_DIR", tempfile.mkdtemp(prefix="snitch-test-"))
