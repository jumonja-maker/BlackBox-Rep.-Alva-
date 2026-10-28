"""Create-new publication of an already closed decoder index."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile

from .session_v2 import safe_path


def export_index_copy(source, destination):
    source, destination = safe_path(source), safe_path(destination)
    if not source.is_file():
        raise ValueError("INVALID_INDEX_FILE")
    if destination.exists() or destination.is_symlink():
        raise ValueError("OUTPUT_EXISTS")
    before = source.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    fd, name = tempfile.mkstemp(prefix=".blackbox-index-export-", dir=destination.parent)
    part = Path(name)
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as original:
            shutil.copyfileobj(original, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        if identity(before) != identity(source.stat()) or part.stat().st_size != before.st_size:
            raise ValueError("INDEX_CHANGED_DURING_EXPORT")
        # Same-directory hard link is an atomic no-clobber publication on the
        # supported filesystems. Failure leaves neither a final partial file
        # nor an overwritten destination; no rename-over-existing fallback.
        os.link(part, destination)
    finally:
        part.unlink(missing_ok=True)

