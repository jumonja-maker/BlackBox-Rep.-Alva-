"""Create-new publication of an already closed decoder index."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .session_v2 import safe_path
from .decoder_limits import checked_index_path, MAX_INDEX_BYTES


def export_index_copy(source, destination):
    source, destination = checked_index_path(source), safe_path(destination)
    def require_new_destination():
        for suffix in ("","-wal","-shm","-journal"):
            reserved = safe_path(Path(str(destination)+suffix))
            if reserved.exists() or reserved.is_symlink():
                raise ValueError("OUTPUT_EXISTS")
    require_new_destination()
    before = source.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    def closed_source():
        safe_path(source)
        for suffix in ("-wal","-journal"):
            path = safe_path(Path(str(source)+suffix))
            if path.exists() and path.stat().st_size:
                raise ValueError("INDEX_SOURCE_NOT_CLOSED")
    closed_source()
    fd, name = tempfile.mkstemp(prefix=".blackbox-index-export-", dir=destination.parent)
    part = Path(name)
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as original:
            if identity(os.fstat(original.fileno()))!=identity(before):
                raise ValueError("INDEX_CHANGED_DURING_EXPORT")
            count = 0
            while chunk := original.read(1024*1024):
                count += len(chunk)
                if count>before.st_size or count>MAX_INDEX_BYTES:
                    raise ValueError("INDEX_CHANGED_DURING_EXPORT")
                target.write(chunk)
            if identity(os.fstat(original.fileno()))!=identity(before):
                raise ValueError("INDEX_CHANGED_DURING_EXPORT")
            target.flush()
            os.fsync(target.fileno())
        if identity(before) != identity(source.stat()) or part.stat().st_size != before.st_size:
            raise ValueError("INDEX_CHANGED_DURING_EXPORT")
        closed_source()
        require_new_destination()
        # Same-directory hard link is an atomic no-clobber publication on the
        # supported filesystems. Failure leaves neither a final partial file
        # nor an overwritten destination; no rename-over-existing fallback.
        os.link(part, destination)
    finally:
        part.unlink(missing_ok=True)

