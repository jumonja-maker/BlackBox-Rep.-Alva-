"""Verify durable v2 close state before claiming primary-session completion.

This is a read-only postcondition, not a repair or an export bypass. It does
not establish why an older QA recording retained RECORDING metadata. Only a
writer that has exited may be checked by SessionStore.finish().
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import stat


class CompletionNotConfirmed(ValueError):
    """A safe reason code, without source paths or untrusted database text."""


def _identity(path: Path) -> tuple[int, int]:
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise CompletionNotConfirmed("V2_COMPLETION_UNSAFE_PATH")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise CompletionNotConfirmed("V2_COMPLETION_UNSAFE_PATH")
    return info.st_dev, info.st_ino


def confirm_v2_completion(path: Path, *, session_uuid: str,
                          origin_ns: int, exit_code: str,
                          expected_standard_samples: int | None = None) -> None:
    """Require the same session's CLOSED commit, including committed WAL data.

    No immutable=1, journal-mode change, UPDATE or checkpoint is used: a WAL
    commit is valid even while another reader holds an older snapshot. A
    caller that owns the closed schema1 recording supplies its *persisted*
    number of base samples; this verifies one-to-one sequence/correlation
    coverage. We never infer missing OS samples between accepted observations.
    """
    if (type(session_uuid) is not str or not session_uuid or
            type(origin_ns) is not int or origin_ns < 0 or
            type(exit_code) is not str or not exit_code or
            (expected_standard_samples is not None and
             (type(expected_standard_samples) is not int or
              not 0 <= expected_standard_samples <= 100_000_000))):
        raise CompletionNotConfirmed("V2_COMPLETION_INVALID_CONTEXT")
    path = Path(path).absolute()
    try:
        before = _identity(path)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                                     timeout=1.0)) as db:
            db.execute("PRAGMA query_only=ON")
            db.set_progress_handler(lambda: 1, 10000)
            if db.execute("PRAGMA user_version").fetchone() != (2,):
                raise CompletionNotConfirmed("V2_COMPLETION_SCHEMA_MISMATCH")
            rows = db.execute(
                "SELECT session_uuid,schema_version,monotonic_origin_ns,status,"
                "ended_monotonic_ns,exit_code FROM sessions LIMIT 2"
            ).fetchall()
            if len(rows) != 1:
                raise CompletionNotConfirmed("V2_COMPLETION_INVALID_CARDINALITY")
            saved_uuid, schema, origin, status, ended, saved_code = rows[0]
            if (saved_uuid != session_uuid or schema != 2 or
                    type(origin) is not int or origin != origin_ns):
                raise CompletionNotConfirmed("V2_COMPLETION_IDENTITY_MISMATCH")
            if (status != "CLOSED" or type(ended) is not int or
                    ended < origin_ns or saved_code != exit_code):
                raise CompletionNotConfirmed("V2_COMPLETION_NOT_CLOSED")
            if expected_standard_samples is not None:
                # Every real base counter snapshot is mirrored under its
                # durable schema1 sequence. DETAILED and CHILD samples are
                # independent and MUST NOT be counted as base snapshots.
                # A CLOSED marker without full base coverage cannot pass.
                count, first, last, bad_mapping = db.execute(
                    "SELECT COUNT(*), COALESCE(MIN(series_seq),0),"
                    " COALESCE(MAX(series_seq),0),"
                    " COALESCE(SUM(CASE WHEN instance_id != 1 OR "
                    "correlation_key != 'schema1:' || series_seq "
                    "THEN 1 ELSE 0 END),0) "
                    "FROM samples WHERE series='STANDARD'"
                ).fetchone()
                if count != expected_standard_samples:
                    raise CompletionNotConfirmed("V2_COMPLETION_BASE_COUNT_MISMATCH")
                if (first != (1 if count else 0) or last != count or
                        bad_mapping):
                    raise CompletionNotConfirmed("V2_COMPLETION_BASE_MAPPING_MISMATCH")
        if _identity(path) != before:
            raise CompletionNotConfirmed("V2_COMPLETION_FILE_CHANGED")
    except CompletionNotConfirmed:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError):
        raise CompletionNotConfirmed("V2_COMPLETION_READ_FAILED") from None
