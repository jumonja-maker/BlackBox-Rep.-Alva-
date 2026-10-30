"""Private, bounded investigation indexes; never migrate diagnostic sources."""
from __future__ import annotations

from contextlib import closing
import hashlib
import html
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from .investigation_graph_contracts import SCHEMA, InvestigationError, canonical_json, use_budget
from .session_v2 import safe_path
from .deep_journal import _SENSITIVE as _DEEP_SENSITIVE
from .package_privacy import _text as _private_text

APPLICATION_ID = 0x42424933
MAX_INDEX_BYTES = 128 * 1024**2
_SECRETS = {"password", "passwd", "token", "access_token", "refresh_token", "authorization",
    "cookie", "credentials", "credential", "secret", "apikey", "api_key", "environment", "environ",
    "memory", "memory_bytes", "bytes_hex", "hex", "value_hex", "original_hex", "expected_hex",
    "replacement_hex", "content", "contents", "raw", "payload", "registry_value", "value_data"}
_SECRETS.update(_DEEP_SENSITIVE)
_SECRETS.update({"data_base64", "passwords", "private_key", "connection_string",
                 "environment_variables", "memory_contents", "replacement_bytes"})


def public_metadata(value, depth=0):
    """Remove private navigation and payloads from saved/exported graph data."""
    if depth > 32:
        raise InvestigationError("INVESTIGATION_METADATA_DEPTH")
    if type(value) is dict:
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise InvestigationError("INVESTIGATION_METADATA_KEY")
            if key.startswith("_"):
                continue
            lowered = key.lower()
            public_key = _private_text(key, b"blackbox.investigation-graph/1:metadata")
            if public_key in result:
                raise InvestigationError("INVESTIGATION_PRIVACY_KEY_COLLISION")
            if lowered in _SECRETS or lowered.endswith(("_password", "_token", "_secret", "_hex", "_bytes_raw")):
                result[public_key] = {"omitted": "SENSITIVE_PAYLOAD"}
            else:
                result[public_key] = public_metadata(item, depth + 1)
        return result
    if type(value) in (list, tuple):
        return [public_metadata(item, depth + 1) for item in value]
    if type(value) is str:
        # Recognizable URLs may contain credentials even under innocuous keys
        # (for example an SDK network.request URL). Reuse share-copy policy.
        # A fixed namespace keeps immutable own-index saves deterministic.
        return _private_text(value, b"blackbox.investigation-graph/1:metadata")
    if value is None or type(value) in (int, float, bool):
        return value
    raise InvestigationError("INVALID_INVESTIGATION_METADATA_TYPE")


def _validated(case, budget):
    from .evidence_graph import validate_case
    budget.check()
    validate_case(case, budget=budget)
    value = public_metadata(case)
    validate_case(value, budget=budget)
    return budget.result(value)


def _stamp(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _hash(path, budget):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            budget.check()
            digest.update(block)
    return digest.hexdigest()


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvestigationError("DUPLICATE_INVESTIGATION_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise InvestigationError("NONFINITE_INVESTIGATION_JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def save_investigation(case, path, *, budget=None, before_publish=None):
    budget = use_budget(budget)
    value = _validated(case, budget)
    destination = safe_path(Path(path))
    if destination.exists():
        existing = load_investigation(destination, budget=budget)
        if canonical_json(existing) != canonical_json(value):
            raise FileExistsError("INVESTIGATION_INDEX_DESTINATION_EXISTS")
        if before_publish is not None:
            before_publish()
        return {"status": "COMPLETED", "path": str(destination), "case_id": value["case_id"],
                "sha256": _hash(destination, budget), "publication": "IDENTICAL_EXISTING_INDEX"}
    descriptor, temporary = tempfile.mkstemp(prefix=".blackbox-investigation-", suffix=".sqlite3", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    try:
        with closing(sqlite3.connect(temporary)) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, budget.max_result_bytes + 65536)
            db.execute("PRAGMA cache_size=-4096")
            db.set_progress_handler(lambda: (budget.check() or 0), 1000)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            db.execute("PRAGMA user_version=1")
            db.executescript("""
                CREATE TABLE investigation(case_id TEXT PRIMARY KEY, schema TEXT NOT NULL,
                    content_json TEXT NOT NULL, content_sha256 TEXT NOT NULL);
                CREATE TABLE nodes(ordinal INTEGER PRIMARY KEY, node_id TEXT UNIQUE NOT NULL, record_json TEXT NOT NULL);
                CREATE TABLE edges(ordinal INTEGER PRIMARY KEY, edge_id TEXT UNIQUE NOT NULL,
                    from_node TEXT NOT NULL, to_node TEXT NOT NULL, record_json TEXT NOT NULL);
                CREATE INDEX related_from ON edges(from_node,ordinal);
                CREATE INDEX related_to ON edges(to_node,ordinal);
            """)
            raw = canonical_json(value)
            db.execute("INSERT INTO investigation VALUES(?,?,?,?)", (value["case_id"], SCHEMA, raw,
                       hashlib.sha256(raw.encode("ascii")).hexdigest()))
            for ordinal, node in enumerate(value["nodes"], 1):
                budget.check()
                db.execute("INSERT INTO nodes VALUES(?,?,?)", (ordinal, node["node_id"], canonical_json(node)))
            for ordinal, edge in enumerate(value["edges"], 1):
                budget.check()
                db.execute("INSERT INTO edges VALUES(?,?,?,?,?)", (ordinal, edge["edge_id"], edge["from_node"],
                           edge["to_node"], canonical_json(edge)))
            db.commit()
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise InvestigationError("INVESTIGATION_INDEX_INTEGRITY")
        if temporary.stat().st_size > MAX_INDEX_BYTES:
            raise InvestigationError("INVESTIGATION_INDEX_SIZE_BUDGET")
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        digest = _hash(temporary, budget)
        budget.check()
        if before_publish is not None:
            before_publish()
        budget.check()
        # Atomic create-new publication; an existing source or index is never overwritten.
        os.link(temporary, destination)
    except sqlite3.Error:
        budget.check()  # SQLite translates progress-handler cancellation into OperationalError.
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return {"status": "COMPLETED", "path": str(destination), "case_id": value["case_id"],
            "sha256": digest, "publication": "ATOMIC_CREATE_NEW"}


def _open_index(path, budget):
    path = safe_path(Path(path))
    if not path.is_file() or not 512 <= path.stat().st_size <= MAX_INDEX_BYTES:
        raise InvestigationError("INVESTIGATION_INDEX_FILE_BUDGET")
    if Path(str(path) + "-wal").exists() and Path(str(path) + "-wal").stat().st_size:
        raise InvestigationError("INVESTIGATION_INDEX_ACTIVE_WAL")
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, budget.max_result_bytes + 65536)
        db.execute("PRAGMA cache_size=-4096")
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.set_progress_handler(lambda: (budget.check() or 0), 1000)
        if (db.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,) or
                db.execute("PRAGMA user_version").fetchone() != (1,)):
            raise InvestigationError("UNSUPPORTED_INVESTIGATION_INDEX_SCHEMA")
        tables = dict(db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('investigation','nodes','edges')"))
        if tables != {"investigation": "table", "nodes": "table", "edges": "table"}:
            raise InvestigationError("INVALID_INVESTIGATION_INDEX_TABLES")
        return path, db
    except BaseException as error:
        db.close()
        if isinstance(error, sqlite3.Error):
            budget.check()
        raise


def load_investigation(path, *, budget=None):
    budget = use_budget(budget)
    path = safe_path(Path(path))
    stamp = _stamp(path)
    if not path.is_file() or not 512 <= stamp[2] <= MAX_INDEX_BYTES:
        raise InvestigationError("INVESTIGATION_INDEX_FILE_BUDGET")
    digest = _hash(path, budget)
    path, db = _open_index(path, budget)
    try:
        if _stamp(path) != stamp or _hash(path, budget) != digest:
            raise InvestigationError("INVESTIGATION_INDEX_CHANGED_DURING_OPEN")
        row = db.execute("SELECT case_id,schema,content_json,content_sha256 FROM investigation LIMIT 2").fetchall()
        if len(row) != 1 or row[0][1] != SCHEMA or len(row[0][2]) > budget.max_result_bytes:
            raise InvestigationError("INVALID_INVESTIGATION_INDEX_RECORD")
        case_id, _, raw, recorded = row[0]
        if hashlib.sha256(raw.encode("ascii")).hexdigest() != recorded:
            raise InvestigationError("INVESTIGATION_INDEX_CONTENT_HASH")
        value = _validated(_json(raw), budget)
        if case_id != value["case_id"]:
            raise InvestigationError("INVESTIGATION_INDEX_CASE_ID")
        for table, key in (("nodes", "node_id"), ("edges", "edge_id")):
            expected = value[table]
            rows = db.execute(f"SELECT {key},record_json FROM {table} ORDER BY ordinal LIMIT ?", (len(expected) + 1,)).fetchall()
            if len(rows) != len(expected) or any(identifier != item[key] or canonical_json(item) != saved
                    for (identifier, saved), item in zip(rows, expected)):
                raise InvestigationError("INVESTIGATION_INDEX_GRAPH_MISMATCH")
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise InvestigationError("INVESTIGATION_INDEX_INTEGRITY")
    except sqlite3.Error:
        budget.check()
        raise
    finally:
        db.close()
    if _stamp(path) != stamp or _hash(path, budget) != digest:
        raise InvestigationError("INVESTIGATION_INDEX_CHANGED_DURING_READ")
    value["analysis_provenance"] = "UNVERIFIED_DERIVATION_RECOMPUTE_SOURCES_FOR_CURRENT_LINK_VALIDATION"
    value["file_trust"] = "UNVERIFIED_IMPORT"
    return value


def query_graph(path, *, kind="nodes", after=0, limit=100, budget=None):
    budget = use_budget(budget)
    if kind not in ("nodes", "edges") or type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 200:
        raise InvestigationError("INVALID_INVESTIGATION_PAGE")
    # Validate the small bounded own index before exposing trusted navigation references.
    case = load_investigation(path, budget=budget)
    records = case[kind]
    page = records[after:after + limit]
    return budget.result({"case_id": case["case_id"], "kind": kind, "records": page,
                          "has_more": after + limit < len(records),
                          "next_cursor": after + len(page), "total": len(records)})


def export_investigation(case, destination, *, format="json", budget=None, cancel_event=None):
    budget = use_budget(budget, cancel_event=cancel_event)
    value = _validated(case, budget)
    if format not in ("json", "html"):
        raise InvestigationError("UNSUPPORTED_INVESTIGATION_EXPORT_FORMAT")
    raw = canonical_json(value)
    if format == "html":
        title = "BLACK.BOX — Investigation Engine 3"
        content = "<!doctype html><html><head><meta charset='utf-8'><title>" + title + "</title></head><body>"
        content += "<h1>" + title + "</h1><p>Evidence, derived observations and hypotheses; root cause is not automatically established.</p>"
        content += "<p>Case: " + html.escape(value["case_id"]) + "</p><h2>Hypotheses</h2><ul>"
        for hypothesis in value.get("hypotheses", []):
            budget.check()
            content += "<li>" + html.escape(str(hypothesis.get("description", ""))) + " — " + html.escape(str(hypothesis.get("status", ""))) + "</li>"
        content += "</ul><h2>Source-linked investigation</h2><pre>" + html.escape(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)) + "</pre></body></html>"
        payload = content.encode("utf-8")
    else:
        payload = raw.encode("ascii")
    if len(payload) > 2 * budget.max_result_bytes:
        raise InvestigationError("INVESTIGATION_EXPORT_BYTE_BUDGET")
    target = safe_path(Path(destination))
    descriptor, temporary = tempfile.mkstemp(prefix=".blackbox-investigation-export-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            for start in range(0, len(payload), 65536):
                budget.check()
                stream.write(payload[start:start + 65536])
            stream.flush()
            os.fsync(stream.fileno())
        budget.check()
        os.link(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"status": "COMPLETED", "path": str(target), "case_id": value["case_id"],
            "format": format, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            "privacy": "METADATA_ONLY_NO_MEMORY_DUMPS_ENVIRONMENT_OR_SECRETS"}


class InvestigationGraphStore:
    def __init__(self, path):
        self.path = Path(path)

    def save(self, case, *, budget=None):
        return save_investigation(case, self.path, budget=budget)

    def load(self, *, budget=None):
        return load_investigation(self.path, budget=budget)

    def page(self, **kwargs):
        return query_graph(self.path, **kwargs)
