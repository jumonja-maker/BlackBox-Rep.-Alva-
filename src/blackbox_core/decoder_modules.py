"""Trace-local native module observations. No path/name-based symbol binding.

A matching imported load window and debug identity is not authenticated OS
provenance. Managed/JIT code and ambiguous loads must remain unbound.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from uuid import UUID

MODULE_SCHEMA = "blackbox.trace-module/1"
MODULE_SOURCE = "TRACEEVENT_NATIVE_LOAD_WINDOW"
MAX_MODULES = 16384
_HEX = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")


def address_value(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise ValueError("INVALID_NATIVE_ADDRESS")
    return int(value[2:], 16)


def integer(value, low=0, high=2**63-1):
    return type(value) is int and low <= value <= high


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and abs(value) < 1e15


def validate_module_frame(row, frame):
    """Validate the complete imported module/frame contract before using RVA."""
    module = frame.get("module")
    if module is None:
        if frame.get("rva") is not None:
            raise ValueError("RVA_WITHOUT_MODULE_IDENTITY")
        return None
    required = {"schema", "source", "process_instance", "module_file_index",
                "image_base", "image_size", "image_timestamp", "load_time_ms",
                "unload_time_ms", "pdb_guid", "pdb_age", "module_name"}
    if (type(module) is not dict or set(module) != required or
            module["schema"] != MODULE_SCHEMA or module["source"] != MODULE_SOURCE or
            not integer(row.get("pid"), 1) or
            not integer(row.get("process_instance")) or
            not integer(module["process_instance"]) or
            module["process_instance"] != row["process_instance"] or
            not integer(module["module_file_index"]) or
            not integer(module["image_size"], 1, 2**32-1) or
            not integer(module["image_timestamp"], 0, 2**32-1) or
            not number(module["load_time_ms"]) or not number(module["unload_time_ms"]) or
            not number(row.get("time_ms")) or
            not module["load_time_ms"] <= row["time_ms"] < module["unload_time_ms"] or
            type(module["module_name"]) is not str or
            not 1 <= len(module["module_name"]) <= 255 or
            any(c in module["module_name"] for c in "\\/:\x00") or
            any(ord(c) < 32 for c in module["module_name"]) or
            not integer(frame.get("rva"), 0, 2**32-1)):
        raise ValueError("INVALID_TRACE_MODULE_FRAME")
    base = address_value(module["image_base"])
    address = address_value(frame["address"])
    if (base == 0 or base + module["image_size"] > 2**64 or
            not base <= address < base + module["image_size"] or
            frame["rva"] != address-base):
        raise ValueError("NATIVE_FRAME_OUTSIDE_MODULE")
    guid, age = module["pdb_guid"], module["pdb_age"]
    if (guid is None) != (age is None):
        raise ValueError("INCOMPLETE_TRACE_PDB_IDENTITY")
    if guid is not None:
        if (type(guid) is not str or not integer(age, 1, 2**32-1)):
            raise ValueError("INVALID_TRACE_PDB_IDENTITY")
        try:
            parsed = UUID(guid)
            if str(parsed) != guid or not parsed.int:
                raise ValueError()
        except ValueError:
            raise ValueError("INVALID_TRACE_PDB_IDENTITY") from None
    return module


def module_key(pid, module):
    # Full provenance, including process instance and load/unload window.
    # Never key only by address, basename or an unsigned local GUID.
    data = json.dumps([pid, module], sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class ModuleCatalog:
    def __init__(self, db):
        self.db = db
        self.observed = self.missing = 0
        self.keys = set()
        db.executescript("""
        CREATE TABLE trace_modules(id INTEGER PRIMARY KEY, module_key TEXT UNIQUE NOT NULL,
            pid INTEGER NOT NULL, process_instance INTEGER NOT NULL,
            name TEXT NOT NULL, frame_count INTEGER NOT NULL,
            first_event_id INTEGER NOT NULL, last_event_id INTEGER NOT NULL, data TEXT NOT NULL);
        CREATE INDEX ix_trace_modules_pid ON trace_modules(pid,id);
        """)

    def accept(self, row):
        for frame in row["frames"]:
            module = validate_module_frame(row, frame)
            if module is None:
                self.missing += 1
                continue
            self.observed += 1
            key = module_key(row["pid"], module)
            if key not in self.keys:
                if len(self.keys) >= MAX_MODULES:
                    raise ValueError("TRACE_MODULE_BUDGET")
                self.keys.add(key)
                self.db.execute("INSERT INTO trace_modules VALUES(NULL,?,?,?,?,1,?,?,?)", (
                    key, row["pid"], row["process_instance"], module["module_name"],
                    row["ordinal"], row["ordinal"], json.dumps(module, allow_nan=False)))
            else:
                self.db.execute("UPDATE trace_modules SET frame_count=frame_count+1,"
                                "last_event_id=? WHERE module_key=?", (row["ordinal"], key))

    def summary(self):
        return {"contract": MODULE_SCHEMA, "modules_observed_in_frames": len(self.keys),
                "frames_with_native_module": self.observed,
                "frames_without_native_module": self.missing,
                "scope": "FRAME_ASSOCIATIONS_NOT_COMPLETE_MODULE_INVENTORY",
                "verification_class": "UNVERIFIED_IMPORT", "symbol_names_resolved": False}


def read_modules(db, *, after, pid, limit, search):
    query = "SELECT id,module_key,pid,process_instance,frame_count,first_event_id,last_event_id,data FROM trace_modules WHERE id>?"
    params = [after]
    if pid:
        query += " AND pid=?"; params.append(pid)
    if search.strip():
        query += " AND instr(lower(name),lower(?))>0"; params.append(search.strip())
    params.append(limit+1)
    rows = db.execute(query+" ORDER BY id LIMIT ?", params).fetchall()
    result = [{"index_id": r[0], "event": {"type": "TRACE_NATIVE_MODULE_OBSERVATION",
        "module_key": r[1], "pid": r[2], "process_instance": r[3], "frame_count": r[4],
        "first_event_id": r[5], "last_event_id": r[6], "module": json.loads(r[7]),
        "verification_class": "UNVERIFIED_IMPORT"}} for r in rows[:limit]]
    return {"rows": result, "has_more": len(rows)>limit,
            "next_cursor": result[-1]["index_id"] if result else after}


def binding_verdict(row, frame, pe, pdb):
    """Require trace/PE/PDB identity AND image layout; report missing evidence."""
    module = validate_module_frame(row, frame)
    if module is None:
        return "TRACE_MODULE_NOT_RECORDED"
    if module["pdb_guid"] is None:
        return "TRACE_PDB_IDENTITY_NOT_RECORDED"
    expected = (module["pdb_guid"], module["pdb_age"])
    if expected != (pe["guid"], pe["age"]) or expected != (pdb["guid"], pdb["age"]):
        return "TRACE_PE_PDB_IDENTITY_MISMATCH"
    if (module["image_size"] != pe["image_size"] or
            module["image_timestamp"] != pe["image_timestamp"]):
        return "TRACE_PE_LAYOUT_MISMATCH"
    return "TRACE_PE_PDB_CONSISTENT_UNVERIFIED"
