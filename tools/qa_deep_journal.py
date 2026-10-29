"""Independent, read-only checks of real diagnostic action journal evidence.

The local hash chain detects changes; it is not authenticated provenance.
Format fixtures exercising this verifier must never be presented as native QA.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3


def _require(value, code):
    if not value:
        raise AssertionError(code)


def _digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_action_journal(database: Path, exported: Path, expected_actions: list[dict],
                          *, forbidden_payloads=(), export_result=None) -> dict:
    """Require every observed action's durable intent/result and exact target.

    Run only after the service has closed, with a freshly exported metadata
    JSONL. Do not create a service or mutate/recover the source journal here.
    """
    for path in (database, exported):
        _require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 32 * 1024 * 1024,
                 "QA_JOURNAL_FILE_BUDGET_OR_IDENTITY")
    original = {path.name: _digest(path) for path in (database, exported)}
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        _require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "QA_JOURNAL_DATABASE_CORRUPT")
        rows = db.execute("SELECT sequence,operation_id,record_json,previous_sha256,record_sha256 "
                          "FROM actions ORDER BY sequence LIMIT 10001").fetchall()
    _require(0 < len(rows) <= 10000, "QA_JOURNAL_ROW_BUDGET")
    export_rows = []
    with exported.open(encoding="utf-8") as stream:
        for line in stream:
            _require(len(export_rows) < 10000 and len(line.encode("utf-8")) <= 1024 * 1024,
                     "QA_JOURNAL_EXPORT_ROW_BUDGET")
            export_rows.append(json.loads(line))
    # A service export publishes an immutable prefix through its REQUESTED
    # record, then durably appends its RESULT. Only that exact acknowledged
    # final record may be absent from the just-published file.
    tail_records = 1 if export_result is not None else 0
    _require(len(export_rows) + tail_records == len(rows), "QA_JOURNAL_EXPORT_COUNT_MISMATCH")
    by_id, action_records = {}, {}
    previous = "0" * 64
    cleanup_count = 0
    for index, row in enumerate(rows, 1):
        sequence, identifier, raw, previous_hash, digest = row
        _require(sequence == index and identifier not in by_id, "QA_JOURNAL_SEQUENCE_OR_DUPLICATE")
        actual = hashlib.sha256(previous.encode("ascii") + raw.encode("utf-8")).hexdigest()
        _require(previous_hash == previous and digest == actual, "QA_JOURNAL_HASH_CHAIN_MISMATCH")
        previous = digest
        record = json.loads(raw)
        _require(record.get("operation_id") == identifier, "QA_JOURNAL_RECORD_ID_MISMATCH")
        exported_row = export_rows[index - 1] if index <= len(export_rows) else None
        if exported_row is not None:
            _require(exported_row == {"record": record, "previous_sha256": previous_hash,
                                      "record_sha256": digest}, "QA_JOURNAL_EXPORT_CONTENT_MISMATCH")
        for forbidden in forbidden_payloads:
            _require(not forbidden or (forbidden not in raw and forbidden not in json.dumps(exported_row)),
                     "QA_JOURNAL_RAW_MEMORY_LEAK")
        by_id[identifier] = (sequence, record, digest)
        if record.get("source") == "BLACKBOX_DIAGNOSTIC_ACTION_ENGINE":
            action_records.setdefault(record.get("action_id"), []).append(identifier)
        elif record.get("source") == "DIAGNOSTIC_SESSION_CLEANUP":
            cleanup_count += 1
    if export_result is not None:
        _require(export_result.get("operation") == "journal.export" and
                 export_result.get("status") == "COMPLETED", "QA_JOURNAL_EXPORT_RESPONSE_NOT_COMPLETED")
        export_id = export_result.get("operation_id")
        _require(type(export_id) is str and export_id, "QA_JOURNAL_EXPORT_ACTION_ID_MISSING")
        requested = by_id.get(export_id + ":requested")
        completed = by_id.get(export_id + ":result")
        _require(requested is not None and completed is not None and
                 requested[0] == len(export_rows) and completed[0] == len(rows),
                 "QA_JOURNAL_EXPORT_FINAL_PAIR_MISMATCH")
        for item, phase in ((requested, "REQUESTED"), (completed, "RESULT")):
            record = item[1]
            _require(record.get("operation") == "journal.export" and
                     record.get("source") == "BLACKBOX_DIAGNOSTIC_JOURNAL_EXPORT" and
                     record.get("phase") == phase and record.get("action_id") == export_id and
                     record.get("target") is None, "QA_JOURNAL_EXPORT_PAIR_ATTRIBUTION_MISMATCH")
        expected_receipt = {"exported_records": len(export_rows), "exported_last_sequence": len(export_rows),
                            "exported_chain_head_sha256": requested[2], "export_published": True,
                            "memory_and_dumps": "EXCLUDED", "export_scope": "SNAPSHOT_THROUGH_EXPORT_REQUESTED"}
        for data in (completed[1].get("data", {}), export_result.get("data", {})):
            _require(all(data.get(key) == value for key, value in expected_receipt.items()),
                     "QA_JOURNAL_EXPORT_PREFIX_RECEIPT_MISMATCH")
        _require(completed[1].get("status") == "COMPLETED" and
                 export_result.get("journal", {}).get("record_sha256") == completed[2] and
                 export_result.get("journal", {}).get("operation_id") == export_id + ":result",
                 "QA_JOURNAL_EXPORT_RESULT_ACKNOWLEDGEMENT_MISMATCH")
    expected_ids = [action.get("operation_id") for action in expected_actions]
    _require(expected_ids and all(type(item) is str and item for item in expected_ids) and
             len(set(expected_ids)) == len(expected_ids), "QA_JOURNAL_EXPECTED_ACTION_IDS_INVALID")
    _require(set(action_records) == set(expected_ids), "QA_JOURNAL_UNEXPECTED_OR_MISSING_ACTION")
    for action in expected_actions:
        identifier = action["operation_id"]
        requested_id, result_id = identifier + ":requested", identifier + ":result"
        _require(action_records[identifier] == [requested_id, result_id],
                 "QA_JOURNAL_INTENT_RESULT_PAIR_MISSING_OR_REORDERED")
        requested, result = by_id[requested_id][1], by_id[result_id][1]
        for record, phase in ((requested, "REQUESTED"), (result, "RESULT")):
            _require(record.get("phase") == phase and record.get("operation") == action.get("operation") and
                     record.get("target") == action.get("target"), "QA_JOURNAL_ACTION_TARGET_OR_PHASE_MISMATCH")
        _require(result.get("status") == action.get("status"), "QA_JOURNAL_OBSERVED_STATUS_MISMATCH")
        acknowledged_hash = action.get("journal", {}).get("record_sha256")
        if acknowledged_hash is not None:
            _require(acknowledged_hash == by_id[result_id][2], "QA_JOURNAL_ACKNOWLEDGED_HASH_MISMATCH")
    _require(all(_digest(path) == original[path.name] for path in (database, exported)),
             "QA_JOURNAL_READ_ONLY_CHECK_CHANGED_SOURCE")
    return {"status": "PASS", "records": len(rows), "observed_actions": len(expected_actions),
            "cleanup_records": cleanup_count, "chain_head_sha256": previous,
            "exported_records": len(export_rows), "verified_export_result_tail_records": tail_records,
            "source_sha256": original, "exact_action_target_status_pairs_verified": True,
            "read_only_source_unchanged": True, "known_raw_memory_omitted": True,
            "scope": "LOCAL_CHANGE_DETECTION_AND_REAL_ACTION_CORRELATION_NOT_AUTHENTICATED_PROVENANCE"}
