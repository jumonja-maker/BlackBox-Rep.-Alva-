"""Independent stdlib-only read-back of actual Wave02 graph exports.

Used only by explicit QA routes, including the packaged --wave02-e2e route.
No product serializer, redactor, graph validator or import reader is an oracle
here. Expected identities come from the actual E2E case before export; this
checks preservation of its recorded evidence, never producer authentication.
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import stat


MAX_GRAPH_EXPORT_BYTES = 64 * 1024**2  # Existing default 2 x 32 MiB export budget.
GRAPH_SCHEMA = 'blackbox.investigation-graph/1'
_ANCHOR = 'Source-linked investigation'


def _require(condition, reason):
    if not condition:
        raise AssertionError('WAVE02_EXPORT_ORACLE_' + reason)


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _read_file(path, *, keep):
    """Bound the real file and bind both path and open handle to one identity."""
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_GRAPH_EXPORT_BYTES,
             'FILE_TYPE_OR_SIZE')
    blocks, count, digest = [], 0, hashlib.sha256()
    with path.open('rb') as stream:
        _require(_stamp(os.fstat(stream.fileno())) == _stamp(before), 'FILE_CHANGED')
        while block := stream.read(65536):
            count += len(block)
            _require(count <= MAX_GRAPH_EXPORT_BYTES, 'FILE_TYPE_OR_SIZE')
            digest.update(block)
            if keep:
                blocks.append(block)
        after = os.fstat(stream.fileno())
    _require(_stamp(before) == _stamp(after) == _stamp(path.lstat())
             and count == before.st_size, 'FILE_CHANGED')
    return b''.join(blocks) if keep else None, digest.hexdigest(), _stamp(before)


class _GraphHTML(HTMLParser):
    """Read the unique final graph metadata block, not an arbitrary <pre>."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.heading = None
        self.anchor_count = 0
        self.awaiting = self.inside = self.finished = False
        self.block_count = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        _require(not self.inside and not self.finished, 'HTML_NESTED_OR_EXTRA_TAG')
        if self.awaiting:
            _require(tag == 'pre' and not attrs, 'HTML_METADATA_ANCHOR')
            self.awaiting = False
            self.inside = True
            self.block_count += 1
        elif tag == 'h2':
            _require(self.heading is None, 'HTML_NESTED_HEADING')
            self.heading = []
        elif self.heading is not None:
            # The actual metadata heading is plain text. A nested heading is
            # ambiguous, even if the HTML renderer might display the same text.
            raise AssertionError('WAVE02_EXPORT_ORACLE_HTML_NESTED_HEADING')

    def handle_endtag(self, tag):
        if self.inside:
            _require(tag == 'pre', 'HTML_NESTED_OR_EXTRA_TAG')
            self.inside = False
            self.finished = True
        elif self.heading is not None:
            _require(tag == 'h2', 'HTML_NESTED_HEADING')
            if ''.join(self.heading).strip() == _ANCHOR:
                self.anchor_count += 1
                _require(self.anchor_count == 1, 'HTML_DUPLICATE_METADATA')
                self.awaiting = True
            self.heading = None
        elif self.awaiting:
            raise AssertionError('WAVE02_EXPORT_ORACLE_HTML_METADATA_ANCHOR')
        elif self.finished:
            _require(tag in ('body', 'html'), 'HTML_NESTED_OR_EXTRA_TAG')

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data)
        elif self.heading is not None:
            self.heading.append(data)
        elif self.awaiting or self.finished:
            _require(not data.strip(), 'HTML_EXTRA_METADATA_TEXT')

    def handle_comment(self, _data):
        _require(not (self.inside or self.awaiting or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def handle_decl(self, _decl):
        _require(not (self.inside or self.awaiting or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def handle_pi(self, _data):
        _require(not (self.inside or self.awaiting or self.finished), 'HTML_EXTRA_METADATA_MARKUP')

    def unknown_decl(self, _data):
        raise AssertionError('WAVE02_EXPORT_ORACLE_HTML_UNKNOWN_DECLARATION')

    def metadata(self):
        _require(self.anchor_count == self.block_count == 1 and self.finished
                 and not self.inside and not self.awaiting and self.heading is None,
                 'HTML_METADATA_MISSING_OR_UNCLOSED')
        return ''.join(self.parts)


def _unique_keys(items):
    value = {}
    for key, item in items:
        _require(key not in value, 'JSON_DUPLICATE_KEY')
        value[key] = item
    return value


def _nonfinite(_value):
    raise AssertionError('WAVE02_EXPORT_ORACLE_JSON_NONFINITE')


def _finite_float(raw):
    value = float(raw)
    _require(math.isfinite(value), 'JSON_NONFINITE')
    return value


def _parse_graph(data, format):
    try:
        text = data.decode('utf-8')
        if format == 'html':
            parser = _GraphHTML()
            parser.feed(text)
            parser.close()
            text = parser.metadata()
        value = json.loads(text, object_pairs_hook=_unique_keys,
                           parse_constant=_nonfinite, parse_float=_finite_float)
    except (UnicodeError, ValueError, RecursionError):
        raise AssertionError('WAVE02_EXPORT_ORACLE_INVALID_UTF8_OR_JSON') from None
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        _require(depth <= 32 and visited <= 2_000_000, 'JSON_STRUCTURE_BUDGET')
        if type(item) is dict:
            _require(len(item) <= 512, 'JSON_STRUCTURE_BUDGET')
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            _require(len(item) <= 250000, 'JSON_STRUCTURE_BUDGET')
            pending.extend((child, depth + 1) for child in item)
    return value


def _rows(value, name, identifier, maximum):
    rows = value.get(name)
    _require(type(rows) is list and len(rows) <= maximum, 'GRAPH_ROWS')
    result = {}
    for row in rows:
        _require(type(row) is dict and type(row.get(identifier)) is str
                 and 0 < len(row[identifier]) <= 256 and row[identifier] not in result,
                 'GRAPH_DUPLICATE_OR_MISSING_ID')
        result[row[identifier]] = row
    return result


def _public_identity(value):
    """Compare recorded identifiers without treating private paths as identity.

    A native ProcessIdentity includes image_path; public export legitimately
    replaces it. No path is inspected, transformed, compared or followed here.
    Exact birth, trace/session scope and recorded image hashes still compare.
    """
    if value is None:
        return None
    _require(type(value) is dict, 'IDENTITY_TYPE')
    # Python equates 123 with 123.0 and False with 0. Recorded PID/FILETIME and
    # exactness types are part of their contracts, so compare type and value.
    return {key: (type(value[key]).__name__, value[key]) for key in (
        'kind', 'pid', 'created_100ns', 'tid', 'thread_created_100ns',
        'trace_sha256', 'process_instance', 'thread_instance', 'instance_id',
        'source_id', 'source_scope', 'producer_id', 'creation_time',
        'exact', 'image_sha256', 'source_sha256',
    ) if key in value}


def _receipt_target(value):
    if value is None:
        return None
    _require(type(value) is dict, 'RECEIPT_TARGET_TYPE')
    return {'identity': _public_identity(value.get('identity')),
            'verified': value.get('verified'), 'scope': value.get('scope')}


def _critical_path_projection(value, nodes, edges):
    if value is None:
        return None
    _require(type(value) is dict and value.get('schema') == 'blackbox.critical-path/1'
             and value.get('status') in ('PARTIAL', 'NOT_ESTABLISHED', 'CONTRADICTED')
             and value.get('end_to_end_established') is False
             and value.get('root_cause_proven', False) is False, 'CRITICAL_PATH_CAUSE_OR_SCHEMA')
    segments = _rows(value, 'segments', 'segment_id', 10000)
    segment_facts = {}
    for identifier, segment in segments.items():
        node = nodes.get(segment.get('node_id'))
        _require(node is not None and segment.get('source_identity') == node.get('source_identity')
                 and segment.get('time_domain') == node.get('time_domain'), 'CRITICAL_PATH_NODE_REFERENCE')
        segment_facts[identifier] = {key: segment.get(key) for key in (
            'node_id', 'source_identity', 'time_domain', 'start', 'end', 'unit',
            'state', 'duration_ms', 'source_event_ids')}
        segment_facts[identifier]['thread_identity'] = _public_identity(segment.get('thread_identity'))
    dependencies = value.get('dependencies')
    route = value.get('path')
    _require(type(dependencies) is list and len(dependencies) <= 20000
             and all(type(row) is dict and row.get('from_segment') in segments
                     and row.get('to_segment') in segments
                     and (row.get('evidence_ref') == 'SHARED_RECORDED_BOUNDARY'
                          or row.get('evidence_ref') in edges) for row in dependencies)
             and type(route) is list and len(route) <= len(segments)
             and all(type(identifier) is str and identifier in segments for identifier in route),
             'CRITICAL_PATH_DEPENDENCY_REFERENCE')
    return {'schema': value['schema'], 'status': value['status'], 'segments': segment_facts,
            'dependencies': dependencies, 'path': route,
            'totals': value.get('totals'), 'longest_observed_component_ms': value.get('longest_observed_component_ms'),
            'segments_omitted': value.get('segments_omitted'), 'unknowns_omitted': value.get('unknowns_omitted')}


def _identity_projection(value):
    """A small external identity oracle, not another product graph validator."""
    _require(type(value) is dict and value.get('schema') == GRAPH_SCHEMA, 'GRAPH_SCHEMA')
    _require(type(value.get('case_id')) is str and 0 < len(value['case_id']) <= 256
             and value.get('algorithm_version') == '3.0.0'
             and type(value.get('graph_version')) is int and value['graph_version'] == 1,
             'GRAPH_HEADER')
    _require(value.get('root_cause') == 'UNKNOWN' and value.get('root_cause_proven') is False
             and value.get('file_trust') == 'UNVERIFIED_IMPORT', 'GRAPH_TRUST_OR_CAUSE')
    sources = _rows(value, 'sources', 'source_id', 64)
    nodes = _rows(value, 'nodes', 'node_id', 10000)
    edges = _rows(value, 'edges', 'edge_id', 20000)
    _require(sources and value.get('source_ids') == sorted(sources), 'GRAPH_SOURCE_IDS')
    source_facts = {}
    for identifier, source in sources.items():
        manifest = source.get('content_manifest')
        _require(type(manifest) is list and 1 <= len(manifest) <= 64
                 and all(type(row) is dict and type(row.get('role')) is str
                         and type(row.get('sha256')) is str and len(row['sha256']) == 64
                         and type(row.get('size_bytes')) is int and row['size_bytes'] > 0
                         for row in manifest), 'SOURCE_MANIFEST')
        roles = [row['role'] for row in manifest]
        _require(type(source.get('source_file_count')) is int
                 and type(source.get('source_size_bytes')) is int
                 and len(set(roles)) == len(roles) == source['source_file_count']
                 and sum(row['size_bytes'] for row in manifest) == source.get('source_size_bytes')
                 and source.get('verification_class') == 'UNVERIFIED_IMPORT'
                 and source.get('provenance', {}).get('producer_authentication') == 'NOT_ESTABLISHED',
                 'SOURCE_MANIFEST_OR_TRUST')
        source_facts[identifier] = {key: source.get(key) for key in (
            'source_type', 'source_sha256', 'source_size_bytes', 'source_file_count',
            'content_manifest', 'selection', 'trace_input_sha256', 'session_uuid', 'coverage')}
    node_facts = {}
    for identifier, node in nodes.items():
        source = sources.get(node.get('source_identity'))
        _require(source is not None and node.get('source_type') == source.get('source_type')
                 and node.get('source_sha256') == source.get('source_sha256'), 'NODE_SOURCE')
        node_facts[identifier] = {key: node.get(key) for key in (
            'observation_type', 'source_identity', 'source_type', 'source_sha256',
            'source_record_id', 'time_domain', 'time_bounds',
            'verification_class', 'completeness_status')}
        node_facts[identifier]['process_identity'] = _public_identity(node.get('process_identity'))
        node_facts[identifier]['thread_identity'] = _public_identity(node.get('thread_identity'))
    edge_facts = {}
    for identifier, edge in edges.items():
        _require(edge.get('from_node') in nodes and edge.get('to_node') in nodes, 'EDGE_ENDPOINT')
        edge_facts[identifier] = {key: edge.get(key) for key in (
            'from_node', 'to_node', 'relation_type', 'verification_class')}
    for name in ('hypotheses', 'actions', 'issues', 'guided_experiments', 'user_annotations'):
        rows = value.get(name, [])
        _require(type(rows) is list and all(type(row) is dict and row.get('root_cause_proven', False) is False
                     and row.get('root_cause_established', False) is False
                     for row in rows), 'GRAPH_INTERPRETATION_CAUSE')
    receipt = value.get('run_receipt')
    _require(type(receipt) is dict and type(receipt.get('contract_version')) is int
             and receipt['contract_version'] == 1
             and receipt.get('operation') == 'investigation.create' and receipt.get('status') == 'COMPLETED'
             and type(receipt.get('run_id')) is str and 0 < len(receipt['run_id']) <= 128
             and receipt.get('execution_started') is True
             and type(receipt.get('cleanup')) is dict and receipt['cleanup'].get('confirmed') is True
             and type(receipt.get('source')) is dict and receipt['source'].get('verified') is True
             and receipt['source'].get('producer_authentication') == 'NOT_ESTABLISHED',
             'GRAPH_RECEIPT')
    completeness = value.get('coverage', {}).get('evidence_completeness')
    _require(completeness in ('INCOMPLETE_EVIDENCE', 'UNKNOWN_CAPTURE_COMPLETENESS'), 'GRAPH_CAPTURE_COMPLETENESS')
    return {
        'case_id': value.get('case_id'), 'graph_version': value.get('graph_version'),
        'algorithm_version': value.get('algorithm_version'),
        'target_identity': _public_identity(value.get('target_identity')),
        'sources': source_facts, 'nodes': node_facts, 'edges': edge_facts,
        'receipt': {key: receipt.get(key) for key in ('contract_version', 'run_id', 'operation',
            'status', 'execution_started', 'coverage', 'cleanup')},
        'receipt_target': _receipt_target(receipt.get('target')),
        'critical_path': _critical_path_projection(value.get('critical_path'), nodes, edges),
        # Source files are already compared above by IDs and complete role
        # manifests. Other descriptive strings in receipt.source.sources can
        # legitimately be privacy-redacted during public export.
        'receipt_source': {key: receipt['source'].get(key) for key in
            ('name', 'verified', 'verification_scope', 'producer_authentication')},
        'evidence_completeness': completeness,
    }


def _same_json_metadata(first, second):
    """Compare all public JSON values, including their scalar types.

    Dict equality alone equates booleans with numbers and integers with floats.
    This independent walk is order-insensitive for objects and preserves array
    order, without allocating another serialized copy of a large graph.
    """
    pending = [(first, second)]
    while pending:
        left, right = pending.pop()
        if type(left) is not type(right):
            return False
        if type(left) is dict:
            if left.keys() != right.keys():
                return False
            pending.extend((value, right[key]) for key, value in left.items())
        elif type(left) is list:
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right))
        elif left != right:
            return False
    return True


def read_graph_export(path, *, format, expected_case, json_reference=None):
    """Return parsed public metadata and a bounded receipt after real read-back.

    HTML must equal the independently parsed JSON from this same E2E case.
    Original source hashes are separately rechecked by the existing native and
    GUI scenarios; no path or source claim inside the export is followed here.
    """
    _require(format in ('json', 'html'), 'FORMAT')
    _require(format != 'html' or type(json_reference) is dict, 'HTML_REQUIRES_JSON_REFERENCE')
    path = Path(path)
    data, digest, stamp = _read_file(path, keep=True)
    value = _parse_graph(data, format)
    _require(_same_json_metadata(_identity_projection(value), _identity_projection(expected_case)),
             'RECORDED_IDENTITIES_CHANGED')
    if format == 'html':
        _require(_same_json_metadata(value, json_reference), 'HTML_JSON_METADATA_DIFFER')
    _, after_digest, after_stamp = _read_file(path, keep=False)
    _require(after_digest == digest and after_stamp == stamp, 'FILE_CHANGED')
    return value, {
        'schema': GRAPH_SCHEMA, 'case_id': value['case_id'], 'format': format,
        'sha256': digest, 'bytes': len(data), 'source_count': len(value['sources']),
        'node_count': len(value['nodes']), 'edge_count': len(value['edges']),
        'semantic_readback_verified': True, 'html_matches_json': format == 'html',
        'export_bytes_unchanged': True, 'producer_authentication': 'NOT_ESTABLISHED',
        'method': 'INDEPENDENT_STDLIB_JSON_AND_HTML_PARSER',
    }
