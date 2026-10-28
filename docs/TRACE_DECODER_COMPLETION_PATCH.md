# Decoder completion patch: support and acceptance contract

This is an unpublished candidate on `patch/trace-decoder-phase5`, based on
BLACK.BOX v0.5.1 (`206b907dd83764d4cc67eee8142349c220cb139d`). The application
version remains v0.5.1. Neither main promotion nor a Release is part of this
patch. The portable CI artifact contains `PATCH-NOTES.md` and
`decoder-patch-provenance.json` to distinguish it from the published release.

## Reliability and recovery

Imports share a wall-clock deadline and explicit limits: 256 MiB input,
250,000 events, 768 MiB index and 1 GiB workspace. The default deadline is
180 seconds (API maximum 600 seconds). The native helper has a 1 GiB managed
heap limit and a monitored 1.5 GiB RSS limit. Read pages have an 8 MiB budget;
dense pages return fewer rows without losing the keyset cursor.

Cancellation, timeout, corruption and budget exhaustion have distinct failure
codes. A failed import does not publish a final index. Recovery means a fresh
retry from the original trace, not resuming an untrusted partial index. The
source hash is checked again immediately before index publication. Index
exports likewise use private temporary files and atomic no-clobber publication.
Original traces are never edited.

## Evidence-based session clock correlation

The explicit GUI action selects a capture journal and a BLACK.BOX session-v2
database. A result is `BOUNDED_LOCAL_CLOCK_CORRELATION` only when source hashes,
session identity, recorder identity, exact boot identity, counter frequency,
source counters and immutable session clock metadata agree. Bracketed local
counter readings yield a bounded offset and an uncertainty interval. Event
projection uses outward rounding and only the validated counter range.

This is a hash-linked local assertion, not authenticated evidence. UTC labels
are not used as proof of alignment. Old sessions, missing metadata, clock
discontinuities, mismatched boots/frequencies and unsupported numeric ranges
remain `NOT_ESTABLISHED`; the decoder does not guess. Selected event details
show the separate bounded projection while preserving the imported timestamp.

## Thread scheduling and waits

The native helper exports typed ETW CSwitch/ReadyThread observations with
process and thread lifetime identities. Off-CPU analysis pairs switch-out and
switch-in boundaries; a matching ready event can separate blocked time from
ready-queue delay. PID/TID and time filters are explicit. The GUI displays up
to 500 intervals; the default exported report allows 10,000 (API maximum
20,000).

Missing identities, contradictory boundaries, unknown or positive event loss,
truncation and timestamp reversal prevent unsupported duration claims.
Observed spans and quality reasons remain available. A scheduler wait reason
does not establish a lock owner or an application's internal root cause.
Traces without scheduler events are reported as such.

## Local symbols

Native MSF7 PDB support adds C13 source locations/checksums, CodeView inline
site annotations and OMAP-to-source address translation. PE/PDB GUID-age and
trace module lifetime checks still apply. Raw addresses are retained; inline
frames do not create extra CPU samples. The decoder does not fetch source
files or symbols over the network.

Compiler-produced optimized native PDBs are checked against an independent
LLVM symbolizer. OMAP validation uses an explicitly augmented compiler PDB
format fixture; it is not represented as acceptance of every optimizing linker.
Portable/embedded managed PDBs and arbitrary JIT native-IP-to-IL reconstruction
without the required method/token/map evidence remain outside this patch.
Existing TraceEvent managed names remain supported.

## Reproducible checks

The isolated `decoder-patch-qa.yml` runs the full Python suite on Linux and
Windows, undefined-name checks, real compiler/PDB checks, import stress and a
portable Windows EXE build. It has read-only repository permissions and no
publication job. Native Windows checks run on GitHub-hosted Windows runners.

```sh
python tools/check_undefined_names.py
python -m unittest discover -s tests -v
python tools/qa_decoder_reliability.py --output qa/reliability --rows 250000
python tools/qa_decoder_symbols.py --output qa/symbols
python tools/qa_decoder_patch.py --output qa/native
```

Windows, after building the self-contained helper:

```powershell
python tools/qa_decoder.py --helper decoder/BLACK.BOX-Decoder.exe --output qa/decoder
python tools/qa_decoder_standard_token.py --helper decoder/BLACK.BOX-Decoder.exe --trace-root qa/decoder --output qa/standard-token
python tools/qa_decoder_waits.py --helper decoder/BLACK.BOX-Decoder.exe --output qa/waits
python tools/qa_decoder_apps.py --helper decoder/BLACK.BOX-Decoder.exe --output qa/apps
```

Native reliability checks damage copies of genuine captured traces, cancel an
actual helper process and retry the intact source. Standard-token acceptance
removes administrator identity/privileges and decodes the real ETL/EventPipe
files again. Controlled scheduling workloads exercise Sleep, event and mutex
waits. Clock acceptance includes same-session evidence and negative controls.

| Application | Controlled workload and expected evidence |
| --- | --- |
| 7-Zip | Compression/extraction, exact content-hash roundtrip, CPU samples, file operations, threads and ETW stacks |
| PowerShell 7 | EventPipe capture, marked CPU/allocation phases, managed stacks and GC events |
| Notepad++ | Pinned portable 8.9.8.1 verified against the official checksum, window responsiveness, edit/save exact-byte oracle, file and scheduler observations |

Installed 7-Zip/PowerShell versions and executable hashes are recorded.
Unavailable applications or missing prerequisites are `NOT_EXECUTED`, never
synthetic success. Fixture-based unit tests and Linux offline parsing are
reported separately from native Windows acceptance.

These are acceptance requirements, not a claim that a particular CI run
passed. The handoff report records the tested commit, actual run results,
artifact hashes and remaining limitations. Physical Windows 10/11 acceptance
is deferred by the owner. One-hour/eight-hour recordings, additional providers,
WPP/TMF, memory dumps and GC heap analysis remain separate work.
