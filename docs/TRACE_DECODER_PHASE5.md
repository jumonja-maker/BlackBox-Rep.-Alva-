# BLACK.BOX Trace Decoder — Phase 5A: local PE/PDB identity preflight

> Integration note (2026-10-28): included in the owner-authorized v0.5.0
> candidate. Historical patch-test results below do not certify the release;
> the exact candidate must pass the full release workflow.

**Status:** development on `main` only. This is not symbol resolution or a
new officially published Release. No automatic search, download, capture or
execution is performed.

## Explicit operation

The sixth **TRACE DECODER** page offers **CHECK LOCAL PDB… / ПРОВЕРИТЬ
ЛОКАЛЬНЫЙ PDB…** after opening a trace. The user separately chooses a local
PE executable/module and a local Windows PDB. The checker reads a small,
bounded subset of the files:

- PE32/PE32+ section and debug-directory headers; CodeView `RSDS` GUID,
  Age and only the basename of the PDB reference. Ambiguous GUID/Age records
  are refused, not selected arbitrarily.
- Windows PDB 7.0/MSF superblock, stream directory and PDB Info stream
  (index 1), extracting its GUID and Age. The file is **not** loaded as a DLL.
- A positive verdict means only `PE_PDB_GUID_AGE_MATCH_UNLINKED_TO_TRACE`.
  A mismatch means `PE_PDB_GUID_AGE_MISMATCH`. Missing, corrupted, changed,
  unsupported or unsafe inputs return `LOCAL_IDENTITY_UNAVAILABLE` with a
  constrained reason code. No guessed symbols are attached to stack frames.

There is **no proof** that the selected PE was loaded in the imported trace,
that it is the same process instance/build, or that the local PDB and PE are
authentic. Matching GUID/Age is necessary for future symbol resolution but
**not sufficient for a verified trace-to-module association**. Every result
includes:

```text
trace_module_identity: NOT_ESTABLISHED
stack_symbols_resolved: false
symbol_server_contacted: false
source_execution: false
```

The saved trace, decoder SQLite index, recorded stacks and source files
are never modified. Opening a different trace clears the previous verdict,
and the status remains visible in RU/EN while examining other events.

## Scope and safety

- Local file pairs only. UNC paths, symlinks and Windows reparse points are
  refused. Input metadata and file identity are compared before/after reading.
  The checker does not initiate network requests; it cannot attest the
  trustworthiness of user-controlled filesystem paths or physical storage.
- Each file is limited to 512 MiB, PE e_lfanew to 1 MiB, at most 96 sections,
  256 debug-directory entries, and 4 MiB for the PDB directory. Only bounded
  ranges are read, not the entire PDB or executable.
- Native Windows MSF 7.0 PDB with the VC70 Info-stream layout is currently
  supported. Portable PDB, legacy NB10 and unsupported/ambiguous formats are
  rejected rather than guessed. A PDB basename mismatch does not override
  a valid GUID/Age pair, but is noted separately.
- No DbgHelp symbol initialization, remote symbol server, PDB source-path
  crawling, arbitrary debugger commands or target-process attachment.
- Do not equate PDB identity verification with independent provenance, full
  unwind, symbol resolution, native CPU samples or a Flame Graph. Those
  remain separate phases. Trace/session clock alignment is still
  `NOT_ESTABLISHED`.

## Validation

- `tests/test_decoder_pdb.py`: synthetic PE/CodeView and MSF7 fixtures,
  matching GUID/Age, wrong GUID/Age, corrupted or unsupported files,
  multi-RSDS ambiguity, symlink and size limits, source-byte preservation.
- `tests/test_decoder_gui.py`: manual RU/EN review, explicit
  `NOT_ESTABLISHED` status, and state reset on a new trace.
- Developer smoke: a real native EXE and Windows PDB produced locally with
  Clang/lld-link were inspected with matching GUID/Age. This is additional
  local evidence, not a substitute for Windows CI or physical acceptance.

References:
- [PE/COFF debug directory and RSDS](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [.NET PE/COFF RSDS GUID and Age contract](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md)
- [LLVM PDB stream header and matching rules](https://llvm.org/docs/PDB/PdbStream.html)
- [LLVM MSF container and directory](https://llvm.org/docs/PDB/MsfFile.html)

Previous stage: [Capture-side QPC evidence](TRACE_DECODER_PHASE4.md).
