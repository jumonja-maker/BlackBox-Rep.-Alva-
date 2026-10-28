# Build-time inventory and concrete notices

Added QA/build-only `tools/build_distribution_inventory.py` and `tests/test_distribution_inventory.py`. No application modules, dependencies or workflows changed by this direction.

## What the tool does

Run after all final portable payload copies and before ZIP:

```
python tools/build_distribution_inventory.py --payload dist/BLACK.BOX-Universal
```

An optional `--output new-external-report.json` writes the identical report outside the payload. The canonical embedded report is always `DISTRIBUTION-INVENTORY.json`. It excludes itself from the SHA-256 inventory; the ZIP checksum will subsequently cover the inventory. Existing manifest/notices directory or external report causes failure, not overwrite. Existing decoder and public notices remain byte-for-byte intact.

Every regular payload file is hashed in streamed 1 MiB blocks. Symlink/reparse and other non-regular entries are refused. Files changed during hashing/copying are refused. On failure the tool removes only paths it created; it never removes pre-existing decoder/source files.

The inventory records installed build-environment distributions, actual versions and metadata License/License-Expression. It explicitly says this is NOT proof that every environment package is bundled. Available actual license/notice texts from safe installed RECORD paths are copied under `third_party_notices/python-packages`; absent texts remain `METADATA_ONLY_REVIEW_REQUIRED` rather than invented.

The five exact vendored Qt texts in `docs/vendor/pyside-6.11.3` are copied only when installed PySide6 and all present PySide family/shiboken versions equal 6.11.3. Runtime Python LICENSE.txt/LICENSE is preferred. Only when that is absent AND actual Python version is exactly 3.11.14 may the exact pinned CPython-3.11.14 license be used. A local Python 3.12 without its actual license fails rather than silently copying the 3.11 text.

`licenseCoverageReviewRequired=true`, `allNativeDllLicensesCertified=false` and explicit limitations prevent legal/complete-SCA overclaims. Precise Qt native third-party license coverage, relinking/distribution conditions and Authenticode are NOT solved by merely writing this inventory.

## Validation

Five fixture-based tests PASS: actual payload hashes and actual fixture license bytes vs metadata, explicit incomplete coverage, preserved pre-existing decoder files, no-clobber repeat/existing output, version mismatch/fallback refusal and actual runtime-license preference, failure rollback, and reparse/symlink metadata rejection. These tests inject an explicit fake build environment; they do not pretend that the local 3.12 host is Windows Python 3.11.14. Actual portable CI must call this tool on the real build payload and installed distributions.

Static undefined-name check of both files PASS. Source SHA-256 manifest is adjacent. Files frozen.
