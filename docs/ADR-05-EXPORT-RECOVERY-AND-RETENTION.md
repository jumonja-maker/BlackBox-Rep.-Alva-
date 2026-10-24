# Owned exports and confirmed retention

Original recordings remain read-only during analysis/export. New exports have a private stage, a versioned journal, native file identities, SHA-256 and exclusive publication. A stopped/expired optional worker leaves its journal for explicit recovery. Recovery is not automatic and never overwrites a competing destination. An incomplete build cannot be called a completed export; unknown/replaced staged files are retained.

All persisted findings are streamed into offline JSON/CSV/HTML. SQLite owns ordering instead of a Python history list. Derived inference quotas and query deadlines remain explicit; no findings[:32] presentation truncation. CSV formula prefixes are neutralized. HTML escapes imported content and denies scripts/network resources. Default share copies omit known notes/paths/application attributes; this is not universal secret detection. Complete raw packages are not claimed when nested/unconfirmed artifacts are omitted.

Trash and permanent deletion are separate actions. Permanent deletion requires a second one-use five-minute review token, local app root/session markers, finalized capture, no active trace journal, an outside-payload inventory, and per-entry native identity checks. Interrupted purge retains its manifest/journal and requires fresh review. It never follows a symlink/reparse point or uses recursive shell deletion. Local markers are not digital signatures or protection from an adversary controlling the same account.

On POSIX, deletion traverses held directory descriptors with O_NOFOLLOW and compares inode/device. On Windows, OPEN_REPARSE_POINT, GetFileInformationByHandle and GetFinalPathNameByHandleW validate the same opened handle before SetFileInformationByHandle(FileDispositionInfo). FILE_DISPOSITION_INFO contains one BOOLEAN. Final removal can be delayed/denied by another open handle; this remains unconfirmed/partial, not success.

Primary API contracts:
- https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
- https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
- https://learn.microsoft.com/windows/win32/api/winbase/ns-winbase-file_disposition_info
- https://learn.microsoft.com/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump

MiniDumpWriteDump returns an HRESULT through GetLastError. A bounded retry for ERROR_BAD_LENGTH is a BLACK.BOX recovery policy for a changing process snapshot, not a documented promise that every such failure is transient. Other errors are not retried; requested capture flags are not reduced. Only a nonempty MDMP header is published. Detailed validity still requires native Windows acceptance/debugger inspection.

Storage budgets are soft. The owned recording is measured every five seconds with bounded metadata work; library totals are cached metadata refreshed at most once per minute. Unknown sizes remain unknown. Exceeding a known selected limit stops recording and preserves observations; it never performs automatic deletion. Logical bytes removed are not declared physical free space, because hard links/open files/cached entries may differ.
