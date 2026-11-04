// Additive, typed FileIO request/result observations from pinned TraceEvent.
// A kernel request token identifies an observed request, not a file or lock owner.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

internal static class FileIoObservations
{
    internal static string? Key(ulong value, string kind)
    {
        if (value == 0) return null;
        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(
            "blackbox.file-io/1:" + kind + ":" + value.ToString("x", CultureInfo.InvariantCulture))))
            .ToLowerInvariant();
    }

    internal static object? Project(TraceEvent e, TraceLog log)
    {
        if (e.ProviderGuid != KernelTraceEventParser.ProviderGuid || (int)e.ID != 65535 ||
            e.Version is < 2 or > 3) return null;
        int opcode = (int)e.Opcode;
        string? operation = null, parser = null, fileName = null;
        ulong request = 0, fileObject = 0;
        long? requestedBytes = null, offset = null;
        uint? status = null;
        string phase = "start";
        if (e is FileIOCreateTraceData create && opcode == 64 && e.EventName == "FileIO/Create")
        {
            operation = "create"; parser = "TRACEEVENT_FILE_IO_CREATE";
            request = create.IrpPtr; fileObject = create.FileObject; fileName = create.FileName;
        }
        else if (e is FileIOReadWriteTraceData rw && opcode is 67 or 68 &&
                 e.EventName == (opcode == 67 ? "FileIO/Read" : "FileIO/Write"))
        {
            operation = opcode == 67 ? "read" : "write"; parser = "TRACEEVENT_FILE_IO_READ_WRITE";
            request = rw.IrpPtr; fileObject = rw.FileObject; fileName = rw.FileName;
            requestedBytes = unchecked((uint)rw.IoSize); offset = rw.Offset;
        }
        else if (e is FileIOSimpleOpTraceData simple && opcode is 65 or 66 or 73)
        {
            operation = opcode switch { 65 => "cleanup", 66 => "close", _ => "flush" };
            string name = opcode switch { 65 => "Cleanup", 66 => "Close", _ => "Flush" };
            if (e.EventName != "FileIO/" + name) return null;
            parser = "TRACEEVENT_FILE_IO_SIMPLE";
            request = simple.IrpPtr; fileObject = simple.FileObject; fileName = simple.FileName;
        }
        else if (e is FileIOInfoTraceData info && opcode is 69 or 70 or 71 or 74 or 75)
        {
            operation = opcode switch { 69 => "set_info", 70 => "delete", 71 => "rename", 74 => "query_info", _ => "fs_control" };
            string name = opcode switch { 69 => "SetInfo", 70 => "Delete", 71 => "Rename", 74 => "QueryInfo", _ => "FSControl" };
            if (e.EventName != "FileIO/" + name) return null;
            parser = "TRACEEVENT_FILE_IO_INFO";
            request = info.IrpPtr; fileObject = info.FileObject; fileName = info.FileName;
        }
        else if (e is FileIODirEnumTraceData directory && opcode is 72 or 77 &&
                 e.EventName == (opcode == 72 ? "FileIO/DirEnum" : "FileIO/DirNotify"))
        {
            operation = opcode == 72 ? "dir_enum" : "dir_notify"; parser = "TRACEEVENT_FILE_IO_DIRECTORY";
            request = directory.IrpPtr; fileObject = directory.FileObject; fileName = directory.DirectoryName;
        }
        else if (e is FileIOOpEndTraceData end && opcode == 76 && e.EventName == "FileIO/OperationEnd")
        {
            operation = "operation_end"; parser = "TRACEEVENT_FILE_IO_OP_END";
            phase = "end"; request = end.IrpPtr; status = unchecked((uint)end.NtStatus);
        }
        if (operation is null) return null;
        string nameStatus = string.IsNullOrEmpty(fileName) ? "UNAVAILABLE" :
            fileName.Length > 2048 ? "TRUNCATED" : "RECORDED";
        if (string.IsNullOrEmpty(fileName)) fileName = null;
        else if (fileName.Length > 2048) fileName = fileName[..2048];
        return new {
            schema = "blackbox.trace-io/1", source = "ETW_KERNEL_FILE_IO", parser, kind = "file",
            phase, operation, request_key = Key(request, "request"),
            file_object_key = Key(fileObject, "file-object"), file_name = fileName, name_status = nameStatus,
            requested_bytes = requestedBytes, offset, ntstatus = status,
            status_domain = phase == "end" ? "NTSTATUS" : "NOT_REPORTED_IN_START_EVENT",
            event_thread = ThreadSchedule.Identity(log, e.ThreadID, e.ProcessID, e.TimeStampRelativeMSec),
            key_basis = "HASHED_KERNEL_REQUEST_TOKEN_SCOPED_TO_SOURCE_TRACE",
            transferred_bytes = (long?)null
        };
    }
}
