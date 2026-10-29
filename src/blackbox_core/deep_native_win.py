"""Typed, lazily loaded Windows x64 APIs for explicit deep inspection.

No API is loaded during import on another platform. Native calls run in the
diagnostic helper, whose owner supplies the final hard timeout boundary.
"""
from __future__ import annotations

import ctypes as C
import os

U16, U32, U64 = C.c_uint16, C.c_uint32, C.c_uint64
I32, I64 = C.c_int32, C.c_int64
PTR, HANDLE, SIZE = C.c_void_p, C.c_void_p, C.c_size_t
BOOL, WCHAR = I32, C.c_wchar
INVALID_HANDLE = C.c_void_p(-1).value


class FILETIME(C.Structure):
    _fields_ = [("low", U32), ("high", U32)]

    @property
    def value(self):
        return (int(self.high) << 32) | int(self.low)


class MODULEENTRY32W(C.Structure):
    _fields_ = [("size", U32), ("module_id", U32), ("pid", U32),
                ("global_usage", U32), ("process_usage", U32),
                ("base", PTR), ("image_size", U32), ("module", HANDLE),
                ("name", WCHAR * 256), ("path", WCHAR * 260)]


class THREADENTRY32(C.Structure):
    _fields_ = [("size", U32), ("usage", U32), ("tid", U32),
                ("pid", U32), ("base_priority", I32),
                ("delta_priority", I32), ("flags", U32)]


class MEMORY_BASIC_INFORMATION(C.Structure):
    _fields_ = [("base", PTR), ("allocation_base", PTR),
                ("allocation_protect", U32), ("partition_id", U16),
                ("region_size", SIZE), ("state", U32), ("protect", U32),
                ("type", U32)]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(C.Structure):
    _fields_ = [("object", PTR), ("pid", SIZE), ("value", SIZE),
                ("access", U32), ("creator_backtrace", U16),
                ("type_index", U16), ("attributes", U32), ("reserved", U32)]


class UNICODE_STRING(C.Structure):
    _fields_ = [("length", U16), ("maximum", U16), ("buffer", PTR)]


class M128A(C.Structure):
    _fields_ = [("low", U64), ("high", I64)]


class CONTEXT64(C.Structure):
    _fields_ = ([("p%dhome" % n, U64) for n in range(1, 7)] +
                [("flags", U32), ("mxcsr", U32)] +
                [(n, U16) for n in ("cs", "ds", "es", "fs", "gs", "ss")] +
                [("eflags", U32)] +
                [(n, U64) for n in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
                                   "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")] +
                [("floating", C.c_ubyte * 512), ("vectors", M128A * 26),
                 ("vector_control", U64), ("debug_control", U64),
                 ("last_branch_to_rip", U64), ("last_branch_from_rip", U64),
                 ("last_exception_to_rip", U64), ("last_exception_from_rip", U64)])


class ADDRESS64(C.Structure):
    _fields_ = [("offset", U64), ("segment", U16), ("mode", U32)]


class KDHELP64(C.Structure):
    _fields_ = [("thread", U64), ("callback_stack", U32),
                ("callback_bstore", U32), ("next_callback", U32),
                ("frame_pointer", U32), ("call_user_mode", U64),
                ("user_callback_dispatcher", U64), ("system_range_start", U64),
                ("user_exception_dispatcher", U64), ("stack_base", U64),
                ("stack_limit", U64), ("build_version", U32),
                ("retpoline_table_size", U32), ("retpoline_table", U64),
                ("retpoline_offset", U32), ("retpoline_size", U32),
                ("reserved", U64 * 2)]


class STACKFRAME64(C.Structure):
    _fields_ = [(n, ADDRESS64) for n in ("pc", "return_address", "frame", "stack", "bstore")] + [
        ("function_table_entry", PTR), ("params", U64 * 4),
        ("far", BOOL), ("virtual", BOOL), ("reserved", U64 * 3), ("kdhelp", KDHELP64)]


def aligned_context():
    """GetThreadContext's CONTEXT must be 16-byte aligned, including on 3.11."""
    storage = C.create_string_buffer(C.sizeof(CONTEXT64) + 15)
    address = (C.addressof(storage) + 15) & ~15
    context = CONTEXT64.from_address(address)
    context.flags = 0x0010000B  # AMD64 CONTROL | INTEGER | DEBUG_REGISTERS
    return storage, context


def library(name):
    if os.name != "nt":
        raise OSError("UNSUPPORTED_PLATFORM")
    # LOAD_LIBRARY_SEARCH_SYSTEM32; no application-directory DLL substitution.
    return C.WinDLL(name, use_last_error=True, winmode=0x800)


def bind(dll, name, restype, *argtypes):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = restype, list(argtypes)
    return fn


class Kernel:
    def __init__(self):
        self.dll = k = library("kernel32")
        self.open_process = bind(k, "OpenProcess", HANDLE, U32, BOOL, U32)
        self.close = bind(k, "CloseHandle", BOOL, HANDLE)
        self.process_times = bind(k, "GetProcessTimes", BOOL, HANDLE, *([C.POINTER(FILETIME)] * 4))
        self.thread_times = bind(k, "GetThreadTimes", BOOL, HANDLE, *([C.POINTER(FILETIME)] * 4))
        self.image = bind(k, "QueryFullProcessImageNameW", BOOL, HANDLE, U32, C.c_wchar_p, C.POINTER(U32))
        self.wait = bind(k, "WaitForSingleObject", U32, HANDLE, U32)
        self.snapshot = bind(k, "CreateToolhelp32Snapshot", HANDLE, U32, U32)
        self.module_first = bind(k, "Module32FirstW", BOOL, HANDLE, C.POINTER(MODULEENTRY32W))
        self.module_next = bind(k, "Module32NextW", BOOL, HANDLE, C.POINTER(MODULEENTRY32W))
        self.thread_first = bind(k, "Thread32First", BOOL, HANDLE, C.POINTER(THREADENTRY32))
        self.thread_next = bind(k, "Thread32Next", BOOL, HANDLE, C.POINTER(THREADENTRY32))
        self.open_thread = bind(k, "OpenThread", HANDLE, U32, BOOL, U32)
        self.thread_pid = bind(k, "GetProcessIdOfThread", U32, HANDLE)
        self.current_pid = bind(k, "GetCurrentProcessId", U32)
        self.current_tid = bind(k, "GetCurrentThreadId", U32)
        self.current_process = bind(k, "GetCurrentProcess", HANDLE)
        self.duplicate = bind(k, "DuplicateHandle", BOOL, HANDLE, HANDLE, HANDLE,
                              C.POINTER(HANDLE), U32, BOOL, U32)
        self.virtual_query = bind(k, "VirtualQueryEx", SIZE, HANDLE, PTR,
                                  C.POINTER(MEMORY_BASIC_INFORMATION), SIZE)
        try:
            self.mapped_file_name = bind(k, "K32GetMappedFileNameW", U32,
                                         HANDLE, PTR, C.c_wchar_p, U32)
        except AttributeError:
            # Keep VirtualQueryEx available when file attribution is unavailable.
            self.mapped_file_name = None
        self.read_memory = bind(k, "ReadProcessMemory", BOOL, HANDLE, PTR, PTR, SIZE, C.POINTER(SIZE))
        self.suspend = bind(k, "SuspendThread", U32, HANDLE)
        self.resume = bind(k, "ResumeThread", U32, HANDLE)
        self.context = bind(k, "GetThreadContext", BOOL, HANDLE, C.POINTER(CONTEXT64))
        self.wow64 = bind(k, "IsWow64Process2", BOOL, HANDLE, C.POINTER(U16), C.POINTER(U16))
        self.process_information = bind(k, "GetProcessInformation", BOOL, HANDLE, I32, PTR, U32)
        self.file_size = bind(k, "GetFileSizeEx", BOOL, HANDLE, C.POINTER(I64))
        self.file_type = bind(k, "GetFileType", U32, HANDLE)
        self.file_pointer = bind(k, "SetFilePointerEx", BOOL, HANDLE, I64, C.POINTER(I64), U32)
        self.write_file = bind(k, "WriteFile", BOOL, HANDLE, PTR, U32, C.POINTER(U32), PTR)
        self.flush_file = bind(k, "FlushFileBuffers", BOOL, HANDLE)
        self.end_file = bind(k, "SetEndOfFile", BOOL, HANDLE)

