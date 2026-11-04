/* Owned BB-WAVE-02 native oracles. Build/run only on GitHub-hosted Windows. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>

static CRITICAL_SECTION output_lock;
static HANDLE ready_event, wait_mutex, ui_thread;
static HWND ui_window;
static DWORD ui_tid;
static WCHAR root_path[MAX_PATH], dump_path[MAX_PATH];
static volatile LONG ui_waiting, burst_stop;
static int mutex_owned;
static unsigned long long created_100ns, frequency;

static unsigned long long filetime_value(FILETIME ft) {
    ULARGE_INTEGER value; value.LowPart = ft.dwLowDateTime; value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

static unsigned long long qpc(void) {
    LARGE_INTEGER value;
    if (!QueryPerformanceCounter(&value)) ExitProcess(91);
    return (unsigned long long)value.QuadPart;
}

static unsigned long long thread_created(HANDLE thread) {
    FILETIME created, exited, kernel, user;
    if (!GetThreadTimes(thread, &created, &exited, &kernel, &user)) return 0;
    return filetime_value(created);
}

static void emit(const char *format, ...) {
    va_list arguments;
    EnterCriticalSection(&output_lock);
    va_start(arguments, format); vprintf(format, arguments); va_end(arguments);
    putchar('\n'); fflush(stdout);
    LeaveCriticalSection(&output_lock);
}

static void state(const char *event) {
    emit("{\"event\":\"%s\",\"pid\":%lu,\"created_100ns\":%llu,"
         "\"control_tid\":%lu,\"control_thread_created_100ns\":%llu,"
         "\"ui_tid\":%lu,\"ui_thread_created_100ns\":%llu,\"hwnd\":%llu,"
         "\"qpc\":%llu,\"qpc_frequency\":%llu,\"ui_waiting\":%ld,\"mutex_owned\":%s}",
         event, GetCurrentProcessId(), created_100ns, GetCurrentThreadId(),
         thread_created(GetCurrentThread()), ui_tid, thread_created(ui_thread),
         (unsigned long long)(uintptr_t)ui_window, qpc(), frequency, ui_waiting,
         mutex_owned ? "true" : "false");
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    if (message == WM_APP + 1) {
        DWORD result;
        unsigned long long started = qpc();
        InterlockedExchange(&ui_waiting, 1);
        emit("{\"event\":\"freeze_enter\",\"pid\":%lu,\"created_100ns\":%llu,"
             "\"tid\":%lu,\"qpc\":%llu,\"qpc_frequency\":%llu}",
             GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started, frequency);
        result = WaitForSingleObject(wait_mutex, 15000);
        if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) ReleaseMutex(wait_mutex);
        InterlockedExchange(&ui_waiting, 0);
        emit("{\"event\":\"freeze_done\",\"pid\":%lu,\"tid\":%lu,"
             "\"start_qpc\":%llu,\"end_qpc\":%llu,\"wait_result\":%lu}",
             GetCurrentProcessId(), GetCurrentThreadId(), started, qpc(), result);
        return 0;
    }
    if (message == WM_CLOSE) { DestroyWindow(hwnd); return 0; }
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, message, wp, lp);
}

static DWORD WINAPI ui_main(LPVOID unused) {
    WNDCLASSW wc;
    MSG message;
    (void)unused;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = window_proc; wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"BLACKBOX_OWNED_WAVE02";
    if (!RegisterClassW(&wc)) { SetEvent(ready_event); return 20; }
    ui_window = CreateWindowExW(0, wc.lpszClassName, L"BLACK.BOX owned Wave02 fixture",
        WS_OVERLAPPEDWINDOW, 30, 30, 320, 180, NULL, NULL, wc.hInstance, NULL);
    if (!ui_window) { SetEvent(ready_event); return 21; }
    ShowWindow(ui_window, SW_SHOWNOACTIVATE);
    SetEvent(ready_event);
    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message); DispatchMessageW(&message);
    }
    return 0;
}

static void path_for(WCHAR *destination, const WCHAR *name) {
    if (swprintf_s(destination, MAX_PATH, L"%ls\\%ls", root_path, name) < 0) ExitProcess(92);
}

static int file_probe(void) {
    WCHAR share_path[MAX_PATH], denied_path[MAX_PATH], positive_path[MAX_PATH];
    HANDLE owner = INVALID_HANDLE_VALUE, attempt = INVALID_HANDLE_VALUE;
    BYTE *original = NULL;
    PSECURITY_DESCRIPTOR replacement = NULL;
    DWORD required = 0, original_flags, error, count = 0;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    unsigned long long started;
    char data[4096], readback[4096];
    int changed = 0, success = 0, acl_restored = 1;
    path_for(share_path, L"sharing.bin"); path_for(denied_path, L"denied.bin");
    path_for(positive_path, L"positive.bin");
    memset(data, 0x5A, sizeof(data));
    owner = CreateFileW(share_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (owner == INVALID_HANDLE_VALUE) goto cleanup;
    started = qpc(); SetLastError(0);
    attempt = CreateFileW(share_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error = attempt == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    emit("{\"event\":\"file_operation\",\"role\":\"sharing_violation\","
         "\"pid\":%lu,\"created_100ns\":%llu,\"tid\":%lu,"
         "\"start_qpc\":%llu,\"end_qpc\":%llu,\"winerror\":%lu}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started, qpc(), error);
    if (attempt != INVALID_HANDLE_VALUE) { CloseHandle(attempt); attempt = INVALID_HANDLE_VALUE; }
    if (error != ERROR_SHARING_VIOLATION) goto cleanup;
    CloseHandle(owner); owner = INVALID_HANDLE_VALUE;
    owner = CreateFileW(denied_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (owner == INVALID_HANDLE_VALUE) goto cleanup;
    CloseHandle(owner); owner = INVALID_HANDLE_VALUE;
    GetFileSecurityW(denied_path, DACL_SECURITY_INFORMATION, NULL, 0, &required);
    if (required < SECURITY_DESCRIPTOR_MIN_LENGTH || required > 65536) goto cleanup;
    original = (BYTE *)HeapAlloc(GetProcessHeap(), 0, required);
    if (!original || !GetFileSecurityW(denied_path, DACL_SECURITY_INFORMATION,
                                     original, required, &required)) goto cleanup;
    if (!GetSecurityDescriptorControl(original, &control, &revision)) goto cleanup;
    original_flags = DACL_SECURITY_INFORMATION | ((control & SE_DACL_PROTECTED) ?
        PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(D;;GW;;;WD)(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1,
            &replacement, NULL)) goto cleanup;
    if (!SetFileSecurityW(denied_path, DACL_SECURITY_INFORMATION |
                         PROTECTED_DACL_SECURITY_INFORMATION, replacement)) goto cleanup;
    changed = 1; acl_restored = 0; started = qpc(); SetLastError(0);
    attempt = CreateFileW(denied_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error = attempt == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    emit("{\"event\":\"file_operation\",\"role\":\"access_denied\","
         "\"pid\":%lu,\"created_100ns\":%llu,\"tid\":%lu,"
         "\"start_qpc\":%llu,\"end_qpc\":%llu,\"winerror\":%lu}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started, qpc(), error);
    if (attempt != INVALID_HANDLE_VALUE) { CloseHandle(attempt); attempt = INVALID_HANDLE_VALUE; }
    if (error != ERROR_ACCESS_DENIED) goto cleanup;
    if (!SetFileSecurityW(denied_path, original_flags, original)) goto cleanup;
    changed = 0; acl_restored = 1;
    owner = CreateFileW(positive_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (owner == INVALID_HANDLE_VALUE) goto cleanup;
    started = qpc();
    if (!WriteFile(owner, data, sizeof(data), &count, NULL) || count != sizeof(data) ||
        !FlushFileBuffers(owner) || SetFilePointer(owner, 0, NULL, FILE_BEGIN) != 0 ||
        !ReadFile(owner, readback, sizeof(readback), &count, NULL) ||
        count != sizeof(readback) || memcmp(data, readback, sizeof(data)) != 0) goto cleanup;
    emit("{\"event\":\"file_operation\",\"role\":\"positive_read_write\","
         "\"pid\":%lu,\"created_100ns\":%llu,\"tid\":%lu,"
         "\"start_qpc\":%llu,\"end_qpc\":%llu,\"winerror\":0,\"bytes\":%lu}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started, qpc(), count);
    success = 1;
cleanup:
    if (attempt != INVALID_HANDLE_VALUE) CloseHandle(attempt);
    if (owner != INVALID_HANDLE_VALUE) CloseHandle(owner);
    if (changed) {
        acl_restored = SetFileSecurityW(denied_path, original_flags, original) != 0;
        if (!acl_restored) success = 0;
    }
    if (replacement) LocalFree(replacement);
    if (original) HeapFree(GetProcessHeap(), 0, original);
    emit("{\"event\":\"file_done\",\"ok\":%s,\"acl_restored\":%s}",
         success ? "true" : "false", acl_restored ? "true" : "false");
    return success;
}

static DWORD WINAPI cpu_main(LPVOID parameter) {
    volatile unsigned long long value = (unsigned long long)(uintptr_t)parameter + 1;
    while (!burst_stop) { unsigned index; for (index = 0; index < 10000; ++index) value = value * 1664525 + 1013904223; }
    return (DWORD)(value & 0x7fffffff);
}

static int burst_probe(void) {
    HANDLE workers[4], file;
    WCHAR path[MAX_PATH];
    BYTE *memory;
    unsigned index, started_workers = 0;
    BOOL workers_exited = FALSE;
    DWORD written;
    unsigned long long started = qpc(), bytes = 0;
    size_t allocated = 64u * 1024u * 1024u;
    path_for(path, L"burst.bin");
    memory = (BYTE *)VirtualAlloc(NULL, allocated, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 0;
    for (index = 0; index < allocated; index += 4096) memory[index] = (BYTE)(index / 4096);
    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (file == INVALID_HANDLE_VALUE) { VirtualFree(memory, 0, MEM_RELEASE); return 0; }
    InterlockedExchange(&burst_stop, 0);
    for (index = 0; index < 4; ++index) {
        workers[index] = CreateThread(NULL, 0, cpu_main, (LPVOID)(uintptr_t)index, 0, NULL);
        if (!workers[index]) break;
        ++started_workers;
    }
    emit("{\"event\":\"burst_begin\",\"pid\":%lu,\"created_100ns\":%llu,"
         "\"tid\":%lu,\"start_qpc\":%llu,\"allocated_bytes\":%llu}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started,
         (unsigned long long)allocated);
    while (qpc() - started < frequency * 6) {
        if (!WriteFile(file, memory, 65536, &written, NULL) || written != 65536) break;
        bytes += written;
        if (bytes >= 16u * 1024u * 1024u) SetFilePointer(file, 0, NULL, FILE_BEGIN);
        Sleep(15);
    }
    InterlockedExchange(&burst_stop, 1);
    if (started_workers) workers_exited =
        WaitForMultipleObjects(started_workers, workers, TRUE, 5000) == WAIT_OBJECT_0;
    for (index = 0; index < started_workers; ++index) CloseHandle(workers[index]);
    FlushFileBuffers(file); CloseHandle(file); VirtualFree(memory, 0, MEM_RELEASE);
    emit("{\"event\":\"burst_done\",\"pid\":%lu,\"created_100ns\":%llu,"
         "\"tid\":%lu,\"start_qpc\":%llu,\"end_qpc\":%llu,"
         "\"allocated_bytes\":%llu,\"io_bytes\":%llu,\"worker_threads\":%u,"
         "\"worker_exit_verified\":%s}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), started, qpc(),
         (unsigned long long)allocated, bytes, started_workers, workers_exited ? "true" : "false");
    return started_workers == 4 && workers_exited && bytes > 0;
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *pointers) {
    HANDLE output;
    BOOL ok = FALSE;
    MINIDUMP_EXCEPTION_INFORMATION information;
    information.ThreadId = GetCurrentThreadId(); information.ExceptionPointers = pointers;
    information.ClientPointers = FALSE;
    output = CreateFileW(dump_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (output != INVALID_HANDLE_VALUE) {
        ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), output,
            (MINIDUMP_TYPE)(MiniDumpWithThreadInfo | MiniDumpWithFullMemoryInfo |
                            MiniDumpWithUnloadedModules), &information, NULL, NULL);
        FlushFileBuffers(output); CloseHandle(output);
    }
    emit("{\"event\":\"crash_dump\",\"pid\":%lu,\"created_100ns\":%llu,"
         "\"tid\":%lu,\"qpc\":%llu,\"exception_code\":%lu,"
         "\"exception_address\":%llu,\"dump_written\":%s}",
         GetCurrentProcessId(), created_100ns, GetCurrentThreadId(), qpc(),
         pointers->ExceptionRecord->ExceptionCode,
         (unsigned long long)(uintptr_t)pointers->ExceptionRecord->ExceptionAddress,
         ok ? "true" : "false");
    return EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) static void wave_crash_leaf(volatile BYTE *page) {
    volatile char private_marker[] = "BLACKBOX_WAVE02_DUMP_PRIVATE_CONTENT";
    *page = (BYTE)private_marker[0];
}
__declspec(noinline) static void wave_crash_middle(volatile BYTE *page) { wave_crash_leaf(page); }
__declspec(noinline) static void wave_crash_entry(void) {
    volatile BYTE *page = (volatile BYTE *)VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (!page) ExitProcess(93);
    wave_crash_middle(page);
}

int wmain(int argc, WCHAR **argv) {
    FILETIME created, exited, kernel, user;
    LARGE_INTEGER value;
    char command[64];
    int result = 0;
    if (argc != 3 || wcslen(argv[1]) >= MAX_PATH || wcslen(argv[2]) >= MAX_PATH) return 2;
    wcscpy_s(root_path, MAX_PATH, argv[1]); wcscpy_s(dump_path, MAX_PATH, argv[2]);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SetUnhandledExceptionFilter(crash_filter);
    InitializeCriticalSection(&output_lock);
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) ||
        !QueryPerformanceFrequency(&value)) return 3;
    created_100ns = filetime_value(created); frequency = (unsigned long long)value.QuadPart;
    ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    wait_mutex = CreateMutexW(NULL, FALSE, NULL);
    ui_thread = CreateThread(NULL, 0, ui_main, NULL, 0, &ui_tid);
    if (!ready_event || !wait_mutex || !ui_thread ||
        WaitForSingleObject(ready_event, 10000) != WAIT_OBJECT_0 || !ui_window) return 4;
    state("ready");
    while (fgets(command, sizeof(command), stdin)) {
        command[strcspn(command, "\r\n")] = 0;
        if (!strcmp(command, "state")) state("state");
        else if (!strcmp(command, "freeze")) {
            if (mutex_owned || WaitForSingleObject(wait_mutex, 0) != WAIT_OBJECT_0) { result = 5; break; }
            mutex_owned = 1;
            if (!PostMessageW(ui_window, WM_APP + 1, 0, 0)) { result = 6; break; }
        } else if (!strcmp(command, "release")) {
            if (!mutex_owned || !ReleaseMutex(wait_mutex)) { result = 7; break; }
            mutex_owned = 0;
        } else if (!strcmp(command, "file")) {
            if (!file_probe()) { result = 8; break; }
        } else if (!strcmp(command, "burst")) {
            if (!burst_probe()) { result = 9; break; }
        } else if (!strcmp(command, "crash")) wave_crash_entry();
        else if (!strcmp(command, "stop")) break;
        else { result = 10; break; }
    }
    if (mutex_owned) { ReleaseMutex(wait_mutex); mutex_owned = 0; }
    PostMessageW(ui_window, WM_CLOSE, 0, 0);
    if (WaitForSingleObject(ui_thread, 8000) != WAIT_OBJECT_0) result = 11;
    CloseHandle(ui_thread); CloseHandle(wait_mutex); CloseHandle(ready_event);
    emit("{\"event\":\"normal_exit\",\"pid\":%lu,\"exit_code\":%d,\"cleanup_complete\":%s}",
         GetCurrentProcessId(), result, result == 0 ? "true" : "false");
    DeleteCriticalSection(&output_lock);
    return result;
}
