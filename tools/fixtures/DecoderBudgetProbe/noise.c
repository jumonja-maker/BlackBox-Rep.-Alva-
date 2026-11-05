/* CI-only real Win32 event handoffs. No target attachment or foreign actions.
 * Build/run only on a disposable GitHub-hosted Windows x64 runner.
 * The decoder's stack depth, events and budgets are never modified here.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#ifndef NOISE_SOURCE_SHA256
#error The checked builder must provide the actual C source SHA-256.
#endif
#if !defined(_M_X64)
#error This disposable fixture requires native Windows x64.
#endif

#define PAIRS 8
#define WORKERS (2 * PAIRS)
#define TTL_SECONDS 210
#define PATH_CAP 32768
#define JSON_CAP 32768
#define MAX_PROGRESS 841

typedef struct Worker {
    HANDLE mine, other, thread;
    DWORD tid;
    unsigned long long created;
    volatile LONG64 handoffs;
    LONG64 begin_qpc, end_qpc;
    int boost_disabled_before, boost_disabled_after;
    int relative_priority_before, relative_priority_after;
    int boost_before_observed, boost_after_observed;
    int priority_before_observed, priority_after_observed;
    int boost_control_verified;
} Worker;

static Worker workers[WORKERS];
static HANDLE events[WORKERS];
static volatile LONG stopping, released, ready_count, error_count;
static const char *errors[32];
static wchar_t output_root[PATH_CAP];
static char executable_sha256[65];
static DWORD process_id;
static unsigned long long process_created;
static LONG64 frequency, begin_qpc, end_qpc;
static unsigned event_created, thread_created, event_closed, thread_closed;
static int stop_requested, all_joined;
static int receipt_io_failed;
static char json_buffer[JSON_CAP];
static size_t json_used;
static const char *thread_boost_policy = "INHERITED";
static int disable_worker_boost;

static void fail(const char *code) {
    LONG slot = InterlockedIncrement(&error_count) - 1;
    if (slot >= 0 && slot < 32) errors[slot] = code;
    InterlockedExchange(&stopping, 1);
}

static LONG64 qpc(void) {
    LARGE_INTEGER value;
    if (!QueryPerformanceCounter(&value)) {
        fail("NATIVE_NOISE_QPC_FAILED");
        return 0;
    }
    return value.QuadPart;
}

static unsigned long long creation(HANDLE handle, int thread) {
    FILETIME first, last, kernel, user;
    BOOL ok = thread ? GetThreadTimes(handle, &first, &last, &kernel, &user)
                     : GetProcessTimes(handle, &first, &last, &kernel, &user);
    if (!ok) {
        fail("NATIVE_NOISE_CREATION_TIME_FAILED");
        return 0;
    }
    return ((unsigned long long)first.dwHighDateTime << 32) | first.dwLowDateTime;
}

static int source_hash_valid(void) {
    const char *hash = NOISE_SOURCE_SHA256;
    size_t i;
    if (strlen(hash) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((hash[i] >= '0' && hash[i] <= '9') || (hash[i] >= 'a' && hash[i] <= 'f')))
            return 0;
    return 1;
}

static int self_hash(void) {
    wchar_t path[PATH_CAP];
    HANDLE file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD object_bytes = 0, returned = 0, received = 0, length;
    LARGE_INTEGER before_size, after_size;
    unsigned long long total = 0;
    unsigned char digest[32], block[65536];
    int ok = 0;
    size_t i;
    length = GetModuleFileNameW(NULL, path, PATH_CAP);
    if (!length || length >= PATH_CAP) goto done;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    if (!GetFileSizeEx(file, &before_size) || before_size.QuadPart <= 0 ||
        before_size.QuadPart > 32LL * 1024 * 1024) goto done;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) goto done;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_bytes,
                         (ULONG)sizeof(object_bytes), &returned, 0) < 0 ||
        returned != sizeof(object_bytes) || !object_bytes || object_bytes > 65536) goto done;
    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_bytes);
    if (!object) goto done;
    if (BCryptCreateHash(algorithm, &hash, object, object_bytes, NULL, 0, 0) < 0) goto done;
    for (;;) {
        if (!ReadFile(file, block, (DWORD)sizeof(block), &received, NULL)) goto done;
        if (!received) break;
        total += received;
        if (total > (unsigned long long)before_size.QuadPart) goto done;
        if (BCryptHashData(hash, block, received, 0) < 0) goto done;
    }
    if (total != (unsigned long long)before_size.QuadPart || !GetFileSizeEx(file, &after_size) ||
        after_size.QuadPart != before_size.QuadPart) goto done;
    if (BCryptFinishHash(hash, digest, (ULONG)sizeof(digest), 0) < 0) goto done;
    for (i = 0; i < sizeof(digest); ++i)
        sprintf_s(executable_sha256 + 2 * i, 3, "%02x", (unsigned)digest[i]);
    executable_sha256[64] = '\0';
    ok = 1;
done:
    if (hash && BCryptDestroyHash(hash) < 0) ok = 0;
    if (algorithm && BCryptCloseAlgorithmProvider(algorithm, 0) < 0) ok = 0;
    if (object && !HeapFree(GetProcessHeap(), 0, object)) ok = 0;
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file)) ok = 0;
    return ok;
}

static void append(const char *format, ...) {
    va_list args;
    int count;
    if (json_used >= JSON_CAP) return;
    va_start(args, format);
    count = vsnprintf_s(json_buffer + json_used, JSON_CAP - json_used, _TRUNCATE, format, args);
    va_end(args);
    if (count < 0) {
        json_used = JSON_CAP;
        return;
    }
    json_used += (size_t)count;
}

static void common(const char *schema) {
    json_used = 0;
    append("{\"schema\":\"%s\",\"implementation\":\"NATIVE_WIN32\","
           "\"expected_native_handles\":32,\"ttl_seconds\":%u,\"progress_limit\":%u,"
           "\"pid\":%lu,\"created_100ns\":\"%llu\","
           "\"source_sha256\":\"%s\",\"executable_sha256\":\"%s\","
           "\"qpc_frequency_hz\":%lld,\"thread_boost_policy\":\"%s\","
           "\"thread_boost_observation_scope\":\"OWNED_WORKERS_BEFORE_READY_RELEASE_CACHED_NOT_CONTINUOUS\"",
           schema, (unsigned)TTL_SECONDS, (unsigned)MAX_PROGRESS,
           (unsigned long)process_id, process_created,
           NOISE_SOURCE_SHA256, executable_sha256, frequency, thread_boost_policy);
}

static void worker_boost_json(const Worker *worker) {
    append(",\"boost_disabled_before\":%s,\"boost_disabled_after\":%s,",
           worker->boost_before_observed ? (worker->boost_disabled_before ? "true" : "false") : "null",
           worker->boost_after_observed ? (worker->boost_disabled_after ? "true" : "false") : "null");
    append("\"relative_priority_before\":");
    if (worker->priority_before_observed) append("%d", worker->relative_priority_before);
    else append("null");
    append(",\"relative_priority_after\":");
    if (worker->priority_after_observed) append("%d", worker->relative_priority_after);
    else append("null");
    append(",\"boost_control_verified\":%s", worker->boost_control_verified ? "true" : "false");
}

static int configure_worker_boost(Worker *worker) {
    BOOL before = FALSE, after = FALSE;
    int relative;
    /* Candidate diagnostic control, not equivalent legacy interference or
     * evidence of the cause of an earlier application deadline. Only these
     * already-owned worker handles are queried/changed, before work release.
     */
    if (!GetThreadPriorityBoost(worker->thread, &before)) {
        fail("NATIVE_NOISE_BOOST_BEFORE_QUERY_FAILED"); return 0;
    }
    worker->boost_disabled_before = before != FALSE;
    worker->boost_before_observed = 1;
    relative = GetThreadPriority(worker->thread);
    if (relative == THREAD_PRIORITY_ERROR_RETURN) {
        fail("NATIVE_NOISE_PRIORITY_BEFORE_QUERY_FAILED"); return 0;
    }
    worker->relative_priority_before = relative;
    worker->priority_before_observed = 1;
    if (disable_worker_boost && !SetThreadPriorityBoost(worker->thread, TRUE)) {
        fail("NATIVE_NOISE_BOOST_DISABLE_FAILED"); return 0;
    }
    if (!GetThreadPriorityBoost(worker->thread, &after)) {
        fail("NATIVE_NOISE_BOOST_AFTER_QUERY_FAILED"); return 0;
    }
    worker->boost_disabled_after = after != FALSE;
    worker->boost_after_observed = 1;
    relative = GetThreadPriority(worker->thread);
    if (relative == THREAD_PRIORITY_ERROR_RETURN) {
        fail("NATIVE_NOISE_PRIORITY_AFTER_QUERY_FAILED"); return 0;
    }
    worker->relative_priority_after = relative;
    worker->priority_after_observed = 1;
    if (worker->relative_priority_before != worker->relative_priority_after) {
        fail("NATIVE_NOISE_BASE_PRIORITY_CHANGED"); return 0;
    }
    if (disable_worker_boost ? !worker->boost_disabled_after :
        worker->boost_disabled_before != worker->boost_disabled_after) {
        fail(disable_worker_boost ? "NATIVE_NOISE_BOOST_DISABLE_UNCONFIRMED" :
                                   "NATIVE_NOISE_INHERITED_BOOST_CHANGED");
        return 0;
    }
    worker->boost_control_verified = 1;
    return 1;
}

static void worker_json(int final) {
    unsigned i;
    append(",\"workers\":[");
    for (i = 0; i < WORKERS; ++i) {
        Worker *worker = &workers[i];
        append("%s{\"tid\":%lu,\"created_100ns\":\"%llu\",\"handoffs\":%lld,"
               "\"begin_qpc\":%lld", i ? "," : "", (unsigned long)worker->tid,
               worker->created, InterlockedCompareExchange64(&worker->handoffs, 0, 0), worker->begin_qpc);
        if (final) append(",\"end_qpc\":%lld", worker->end_qpc);
        worker_boost_json(worker);
        append("}");
    }
    append("]");
}

static int receipt(const wchar_t *name) {
    wchar_t destination[PATH_CAP], temporary[PATH_CAP];
    HANDLE file;
    DWORD written = 0;
    int ok;
    if (json_used >= JSON_CAP ||
        _snwprintf_s(destination, PATH_CAP, _TRUNCATE, L"%s\\%s", output_root, name) < 0 ||
        _snwprintf_s(temporary, PATH_CAP, _TRUNCATE, L"%s.tmp", destination) < 0) {
        receipt_io_failed = 1;
        return 0;
    }
    /* Every target is fresh, immutable and closed before atomic publication.
     * No overwrite flag and no deletion of an uncertain/replaced file.
     */
    file = CreateFileW(temporary, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        receipt_io_failed = 1;
        return 0;
    }
    ok = WriteFile(file, json_buffer, (DWORD)json_used, &written, NULL) && written == json_used;
    if (!FlushFileBuffers(file)) ok = 0;
    if (!CloseHandle(file)) ok = 0;
    if (ok && !MoveFileExW(temporary, destination, MOVEFILE_WRITE_THROUGH)) ok = 0;
    if (!ok) receipt_io_failed = 1;
    return ok;
}

static DWORD WINAPI worker_main(void *argument) {
    Worker *worker = (Worker *)argument;
    worker->tid = GetCurrentThreadId();
    worker->created = creation(GetCurrentThread(), 1);
    worker->begin_qpc = qpc();
    InterlockedIncrement(&ready_count);
    while (!InterlockedCompareExchange(&released, 0, 0) &&
           !InterlockedCompareExchange(&stopping, 0, 0)) Sleep(1);
    while (!InterlockedCompareExchange(&stopping, 0, 0)) {
        DWORD answer = WaitForSingleObject(worker->mine, 250);
        if (InterlockedCompareExchange(&stopping, 0, 0)) break;
        if (answer == WAIT_TIMEOUT) continue;
        if (answer != WAIT_OBJECT_0) {
            fail("NATIVE_NOISE_WAIT_FAILED");
            break;
        }
        if (!SetEvent(worker->other)) {
            fail("NATIVE_NOISE_HANDOFF_FAILED");
            break;
        }
        InterlockedIncrement64(&worker->handoffs);
    }
    worker->end_qpc = qpc();
    return 0;
}

static int stop_file(void) {
    wchar_t path[PATH_CAP];
    DWORD attributes, error;
    if (_snwprintf_s(path, PATH_CAP, _TRUNCATE, L"%s\\stop.request", output_root) < 0) {
        fail("NATIVE_NOISE_STOP_PATH_FAILED");
        return 0;
    }
    SetLastError(ERROR_SUCCESS);
    attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            fail("NATIVE_NOISE_STOP_REQUEST_TYPE_FAILED");
        else return 1;
    } else {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) fail("NATIVE_NOISE_STOP_REQUEST_READ_FAILED");
    }
    return 0;
}

static int run(void) {
    unsigned i, sequence = 0;
    ULONGLONG deadline, next_progress;
    HANDLE thread_handles[WORKERS];
    LARGE_INTEGER hz;
    int created_joined;
    if (!QueryPerformanceFrequency(&hz) || hz.QuadPart <= 0) return 1;
    frequency = hz.QuadPart;
    process_id = GetCurrentProcessId();
    process_created = creation(GetCurrentProcess(), 0);
    if (!process_created || !self_hash()) return 1;
    for (i = 0; i < WORKERS; ++i) {
        events[i] = CreateEventW(NULL, FALSE, (i % 2) == 0, NULL);
        if (!events[i]) { fail("NATIVE_NOISE_EVENT_CREATE_FAILED"); goto cleanup; }
        ++event_created;
    }
    for (i = 0; i < WORKERS; ++i) {
        workers[i].mine = events[i];
        workers[i].other = events[i ^ 1];
        workers[i].thread = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (!workers[i].thread) { fail("NATIVE_NOISE_THREAD_CREATE_FAILED"); goto cleanup; }
        thread_handles[thread_created++] = workers[i].thread;
    }
    deadline = GetTickCount64() + 10000;
    while (InterlockedCompareExchange(&ready_count, 0, 0) != WORKERS &&
           !InterlockedCompareExchange(&error_count, 0, 0) && GetTickCount64() < deadline) Sleep(1);
    if (InterlockedCompareExchange(&ready_count, 0, 0) != WORKERS || error_count) {
        fail("NATIVE_NOISE_READY_BARRIER_FAILED"); goto cleanup;
    }
    for (i = 0; i < WORKERS; ++i)
        if (!configure_worker_boost(&workers[i])) goto cleanup;
    begin_qpc = qpc();
    common("blackbox.scheduler-noise/1");
    append(",\"status\":\"READY\",\"pairs\":8,\"begin_qpc\":%lld", begin_qpc);
    worker_json(0); append("}\n");
    if (!receipt(L"ready.json")) { fail("NATIVE_NOISE_READY_WRITE_FAILED"); goto cleanup; }
    /* Exactly the fixed 210-second workload TTL starts after READY publication. */
    deadline = GetTickCount64() + TTL_SECONDS * 1000ULL;
    next_progress = GetTickCount64();
    InterlockedExchange(&released, 1);
    while (!error_count && GetTickCount64() < deadline) {
        ULONGLONG now;
        stop_requested = stop_file();
        if (stop_requested || error_count) break;
        now = GetTickCount64();
        if (now >= next_progress) {
            LONG64 first, last, counts[WORKERS], total = 0;
            wchar_t name[64];
            if (++sequence > MAX_PROGRESS) { fail("NATIVE_NOISE_PROGRESS_LIMIT"); break; }
            first = qpc();
            for (i = 0; i < WORKERS; ++i) counts[i] = InterlockedCompareExchange64(&workers[i].handoffs, 0, 0);
            last = qpc();
            common("blackbox.scheduler-noise-progress/1");
            append(",\"sequence\":%u,\"qpc\":%lld,\"sample_begin_qpc\":%lld,"
                   "\"sample_end_qpc\":%lld,\"workers\":[", sequence, last, first, last);
            for (i = 0; i < WORKERS; ++i) {
                total += counts[i];
                append("%s{\"tid\":%lu,\"handoffs\":%lld", i ? "," : "",
                       (unsigned long)workers[i].tid, counts[i]);
                worker_boost_json(&workers[i]);
                append("}");
            }
            append("],\"total_handoffs\":%lld}\n", total);
            if (_snwprintf_s(name, 64, _TRUNCATE, L"progress-%04u.json", sequence) < 0 || !receipt(name)) {
                fail("NATIVE_NOISE_PROGRESS_WRITE_FAILED"); break;
            }
            next_progress = GetTickCount64() + 250;
        }
        Sleep(20);
    }
    if (!stop_requested && !error_count) fail("NATIVE_NOISE_TTL_EXPIRED");
cleanup:
    InterlockedExchange(&stopping, 1);
    InterlockedExchange(&released, 1);
    for (i = 0; i < event_created; ++i)
        if (!SetEvent(events[i])) fail("NATIVE_NOISE_RELEASE_FAILED");
    /* One shared three-second deadline, never three seconds per worker. */
    deadline = GetTickCount64() + 3000;
    created_joined = 1;
    for (i = 0; i < thread_created; ++i) {
        ULONGLONG now = GetTickCount64();
        DWORD remaining = now < deadline ? (DWORD)(deadline - now) : 0;
        if (WaitForSingleObject(thread_handles[i], remaining) != WAIT_OBJECT_0) {
            created_joined = 0; fail("NATIVE_NOISE_THREAD_JOIN_FAILED");
        }
    }
    all_joined = thread_created == WORKERS && created_joined;
    /* All created workers must be joined before either class of handle closes. */
    if (created_joined) {
        for (i = 0; i < thread_created; ++i)
            if (CloseHandle(thread_handles[i])) ++thread_closed;
            else fail("NATIVE_NOISE_THREAD_HANDLE_CLOSE_FAILED");
        for (i = 0; i < event_created; ++i)
            if (CloseHandle(events[i])) ++event_closed;
            else fail("NATIVE_NOISE_EVENT_HANDLE_CLOSE_FAILED");
    }
    end_qpc = qpc();
    if (all_joined)
        for (i = 0; i < WORKERS; ++i)
            if (!workers[i].created || workers[i].begin_qpc >= workers[i].end_qpc ||
                InterlockedCompareExchange64(&workers[i].handoffs, 0, 0) <= 0)
                fail("NATIVE_NOISE_REAL_WORK_MISSING");
    common("blackbox.scheduler-noise/1");
    append(",\"status\":\"%s\",\"pairs\":8,\"begin_qpc\":%lld,\"end_qpc\":%lld,"
           "\"stop_requested\":%s,\"all_threads_joined\":%s,"
           "\"native_handle_scope\":\"EVENT_AND_WORKER_THREAD_HANDLES\","
           "\"native_handles_created\":%u,\"native_handles_closed\":%u,"
           "\"event_handles_created\":%u,\"event_handles_closed\":%u,"
           "\"thread_handles_created\":%u,\"thread_handles_closed\":%u,"
           "\"cleanup_required\":%s,\"errors\":[",
           !error_count && !receipt_io_failed && stop_requested && all_joined &&
           event_closed == WORKERS && thread_closed == WORKERS ? "COMPLETED" : "FAILED",
           begin_qpc, end_qpc, stop_requested ? "true" : "false", all_joined ? "true" : "false",
           event_created + thread_created, event_closed + thread_closed,
           event_created, event_closed, thread_created, thread_closed,
           !receipt_io_failed && created_joined && event_closed == event_created &&
           thread_closed == thread_created ? "false" : "true");
    for (i = 0; i < (unsigned)error_count && i < 32; ++i)
        append("%s\"%s\"", i ? "," : "", errors[i] ? errors[i] : "NATIVE_NOISE_UNKNOWN_FAILURE");
    append("]"); worker_json(1); append("}\n");
    if (!receipt(L"oracle.json")) return 1;
    return !error_count && !receipt_io_failed && stop_requested && all_joined &&
           event_closed == WORKERS && thread_closed == WORKERS ? 0 : 1;
}

int wmain(int argc, wchar_t **argv) {
    wchar_t actions[16], environment[32];
    DWORD a = GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16);
    DWORD e = GetEnvironmentVariableW(L"RUNNER_ENVIRONMENT", environment, 32);
    if ((argc != 3 && argc != 5) || wcscmp(argv[1], L"--output") != 0 || !a || a >= 16 || !e || e >= 32 ||
        wcscmp(actions, L"true") != 0 || wcscmp(environment, L"github-hosted") != 0 ||
        !source_hash_valid() || !argv[2][0] || wcslen(argv[2]) >= PATH_CAP - 64) return 2;
    if (argc == 5) {
        if (wcscmp(argv[3], L"--thread-boost-policy") != 0) return 2;
        if (wcscmp(argv[4], L"DISABLED") == 0) {
            disable_worker_boost = 1;
            thread_boost_policy = "DISABLED";
        } else if (wcscmp(argv[4], L"INHERITED") != 0) return 2;
    }
    if (wcscpy_s(output_root, PATH_CAP, argv[2]) != 0 || !CreateDirectoryW(output_root, NULL)) return 2;
    return run();
}
