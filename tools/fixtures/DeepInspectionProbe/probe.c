/* BB-DEEP-001 owned, local-only Windows acceptance workload.
 * Build and execute only on a disposable GitHub-hosted Windows runner.
 * The breakpoint function runs only after the explicit "call" command.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static HANDLE stop_event, wait_event, data_file;
static HANDLE heartbeat_thread, wait_thread, io_thread;
static DWORD heartbeat_tid, wait_tid, io_tid;
static volatile LONG64 heartbeat, io_cycles, network_cycles;
static volatile LONG64 breakpoint_calls;
static unsigned char *known_memory;
static SOCKET tcp4_listener = INVALID_SOCKET, tcp4_client = INVALID_SOCKET;
static SOCKET tcp4_server = INVALID_SOCKET, udp4 = INVALID_SOCKET;
static SOCKET tcp6_listener = INVALID_SOCKET, tcp6_client = INVALID_SOCKET;
static SOCKET tcp6_server = INVALID_SOCKET, udp6 = INVALID_SOCKET;
static unsigned short tcp4_port, udp4_port, tcp6_port, udp6_port;
static PSECURITY_DESCRIPTOR original_process_security;

static int restore_process_read(void) {
    if (!original_process_security) return 1;
    if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION,
                                 original_process_security)) return 0;
    HeapFree(GetProcessHeap(), 0, original_process_security);
    original_process_security = NULL;
    return 1;
}

static int deny_process_read(void) {
    DWORD length = 0;
    PSECURITY_DESCRIPTOR denied = NULL;
    if (original_process_security) return 0;
    GetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, NULL, 0, &length);
    if (!length || length > 65536) return 0;
    original_process_security = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length);
    if (!original_process_security ||
        !GetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION,
                                 original_process_security, length, &length)) return 0;
    /* Only this disposable fixture object changes; no account or system policy.
     * Deny VM_READ to everyone, retain other rights for owner and SYSTEM.
     */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(D;;0x10;;;WD)(A;;GA;;;OW)(A;;GA;;;SY)", SDDL_REVISION_1, &denied, NULL)) return 0;
    if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, denied)) {
        LocalFree(denied);
        return 0;
    }
    LocalFree(denied);
    return 1;
}

__declspec(noinline) __declspec(dllexport)
unsigned long long bb_deep_breakpoint_probe(unsigned long long input) {
    volatile unsigned long long local = input * 17 + 11;
    InterlockedIncrement64(&breakpoint_calls);
    return local + 7;
}

static unsigned long long created(HANDLE object, int thread) {
    FILETIME start, exit_time, kernel, user;
    BOOL ok = thread ? GetThreadTimes(object, &start, &exit_time, &kernel, &user)
                     : GetProcessTimes(object, &start, &exit_time, &kernel, &user);
    if (!ok) return 0;
    return ((unsigned long long)start.dwHighDateTime << 32) | start.dwLowDateTime;
}

static DWORD WINAPI heartbeat_main(void *unused) {
    (void)unused;
    while (WaitForSingleObject(stop_event, 10) == WAIT_TIMEOUT)
        InterlockedIncrement64(&heartbeat);
    return 0;
}

__declspec(noinline) static DWORD WINAPI wait_main(void *unused) {
    HANDLE events[2] = {stop_event, wait_event};
    (void)unused;
    while (WaitForMultipleObjects(2, events, FALSE, 250) == WAIT_TIMEOUT) {}
    return 0;
}

static void timeout_socket(SOCKET s) {
    DWORD timeout = 300;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
}

static int tcp_pair(int family, SOCKET *listener, SOCKET *client,
                    SOCKET *server, unsigned short *port) {
    struct sockaddr_storage address;
    int length;
    memset(&address, 0, sizeof(address));
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        length = sizeof(*v6);
    }
    *listener = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (*listener == INVALID_SOCKET ||
        bind(*listener, (const struct sockaddr *)&address, length) != 0 ||
        getsockname(*listener, (struct sockaddr *)&address, &length) != 0 ||
        listen(*listener, 1) != 0) return 0;
    *port = family == AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port)
                             : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    *client = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (*client == INVALID_SOCKET ||
        connect(*client, (const struct sockaddr *)&address, length) != 0) return 0;
    *server = accept(*listener, NULL, NULL);
    if (*server == INVALID_SOCKET) return 0;
    timeout_socket(*client);
    timeout_socket(*server);
    return 1;
}

static int udp_endpoint(int family, SOCKET *value, unsigned short *port) {
    struct sockaddr_storage address;
    int length;
    memset(&address, 0, sizeof(address));
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        length = sizeof(*v6);
    }
    *value = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (*value == INVALID_SOCKET ||
        bind(*value, (const struct sockaddr *)&address, length) != 0 ||
        getsockname(*value, (struct sockaddr *)&address, &length) != 0) return 0;
    *port = family == AF_INET ? ntohs(((struct sockaddr_in *)&address)->sin_port)
                             : ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    timeout_socket(*value);
    return 1;
}

static int udp_roundtrip(SOCKET value) {
    struct sockaddr_storage address;
    int length = sizeof(address);
    char sent = 'Q', received = 0;
    if (getsockname(value, (struct sockaddr *)&address, &length) != 0) return 0;
    return sendto(value, &sent, 1, 0, (struct sockaddr *)&address, length) == 1 &&
           recvfrom(value, &received, 1, 0, NULL, NULL) == 1 && received == sent;
}

static int tcp_roundtrip(SOCKET client, SOCKET server) {
    char sent = 'B', received = 0;
    return send(client, &sent, 1, 0) == 1 && recv(server, &received, 1, 0) == 1 &&
           received == sent;
}

static DWORD WINAPI io_main(void *unused) {
    unsigned char data[4096], readback[4096];
    DWORD written, read;
    LARGE_INTEGER offset;
    (void)unused;
    memset(data, 0x5A, sizeof(data));
    offset.QuadPart = 0;
    while (WaitForSingleObject(stop_event, 50) == WAIT_TIMEOUT) {
        if (SetFilePointerEx(data_file, offset, NULL, FILE_BEGIN) &&
            WriteFile(data_file, data, sizeof(data), &written, NULL) &&
            written == sizeof(data) && FlushFileBuffers(data_file) &&
            SetFilePointerEx(data_file, offset, NULL, FILE_BEGIN) &&
            ReadFile(data_file, readback, sizeof(readback), &read, NULL) &&
            read == sizeof(readback) && memcmp(data, readback, sizeof(data)) == 0)
            InterlockedIncrement64(&io_cycles);
        else {
            SetEvent(stop_event);
            return 7;
        }
        if (tcp_roundtrip(tcp4_client, tcp4_server) &&
            tcp_roundtrip(tcp6_client, tcp6_server) &&
            udp_roundtrip(udp4) && udp_roundtrip(udp6))
            InterlockedIncrement64(&network_cycles);
        else {
            SetEvent(stop_event);
            return 8;
        }
    }
    return 0;
}

static void state(const char *kind) {
    unsigned int i;
    printf("{\"kind\":\"%s\",\"pid\":%lu,\"created_100ns\":%llu,"
           "\"buffer_address\":%llu,\"buffer_size\":64,\"buffer_hex\":\"",
           kind, GetCurrentProcessId(), created(GetCurrentProcess(), 0),
           (unsigned long long)(uintptr_t)known_memory);
    for (i = 0; i < 64; i++) printf("%02x", known_memory[i]);
    printf("\",\"function_address\":%llu,\"main_tid\":%lu,"
           "\"main_thread_created_100ns\":%llu,"
           "\"heartbeat_tid\":%lu,\"heartbeat_thread_created_100ns\":%llu,"
           "\"wait_tid\":%lu,\"wait_thread_created_100ns\":%llu,"
           "\"io_tid\":%lu,\"io_thread_created_100ns\":%llu,"
           "\"heartbeat\":%lld,\"io_cycles\":%lld,\"network_cycles\":%lld,"
           "\"breakpoint_calls\":%lld,"
           "\"tcp4_port\":%u,\"tcp6_port\":%u,\"udp4_port\":%u,\"udp6_port\":%u}\n",
           (unsigned long long)(uintptr_t)&bb_deep_breakpoint_probe,
           GetCurrentThreadId(), created(GetCurrentThread(), 1),
           heartbeat_tid, created(heartbeat_thread, 1), wait_tid,
           created(wait_thread, 1), io_tid, created(io_thread, 1),
           heartbeat, io_cycles, network_cycles, breakpoint_calls,
           tcp4_port, tcp6_port, udp4_port, udp6_port);
    fflush(stdout);
}

int wmain(int argc, wchar_t **argv) {
    WSADATA wsa;
    char command[64];
    HANDLE workers[3];
    SOCKET sockets[8];
    unsigned int i;
    if (argc != 2 || WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    wait_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    known_memory = (unsigned char *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    data_file = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (!stop_event || !wait_event || !known_memory || data_file == INVALID_HANDLE_VALUE) return 3;
    for (i = 0; i < 64; i++) known_memory[i] = (unsigned char)(i ^ 0x5A);
    if (!tcp_pair(AF_INET, &tcp4_listener, &tcp4_client, &tcp4_server, &tcp4_port) ||
        !tcp_pair(AF_INET6, &tcp6_listener, &tcp6_client, &tcp6_server, &tcp6_port) ||
        !udp_endpoint(AF_INET, &udp4, &udp4_port) ||
        !udp_endpoint(AF_INET6, &udp6, &udp6_port)) return 4;
    heartbeat_thread = CreateThread(NULL, 0, heartbeat_main, NULL, 0, &heartbeat_tid);
    wait_thread = CreateThread(NULL, 0, wait_main, NULL, 0, &wait_tid);
    io_thread = CreateThread(NULL, 0, io_main, NULL, 0, &io_tid);
    if (!heartbeat_thread || !wait_thread || !io_thread) return 5;
    state("ready");
    while (fgets(command, sizeof(command), stdin)) {
        command[strcspn(command, "\r\n")] = 0;
        if (!strcmp(command, "state")) state("state");
        else if (!strcmp(command, "call")) {
            unsigned long long result = bb_deep_breakpoint_probe(7);
            printf("{\"kind\":\"called\",\"result\":%llu,\"calls\":%lld}\n", result, breakpoint_calls);
            fflush(stdout);
        } else if (!strcmp(command, "stop")) break;
        else if (!strcmp(command, "deny_read") || !strcmp(command, "allow_read")) {
            int ok = !strcmp(command, "deny_read") ? deny_process_read() : restore_process_read();
            printf("{\"kind\":\"permissions\",\"ok\":%s,\"winerror\":%lu}\n",
                   ok ? "true" : "false", ok ? 0UL : GetLastError());
            fflush(stdout);
        }
        else {
            printf("{\"kind\":\"invalid_command\"}\n");
            fflush(stdout);
        }
    }
    SetEvent(stop_event);
    if (!restore_process_read()) return 9;
    workers[0] = heartbeat_thread; workers[1] = wait_thread; workers[2] = io_thread;
    if (WaitForMultipleObjects(3, workers, TRUE, 8000) != WAIT_OBJECT_0) return 6;
    state("stopped");
    for (i = 0; i < 3; i++) CloseHandle(workers[i]);
    sockets[0] = tcp4_listener; sockets[1] = tcp4_client; sockets[2] = tcp4_server; sockets[3] = udp4;
    sockets[4] = tcp6_listener; sockets[5] = tcp6_client; sockets[6] = tcp6_server; sockets[7] = udp6;
    for (i = 0; i < 8; i++) if (sockets[i] != INVALID_SOCKET) closesocket(sockets[i]);
    CloseHandle(data_file); CloseHandle(wait_event); CloseHandle(stop_event);
    VirtualFree(known_memory, 0, MEM_RELEASE);
    WSACleanup();
    return 0;
}
