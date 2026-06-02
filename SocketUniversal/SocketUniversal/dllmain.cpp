// NetworkHookSample_Ultimate_Advanced_Full.cpp
// Educational / Debugging only - Comprehensive network monitoring with tracking

#include "pch.h"

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <winhttp.h>
#include <wininet.h>
#include <sspi.h>
#include <schannel.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET
#define WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET 114
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "MinHook.h"

// ===================================================================
// Config / State
// ===================================================================

struct RuntimeConfig {
    bool dumpData = true;
    bool logHttpHeaders = true;
    bool console = true;
    bool redact = false;
    bool jsonl = true;
    bool namedPipe = true;
    bool consoleColor = true;
    bool callStack = true;
    bool scriptFileCapture = true;
    bool scriptExportScan = true;
    bool scriptStringScan = true;
    bool webSocketCapture = true;
    bool webSocketFrameScan = true;
    bool graalProbes = false;
    bool loggingEnabled = true;
    int maxDumpBytes = 4096; // Set SOCKETUNIVERSAL_MAX_DUMP_BYTES=0 for no cap.
    int maxCallStackFrames = 8;
    int maxScriptExportLogs = 256;
    int maxScriptStringLogs = 128;
    int maxMappedScriptPreviewBytes = 65536;
    int maxWebSocketFramesPerBuffer = 16;
    int maxWebSocketFramePreviewBytes = 65536;
    int maxGraalBytecodeBytes = 1048576;
    unsigned long long rotateBytes = 10ull * 1024ull * 1024ull;
    int rotateFiles = 5;
    DWORD threadFilter = 0;
    std::string processFilter;
    std::string graalModuleFilter = "MyGame.dll";
    std::string logPath;
    std::string jsonlPath;
    std::string pipeName = R"(\\.\pipe\SocketUniversal)";
    uintptr_t graalDecryptScriptRva = 0x5B7454;
    uintptr_t graalExecScriptRva = 0x7C3894;
    uintptr_t graalBindBytecodeRva = 0x84FFC0;
    uintptr_t graalEventCallRva = 0x8132C8;
    uintptr_t graalFindObjectRva = 0x6614E4;
    uintptr_t graalFindInTableRva = 0x5C2608;
    uintptr_t graalExecEventRva = 0x84C254;
    uintptr_t graalOpCallRva = 0x82E11C;
    uintptr_t graalLookupFunctionRva = 0x811458;
    uintptr_t graalResolveVariableRva = 0x826878;
    uintptr_t graalGlobalContextRva = 0x920630;
    uintptr_t graalXorKeyRva = 0x91DDEC;
};

struct HttpHandleInfo {
    std::string kind;
    std::string host;
    INTERNET_PORT port = 0;
    std::string method;
    std::string path;
    bool secure = false;
    bool webSocketUpgrade = false;
};

struct PayloadPreview {
    std::string text;
    std::string hex;
    std::string scriptKind;
    size_t previewBytes = 0;
    bool textLike = false;
    bool truncated = false;
    bool redacted = false;
};

struct EndpointParts {
    std::string server;
    std::string port;
};

struct CaptureContext {
    std::string returnSite;
    std::vector<std::string> callStack;
    std::string scriptHint;
};

struct OverlappedOperation {
    std::string api;
    std::string endpoint;
    SOCKET socket = INVALID_SOCKET;
    bool inbound = false;
    std::vector<WSABUF> buffers;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine = nullptr;
};

struct FileHandleInfo {
    std::string path;
    std::string scriptKind;
    unsigned long long fileSize = 0;
    unsigned long long totalRead = 0;
};

struct MappingInfo {
    std::string path;
    std::string scriptKind;
    unsigned long long fileSize = 0;
};

struct ViewInfo {
    std::string path;
    std::string scriptKind;
    SIZE_T viewSize = 0;
};

static RuntimeConfig g_Config;
static HMODULE g_Module = nullptr;
static FILE* g_LogFile = nullptr;
static FILE* g_JsonlFile = nullptr;
static HANDLE g_Pipe = INVALID_HANDLE_VALUE;
static bool g_PipeConnected = false;
static WORD g_DefaultConsoleAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static std::mutex g_LogMutex;
static std::mutex g_StateMutex;
static std::mutex g_DynamicHookMutex;
static std::atomic<bool> g_MinHookInitialized{ false };
static std::atomic<bool> g_HooksEnabled{ false };
static std::atomic<bool> g_ShuttingDown{ false };

static std::unordered_map<SOCKET, std::string> g_SocketToHost;
static std::unordered_map<HINTERNET, HttpHandleInfo> g_HandleInfo;
static std::unordered_map<HANDLE, FileHandleInfo> g_FileInfo;
static std::unordered_map<HANDLE, MappingInfo> g_MappingInfo;
static std::unordered_map<LPCVOID, ViewInfo> g_ViewInfo;
static std::unordered_map<LPWSAOVERLAPPED, OverlappedOperation> g_OverlappedOps;
static std::unordered_set<SOCKET> g_WebSocketSockets;
static std::unordered_set<void*> g_OpenSslWebSocketContexts;
static std::unordered_set<std::string> g_SchannelWebSocketContexts;
static std::unordered_set<LPVOID> g_DynamicHookTargets;
static std::unordered_set<HMODULE> g_ScriptScannedModules;
static std::unordered_set<HMODULE> g_GraalProbeModules;
static thread_local int g_HookDepth = 0;

void LogEvent(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    long long bytes,
    const std::string& status = {},
    const std::string& detail = {},
    const void* payloadData = nullptr,
    size_t payloadLength = 0);

// ===================================================================
// Original Function Pointers
// ===================================================================

// Winsock
static int (WINAPI* Real_connect)(SOCKET, const sockaddr*, int) = nullptr;
static int (WINAPI* Real_WSAConnect)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS) = nullptr;
static int (WINAPI* Real_send)(SOCKET, const char*, int, int) = nullptr;
static int (WINAPI* Real_recv)(SOCKET, char*, int, int) = nullptr;
static int (WINAPI* Real_sendto)(SOCKET, const char*, int, int, const sockaddr*, int) = nullptr;
static int (WINAPI* Real_recvfrom)(SOCKET, char*, int, int, sockaddr*, int*) = nullptr;
static int (WINAPI* Real_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WINAPI* Real_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static int (WINAPI* Real_WSAIoctl)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE) = nullptr;
static BOOL(WINAPI* Real_WSAGetOverlappedResult)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD) = nullptr;
static int (WINAPI* Real_closesocket)(SOCKET) = nullptr;
static int (WINAPI* Real_shutdown)(SOCKET, int) = nullptr;
static int (WINAPI* Real_bind)(SOCKET, const sockaddr*, int) = nullptr;
static int (WINAPI* Real_listen)(SOCKET, int) = nullptr;
static SOCKET(WINAPI* Real_accept)(SOCKET, sockaddr*, int*) = nullptr;
static SOCKET(WINAPI* Real_WSASocketA)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD) = nullptr;
static SOCKET(WINAPI* Real_WSASocketW)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD) = nullptr;
static BOOL(WINAPI* Real_GetOverlappedResult)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL) = nullptr;
static BOOL(WINAPI* Real_GetQueuedCompletionStatus)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD) = nullptr;
static BOOL(WINAPI* Real_GetQueuedCompletionStatusEx)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL) = nullptr;
static HANDLE(WINAPI* Real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
static HANDLE(WINAPI* Real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
static BOOL(WINAPI* Real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = nullptr;
static BOOL(WINAPI* Real_CloseHandle)(HANDLE) = nullptr;
static HANDLE(WINAPI* Real_CreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR) = nullptr;
static HANDLE(WINAPI* Real_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) = nullptr;
static LPVOID(WINAPI* Real_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T) = nullptr;
static LPVOID(WINAPI* Real_MapViewOfFileEx)(HANDLE, DWORD, DWORD, DWORD, SIZE_T, LPVOID) = nullptr;
static BOOL(WINAPI* Real_UnmapViewOfFile)(LPCVOID) = nullptr;

// DNS
static int (WINAPI* Real_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*) = nullptr;
static int (WINAPI* Real_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*) = nullptr;

// WinHTTP
static HINTERNET(WINAPI* Real_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = nullptr;
static HINTERNET(WINAPI* Real_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) = nullptr;
static HINTERNET(WINAPI* Real_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD) = nullptr;
static BOOL(WINAPI* Real_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) = nullptr;
static BOOL(WINAPI* Real_WinHttpReceiveResponse)(HINTERNET, LPVOID) = nullptr;
static BOOL(WINAPI* Real_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_WinHttpWriteData)(HINTERNET, LPCVOID, DWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD) = nullptr;
static HINTERNET(WINAPI* Real_WinHttpWebSocketCompleteUpgrade)(HINTERNET, DWORD_PTR) = nullptr;
static DWORD(WINAPI* Real_WinHttpWebSocketSend)(HINTERNET, WINHTTP_WEB_SOCKET_BUFFER_TYPE, PVOID, DWORD) = nullptr;
static DWORD(WINAPI* Real_WinHttpWebSocketReceive)(HINTERNET, PVOID, DWORD, DWORD*, WINHTTP_WEB_SOCKET_BUFFER_TYPE*) = nullptr;
static DWORD(WINAPI* Real_WinHttpWebSocketClose)(HINTERNET, USHORT, PVOID, DWORD) = nullptr;
static DWORD(WINAPI* Real_WinHttpWebSocketShutdown)(HINTERNET, USHORT, PVOID, DWORD) = nullptr;
static DWORD(WINAPI* Real_WinHttpWebSocketQueryCloseStatus)(HINTERNET, USHORT*, PVOID, DWORD, DWORD*) = nullptr;
static BOOL(WINAPI* Real_WinHttpCloseHandle)(HINTERNET) = nullptr;

// WinINet
static HINTERNET(WINAPI* Real_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = nullptr;
static HINTERNET(WINAPI* Real_InternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = nullptr;
static HINTERNET(WINAPI* Real_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = nullptr;
static HINTERNET(WINAPI* Real_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR) = nullptr;
static HINTERNET(WINAPI* Real_HttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR) = nullptr;
static HINTERNET(WINAPI* Real_HttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR) = nullptr;
static BOOL(WINAPI* Real_HttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD) = nullptr;
static BOOL(WINAPI* Real_HttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD) = nullptr;
static BOOL(WINAPI* Real_HttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_HttpQueryInfoW)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_InternetWriteFile)(HINTERNET, LPCVOID, DWORD, LPDWORD) = nullptr;
static BOOL(WINAPI* Real_InternetCloseHandle)(HINTERNET) = nullptr;

// Dynamic extension / TLS hooks
static LPFN_CONNECTEX Real_ConnectEx = nullptr;
static LPFN_ACCEPTEX Real_AcceptEx = nullptr;
static LPFN_WSASENDMSG Real_WSASendMsg = nullptr;
static LPFN_WSARECVMSG Real_WSARecvMsg = nullptr;
static int (WINAPI* Real_SSL_read)(void*, void*, int) = nullptr;
static int (WINAPI* Real_SSL_write)(void*, const void*, int) = nullptr;
static int (WINAPI* Real_SSL_read_ex)(void*, void*, size_t, size_t*) = nullptr;
static int (WINAPI* Real_SSL_write_ex)(void*, const void*, size_t, size_t*) = nullptr;
static int (*Real_luaL_loadbufferx)(void*, const char*, size_t, const char*, const char*) = nullptr;
static int (*Real_luaL_loadbuffer)(void*, const char*, size_t, const char*) = nullptr;
static int (*Real_luaL_loadstring)(void*, const char*) = nullptr;
static int (*Real_lua_pcallk)(void*, int, int, int, intptr_t, void*) = nullptr;
static void(__fastcall* Real_GraalDecryptScript)(void*, void*, int, void*, int, void*) = nullptr;
static void(__fastcall* Real_GraalExecScript)(void*, void*, int, void*, void*) = nullptr;
static void(__fastcall* Real_GraalBindBytecode)(void*, void*) = nullptr;
static int64_t(__fastcall* Real_GraalEventCall)(void*, void*, const char*, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = nullptr;
static void* (__fastcall* Real_GraalFindObject)(void*, void*) = nullptr;
static void* (__fastcall* Real_GraalFindInTable)(void*, int, void*) = nullptr;
static void* (__fastcall* Real_GraalExecEvent)(void*, void*) = nullptr;
static int64_t(__fastcall* Real_GraalOpCall)(void*, void*) = nullptr;
static void* (__fastcall* Real_GraalLookupFunction)(void*, void*) = nullptr;
static void(__fastcall* Real_GraalResolveVariable)(void*, void*) = nullptr;
static HMODULE(WINAPI* Real_LoadLibraryA)(LPCSTR) = nullptr;
static HMODULE(WINAPI* Real_LoadLibraryW)(LPCWSTR) = nullptr;
static HMODULE(WINAPI* Real_LoadLibraryExA)(LPCSTR, HANDLE, DWORD) = nullptr;
static HMODULE(WINAPI* Real_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = nullptr;

// Schannel (TLS)
static SECURITY_STATUS(WINAPI* Real_EncryptMessage)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG) = nullptr;
static SECURITY_STATUS(WINAPI* Real_DecryptMessage)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG) = nullptr;

// ===================================================================
// Utility
// ===================================================================

std::string FormatString(const char* fmt, ...)
{
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    return std::string(buffer);
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string Trim(const std::string& value)
{
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
        first++;
    }

    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) {
        last--;
    }

    return value.substr(first, last - first);
}

std::string GetEnvString(const char* name)
{
    DWORD needed = GetEnvironmentVariableA(name, nullptr, 0);
    if (needed == 0) {
        return {};
    }

    std::vector<char> buffer(needed);
    DWORD copied = GetEnvironmentVariableA(name, buffer.data(), needed);
    if (copied == 0 || copied >= needed) {
        return {};
    }

    return std::string(buffer.data(), copied);
}

bool ParseBoolEnv(const char* name, bool fallback)
{
    std::string value = Lower(Trim(GetEnvString(name)));
    if (value.empty()) {
        return fallback;
    }

    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }

    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }

    return fallback;
}

int ParseIntEnv(const char* name, int fallback)
{
    std::string value = Trim(GetEnvString(name));
    if (value.empty()) {
        return fallback;
    }

    char* end = nullptr;
    long parsed = std::strtol(value.c_str(), &end, 10);
    if (!end || *end != '\0') {
        return fallback;
    }

    if (parsed < 0) {
        return fallback;
    }

    return static_cast<int>(parsed);
}

unsigned long long ParseUllEnv(const char* name, unsigned long long fallback)
{
    std::string value = Trim(GetEnvString(name));
    if (value.empty()) {
        return fallback;
    }

    char* end = nullptr;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (!end || *end != '\0') {
        return fallback;
    }

    return parsed;
}

uintptr_t ParseAddressEnv(const char* name, uintptr_t fallback)
{
    std::string value = Trim(GetEnvString(name));
    if (value.empty()) {
        return fallback;
    }

    int base = 10;
    const char* start = value.c_str();
    if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        base = 16;
        start += 2;
    }

    char* end = nullptr;
    unsigned long long parsed = std::strtoull(start, &end, base);
    if (!end || *end != '\0') {
        return fallback;
    }

    return static_cast<uintptr_t>(parsed);
}

DWORD ParseDwordEnv(const char* name, DWORD fallback)
{
    std::string value = Trim(GetEnvString(name));
    if (value.empty()) {
        return fallback;
    }

    char* end = nullptr;
    unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
    if (!end || *end != '\0') {
        return fallback;
    }

    return static_cast<DWORD>(parsed);
}

std::string Timestamp()
{
    SYSTEMTIME localTime;
    GetLocalTime(&localTime);

    char buffer[64];
    sprintf_s(
        buffer,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03u",
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond,
        localTime.wMilliseconds);
    return buffer;
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20) {
                char escaped[8];
                sprintf_s(escaped, "\\u%04x", ch);
                out << escaped;
            }
            else {
                out << static_cast<char>(ch);
            }
            break;
        }
    }
    return out.str();
}

std::string WideToUtf8(LPCWSTR value, int chars = -1)
{
    if (!value) {
        return {};
    }

    int needed = WideCharToMultiByte(CP_UTF8, 0, value, chars, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }

    std::string output(needed, '\0');
    int written = WideCharToMultiByte(CP_UTF8, 0, value, chars, output.data(), needed, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }

    output.resize(written);
    if (!output.empty() && output.back() == '\0') {
        output.pop_back();
    }
    return output;
}

std::string AnsiString(LPCSTR value, DWORD length)
{
    if (!value) {
        return {};
    }

    if (length == static_cast<DWORD>(-1)) {
        return std::string(value);
    }

    return std::string(value, value + length);
}

std::string ModuleDirectory(HMODULE module)
{
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
        return ".";
    }

    PathRemoveFileSpecA(path);
    return path;
}

std::string CurrentProcessPath()
{
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, path, static_cast<DWORD>(sizeof(path)))) {
        return {};
    }
    return path;
}

class HookReentrancyGuard {
public:
    HookReentrancyGuard() : nested_(g_HookDepth++ > 0) {}
    ~HookReentrancyGuard() { g_HookDepth--; }
    bool nested() const { return nested_; }

private:
    bool nested_;
};

#define SOCKETU_GUARD_RETURN(expr) HookReentrancyGuard hookGuard; if (hookGuard.nested()) { return (expr); }

std::string HexAddress(uintptr_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}

std::string ModuleSiteFromAddress(void* address)
{
    if (!address) {
        return "undefined";
    }

    HMODULE module = nullptr;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address),
        &module) || !module) {
        return "unknown!" + HexAddress(reinterpret_cast<uintptr_t>(address));
    }

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
        return "unknown!" + HexAddress(reinterpret_cast<uintptr_t>(address));
    }

    const char* name = PathFindFileNameA(path);
    uintptr_t offset = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(module);
    return std::string(name ? name : path) + " + " + HexAddress(offset);
}

std::string ModuleNameFromAddress(void* address)
{
    HMODULE module = nullptr;
    if (!address ||
        !GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address),
            &module) ||
        !module) {
        return {};
    }

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
        return {};
    }

    const char* name = PathFindFileNameA(path);
    return name ? name : path;
}

std::string ModuleNameFromHandle(HMODULE module)
{
    if (!module) {
        return {};
    }

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
        return {};
    }

    const char* name = PathFindFileNameA(path);
    return name ? name : path;
}

template <typename T>
bool SafeReadValue(const void* address, T& value)
{
    if (!address) {
        return false;
    }

    __try {
        value = *reinterpret_cast<const T*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SafeCopyMemory(const void* address, void* output, size_t size)
{
    if (!address || !output || size == 0) {
        return false;
    }

    __try {
        memcpy(output, address, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::string SafeReadBytesAsString(const void* address, size_t size)
{
    if (!address || size == 0 || size > static_cast<size_t>(g_Config.maxGraalBytecodeBytes)) {
        return {};
    }

    std::string value(size, '\0');
    if (!SafeCopyMemory(address, value.data(), size)) {
        return {};
    }
    return value;
}

std::string SafeReadCString(const char* address, size_t maxLength = 4096)
{
    if (!address || maxLength == 0) {
        return {};
    }

    std::string value;
    value.reserve(128);
    for (size_t i = 0; i < maxLength; ++i) {
        char ch = 0;
        if (!SafeReadValue(address + i, ch)) {
            break;
        }
        if (ch == '\0') {
            break;
        }
        if (std::isprint(static_cast<unsigned char>(ch)) || ch == '\t' || ch == '\r' || ch == '\n') {
            value.push_back(ch);
        }
        else {
            value.push_back('.');
        }
    }
    return value;
}

bool IsOwnModuleAddress(void* address)
{
    HMODULE module = nullptr;
    return address &&
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address),
            &module) &&
        module == g_Module;
}

bool IsSystemOrHookModuleName(const std::string& moduleName)
{
    std::string name = Lower(moduleName);
    return name.empty() ||
        name == "socketuniversal.dll" ||
        name == "ws2_32.dll" ||
        name == "mswsock.dll" ||
        name == "winhttp.dll" ||
        name == "wininet.dll" ||
        name == "secur32.dll" ||
        name == "schannel.dll" ||
        name == "kernel32.dll" ||
        name == "kernelbase.dll" ||
        name == "ntdll.dll" ||
        name.find("vcruntime") != std::string::npos ||
        name.find("ucrtbase") != std::string::npos;
}

std::string DetectScriptKindFromText(const std::string& value)
{
    if (value.empty()) {
        return {};
    }

    std::string lower = Lower(value);
    if (lower.find("\x1blu") != std::string::npos || lower.find(".lua") != std::string::npos ||
        lower.find("lua_") != std::string::npos ||
        (lower.find("function ") != std::string::npos && lower.find(" end") != std::string::npos)) {
        return "lua";
    }

    if (lower.find(".gsc") != std::string::npos || lower.find("maps/mp/gametypes") != std::string::npos ||
        lower.find("level.") != std::string::npos || lower.find("self ") != std::string::npos ||
        lower.find("endon(") != std::string::npos || lower.find("waittill(") != std::string::npos) {
        return "gsc";
    }

    if (lower.find(".gs2") != std::string::npos || lower.find("gs2") != std::string::npos) {
        return "gs2";
    }

    if (lower.find(".nut") != std::string::npos || lower.find("squirrel") != std::string::npos) {
        return "squirrel";
    }

    if (lower.find(".as") != std::string::npos || lower.find("angelscript") != std::string::npos) {
        return "angelscript";
    }

    if (lower.find("<script") != std::string::npos || lower.find(".js") != std::string::npos ||
        lower.find("function(") != std::string::npos || lower.find("=>") != std::string::npos) {
        return "javascript";
    }

    return {};
}

std::string DetectScriptKindFromPath(const std::string& path)
{
    std::string lower = Lower(path);
    if (lower.find(".gsc") != std::string::npos || lower.find(".csc") != std::string::npos ||
        lower.find("gscbin") != std::string::npos || lower.find("maps/mp/gametypes") != std::string::npos) {
        return "gsc";
    }

    if (lower.find(".gs2") != std::string::npos || lower.find("gs2bin") != std::string::npos) {
        return "gs2";
    }

    if (lower.find(".lua") != std::string::npos || lower.find(".luac") != std::string::npos) {
        return "lua";
    }

    if (lower.find(".nut") != std::string::npos) {
        return "squirrel";
    }

    if (lower.find(".as") != std::string::npos || lower.find("angelscript") != std::string::npos) {
        return "angelscript";
    }

    return {};
}

bool IsScriptPath(const std::string& path)
{
    return !DetectScriptKindFromPath(path).empty();
}

bool IsLikelyScriptExportName(const std::string& name)
{
    std::string lower = Lower(name);
    return lower.find("gsc") != std::string::npos ||
        lower.find("gs2") != std::string::npos ||
        lower.find("csc") != std::string::npos ||
        lower.find("scr_") != std::string::npos ||
        lower.find("script") != std::string::npos ||
        lower.find("gscr") != std::string::npos ||
        lower.find("cscr") != std::string::npos ||
        lower.find("loadscript") != std::string::npos ||
        lower.find("exec") != std::string::npos ||
        lower.find("compile") != std::string::npos ||
        lower.find("parse") != std::string::npos ||
        lower.find("vm") != std::string::npos ||
        lower.find("sl_get") != std::string::npos;
}

bool IsLikelyGameModuleName(const std::string& moduleName)
{
    if (moduleName.empty()) {
        return false;
    }

    return !IsSystemOrHookModuleName(moduleName) &&
        Lower(moduleName).find("minhook") == std::string::npos;
}

bool ShouldProbeGraalModule(HMODULE module)
{
    if (!g_Config.graalProbes || !module) {
        return false;
    }

    std::string moduleName = ModuleNameFromHandle(module);
    if (moduleName.empty()) {
        return false;
    }

    if (!g_Config.graalModuleFilter.empty()) {
        return Lower(moduleName).find(Lower(g_Config.graalModuleFilter)) != std::string::npos;
    }

    return IsLikelyGameModuleName(moduleName);
}

std::string ReadGraalStringWrapper(void* wrapper)
{
    void* stringStruct = nullptr;
    if (!SafeReadValue(wrapper, stringStruct) || !stringStruct) {
        return {};
    }

    int length = 0;
    if (!SafeReadValue(stringStruct, length) || length <= 0 || length > 4096) {
        return SafeReadCString(reinterpret_cast<const char*>(stringStruct) + 8);
    }

    return SafeReadBytesAsString(reinterpret_cast<unsigned char*>(stringStruct) + 8, static_cast<size_t>(length));
}

std::string ReadGraalEncryptedObjectName(void* object, HMODULE module)
{
    if (!object || !module || g_Config.graalXorKeyRva == 0) {
        return {};
    }

    void* stringStruct = nullptr;
    if (!SafeReadValue(reinterpret_cast<unsigned char*>(object) + 32, stringStruct) || !stringStruct) {
        return {};
    }

    int length = 0;
    if (!SafeReadValue(stringStruct, length) || length <= 0 || length > 4096) {
        return {};
    }

    unsigned char key[3] = {};
    if (!SafeCopyMemory(reinterpret_cast<unsigned char*>(module) + g_Config.graalXorKeyRva, key, sizeof(key))) {
        return {};
    }

    std::string encrypted = SafeReadBytesAsString(reinterpret_cast<unsigned char*>(stringStruct) + 8, static_cast<size_t>(length));
    if (encrypted.empty()) {
        return {};
    }

    std::string decrypted;
    decrypted.reserve(encrypted.size());
    for (size_t i = 0; i < encrypted.size(); ++i) {
        decrypted.push_back(static_cast<char>(static_cast<unsigned char>(encrypted[i]) ^ key[i % 3]));
    }
    return decrypted;
}

bool ReadGraalBytecodeHeader(void* bytecode, uint32_t& realSize, uint32_t& version, uint32_t& flags)
{
    realSize = 0;
    version = 0;
    flags = 0;
    if (!bytecode) {
        return false;
    }

    if (!SafeReadValue(bytecode, realSize)) {
        return false;
    }
    SafeReadValue(reinterpret_cast<unsigned char*>(bytecode) + 4, version);
    SafeReadValue(reinterpret_cast<unsigned char*>(bytecode) + 8, flags);
    return realSize > 0 && realSize <= static_cast<uint32_t>(g_Config.maxGraalBytecodeBytes);
}

void LogGraalBytecode(const char* api, void* bytecode, const std::string& name, const std::string& detail)
{
    uint32_t realSize = 0;
    uint32_t version = 0;
    uint32_t flags = 0;
    bool valid = ReadGraalBytecodeHeader(bytecode, realSize, version, flags);
    std::string endpoint = name.empty() ? "graal-runtime" : ("graal-runtime/" + name);
    std::string status = valid ? "gs2-bytecode" : "gs2-bytecode-invalid";
    std::string fullDetail = FormatString(
        "%s ptr=%p real_size=%u version=%u flags=0x%08X",
        detail.c_str(),
        bytecode,
        realSize,
        version,
        flags);

    LogEvent(
        api ? api : "GraalBytecode",
        "script",
        endpoint,
        valid ? realSize : 0,
        status,
        fullDetail,
        valid ? bytecode : nullptr,
        valid ? realSize : 0);
}

void ScanGraalScriptManager(HMODULE module, const char* reason)
{
    if (!g_Config.graalProbes || !module || g_Config.graalGlobalContextRva == 0) {
        return;
    }

    void* context = nullptr;
    if (!SafeReadValue(reinterpret_cast<unsigned char*>(module) + g_Config.graalGlobalContextRva, context) || !context) {
        LogEvent("GraalScriptManager", "script-manager", ModuleNameFromHandle(module), 0, "missing-context", FormatString("reason=%s global_rva=%s", reason ? reason : "?", HexAddress(g_Config.graalGlobalContextRva).c_str()));
        return;
    }

    void* scriptManager = nullptr;
    if (!SafeReadValue(reinterpret_cast<unsigned char*>(context) + 0xB30, scriptManager) || !scriptManager) {
        LogEvent("GraalScriptManager", "script-manager", ModuleNameFromHandle(module), 0, "missing-manager", FormatString("reason=%s context=%p offset=0xB30", reason ? reason : "?", context));
        return;
    }

    void* listStruct = nullptr;
    int count = 0;
    void* dataArray = nullptr;
    SafeReadValue(reinterpret_cast<unsigned char*>(scriptManager) + 0x38, listStruct);
    if (listStruct) {
        SafeReadValue(reinterpret_cast<unsigned char*>(listStruct) + 12, count);
        SafeReadValue(reinterpret_cast<unsigned char*>(listStruct) + 16, dataArray);
    }

    LogEvent(
        "GraalScriptManager",
        "script-manager",
        ModuleNameFromHandle(module),
        count,
        "gs2",
        FormatString("reason=%s module_base=%p context=%p manager=%p list=%p array=%p", reason ? reason : "?", module, context, scriptManager, listStruct, dataArray));

    if (count <= 0 || count > 4096 || !dataArray) {
        return;
    }

    int maxToLog = count < 64 ? count : 64;
    for (int i = 0; i < maxToLog; ++i) {
        void* scriptObject = nullptr;
        if (!SafeReadValue(reinterpret_cast<unsigned char*>(dataArray) + i * sizeof(void*), scriptObject) || !scriptObject) {
            continue;
        }

        void* vtable = nullptr;
        void* vtable16 = nullptr;
        SafeReadValue(scriptObject, vtable);
        if (vtable) {
            SafeReadValue(reinterpret_cast<unsigned char*>(vtable) + 128, vtable16);
        }

        std::string objectName = ReadGraalEncryptedObjectName(scriptObject, module);
        LogEvent(
            "GraalScriptManager",
            "script-object",
            objectName.empty() ? ModuleNameFromHandle(module) : objectName,
            0,
            "gs2",
            FormatString("index=%d object=%p vtable=%p vtable16=%s", i, scriptObject, vtable, ModuleSiteFromAddress(vtable16).c_str()));
    }
}

std::string DetectScriptKindFromStack(const std::vector<std::string>& frames)
{
    for (const std::string& frame : frames) {
        std::string lower = Lower(frame);
        if (lower.find("lua") != std::string::npos) return "lua";
        if (lower.find("gsc") != std::string::npos) return "gsc";
        if (lower.find("gs2") != std::string::npos) return "gs2";
        if (lower.find("script") != std::string::npos) return "script-runtime";
        if (lower.find("squirrel") != std::string::npos) return "squirrel";
        if (lower.find("angel") != std::string::npos) return "angelscript";
    }

    return {};
}

CaptureContext CaptureContextForEvent()
{
    CaptureContext context;
    if (!g_Config.callStack) {
        context.returnSite = "disabled";
        return context;
    }

    constexpr USHORT kMaxFrames = 48;
    void* frames[kMaxFrames] = {};
    USHORT captured = CaptureStackBackTrace(0, kMaxFrames, frames, nullptr);

    std::string firstExternal;
    std::string firstPreferred;
    for (USHORT i = 0; i < captured; ++i) {
        if (!frames[i] || IsOwnModuleAddress(frames[i])) {
            continue;
        }

        std::string moduleName = ModuleNameFromAddress(frames[i]);
        std::string site = ModuleSiteFromAddress(frames[i]);
        if (firstExternal.empty()) {
            firstExternal = site;
        }

        if (!IsSystemOrHookModuleName(moduleName)) {
            if (firstPreferred.empty()) {
                firstPreferred = site;
            }
            if (static_cast<int>(context.callStack.size()) < g_Config.maxCallStackFrames) {
                context.callStack.push_back(site);
            }
        }
    }

    context.returnSite = !firstPreferred.empty() ? firstPreferred : (!firstExternal.empty() ? firstExternal : "undefined");
    context.scriptHint = DetectScriptKindFromStack(context.callStack);
    return context;
}

EndpointParts SplitEndpoint(const std::string& endpoint)
{
    EndpointParts parts;
    if (endpoint.empty() || endpoint == "?") {
        return parts;
    }

    std::string value = endpoint;
    size_t slash = value.find('/');
    if (slash != std::string::npos) {
        value.resize(slash);
    }

    if (!value.empty() && value.front() == '[') {
        size_t close = value.find(']');
        if (close != std::string::npos) {
            parts.server = value.substr(1, close - 1);
            if (close + 2 <= value.size() && value[close + 1] == ':') {
                parts.port = value.substr(close + 2);
            }
            return parts;
        }
    }

    size_t colon = value.rfind(':');
    if (colon != std::string::npos && value.find(':') == colon) {
        parts.server = value.substr(0, colon);
        parts.port = value.substr(colon + 1);
    }
    else {
        parts.server = value;
    }

    return parts;
}

WORD ColorForEvent(const std::string& direction, const std::string& status, const std::string& scriptKind)
{
    std::string statusLower = Lower(status);
    if (statusLower.find("fail") != std::string::npos || statusLower.find("error") != std::string::npos) {
        return FOREGROUND_RED | FOREGROUND_INTENSITY;
    }

    if (!scriptKind.empty()) {
        return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }

    std::string dir = Lower(direction);
    if (dir.find("out") != std::string::npos || dir.find("send") != std::string::npos) {
        return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }

    if (dir.find("in") != std::string::npos || dir.find("recv") != std::string::npos) {
        return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    }

    if (dir.find("tls") != std::string::npos) {
        return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    }

    if (dir.find("dns") != std::string::npos) {
        return FOREGROUND_BLUE | FOREGROUND_GREEN;
    }

    return g_DefaultConsoleAttributes;
}

std::string JoinPath(const std::string& directory, const std::string& filename)
{
    if (directory.empty()) {
        return filename;
    }

    char last = directory.back();
    if (last == '\\' || last == '/') {
        return directory + filename;
    }

    return directory + "\\" + filename;
}

bool ShouldLog()
{
    if (g_ShuttingDown.load()) {
        return false;
    }

    if (!g_Config.loggingEnabled) {
        return false;
    }

    if (g_Config.threadFilter != 0 && GetCurrentThreadId() != g_Config.threadFilter) {
        return false;
    }

    return true;
}

unsigned long long FileSize(const std::string& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
        return 0;
    }

    ULARGE_INTEGER size = {};
    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;
    return size.QuadPart;
}

void RotateFileLocked(FILE** file, const std::string& path, size_t pendingBytes)
{
    if (!file || !*file || path.empty() || g_Config.rotateBytes == 0 || g_Config.rotateFiles <= 0) {
        return;
    }

    if (FileSize(path) + pendingBytes <= g_Config.rotateBytes) {
        return;
    }

    fclose(*file);
    *file = nullptr;

    for (int index = g_Config.rotateFiles - 1; index >= 1; --index) {
        std::string from = path + "." + std::to_string(index);
        std::string to = path + "." + std::to_string(index + 1);
        MoveFileExA(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING);
    }

    std::string first = path + ".1";
    MoveFileExA(path.c_str(), first.c_str(), MOVEFILE_REPLACE_EXISTING);
    fopen_s(file, path.c_str(), "a");
}

void OpenNamedPipe()
{
    if (!g_Config.namedPipe || g_Config.pipeName.empty() || g_Pipe != INVALID_HANDLE_VALUE) {
        return;
    }

    g_Pipe = CreateNamedPipeA(
        g_Config.pipeName.c_str(),
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
        1,
        65536,
        65536,
        0,
        nullptr);
}

void WritePipeLineLocked(const std::string& line)
{
    if (!g_Config.namedPipe || g_Pipe == INVALID_HANDLE_VALUE) {
        return;
    }

    if (!g_PipeConnected) {
        BOOL connected = ConnectNamedPipe(g_Pipe, nullptr);
        DWORD error = GetLastError();
        g_PipeConnected = connected || error == ERROR_PIPE_CONNECTED;
        if (!g_PipeConnected) {
            return;
        }
    }

    DWORD written = 0;
    if (!WriteFile(g_Pipe, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr)) {
        DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_NO_DATA) {
            DisconnectNamedPipe(g_Pipe);
            g_PipeConnected = false;
        }
    }
}

void CloseNamedPipe()
{
    std::lock_guard<std::mutex> lock(g_LogMutex);
    if (g_Pipe != INVALID_HANDLE_VALUE) {
        if (g_PipeConnected) {
            DisconnectNamedPipe(g_Pipe);
        }
        CloseHandle(g_Pipe);
        g_Pipe = INVALID_HANDLE_VALUE;
        g_PipeConnected = false;
    }
}

void WriteHumanLine(const std::string& message, WORD color = 0)
{
    std::string line = "[" + Timestamp() + "][pid:" +
        std::to_string(GetCurrentProcessId()) + " tid:" +
        std::to_string(GetCurrentThreadId()) + "] " +
        message + "\n";

    std::lock_guard<std::mutex> lock(g_LogMutex);

    OutputDebugStringA("[NetHook] ");
    OutputDebugStringA(message.c_str());
    OutputDebugStringA("\n");

    if (g_Config.console) {
        FILE* console = stdout ? stdout : stderr;
        if (console) {
            HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
            bool colored = g_Config.consoleColor && color != 0 && consoleHandle != INVALID_HANDLE_VALUE;
            if (colored) {
                SetConsoleTextAttribute(consoleHandle, color);
            }
            fputs(line.c_str(), console);
            fflush(console);
            if (colored) {
                SetConsoleTextAttribute(consoleHandle, g_DefaultConsoleAttributes);
            }
        }
    }

    if (g_LogFile) {
        RotateFileLocked(&g_LogFile, g_Config.logPath, line.size());
        fputs(line.c_str(), g_LogFile);
        fflush(g_LogFile);
    }

    WritePipeLineLocked(line);
}

void WriteJsonLine(const std::string& json)
{
    if (!g_Config.jsonl || !g_JsonlFile) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_LogMutex);
    RotateFileLocked(&g_JsonlFile, g_Config.jsonlPath, json.size() + 1);
    fputs(json.c_str(), g_JsonlFile);
    fputc('\n', g_JsonlFile);
    fflush(g_JsonlFile);
}

void LogMessage(const char* fmt, ...)
{
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    buffer[sizeof(buffer) - 1] = '\0';
    WriteHumanLine(buffer);
}

void CreateDebugConsole()
{
    if (!g_Config.console) {
        return;
    }

    if (!GetConsoleWindow()) {
        AllocConsole();
    }

    FILE* fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo = {};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consoleInfo)) {
        g_DefaultConsoleAttributes = consoleInfo.wAttributes;
    }
    SetConsoleTitleA("SocketUniversal Network Console");
}

void OpenLogFiles()
{
    std::lock_guard<std::mutex> lock(g_LogMutex);

    if (!g_Config.logPath.empty()) {
        fopen_s(&g_LogFile, g_Config.logPath.c_str(), "a");
    }

    if (g_Config.jsonl && !g_Config.jsonlPath.empty()) {
        fopen_s(&g_JsonlFile, g_Config.jsonlPath.c_str(), "a");
    }

    OpenNamedPipe();
}

void CloseLogFiles()
{
    std::lock_guard<std::mutex> lock(g_LogMutex);

    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }

    if (g_JsonlFile) {
        fclose(g_JsonlFile);
        g_JsonlFile = nullptr;
    }
}

void LoadConfig()
{
    std::string moduleDir = ModuleDirectory(g_Module);

    g_Config.dumpData = ParseBoolEnv("SOCKETUNIVERSAL_DUMP_DATA", true);
    g_Config.logHttpHeaders = ParseBoolEnv("SOCKETUNIVERSAL_LOG_HEADERS", true);
    g_Config.console = ParseBoolEnv("SOCKETUNIVERSAL_CONSOLE", true);
    g_Config.redact = ParseBoolEnv("SOCKETUNIVERSAL_REDACT", false);
    g_Config.jsonl = ParseBoolEnv("SOCKETUNIVERSAL_JSONL", true);
    g_Config.namedPipe = ParseBoolEnv("SOCKETUNIVERSAL_PIPE", true);
    g_Config.consoleColor = ParseBoolEnv("SOCKETUNIVERSAL_COLOR", true);
    g_Config.callStack = ParseBoolEnv("SOCKETUNIVERSAL_CALLSTACK", true);
    g_Config.scriptFileCapture = ParseBoolEnv("SOCKETUNIVERSAL_SCRIPT_FILE_CAPTURE", true);
    g_Config.scriptExportScan = ParseBoolEnv("SOCKETUNIVERSAL_SCRIPT_EXPORT_SCAN", true);
    g_Config.scriptStringScan = ParseBoolEnv("SOCKETUNIVERSAL_SCRIPT_STRING_SCAN", true);
    g_Config.webSocketCapture = ParseBoolEnv("SOCKETUNIVERSAL_WEBSOCKET_CAPTURE", true);
    g_Config.webSocketFrameScan = ParseBoolEnv("SOCKETUNIVERSAL_WEBSOCKET_FRAME_SCAN", true);
    g_Config.graalProbes = ParseBoolEnv("SOCKETUNIVERSAL_GRAAL_PROBES", false);
    g_Config.maxDumpBytes = ParseIntEnv("SOCKETUNIVERSAL_MAX_DUMP_BYTES", 4096);
    g_Config.maxCallStackFrames = ParseIntEnv("SOCKETUNIVERSAL_CALLSTACK_FRAMES", 8);
    g_Config.maxScriptExportLogs = ParseIntEnv("SOCKETUNIVERSAL_SCRIPT_EXPORT_LIMIT", 256);
    g_Config.maxScriptStringLogs = ParseIntEnv("SOCKETUNIVERSAL_SCRIPT_STRING_LIMIT", 128);
    g_Config.maxMappedScriptPreviewBytes = ParseIntEnv("SOCKETUNIVERSAL_SCRIPT_MAP_PREVIEW_BYTES", 65536);
    g_Config.maxWebSocketFramesPerBuffer = ParseIntEnv("SOCKETUNIVERSAL_WEBSOCKET_FRAME_LIMIT", 16);
    g_Config.maxWebSocketFramePreviewBytes = ParseIntEnv("SOCKETUNIVERSAL_WEBSOCKET_PREVIEW_BYTES", 65536);
    g_Config.maxGraalBytecodeBytes = ParseIntEnv("SOCKETUNIVERSAL_GRAAL_MAX_BYTECODE_BYTES", 1048576);
    g_Config.rotateBytes = ParseUllEnv("SOCKETUNIVERSAL_ROTATE_BYTES", 10ull * 1024ull * 1024ull);
    g_Config.rotateFiles = ParseIntEnv("SOCKETUNIVERSAL_ROTATE_FILES", 5);
    g_Config.threadFilter = ParseDwordEnv("SOCKETUNIVERSAL_THREAD_FILTER", 0);
    g_Config.processFilter = Trim(GetEnvString("SOCKETUNIVERSAL_PROCESS_FILTER"));
    g_Config.graalModuleFilter = Trim(GetEnvString("SOCKETUNIVERSAL_GRAAL_MODULE"));
    g_Config.logPath = Trim(GetEnvString("SOCKETUNIVERSAL_LOG_FILE"));
    g_Config.jsonlPath = Trim(GetEnvString("SOCKETUNIVERSAL_JSONL_FILE"));
    g_Config.pipeName = Trim(GetEnvString("SOCKETUNIVERSAL_PIPE_NAME"));
    g_Config.graalDecryptScriptRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_DECRYPT_RVA", g_Config.graalDecryptScriptRva);
    g_Config.graalExecScriptRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_EXEC_RVA", g_Config.graalExecScriptRva);
    g_Config.graalBindBytecodeRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_BIND_RVA", g_Config.graalBindBytecodeRva);
    g_Config.graalEventCallRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_EVENT_CALL_RVA", g_Config.graalEventCallRva);
    g_Config.graalFindObjectRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_FIND_OBJECT_RVA", g_Config.graalFindObjectRva);
    g_Config.graalFindInTableRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_FIND_TABLE_RVA", g_Config.graalFindInTableRva);
    g_Config.graalExecEventRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_EXEC_EVENT_RVA", g_Config.graalExecEventRva);
    g_Config.graalOpCallRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_OP_CALL_RVA", g_Config.graalOpCallRva);
    g_Config.graalLookupFunctionRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_LOOKUP_RVA", g_Config.graalLookupFunctionRva);
    g_Config.graalResolveVariableRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_RESOLVE_RVA", g_Config.graalResolveVariableRva);
    g_Config.graalGlobalContextRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_CONTEXT_RVA", g_Config.graalGlobalContextRva);
    g_Config.graalXorKeyRva = ParseAddressEnv("SOCKETUNIVERSAL_GRAAL_XOR_KEY_RVA", g_Config.graalXorKeyRva);

    if (g_Config.graalModuleFilter.empty()) {
        g_Config.graalModuleFilter = "MyGame.dll";
    }

    if (g_Config.logPath.empty()) {
        g_Config.logPath = JoinPath(moduleDir, "SocketUniversal.log");
    }

    if (g_Config.jsonlPath.empty()) {
        g_Config.jsonlPath = JoinPath(moduleDir, "SocketUniversal.jsonl");
    }

    if (g_Config.pipeName.empty()) {
        g_Config.pipeName = R"(\\.\pipe\SocketUniversal)";
    }

    if (!g_Config.processFilter.empty()) {
        std::string process = Lower(CurrentProcessPath());
        std::string filter = Lower(g_Config.processFilter);
        g_Config.loggingEnabled = process.find(filter) != std::string::npos;
    }
}

// ===================================================================
// Redaction / Payload formatting
// ===================================================================

bool IsSensitiveHeaderName(const std::string& name)
{
    std::string lower = Lower(Trim(name));
    return lower == "authorization" ||
        lower == "proxy-authorization" ||
        lower == "cookie" ||
        lower == "set-cookie" ||
        lower == "x-api-key" ||
        lower == "api-key" ||
        lower == "x-auth-token" ||
        lower == "x-csrf-token" ||
        lower == "x-xsrf-token";
}

std::string RedactPatterns(const std::string& input)
{
    if (!g_Config.redact || input.empty()) {
        return input;
    }

    try {
        std::string output = input;
        output = std::regex_replace(output, std::regex(R"((authorization\s*:\s*)[^\r\n]+)", std::regex_constants::icase), "$1<redacted>");
        output = std::regex_replace(output, std::regex(R"((proxy-authorization\s*:\s*)[^\r\n]+)", std::regex_constants::icase), "$1<redacted>");
        output = std::regex_replace(output, std::regex(R"(((?:set-cookie|cookie)\s*:\s*)[^\r\n]+)", std::regex_constants::icase), "$1<redacted>");
        output = std::regex_replace(output, std::regex(R"((bearer\s+)[A-Za-z0-9._~+/=-]+)", std::regex_constants::icase), "$1<redacted>");
        output = std::regex_replace(output, std::regex(R"((basic\s+)[A-Za-z0-9+/=]+)", std::regex_constants::icase), "$1<redacted>");
        output = std::regex_replace(
            output,
            std::regex(R"((["']?(?:password|passwd|pwd|token|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|authorization)["']?\s*[:=]\s*["']?)[^"',&\s\r\n}]+)", std::regex_constants::icase),
            "$1<redacted>");
        output = std::regex_replace(
            output,
            std::regex(R"(((?:[?&;])(?:password|passwd|pwd|token|api_key|apikey|access_token|refresh_token|client_secret|secret|key)=)[^&\s]+)", std::regex_constants::icase),
            "$1<redacted>");
        return output;
    }
    catch (...) {
        return input;
    }
}

std::string RedactHeaders(const std::string& headers)
{
    if (!g_Config.redact || headers.empty()) {
        return headers;
    }

    std::string output;
    size_t offset = 0;

    while (offset < headers.size()) {
        size_t lineEnd = headers.find('\n', offset);
        bool hadNewline = lineEnd != std::string::npos;
        std::string line = hadNewline ? headers.substr(offset, lineEnd - offset) : headers.substr(offset);

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        size_t colon = line.find(':');
        if (colon != std::string::npos && IsSensitiveHeaderName(line.substr(0, colon))) {
            output += line.substr(0, colon);
            output += ": <redacted>";
        }
        else {
            output += RedactPatterns(line);
        }

        if (hadNewline) {
            output += "\n";
            offset = lineEnd + 1;
        }
        else {
            break;
        }
    }

    return output;
}

bool IsLikelyText(const unsigned char* data, size_t length)
{
    if (!data || length == 0) {
        return false;
    }

    size_t printable = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = data[i];
        if ((ch >= 32 && ch < 127) || ch == '\r' || ch == '\n' || ch == '\t') {
            printable++;
        }
    }

    return printable * 100 / length >= 70;
}

bool TryDecodeChunked(const std::string& input, std::string& output)
{
    output.clear();
    size_t offset = 0;
    bool decodedAny = false;

    while (offset < input.size()) {
        size_t lineEnd = input.find("\r\n", offset);
        if (lineEnd == std::string::npos) {
            return decodedAny;
        }

        std::string sizeLine = input.substr(offset, lineEnd - offset);
        size_t extension = sizeLine.find(';');
        if (extension != std::string::npos) {
            sizeLine.resize(extension);
        }
        sizeLine = Trim(sizeLine);
        if (sizeLine.empty()) {
            return decodedAny;
        }

        char* end = nullptr;
        unsigned long chunkSize = std::strtoul(sizeLine.c_str(), &end, 16);
        if (!end || *end != '\0') {
            return decodedAny;
        }

        offset = lineEnd + 2;
        if (chunkSize == 0) {
            return decodedAny;
        }

        if (offset + chunkSize > input.size()) {
            return decodedAny;
        }

        output.append(input.data() + offset, chunkSize);
        decodedAny = true;
        offset += chunkSize;

        if (offset + 2 <= input.size() && input.compare(offset, 2, "\r\n") == 0) {
            offset += 2;
        }
        else {
            return decodedAny;
        }
    }

    return decodedAny;
}

PayloadPreview BuildPayloadPreview(const void* data, size_t length)
{
    PayloadPreview preview;

    if (!g_Config.dumpData || !data || length == 0) {
        return preview;
    }

    size_t cap = g_Config.maxDumpBytes == 0 ? length : static_cast<size_t>(g_Config.maxDumpBytes);
    size_t previewBytes = length < cap ? length : cap;
    const unsigned char* bytes = static_cast<const unsigned char*>(data);

    preview.previewBytes = previewBytes;
    preview.truncated = previewBytes < length;

    std::string compressionNote;
    if (previewBytes >= 4 && bytes[0] == 0x1B && bytes[1] == 'L' && bytes[2] == 'u' && bytes[3] == 'a') {
        preview.scriptKind = "lua-bytecode";
    }

    if (previewBytes >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B) {
        compressionNote = "[gzip-compressed body; raw bytes shown]\n";
    }
    else if (previewBytes >= 2 && bytes[0] == 0x78 && (bytes[1] == 0x01 || bytes[1] == 0x5E || bytes[1] == 0x9C || bytes[1] == 0xDA)) {
        compressionNote = "[zlib/deflate-compressed body; raw bytes shown]\n";
    }

    preview.textLike = IsLikelyText(bytes, previewBytes);

    if (preview.textLike) {
        std::string text;
        text.reserve(previewBytes);
        for (size_t i = 0; i < previewBytes; ++i) {
            unsigned char ch = bytes[i];
            if ((ch >= 32 && ch < 127) || ch == '\r' || ch == '\n' || ch == '\t') {
                text.push_back(static_cast<char>(ch));
            }
            else {
                text.push_back('.');
            }
        }

        std::string decoded;
        if (TryDecodeChunked(text, decoded)) {
            text = "[chunked decoded]\n" + decoded;
        }

        preview.scriptKind = DetectScriptKindFromText(text);
        preview.text = RedactPatterns(text);
        preview.redacted = preview.text != text;
        return preview;
    }

    static const char* hexChars = "0123456789ABCDEF";
    preview.hex.reserve(previewBytes * 3);
    std::string ascii;
    ascii.reserve(previewBytes);

    for (size_t i = 0; i < previewBytes; ++i) {
        unsigned char ch = bytes[i];
        preview.hex.push_back(hexChars[(ch >> 4) & 0xF]);
        preview.hex.push_back(hexChars[ch & 0xF]);
        if (i + 1 < previewBytes) {
            preview.hex.push_back(' ');
        }
        ascii.push_back((ch >= 32 && ch < 127) ? static_cast<char>(ch) : '.');
    }

    std::string rawText = compressionNote + ascii;
    if (preview.scriptKind.empty()) {
        preview.scriptKind = DetectScriptKindFromText(rawText);
    }
    preview.text = RedactPatterns(rawText);
    preview.redacted = preview.text != rawText;
    return preview;
}

// ===================================================================
// Tracking
// ===================================================================

std::string EndpointFromSockaddr(const sockaddr* address, int length)
{
    if (!address || length <= 0) {
        return "?";
    }

    char host[NI_MAXHOST] = {};
    char port[NI_MAXSERV] = {};
    int result = getnameinfo(address, length, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (result != 0) {
        return "?";
    }

    std::string hostText = host;
    if (hostText.find(':') != std::string::npos) {
        hostText = "[" + hostText + "]";
    }

    return hostText + ":" + port;
}

void TrackSocket(SOCKET socket, const std::string& endpoint)
{
    if (socket == INVALID_SOCKET || endpoint.empty() || endpoint == "?") {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_SocketToHost[socket] = endpoint;
}

std::string SocketEndpoint(SOCKET socket)
{
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        auto it = g_SocketToHost.find(socket);
        if (it != g_SocketToHost.end()) {
            return it->second;
        }
    }

    sockaddr_storage address = {};
    int addressLength = sizeof(address);
    if (getpeername(socket, reinterpret_cast<sockaddr*>(&address), &addressLength) == 0) {
        std::string endpoint = EndpointFromSockaddr(reinterpret_cast<sockaddr*>(&address), addressLength);
        TrackSocket(socket, endpoint);
        return endpoint;
    }

    return "?";
}

void TrackHandle(HINTERNET handle, const HttpHandleInfo& info)
{
    if (!handle) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_HandleInfo[handle] = info;
}

HttpHandleInfo GetHandleInfo(HINTERNET handle)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_HandleInfo.find(handle);
    return it != g_HandleInfo.end() ? it->second : HttpHandleInfo{};
}

void RemoveHandle(HINTERNET handle)
{
    if (!handle) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_HandleInfo.erase(handle);
}

std::string EndpointFromHttpInfo(const HttpHandleInfo& info)
{
    if (info.host.empty()) {
        return "?";
    }

    std::string endpoint = info.host;
    if (info.port != 0) {
        endpoint += ":" + std::to_string(info.port);
    }

    if (!info.path.empty()) {
        endpoint += info.path;
    }

    return endpoint;
}

bool TextContainsWebSocketUpgrade(const std::string& value)
{
    if (value.empty()) {
        return false;
    }

    std::string lower = Lower(value);
    return lower.find("upgrade: websocket") != std::string::npos ||
        lower.find("sec-websocket-key:") != std::string::npos ||
        lower.find("sec-websocket-accept:") != std::string::npos;
}

bool PayloadLooksLikeWebSocketHandshake(const void* data, size_t length)
{
    if (!data || length == 0) {
        return false;
    }

    size_t scanLength = length < 16384 ? length : 16384;
    std::string text(static_cast<const char*>(data), scanLength);
    return TextContainsWebSocketUpgrade(text);
}

void MarkHttpHandleWebSocketUpgrade(HINTERNET handle)
{
    if (!handle) {
        return;
    }

    HttpHandleInfo info = GetHandleInfo(handle);
    info.webSocketUpgrade = true;
    if (info.method.empty()) {
        info.method = "GET";
    }
    TrackHandle(handle, info);
}

void MarkSocketWebSocket(SOCKET socket)
{
    if (socket == INVALID_SOCKET) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_WebSocketSockets.insert(socket);
}

bool IsTrackedWebSocketSocket(SOCKET socket)
{
    if (socket == INVALID_SOCKET) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    return g_WebSocketSockets.find(socket) != g_WebSocketSockets.end();
}

void RemoveWebSocketSocket(SOCKET socket)
{
    if (socket == INVALID_SOCKET) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_WebSocketSockets.erase(socket);
}

void MarkOpenSslWebSocketContext(void* ssl)
{
    if (!ssl) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_OpenSslWebSocketContexts.insert(ssl);
}

bool IsTrackedOpenSslWebSocketContext(void* ssl)
{
    if (!ssl) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    return g_OpenSslWebSocketContexts.find(ssl) != g_OpenSslWebSocketContexts.end();
}

std::string SchannelContextKey(PCtxtHandle context)
{
    if (!context) {
        return {};
    }

    return FormatString(
        "%llX:%llX",
        static_cast<unsigned long long>(context->dwLower),
        static_cast<unsigned long long>(context->dwUpper));
}

void MarkSchannelWebSocketContext(PCtxtHandle context)
{
    std::string key = SchannelContextKey(context);
    if (key.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_SchannelWebSocketContexts.insert(key);
}

bool IsTrackedSchannelWebSocketContext(PCtxtHandle context)
{
    std::string key = SchannelContextKey(context);
    if (key.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    return g_SchannelWebSocketContexts.find(key) != g_SchannelWebSocketContexts.end();
}

const char* WebSocketBufferTypeName(WINHTTP_WEB_SOCKET_BUFFER_TYPE type)
{
    switch (type) {
    case WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE:
        return "binary-message";
    case WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE:
        return "binary-fragment";
    case WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE:
        return "text-message";
    case WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE:
        return "text-fragment";
    case WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE:
        return "close";
    default:
        return "unknown";
    }
}

bool WebSocketBufferTypeHasPayload(WINHTTP_WEB_SOCKET_BUFFER_TYPE type)
{
    return type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
        type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE ||
        type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE ||
        type == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE ||
        type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE;
}

const char* WebSocketOpcodeName(unsigned char opcode)
{
    switch (opcode) {
    case 0x0:
        return "continuation";
    case 0x1:
        return "text";
    case 0x2:
        return "binary";
    case 0x8:
        return "close";
    case 0x9:
        return "ping";
    case 0xA:
        return "pong";
    default:
        return "unknown";
    }
}

bool IsValidWebSocketOpcode(unsigned char opcode)
{
    return opcode == 0x0 || opcode == 0x1 || opcode == 0x2 ||
        opcode == 0x8 || opcode == 0x9 || opcode == 0xA;
}

bool DirectionIsOutbound(const char* direction)
{
    std::string lower = Lower(direction ? direction : "");
    return lower.find("out") != std::string::npos ||
        lower.find("write") != std::string::npos;
}

const char* WebSocketDirection(const char* direction)
{
    return DirectionIsOutbound(direction) ? "websocket-out" : "websocket-in";
}

struct WebSocketFrameInfo {
    bool fin = false;
    bool masked = false;
    unsigned char opcode = 0;
    unsigned long long payloadLength = 0;
    size_t headerLength = 0;
    size_t frameLength = 0;
    const unsigned char* payload = nullptr;
    unsigned char maskKey[4] = {};
};

bool TryParseWebSocketFrame(const unsigned char* data, size_t length, WebSocketFrameInfo& frame)
{
    frame = WebSocketFrameInfo{};
    if (!data || length < 2) {
        return false;
    }

    unsigned char first = data[0];
    unsigned char second = data[1];
    if ((first & 0x70) != 0) {
        return false;
    }

    frame.fin = (first & 0x80) != 0;
    frame.opcode = first & 0x0F;
    if (!IsValidWebSocketOpcode(frame.opcode)) {
        return false;
    }

    frame.masked = (second & 0x80) != 0;
    unsigned long long payloadLength = second & 0x7F;
    size_t offset = 2;

    if (payloadLength == 126) {
        if (length < offset + 2) {
            return false;
        }
        payloadLength = (static_cast<unsigned long long>(data[offset]) << 8) |
            static_cast<unsigned long long>(data[offset + 1]);
        offset += 2;
    }
    else if (payloadLength == 127) {
        if (length < offset + 8 || (data[offset] & 0x80) != 0) {
            return false;
        }

        payloadLength = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLength = (payloadLength << 8) | static_cast<unsigned long long>(data[offset + i]);
        }
        offset += 8;
    }

    if (frame.opcode >= 0x8 && (!frame.fin || payloadLength > 125)) {
        return false;
    }

    if (frame.masked) {
        if (length < offset + 4) {
            return false;
        }
        memcpy(frame.maskKey, data + offset, sizeof(frame.maskKey));
        offset += 4;
    }

    if (payloadLength > static_cast<unsigned long long>(length - offset)) {
        return false;
    }

    frame.payloadLength = payloadLength;
    frame.headerLength = offset;
    frame.frameLength = offset + static_cast<size_t>(payloadLength);
    frame.payload = data + offset;
    return true;
}

void LogWebSocketApiMessage(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType,
    DWORD result,
    const void* payloadData,
    size_t payloadLength,
    const std::string& extraDetail = {})
{
    if (!g_Config.webSocketCapture) {
        return;
    }

    std::string status = result == ERROR_SUCCESS ? WebSocketBufferTypeName(bufferType) : FormatString("error=%lu", result);
    std::string detail = FormatString("type=%s", WebSocketBufferTypeName(bufferType));
    if (!extraDetail.empty()) {
        detail += " " + extraDetail;
    }

    size_t previewLength = payloadLength;
    if (g_Config.maxWebSocketFramePreviewBytes > 0 && previewLength > static_cast<size_t>(g_Config.maxWebSocketFramePreviewBytes)) {
        previewLength = static_cast<size_t>(g_Config.maxWebSocketFramePreviewBytes);
        detail += FormatString(" payload_preview_bytes=%zu", previewLength);
    }

    LogEvent(
        api,
        direction,
        endpoint,
        static_cast<long long>(payloadLength),
        status,
        detail,
        WebSocketBufferTypeHasPayload(bufferType) && payloadData && previewLength > 0 ? payloadData : nullptr,
        WebSocketBufferTypeHasPayload(bufferType) && payloadData && previewLength > 0 ? previewLength : 0);
}

bool LogWebSocketWireFrames(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    const void* data,
    size_t length)
{
    if (!g_Config.webSocketCapture || !g_Config.webSocketFrameScan || !data || length < 2) {
        return false;
    }

    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    size_t offset = 0;
    int logged = 0;
    int frameLimit = g_Config.maxWebSocketFramesPerBuffer > 0 ? g_Config.maxWebSocketFramesPerBuffer : 16;

    while (offset < length && logged < frameLimit) {
        WebSocketFrameInfo frame;
        if (!TryParseWebSocketFrame(bytes + offset, length - offset, frame) || frame.frameLength == 0) {
            break;
        }

        std::string detail = FormatString(
            "opcode=%s(0x%X) fin=%s masked=%s header=%zu offset=%zu",
            WebSocketOpcodeName(frame.opcode),
            static_cast<unsigned>(frame.opcode),
            frame.fin ? "yes" : "no",
            frame.masked ? "yes" : "no",
            frame.headerLength,
            offset);

        size_t previewLength = static_cast<size_t>(frame.payloadLength);
        if (g_Config.maxWebSocketFramePreviewBytes > 0 && previewLength > static_cast<size_t>(g_Config.maxWebSocketFramePreviewBytes)) {
            previewLength = static_cast<size_t>(g_Config.maxWebSocketFramePreviewBytes);
            detail += FormatString(" payload_preview_bytes=%zu", previewLength);
        }

        if (frame.masked && previewLength > 0) {
            std::string unmasked(previewLength, '\0');
            for (size_t i = 0; i < previewLength; ++i) {
                unmasked[i] = static_cast<char>(frame.payload[i] ^ frame.maskKey[i % 4]);
            }
            LogEvent(api, WebSocketDirection(direction), endpoint, static_cast<long long>(frame.payloadLength), WebSocketOpcodeName(frame.opcode), detail, unmasked.data(), unmasked.size());
        }
        else {
            LogEvent(api, WebSocketDirection(direction), endpoint, static_cast<long long>(frame.payloadLength), WebSocketOpcodeName(frame.opcode), detail, frame.payload, previewLength);
        }

        offset += frame.frameLength;
        logged++;
    }

    if (logged == frameLimit && offset < length) {
        LogEvent(api, WebSocketDirection(direction), endpoint, static_cast<long long>(length - offset), "frame-limit", FormatString("remaining=%zu limit=%d", length - offset, frameLimit));
    }

    return logged > 0;
}

void ObserveSocketWebSocketPayload(
    SOCKET socket,
    const char* api,
    const char* direction,
    const std::string& endpoint,
    const void* data,
    size_t length)
{
    if (!g_Config.webSocketCapture || !data || length == 0) {
        return;
    }

    if (PayloadLooksLikeWebSocketHandshake(data, length)) {
        MarkSocketWebSocket(socket);
        LogEvent(api, "websocket-handshake", endpoint, static_cast<long long>(length), DirectionIsOutbound(direction) ? "request" : "response", {}, data, length);
        return;
    }

    if (IsTrackedWebSocketSocket(socket)) {
        LogWebSocketWireFrames(api, direction, endpoint, data, length);
    }
}

void ObserveSocketWebSocketBuffers(
    SOCKET socket,
    const char* api,
    const char* direction,
    const std::string& endpoint,
    LPWSABUF buffers,
    DWORD bufferCount,
    size_t byteLimit)
{
    if (!buffers || bufferCount == 0 || byteLimit == 0) {
        return;
    }

    size_t remaining = byteLimit;
    bool limited = byteLimit != static_cast<size_t>(-1);
    for (DWORD i = 0; i < bufferCount; ++i) {
        if (!buffers[i].buf || buffers[i].len == 0) {
            continue;
        }

        size_t chunk = buffers[i].len;
        if (limited) {
            if (remaining == 0) {
                break;
            }
            chunk = chunk < remaining ? chunk : remaining;
            remaining -= chunk;
        }

        ObserveSocketWebSocketPayload(socket, api, direction, endpoint, buffers[i].buf, chunk);
    }
}

void ObserveOpenSslWebSocketPayload(
    void* ssl,
    const char* api,
    const char* direction,
    const std::string& endpoint,
    const void* data,
    size_t length)
{
    if (!g_Config.webSocketCapture || !ssl || !data || length == 0) {
        return;
    }

    if (PayloadLooksLikeWebSocketHandshake(data, length)) {
        MarkOpenSslWebSocketContext(ssl);
        LogEvent(api, "websocket-handshake", endpoint, static_cast<long long>(length), DirectionIsOutbound(direction) ? "request" : "response", "openssl", data, length);
        return;
    }

    if (IsTrackedOpenSslWebSocketContext(ssl)) {
        LogWebSocketWireFrames(api, direction, endpoint, data, length);
    }
}

void ObserveSchannelWebSocketPayload(
    PCtxtHandle context,
    const char* api,
    const char* direction,
    const std::string& endpoint,
    const void* data,
    size_t length)
{
    if (!g_Config.webSocketCapture || !context || !data || length == 0) {
        return;
    }

    if (PayloadLooksLikeWebSocketHandshake(data, length)) {
        MarkSchannelWebSocketContext(context);
        LogEvent(api, "websocket-handshake", endpoint, static_cast<long long>(length), DirectionIsOutbound(direction) ? "request" : "response", "schannel", data, length);
        return;
    }

    if (IsTrackedSchannelWebSocketContext(context)) {
        LogWebSocketWireFrames(api, direction, endpoint, data, length);
    }
}

// ===================================================================
// Structured event logging
// ===================================================================

void WriteEventJson(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    const EndpointParts& endpointParts,
    long long bytes,
    const std::string& status,
    const std::string& detail,
    const PayloadPreview* payload,
    const CaptureContext& context,
    const std::string& scriptKind)
{
    std::ostringstream json;
    json << "{";
    json << "\"timestamp\":\"" << JsonEscape(Timestamp()) << "\",";
    json << "\"pid\":" << GetCurrentProcessId() << ",";
    json << "\"tid\":" << GetCurrentThreadId() << ",";
    json << "\"api\":\"" << JsonEscape(api ? api : "") << "\",";
    json << "\"direction\":\"" << JsonEscape(direction ? direction : "") << "\",";
    json << "\"endpoint\":\"" << JsonEscape(endpoint) << "\",";
    json << "\"server\":\"" << JsonEscape(endpointParts.server) << "\",";
    json << "\"port\":\"" << JsonEscape(endpointParts.port) << "\",";
    json << "\"bytes\":" << bytes << ",";
    json << "\"status\":\"" << JsonEscape(status) << "\",";
    json << "\"detail\":\"" << JsonEscape(detail) << "\",";
    json << "\"return_site\":\"" << JsonEscape(context.returnSite) << "\",";
    json << "\"script\":\"" << JsonEscape(scriptKind) << "\",";
    json << "\"call_stack\":[";
    for (size_t i = 0; i < context.callStack.size(); ++i) {
        if (i > 0) {
            json << ",";
        }
        json << "\"" << JsonEscape(context.callStack[i]) << "\"";
    }
    json << "]";

    if (payload && payload->previewBytes > 0) {
        json << ",\"preview_bytes\":" << payload->previewBytes;
        json << ",\"truncated\":" << (payload->truncated ? "true" : "false");
        json << ",\"redacted\":" << (payload->redacted ? "true" : "false");
        json << ",\"payload_text\":\"" << JsonEscape(payload->text) << "\"";
        if (!payload->hex.empty()) {
            json << ",\"payload_hex\":\"" << JsonEscape(payload->hex) << "\"";
        }
    }

    json << "}";
    WriteJsonLine(json.str());
}

void LogEvent(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    long long bytes,
    const std::string& status,
    const std::string& detail,
    const void* payloadData,
    size_t payloadLength)
{
    if (!ShouldLog()) {
        return;
    }

    PayloadPreview payload = BuildPayloadPreview(payloadData, payloadLength);
    CaptureContext context = CaptureContextForEvent();
    EndpointParts endpointParts = SplitEndpoint(endpoint);
    std::string scriptKind = !payload.scriptKind.empty() ? payload.scriptKind : context.scriptHint;
    WORD color = ColorForEvent(direction ? direction : "", status, scriptKind);

    std::string message = FormatString(
        "[%s] %s bytes=%lld server=%s port=%s endpoint=%s",
        direction ? direction : "?",
        api ? api : "?",
        bytes,
        endpointParts.server.empty() ? "?" : endpointParts.server.c_str(),
        endpointParts.port.empty() ? "?" : endpointParts.port.c_str(),
        endpoint.empty() ? "?" : endpoint.c_str());

    message += " return=" + context.returnSite;

    if (!scriptKind.empty()) {
        message += " script=" + scriptKind;
    }

    if (!status.empty()) {
        message += " status=" + status;
    }

    if (!detail.empty()) {
        message += " " + detail;
    }

    WriteHumanLine(message, color);

    if (!context.callStack.empty()) {
        WriteHumanLine("  call stack:", color);
        for (size_t i = 0; i < context.callStack.size(); ++i) {
            WriteHumanLine(FormatString("    [%zu] %s", i, context.callStack[i].c_str()), color);
        }
    }

    if (payload.previewBytes > 0) {
        std::string prefix = FormatString(
            "  payload preview=%zu%s%s",
            payload.previewBytes,
            payload.truncated ? " truncated" : "",
            payload.redacted ? " redacted" : "");
        WriteHumanLine(prefix, color);

        if (!payload.text.empty()) {
            WriteHumanLine("  text: " + payload.text, color);
        }

        if (!payload.hex.empty()) {
            WriteHumanLine("  hex: " + payload.hex, color);
        }
    }

    WriteEventJson(api, direction, endpoint, endpointParts, bytes, status, detail, payload.previewBytes > 0 ? &payload : nullptr, context, scriptKind);
}

void LogHeaders(const char* api, const std::string& endpoint, const std::string& headers)
{
    if (!ShouldLog() || !g_Config.logHttpHeaders || headers.empty()) {
        return;
    }

    std::string redacted = RedactHeaders(headers);
    WriteHumanLine(FormatString("%s headers endpoint=%s", api ? api : "?", endpoint.empty() ? "?" : endpoint.c_str()));
    WriteHumanLine(redacted);

    PayloadPreview payload;
    payload.text = redacted;
    payload.previewBytes = redacted.size();
    payload.textLike = true;
    payload.scriptKind = DetectScriptKindFromText(redacted);
    payload.redacted = redacted != headers;
    CaptureContext context = CaptureContextForEvent();
    EndpointParts endpointParts = SplitEndpoint(endpoint);
    std::string scriptKind = !payload.scriptKind.empty() ? payload.scriptKind : context.scriptHint;
    WriteEventJson(api, "headers", endpoint, endpointParts, static_cast<long long>(headers.size()), "ok", "headers", &payload, context, scriptKind);
}

void LogBuffers(const char* api, const char* direction, const std::string& endpoint, LPWSABUF buffers, DWORD count)
{
    if (!buffers || count == 0) {
        LogEvent(api, direction, endpoint, 0);
        return;
    }

    unsigned long long total = 0;
    for (DWORD i = 0; i < count; ++i) {
        total += buffers[i].len;
    }

    LogEvent(api, direction, endpoint, static_cast<long long>(total), "buffers", FormatString("count=%lu", count));
    for (DWORD i = 0; i < count; ++i) {
        if (buffers[i].buf && buffers[i].len > 0) {
            LogEvent(api, direction, endpoint, buffers[i].len, "buffer", FormatString("index=%lu", i), buffers[i].buf, buffers[i].len);
        }
    }
}

unsigned long long FileSizeFromHandle(HANDLE handle)
{
    LARGE_INTEGER size = {};
    if (handle != INVALID_HANDLE_VALUE && GetFileSizeEx(handle, &size)) {
        return static_cast<unsigned long long>(size.QuadPart);
    }
    return 0;
}

std::string FinalPathFromHandle(HANDLE handle)
{
    if (handle == INVALID_HANDLE_VALUE || !handle) {
        return {};
    }

    std::vector<char> path(MAX_PATH * 4);
    DWORD copied = GetFinalPathNameByHandleA(handle, path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED);
    if (copied == 0 || copied >= path.size()) {
        return {};
    }

    std::string value(path.data(), copied);
    const std::string devicePrefix = R"(\\?\)";
    if (value.rfind(devicePrefix, 0) == 0) {
        value.erase(0, devicePrefix.size());
    }
    return value;
}

void TrackScriptFileHandle(HANDLE handle, const std::string& requestedPath, const char* api, DWORD desiredAccess, DWORD creationDisposition)
{
    if (!g_Config.scriptFileCapture || handle == INVALID_HANDLE_VALUE || !handle) {
        return;
    }

    std::string path = requestedPath.empty() ? FinalPathFromHandle(handle) : requestedPath;
    std::string scriptKind = DetectScriptKindFromPath(path);
    if (scriptKind.empty()) {
        return;
    }

    FileHandleInfo info;
    info.path = path;
    info.scriptKind = scriptKind;
    info.fileSize = FileSizeFromHandle(handle);
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        g_FileInfo[handle] = info;
    }

    LogEvent(
        api ? api : "CreateFile",
        "script-file-open",
        path,
        static_cast<long long>(info.fileSize),
        scriptKind,
        FormatString("desired_access=0x%08lX disposition=%lu handle=%p", desiredAccess, creationDisposition, handle));
}

bool GetTrackedFile(HANDLE handle, FileHandleInfo& info)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_FileInfo.find(handle);
    if (it == g_FileInfo.end()) {
        return false;
    }
    info = it->second;
    return true;
}

void UpdateTrackedFileRead(HANDLE handle, DWORD bytesRead)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_FileInfo.find(handle);
    if (it != g_FileInfo.end()) {
        it->second.totalRead += bytesRead;
    }
}

void RemoveTrackedHandle(HANDLE handle)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_FileInfo.erase(handle);
    g_MappingInfo.erase(handle);
}

void TrackScriptMapping(HANDLE mapping, HANDLE file, const char* api, DWORD protect, const std::string& mappingName)
{
    if (!g_Config.scriptFileCapture || !mapping || mapping == INVALID_HANDLE_VALUE) {
        return;
    }

    FileHandleInfo fileInfo;
    if (!GetTrackedFile(file, fileInfo)) {
        return;
    }

    MappingInfo mappingInfo;
    mappingInfo.path = fileInfo.path;
    mappingInfo.scriptKind = fileInfo.scriptKind;
    mappingInfo.fileSize = fileInfo.fileSize;
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        g_MappingInfo[mapping] = mappingInfo;
    }

    LogEvent(
        api ? api : "CreateFileMapping",
        "script-map-create",
        mappingInfo.path,
        static_cast<long long>(mappingInfo.fileSize),
        mappingInfo.scriptKind,
        FormatString("protect=0x%08lX mapping=%p name=%s", protect, mapping, mappingName.empty() ? "?" : mappingName.c_str()));
}

bool GetTrackedMapping(HANDLE mapping, MappingInfo& info)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_MappingInfo.find(mapping);
    if (it == g_MappingInfo.end()) {
        return false;
    }
    info = it->second;
    return true;
}

void TrackMappedView(LPCVOID view, const MappingInfo& mapping, SIZE_T requestedBytes)
{
    if (!view) {
        return;
    }

    ViewInfo viewInfo;
    viewInfo.path = mapping.path;
    viewInfo.scriptKind = mapping.scriptKind;
    viewInfo.viewSize = requestedBytes != 0 ? requestedBytes : static_cast<SIZE_T>(mapping.fileSize);
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        g_ViewInfo[view] = viewInfo;
    }

    SIZE_T previewBytes = viewInfo.viewSize;
    if (g_Config.maxMappedScriptPreviewBytes > 0 && previewBytes > static_cast<SIZE_T>(g_Config.maxMappedScriptPreviewBytes)) {
        previewBytes = static_cast<SIZE_T>(g_Config.maxMappedScriptPreviewBytes);
    }

    LogEvent(
        "MapViewOfFile",
        "script-map-view",
        mapping.path,
        static_cast<long long>(viewInfo.viewSize),
        mapping.scriptKind,
        FormatString("view=%p preview=%zu", view, previewBytes),
        view,
        previewBytes);
}

void RemoveMappedView(LPCVOID view)
{
    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_ViewInfo.erase(view);
}

void TrackOverlappedOperation(
    LPWSAOVERLAPPED overlapped,
    SOCKET socket,
    const char* api,
    const std::string& endpoint,
    bool inbound,
    LPWSABUF buffers,
    DWORD bufferCount,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    if (!overlapped || !buffers || bufferCount == 0) {
        return;
    }

    OverlappedOperation operation;
    operation.api = api ? api : "?";
    operation.endpoint = endpoint;
    operation.socket = socket;
    operation.inbound = inbound;
    operation.completionRoutine = completionRoutine;
    operation.buffers.assign(buffers, buffers + bufferCount);

    std::lock_guard<std::mutex> lock(g_StateMutex);
    g_OverlappedOps[overlapped] = operation;
}

bool TakeOverlappedOperation(LPWSAOVERLAPPED overlapped, OverlappedOperation& operation)
{
    if (!overlapped) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_OverlappedOps.find(overlapped);
    if (it == g_OverlappedOps.end()) {
        return false;
    }

    operation = it->second;
    g_OverlappedOps.erase(it);
    return true;
}

bool FindOverlappedOperation(LPWSAOVERLAPPED overlapped, OverlappedOperation& operation)
{
    if (!overlapped) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_OverlappedOps.find(overlapped);
    if (it == g_OverlappedOps.end()) {
        return false;
    }

    operation = it->second;
    return true;
}

void LogCompletedOverlapped(const OverlappedOperation& operation, DWORD bytesTransferred, const char* completionSource, DWORD errorCode)
{
    std::string direction = operation.inbound ? "async-in" : "async-out";
    LogEvent(
        operation.api.c_str(),
        direction.c_str(),
        operation.endpoint,
        bytesTransferred,
        FormatString("completion=%s error=%lu", completionSource ? completionSource : "?", errorCode));

    if (!operation.inbound || bytesTransferred == 0) {
        return;
    }

    DWORD remaining = bytesTransferred;
    for (size_t i = 0; i < operation.buffers.size() && remaining > 0; ++i) {
        const WSABUF& buffer = operation.buffers[i];
        DWORD chunk = buffer.len < remaining ? buffer.len : remaining;
        if (buffer.buf && chunk > 0) {
            LogEvent(operation.api.c_str(), "async-in", operation.endpoint, chunk, "buffer", FormatString("index=%zu", i), buffer.buf, chunk);
            ObserveSocketWebSocketPayload(operation.socket, operation.api.c_str(), "async-in", operation.endpoint, buffer.buf, chunk);
        }
        remaining -= chunk;
    }
}

void CALLBACK Hook_WSACompletionRoutine(DWORD error, DWORD bytesTransferred, LPWSAOVERLAPPED overlapped, DWORD flags)
{
    OverlappedOperation operation;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE original = nullptr;
    if (TakeOverlappedOperation(overlapped, operation)) {
        original = operation.completionRoutine;
        LogCompletedOverlapped(operation, bytesTransferred, "completion-routine", error);
    }

    if (original) {
        original(error, bytesTransferred, overlapped, flags);
    }
}

// ===================================================================
// Hook Functions - Script File / Mapping Capture
// ===================================================================

HANDLE WINAPI Hook_CreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
{
    SOCKETU_GUARD_RETURN(Real_CreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile));
    HANDLE handle = Real_CreateFileA(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    TrackScriptFileHandle(handle, fileName ? fileName : "", "CreateFileA", desiredAccess, creationDisposition);
    return handle;
}

HANDLE WINAPI Hook_CreateFileW(LPCWSTR fileName, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
{
    SOCKETU_GUARD_RETURN(Real_CreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile));
    HANDLE handle = Real_CreateFileW(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
    TrackScriptFileHandle(handle, WideToUtf8(fileName), "CreateFileW", desiredAccess, creationDisposition);
    return handle;
}

BOOL WINAPI Hook_ReadFile(HANDLE file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead, LPOVERLAPPED overlapped)
{
    SOCKETU_GUARD_RETURN(Real_ReadFile(file, buffer, bytesToRead, bytesRead, overlapped));
    FileHandleInfo info;
    bool tracked = GetTrackedFile(file, info);
    BOOL result = Real_ReadFile(file, buffer, bytesToRead, bytesRead, overlapped);
    DWORD actual = bytesRead ? *bytesRead : 0;

    if (tracked) {
        unsigned long long offset = info.totalRead;
        if (overlapped) {
            ULARGE_INTEGER overlappedOffset = {};
            overlappedOffset.LowPart = overlapped->Offset;
            overlappedOffset.HighPart = overlapped->OffsetHigh;
            offset = overlappedOffset.QuadPart;
        }

        if (result && actual > 0) {
            LogEvent(
                "ReadFile",
                "script-file-read",
                info.path,
                actual,
                info.scriptKind,
                FormatString("offset=%llu requested=%lu overlapped=%s", offset, bytesToRead, overlapped ? "yes" : "no"),
                buffer,
                actual);
            if (!overlapped) {
                UpdateTrackedFileRead(file, actual);
            }
        }
        else {
            LogEvent(
                "ReadFile",
                "script-file-read",
                info.path,
                actual,
                result ? info.scriptKind : FormatString("failed=%lu", GetLastError()),
                FormatString("offset=%llu requested=%lu overlapped=%s", offset, bytesToRead, overlapped ? "yes" : "no"));
        }
    }

    return result;
}

HANDLE WINAPI Hook_CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES attributes, DWORD protect, DWORD maxSizeHigh, DWORD maxSizeLow, LPCSTR name)
{
    SOCKETU_GUARD_RETURN(Real_CreateFileMappingA(file, attributes, protect, maxSizeHigh, maxSizeLow, name));
    HANDLE mapping = Real_CreateFileMappingA(file, attributes, protect, maxSizeHigh, maxSizeLow, name);
    TrackScriptMapping(mapping, file, "CreateFileMappingA", protect, name ? name : "");
    return mapping;
}

HANDLE WINAPI Hook_CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES attributes, DWORD protect, DWORD maxSizeHigh, DWORD maxSizeLow, LPCWSTR name)
{
    SOCKETU_GUARD_RETURN(Real_CreateFileMappingW(file, attributes, protect, maxSizeHigh, maxSizeLow, name));
    HANDLE mapping = Real_CreateFileMappingW(file, attributes, protect, maxSizeHigh, maxSizeLow, name);
    TrackScriptMapping(mapping, file, "CreateFileMappingW", protect, WideToUtf8(name));
    return mapping;
}

LPVOID WINAPI Hook_MapViewOfFile(HANDLE mapping, DWORD desiredAccess, DWORD fileOffsetHigh, DWORD fileOffsetLow, SIZE_T bytesToMap)
{
    SOCKETU_GUARD_RETURN(Real_MapViewOfFile(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap));
    LPVOID view = Real_MapViewOfFile(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap);
    MappingInfo info;
    if (view && GetTrackedMapping(mapping, info)) {
        ULARGE_INTEGER offset = {};
        offset.LowPart = fileOffsetLow;
        offset.HighPart = fileOffsetHigh;
        LogEvent("MapViewOfFile", "script-map", info.path, static_cast<long long>(bytesToMap), info.scriptKind, FormatString("offset=%llu access=0x%08lX view=%p", offset.QuadPart, desiredAccess, view));
        TrackMappedView(view, info, bytesToMap);
    }
    return view;
}

LPVOID WINAPI Hook_MapViewOfFileEx(HANDLE mapping, DWORD desiredAccess, DWORD fileOffsetHigh, DWORD fileOffsetLow, SIZE_T bytesToMap, LPVOID baseAddress)
{
    SOCKETU_GUARD_RETURN(Real_MapViewOfFileEx(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap, baseAddress));
    LPVOID view = Real_MapViewOfFileEx(mapping, desiredAccess, fileOffsetHigh, fileOffsetLow, bytesToMap, baseAddress);
    MappingInfo info;
    if (view && GetTrackedMapping(mapping, info)) {
        ULARGE_INTEGER offset = {};
        offset.LowPart = fileOffsetLow;
        offset.HighPart = fileOffsetHigh;
        LogEvent("MapViewOfFileEx", "script-map", info.path, static_cast<long long>(bytesToMap), info.scriptKind, FormatString("offset=%llu access=0x%08lX view=%p requested_base=%p", offset.QuadPart, desiredAccess, view, baseAddress));
        TrackMappedView(view, info, bytesToMap);
    }
    return view;
}

BOOL WINAPI Hook_UnmapViewOfFile(LPCVOID baseAddress)
{
    SOCKETU_GUARD_RETURN(Real_UnmapViewOfFile(baseAddress));
    ViewInfo info;
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        auto it = g_ViewInfo.find(baseAddress);
        if (it != g_ViewInfo.end()) {
            info = it->second;
        }
    }

    BOOL result = Real_UnmapViewOfFile(baseAddress);
    if (!info.path.empty()) {
        LogEvent("UnmapViewOfFile", "script-map-close", info.path, static_cast<long long>(info.viewSize), result ? info.scriptKind : FormatString("failed=%lu", GetLastError()), FormatString("view=%p", baseAddress));
        if (result) {
            RemoveMappedView(baseAddress);
        }
    }
    return result;
}

BOOL WINAPI Hook_CloseHandle(HANDLE handle)
{
    SOCKETU_GUARD_RETURN(Real_CloseHandle(handle));
    FileHandleInfo fileInfo;
    MappingInfo mappingInfo;
    bool hadFile = GetTrackedFile(handle, fileInfo);
    bool hadMapping = GetTrackedMapping(handle, mappingInfo);

    BOOL result = Real_CloseHandle(handle);
    if (hadFile) {
        LogEvent("CloseHandle", "script-file-close", fileInfo.path, static_cast<long long>(fileInfo.totalRead), result ? fileInfo.scriptKind : FormatString("failed=%lu", GetLastError()), FormatString("handle=%p file_size=%llu", handle, fileInfo.fileSize));
    }
    if (hadMapping) {
        LogEvent("CloseHandle", "script-map-close", mappingInfo.path, static_cast<long long>(mappingInfo.fileSize), result ? mappingInfo.scriptKind : FormatString("failed=%lu", GetLastError()), FormatString("mapping=%p", handle));
    }
    if (result) {
        RemoveTrackedHandle(handle);
    }
    return result;
}

// ===================================================================
// Hook Functions - Winsock / DNS
// ===================================================================

int WINAPI Hook_connect(SOCKET socket, const sockaddr* name, int namelen)
{
    SOCKETU_GUARD_RETURN(Real_connect(socket, name, namelen));
    std::string endpoint = EndpointFromSockaddr(name, namelen);
    TrackSocket(socket, endpoint);
    LogEvent("connect", "out", endpoint, 0);
    return Real_connect(socket, name, namelen);
}

int WINAPI Hook_WSAConnect(SOCKET socket, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos)
{
    SOCKETU_GUARD_RETURN(Real_WSAConnect(socket, name, namelen, callerData, calleeData, sqos, gqos));
    std::string endpoint = EndpointFromSockaddr(name, namelen);
    TrackSocket(socket, endpoint);
    LogEvent("WSAConnect", "out", endpoint, 0);
    if (callerData && callerData->buf && callerData->len > 0) {
        LogEvent("WSAConnect", "out", endpoint, callerData->len, "caller-data", {}, callerData->buf, callerData->len);
    }
    return Real_WSAConnect(socket, name, namelen, callerData, calleeData, sqos, gqos);
}

int WINAPI Hook_send(SOCKET socket, const char* buffer, int length, int flags)
{
    SOCKETU_GUARD_RETURN(Real_send(socket, buffer, length, flags));
    std::string endpoint = SocketEndpoint(socket);
    LogEvent("send", "out", endpoint, length, FormatString("flags=%d", flags), {}, buffer, length > 0 ? static_cast<size_t>(length) : 0);
    if (length > 0) {
        ObserveSocketWebSocketPayload(socket, "send", "out", endpoint, buffer, static_cast<size_t>(length));
    }
    return Real_send(socket, buffer, length, flags);
}

int WINAPI Hook_recv(SOCKET socket, char* buffer, int length, int flags)
{
    SOCKETU_GUARD_RETURN(Real_recv(socket, buffer, length, flags));
    int result = Real_recv(socket, buffer, length, flags);
    if (result > 0) {
        std::string endpoint = SocketEndpoint(socket);
        LogEvent("recv", "in", endpoint, result, FormatString("flags=%d", flags), {}, buffer, static_cast<size_t>(result));
        ObserveSocketWebSocketPayload(socket, "recv", "in", endpoint, buffer, static_cast<size_t>(result));
    }
    else {
        LogEvent("recv", "in", SocketEndpoint(socket), result, FormatString("flags=%d", flags));
    }
    return result;
}

int WINAPI Hook_sendto(SOCKET socket, const char* buffer, int length, int flags, const sockaddr* to, int tolen)
{
    SOCKETU_GUARD_RETURN(Real_sendto(socket, buffer, length, flags, to, tolen));
    std::string endpoint = EndpointFromSockaddr(to, tolen);
    LogEvent("sendto", "out", endpoint, length, FormatString("flags=%d", flags), {}, buffer, length > 0 ? static_cast<size_t>(length) : 0);
    return Real_sendto(socket, buffer, length, flags, to, tolen);
}

int WINAPI Hook_recvfrom(SOCKET socket, char* buffer, int length, int flags, sockaddr* from, int* fromlen)
{
    SOCKETU_GUARD_RETURN(Real_recvfrom(socket, buffer, length, flags, from, fromlen));
    int result = Real_recvfrom(socket, buffer, length, flags, from, fromlen);
    std::string endpoint = (from && fromlen && *fromlen > 0) ? EndpointFromSockaddr(from, *fromlen) : SocketEndpoint(socket);
    if (result > 0) {
        LogEvent("recvfrom", "in", endpoint, result, FormatString("flags=%d", flags), {}, buffer, static_cast<size_t>(result));
    }
    else {
        LogEvent("recvfrom", "in", endpoint, result, FormatString("flags=%d", flags));
    }
    return result;
}

int WINAPI Hook_WSASend(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    SOCKETU_GUARD_RETURN(Real_WSASend(socket, buffers, bufferCount, bytesSent, flags, overlapped, completionRoutine));
    std::string endpoint = SocketEndpoint(socket);
    LogBuffers("WSASend", "out", endpoint, buffers, bufferCount);
    ObserveSocketWebSocketBuffers(socket, "WSASend", "out", endpoint, buffers, bufferCount, static_cast<size_t>(-1));
    if (overlapped) {
        TrackOverlappedOperation(overlapped, socket, "WSASend", endpoint, false, buffers, bufferCount, completionRoutine);
    }
    int result = Real_WSASend(socket, buffers, bufferCount, bytesSent, flags, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    LogEvent("WSASend", "result", endpoint, bytesSent ? *bytesSent : 0, FormatString("result=%d flags=%lu overlapped=%s", result, flags, overlapped ? "yes" : "no"));
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        OverlappedOperation ignored;
        TakeOverlappedOperation(overlapped, ignored);
    }
    return result;
}

int WINAPI Hook_WSARecv(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesReceived, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    SOCKETU_GUARD_RETURN(Real_WSARecv(socket, buffers, bufferCount, bytesReceived, flags, overlapped, completionRoutine));
    std::string endpoint = SocketEndpoint(socket);
    if (overlapped) {
        TrackOverlappedOperation(overlapped, socket, "WSARecv", endpoint, true, buffers, bufferCount, completionRoutine);
    }
    int result = Real_WSARecv(socket, buffers, bufferCount, bytesReceived, flags, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    DWORD received = bytesReceived ? *bytesReceived : 0;

    if (result == 0 && received > 0 && buffers) {
        DWORD remaining = received;
        for (DWORD i = 0; i < bufferCount && remaining > 0; ++i) {
            DWORD chunk = buffers[i].len < remaining ? buffers[i].len : remaining;
            if (buffers[i].buf && chunk > 0) {
                LogEvent("WSARecv", "in", endpoint, chunk, "buffer", FormatString("index=%lu", i), buffers[i].buf, chunk);
                ObserveSocketWebSocketPayload(socket, "WSARecv", "in", endpoint, buffers[i].buf, chunk);
            }
            remaining -= chunk;
        }
    }
    else {
        LogEvent("WSARecv", "in", endpoint, received, FormatString("result=%d overlapped=%s", result, overlapped ? "yes" : "no"));
    }

    if (overlapped && result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        OverlappedOperation ignored;
        TakeOverlappedOperation(overlapped, ignored);
    }
    else if (overlapped && result == 0) {
        OverlappedOperation ignored;
        TakeOverlappedOperation(overlapped, ignored);
    }

    return result;
}

SOCKET WINAPI Hook_WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA protocolInfo, GROUP group, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_WSASocketA(af, type, protocol, protocolInfo, group, flags));
    SOCKET socket = Real_WSASocketA(af, type, protocol, protocolInfo, group, flags);
    LogEvent("WSASocketA", "create", "?", socket == INVALID_SOCKET ? -1 : 0, FormatString("socket=%llu af=%d type=%d protocol=%d flags=%lu", static_cast<unsigned long long>(socket), af, type, protocol, flags));
    return socket;
}

SOCKET WINAPI Hook_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW protocolInfo, GROUP group, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_WSASocketW(af, type, protocol, protocolInfo, group, flags));
    SOCKET socket = Real_WSASocketW(af, type, protocol, protocolInfo, group, flags);
    LogEvent("WSASocketW", "create", "?", socket == INVALID_SOCKET ? -1 : 0, FormatString("socket=%llu af=%d type=%d protocol=%d flags=%lu", static_cast<unsigned long long>(socket), af, type, protocol, flags));
    return socket;
}

BOOL PASCAL Hook_ConnectEx(SOCKET socket, const sockaddr* name, int namelen, PVOID sendBuffer, DWORD sendDataLength, LPDWORD bytesSent, LPOVERLAPPED overlapped)
{
    SOCKETU_GUARD_RETURN(Real_ConnectEx(socket, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped));
    std::string endpoint = EndpointFromSockaddr(name, namelen);
    TrackSocket(socket, endpoint);
    if (sendBuffer && sendDataLength > 0) {
        LogEvent("ConnectEx", "out", endpoint, sendDataLength, "initial-data", {}, sendBuffer, sendDataLength);
    }
    else {
        LogEvent("ConnectEx", "out", endpoint, 0);
    }
    return Real_ConnectEx(socket, name, namelen, sendBuffer, sendDataLength, bytesSent, overlapped);
}

BOOL PASCAL Hook_AcceptEx(SOCKET listenSocket, SOCKET acceptSocket, PVOID outputBuffer, DWORD receiveDataLength, DWORD localAddressLength, DWORD remoteAddressLength, LPDWORD bytesReceived, LPOVERLAPPED overlapped)
{
    SOCKETU_GUARD_RETURN(Real_AcceptEx(listenSocket, acceptSocket, outputBuffer, receiveDataLength, localAddressLength, remoteAddressLength, bytesReceived, overlapped));
    std::string endpoint = SocketEndpoint(listenSocket);
    BOOL result = Real_AcceptEx(listenSocket, acceptSocket, outputBuffer, receiveDataLength, localAddressLength, remoteAddressLength, bytesReceived, overlapped);
    if (result && outputBuffer && bytesReceived && *bytesReceived > 0) {
        LogEvent("AcceptEx", "in", endpoint, *bytesReceived, "initial-data", {}, outputBuffer, *bytesReceived);
    }
    else {
        LogEvent("AcceptEx", "accept", endpoint, bytesReceived ? *bytesReceived : 0, result ? "ok" : FormatString("pending_or_failed=%lu", WSAGetLastError()));
    }
    return result;
}

int WSAAPI Hook_WSASendMsg(SOCKET socket, LPWSAMSG message, DWORD flags, LPDWORD bytesSent, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    SOCKETU_GUARD_RETURN(Real_WSASendMsg(socket, message, flags, bytesSent, overlapped, completionRoutine));
    std::string endpoint = SocketEndpoint(socket);
    if (message) {
        LogBuffers("WSASendMsg", "out", endpoint, message->lpBuffers, message->dwBufferCount);
        ObserveSocketWebSocketBuffers(socket, "WSASendMsg", "out", endpoint, message->lpBuffers, message->dwBufferCount, static_cast<size_t>(-1));
        if (overlapped) {
            TrackOverlappedOperation(overlapped, socket, "WSASendMsg", endpoint, false, message->lpBuffers, message->dwBufferCount, completionRoutine);
        }
    }

    int result = Real_WSASendMsg(socket, message, flags, bytesSent, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    LogEvent("WSASendMsg", "result", endpoint, bytesSent ? *bytesSent : 0, FormatString("result=%d flags=%lu overlapped=%s", result, flags, overlapped ? "yes" : "no"));
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        OverlappedOperation ignored;
        TakeOverlappedOperation(overlapped, ignored);
    }
    return result;
}

int WSAAPI Hook_WSARecvMsg(SOCKET socket, LPWSAMSG message, LPDWORD bytesReceived, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    SOCKETU_GUARD_RETURN(Real_WSARecvMsg(socket, message, bytesReceived, overlapped, completionRoutine));
    std::string endpoint = SocketEndpoint(socket);
    if (message && overlapped) {
        TrackOverlappedOperation(overlapped, socket, "WSARecvMsg", endpoint, true, message->lpBuffers, message->dwBufferCount, completionRoutine);
    }

    int result = Real_WSARecvMsg(socket, message, bytesReceived, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    DWORD received = bytesReceived ? *bytesReceived : 0;
    if (result == 0 && received > 0 && message) {
        DWORD remaining = received;
        for (DWORD i = 0; i < message->dwBufferCount && remaining > 0; ++i) {
            DWORD chunk = message->lpBuffers[i].len < remaining ? message->lpBuffers[i].len : remaining;
            if (message->lpBuffers[i].buf && chunk > 0) {
                LogEvent("WSARecvMsg", "in", endpoint, chunk, "buffer", FormatString("index=%lu", i), message->lpBuffers[i].buf, chunk);
                ObserveSocketWebSocketPayload(socket, "WSARecvMsg", "in", endpoint, message->lpBuffers[i].buf, chunk);
            }
            remaining -= chunk;
        }
    }
    else {
        LogEvent("WSARecvMsg", "in", endpoint, received, FormatString("result=%d overlapped=%s", result, overlapped ? "yes" : "no"));
    }

    if (overlapped && ((result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) || result == 0)) {
        OverlappedOperation ignored;
        TakeOverlappedOperation(overlapped, ignored);
    }
    return result;
}

void ReplaceExtensionFunctionPointer(LPVOID outBuffer, DWORD outBufferLength, const GUID& extensionId)
{
    if (!outBuffer || outBufferLength < sizeof(LPVOID)) {
        return;
    }

    LPVOID* functionPointer = static_cast<LPVOID*>(outBuffer);
    if (IsEqualGUID(extensionId, WSAID_CONNECTEX)) {
        Real_ConnectEx = reinterpret_cast<LPFN_CONNECTEX>(*functionPointer);
        *functionPointer = reinterpret_cast<LPVOID>(Hook_ConnectEx);
        LogEvent("WSAIoctl", "extension", "ConnectEx", 0, "replaced");
    }
    else if (IsEqualGUID(extensionId, WSAID_ACCEPTEX)) {
        Real_AcceptEx = reinterpret_cast<LPFN_ACCEPTEX>(*functionPointer);
        *functionPointer = reinterpret_cast<LPVOID>(Hook_AcceptEx);
        LogEvent("WSAIoctl", "extension", "AcceptEx", 0, "replaced");
    }
    else if (IsEqualGUID(extensionId, WSAID_WSASENDMSG)) {
        Real_WSASendMsg = reinterpret_cast<LPFN_WSASENDMSG>(*functionPointer);
        *functionPointer = reinterpret_cast<LPVOID>(Hook_WSASendMsg);
        LogEvent("WSAIoctl", "extension", "WSASendMsg", 0, "replaced");
    }
    else if (IsEqualGUID(extensionId, WSAID_WSARECVMSG)) {
        Real_WSARecvMsg = reinterpret_cast<LPFN_WSARECVMSG>(*functionPointer);
        *functionPointer = reinterpret_cast<LPVOID>(Hook_WSARecvMsg);
        LogEvent("WSAIoctl", "extension", "WSARecvMsg", 0, "replaced");
    }
}

int WINAPI Hook_WSAIoctl(SOCKET socket, DWORD controlCode, LPVOID inBuffer, DWORD inBufferLength, LPVOID outBuffer, DWORD outBufferLength, LPDWORD bytesReturned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    SOCKETU_GUARD_RETURN(Real_WSAIoctl(socket, controlCode, inBuffer, inBufferLength, outBuffer, outBufferLength, bytesReturned, overlapped, completionRoutine));
    int result = Real_WSAIoctl(socket, controlCode, inBuffer, inBufferLength, outBuffer, outBufferLength, bytesReturned, overlapped, completionRoutine);
    if (result == 0 && controlCode == SIO_GET_EXTENSION_FUNCTION_POINTER && inBuffer && inBufferLength >= sizeof(GUID)) {
        ReplaceExtensionFunctionPointer(outBuffer, outBufferLength, *static_cast<GUID*>(inBuffer));
    }
    return result;
}

BOOL WINAPI Hook_WSAGetOverlappedResult(SOCKET socket, LPWSAOVERLAPPED overlapped, LPDWORD bytesTransferred, BOOL wait, LPDWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_WSAGetOverlappedResult(socket, overlapped, bytesTransferred, wait, flags));
    BOOL result = Real_WSAGetOverlappedResult(socket, overlapped, bytesTransferred, wait, flags);
    if (result && bytesTransferred) {
        OverlappedOperation operation;
        if (TakeOverlappedOperation(overlapped, operation)) {
            LogCompletedOverlapped(operation, *bytesTransferred, "WSAGetOverlappedResult", 0);
        }
    }
    return result;
}

BOOL WINAPI Hook_GetOverlappedResult(HANDLE file, LPOVERLAPPED overlapped, LPDWORD bytesTransferred, BOOL wait)
{
    SOCKETU_GUARD_RETURN(Real_GetOverlappedResult(file, overlapped, bytesTransferred, wait));
    BOOL result = Real_GetOverlappedResult(file, overlapped, bytesTransferred, wait);
    if (result && bytesTransferred) {
        OverlappedOperation operation;
        if (TakeOverlappedOperation(reinterpret_cast<LPWSAOVERLAPPED>(overlapped), operation)) {
            LogCompletedOverlapped(operation, *bytesTransferred, "GetOverlappedResult", 0);
        }
    }
    return result;
}

BOOL WINAPI Hook_GetQueuedCompletionStatus(HANDLE completionPort, LPDWORD bytesTransferred, PULONG_PTR completionKey, LPOVERLAPPED* overlapped, DWORD milliseconds)
{
    SOCKETU_GUARD_RETURN(Real_GetQueuedCompletionStatus(completionPort, bytesTransferred, completionKey, overlapped, milliseconds));
    BOOL result = Real_GetQueuedCompletionStatus(completionPort, bytesTransferred, completionKey, overlapped, milliseconds);
    if (overlapped && *overlapped && bytesTransferred) {
        OverlappedOperation operation;
        if (TakeOverlappedOperation(reinterpret_cast<LPWSAOVERLAPPED>(*overlapped), operation)) {
            LogCompletedOverlapped(operation, *bytesTransferred, "GetQueuedCompletionStatus", result ? 0 : GetLastError());
        }
    }
    return result;
}

BOOL WINAPI Hook_GetQueuedCompletionStatusEx(HANDLE completionPort, LPOVERLAPPED_ENTRY entries, ULONG count, PULONG removed, DWORD milliseconds, BOOL alertable)
{
    SOCKETU_GUARD_RETURN(Real_GetQueuedCompletionStatusEx(completionPort, entries, count, removed, milliseconds, alertable));
    BOOL result = Real_GetQueuedCompletionStatusEx(completionPort, entries, count, removed, milliseconds, alertable);
    ULONG completed = result && removed ? *removed : 0;
    for (ULONG i = 0; i < completed; ++i) {
        OverlappedOperation operation;
        if (entries[i].lpOverlapped && TakeOverlappedOperation(reinterpret_cast<LPWSAOVERLAPPED>(entries[i].lpOverlapped), operation)) {
            LogCompletedOverlapped(operation, static_cast<DWORD>(entries[i].dwNumberOfBytesTransferred), "GetQueuedCompletionStatusEx", 0);
        }
    }
    return result;
}

int WINAPI Hook_closesocket(SOCKET socket)
{
    SOCKETU_GUARD_RETURN(Real_closesocket(socket));
    std::string endpoint = SocketEndpoint(socket);
    int result = Real_closesocket(socket);
    LogEvent("closesocket", "close", endpoint, 0, FormatString("result=%d", result));
    {
        std::lock_guard<std::mutex> lock(g_StateMutex);
        g_SocketToHost.erase(socket);
        g_WebSocketSockets.erase(socket);
    }
    return result;
}

int WINAPI Hook_shutdown(SOCKET socket, int how)
{
    SOCKETU_GUARD_RETURN(Real_shutdown(socket, how));
    std::string endpoint = SocketEndpoint(socket);
    int result = Real_shutdown(socket, how);
    LogEvent("shutdown", "close", endpoint, 0, FormatString("how=%d result=%d", how, result));
    return result;
}

int WINAPI Hook_bind(SOCKET socket, const sockaddr* name, int namelen)
{
    SOCKETU_GUARD_RETURN(Real_bind(socket, name, namelen));
    std::string endpoint = EndpointFromSockaddr(name, namelen);
    TrackSocket(socket, endpoint);
    LogEvent("bind", "listen", endpoint, 0);
    return Real_bind(socket, name, namelen);
}

int WINAPI Hook_listen(SOCKET socket, int backlog)
{
    SOCKETU_GUARD_RETURN(Real_listen(socket, backlog));
    std::string endpoint = SocketEndpoint(socket);
    LogEvent("listen", "listen", endpoint, 0, FormatString("backlog=%d", backlog));
    return Real_listen(socket, backlog);
}

SOCKET WINAPI Hook_accept(SOCKET socket, sockaddr* address, int* addressLength)
{
    SOCKETU_GUARD_RETURN(Real_accept(socket, address, addressLength));
    SOCKET accepted = Real_accept(socket, address, addressLength);
    std::string endpoint = (accepted != INVALID_SOCKET && address && addressLength && *addressLength > 0) ? EndpointFromSockaddr(address, *addressLength) : SocketEndpoint(socket);
    TrackSocket(accepted, endpoint);
    LogEvent("accept", "in", endpoint, accepted == INVALID_SOCKET ? -1 : 0, FormatString("accepted=%llu", static_cast<unsigned long long>(accepted)));
    return accepted;
}

int WINAPI Hook_getaddrinfo(PCSTR nodeName, PCSTR serviceName, const ADDRINFOA* hints, PADDRINFOA* result)
{
    SOCKETU_GUARD_RETURN(Real_getaddrinfo(nodeName, serviceName, hints, result));
    int status = Real_getaddrinfo(nodeName, serviceName, hints, result);
    LogEvent("getaddrinfo", "dns", nodeName ? nodeName : "?", 0, FormatString("status=%d service=%s", status, serviceName ? serviceName : ""));
    return status;
}

int WINAPI Hook_GetAddrInfoW(PCWSTR nodeName, PCWSTR serviceName, const ADDRINFOW* hints, PADDRINFOW* result)
{
    SOCKETU_GUARD_RETURN(Real_GetAddrInfoW(nodeName, serviceName, hints, result));
    int status = Real_GetAddrInfoW(nodeName, serviceName, hints, result);
    LogEvent("GetAddrInfoW", "dns", WideToUtf8(nodeName), 0, FormatString("status=%d service=%s", status, WideToUtf8(serviceName).c_str()));
    return status;
}

// ===================================================================
// Hook Functions - WinHTTP
// ===================================================================

HINTERNET WINAPI Hook_WinHttpOpen(LPCWSTR userAgent, DWORD accessType, LPCWSTR proxyName, LPCWSTR proxyBypass, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpOpen(userAgent, accessType, proxyName, proxyBypass, flags));
    HINTERNET session = Real_WinHttpOpen(userAgent, accessType, proxyName, proxyBypass, flags);
    LogEvent("WinHttpOpen", "open", "?", 0, session ? "ok" : "failed", FormatString("user_agent=%s", WideToUtf8(userAgent).c_str()));
    return session;
}

HINTERNET WINAPI Hook_WinHttpConnect(HINTERNET session, LPCWSTR serverName, INTERNET_PORT serverPort, DWORD reserved)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpConnect(session, serverName, serverPort, reserved));
    HINTERNET connection = Real_WinHttpConnect(session, serverName, serverPort, reserved);
    HttpHandleInfo info;
    info.kind = "winhttp-connect";
    info.host = WideToUtf8(serverName);
    info.port = serverPort;
    TrackHandle(connection, info);
    LogEvent("WinHttpConnect", "connect", EndpointFromHttpInfo(info), 0, connection ? "ok" : "failed");
    return connection;
}

HINTERNET WINAPI Hook_WinHttpOpenRequest(HINTERNET connection, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpOpenRequest(connection, verb, objectName, version, referrer, acceptTypes, flags));
    HINTERNET request = Real_WinHttpOpenRequest(connection, verb, objectName, version, referrer, acceptTypes, flags);
    HttpHandleInfo parent = GetHandleInfo(connection);
    HttpHandleInfo info = parent;
    info.kind = "winhttp-request";
    info.method = WideToUtf8(verb);
    info.path = WideToUtf8(objectName);
    info.secure = (flags & WINHTTP_FLAG_SECURE) != 0;
    TrackHandle(request, info);
    LogEvent("WinHttpOpenRequest", "open", EndpointFromHttpInfo(info), 0, request ? "ok" : "failed", FormatString("method=%s secure=%s", info.method.c_str(), info.secure ? "yes" : "no"));
    return request;
}

BOOL WINAPI Hook_WinHttpSendRequest(HINTERNET request, LPCWSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength, DWORD totalLength, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpSendRequest(request, headers, headersLength, optional, optionalLength, totalLength, context));
    HttpHandleInfo info = GetHandleInfo(request);
    std::string endpoint = EndpointFromHttpInfo(info);
    std::string headerText = WideToUtf8(headers, headersLength == static_cast<DWORD>(-1) ? -1 : static_cast<int>(headersLength));
    if (TextContainsWebSocketUpgrade(headerText)) {
        info.webSocketUpgrade = true;
        TrackHandle(request, info);
    }
    LogHeaders("WinHttpSendRequest", endpoint, headerText);
    if (optional && optionalLength > 0) {
        LogEvent("WinHttpSendRequest", "out", endpoint, optionalLength, FormatString("total=%lu method=%s", totalLength, info.method.c_str()), {}, optional, optionalLength);
    }
    else {
        LogEvent("WinHttpSendRequest", "out", endpoint, 0, FormatString("total=%lu method=%s", totalLength, info.method.c_str()));
    }
    return Real_WinHttpSendRequest(request, headers, headersLength, optional, optionalLength, totalLength, context);
}

BOOL WINAPI Hook_WinHttpReceiveResponse(HINTERNET request, LPVOID reserved)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpReceiveResponse(request, reserved));
    BOOL result = Real_WinHttpReceiveResponse(request, reserved);
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    LogEvent("WinHttpReceiveResponse", "response", endpoint, 0, result ? "ok" : FormatString("failed=%lu", GetLastError()));
    return result;
}

BOOL WINAPI Hook_WinHttpQueryHeaders(HINTERNET request, DWORD infoLevel, LPCWSTR name, LPVOID buffer, LPDWORD bufferLength, LPDWORD index)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpQueryHeaders(request, infoLevel, name, buffer, bufferLength, index));
    BOOL result = Real_WinHttpQueryHeaders(request, infoLevel, name, buffer, bufferLength, index);
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    if (result && buffer && bufferLength && !(infoLevel & WINHTTP_QUERY_FLAG_NUMBER)) {
        DWORD chars = *bufferLength / sizeof(wchar_t);
        std::string headers = WideToUtf8(static_cast<LPCWSTR>(buffer), static_cast<int>(chars));
        LogHeaders("WinHttpQueryHeaders", endpoint, headers);
    }
    else {
        LogEvent("WinHttpQueryHeaders", "headers", endpoint, bufferLength ? *bufferLength : 0, result ? "ok" : FormatString("failed=%lu", GetLastError()), FormatString("level=0x%08lX", infoLevel));
    }
    return result;
}

BOOL WINAPI Hook_WinHttpReadData(HINTERNET request, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpReadData(request, buffer, bytesToRead, bytesRead));
    BOOL result = Real_WinHttpReadData(request, buffer, bytesToRead, bytesRead);
    DWORD read = bytesRead ? *bytesRead : 0;
    HttpHandleInfo info = GetHandleInfo(request);
    std::string endpoint = EndpointFromHttpInfo(info);
    if (result && read > 0) {
        LogEvent("WinHttpReadData", "in", endpoint, read, "ok", {}, buffer, read);
        if (info.webSocketUpgrade) {
            LogWebSocketWireFrames("WinHttpReadData", "in", endpoint, buffer, read);
        }
    }
    else {
        LogEvent("WinHttpReadData", "in", endpoint, read, result ? "ok" : "failed");
    }
    return result;
}

BOOL WINAPI Hook_WinHttpWriteData(HINTERNET request, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWriteData(request, buffer, bytesToWrite, bytesWritten));
    HttpHandleInfo info = GetHandleInfo(request);
    std::string endpoint = EndpointFromHttpInfo(info);
    LogEvent("WinHttpWriteData", "out", endpoint, bytesToWrite, "before-call", {}, buffer, bytesToWrite);
    if (info.webSocketUpgrade) {
        LogWebSocketWireFrames("WinHttpWriteData", "out", endpoint, buffer, bytesToWrite);
    }
    BOOL result = Real_WinHttpWriteData(request, buffer, bytesToWrite, bytesWritten);
    LogEvent("WinHttpWriteData", "result", endpoint, bytesWritten ? *bytesWritten : 0, result ? "ok" : "failed");
    return result;
}

BOOL WINAPI Hook_WinHttpSetOption(HINTERNET handle, DWORD option, LPVOID buffer, DWORD bufferLength)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpSetOption(handle, option, buffer, bufferLength));
    BOOL result = Real_WinHttpSetOption(handle, option, buffer, bufferLength);
    if (option == WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET) {
        MarkHttpHandleWebSocketUpgrade(handle);
        std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(handle));
        LogEvent(
            "WinHttpSetOption",
            "websocket-upgrade",
            endpoint,
            bufferLength,
            result ? "ok" : FormatString("failed=%lu", GetLastError()),
            FormatString("option=WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET buffer=%p", buffer));
    }
    return result;
}

HINTERNET WINAPI Hook_WinHttpWebSocketCompleteUpgrade(HINTERNET request, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketCompleteUpgrade(request, context));
    HttpHandleInfo info = GetHandleInfo(request);
    info.kind = "winhttp-websocket";
    info.webSocketUpgrade = true;
    if (info.method.empty()) {
        info.method = "GET";
    }

    HINTERNET webSocket = Real_WinHttpWebSocketCompleteUpgrade(request, context);
    if (webSocket) {
        TrackHandle(webSocket, info);
    }

    LogEvent(
        "WinHttpWebSocketCompleteUpgrade",
        "websocket-open",
        EndpointFromHttpInfo(info),
        0,
        webSocket ? "ok" : FormatString("failed=%lu", GetLastError()),
        FormatString("request=%p websocket=%p context=%llu", request, webSocket, static_cast<unsigned long long>(context)));
    return webSocket;
}

DWORD WINAPI Hook_WinHttpWebSocketSend(HINTERNET webSocket, WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType, PVOID buffer, DWORD bufferLength)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketSend(webSocket, bufferType, buffer, bufferLength));
    HttpHandleInfo info = GetHandleInfo(webSocket);
    std::string endpoint = EndpointFromHttpInfo(info);
    LogWebSocketApiMessage("WinHttpWebSocketSend", "websocket-out", endpoint, bufferType, ERROR_SUCCESS, buffer, bufferLength, "before-call");
    DWORD result = Real_WinHttpWebSocketSend(webSocket, bufferType, buffer, bufferLength);
    if (result != ERROR_SUCCESS) {
        LogWebSocketApiMessage("WinHttpWebSocketSend", "result", endpoint, bufferType, result, nullptr, 0);
    }
    return result;
}

DWORD WINAPI Hook_WinHttpWebSocketReceive(HINTERNET webSocket, PVOID buffer, DWORD bufferLength, DWORD* bytesRead, WINHTTP_WEB_SOCKET_BUFFER_TYPE* bufferType)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketReceive(webSocket, buffer, bufferLength, bytesRead, bufferType));
    DWORD result = Real_WinHttpWebSocketReceive(webSocket, buffer, bufferLength, bytesRead, bufferType);
    DWORD actual = bytesRead ? *bytesRead : 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE type = bufferType ? *bufferType : WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(webSocket));
    if (result == ERROR_SUCCESS && actual > 0) {
        LogWebSocketApiMessage("WinHttpWebSocketReceive", "websocket-in", endpoint, type, result, buffer, actual, FormatString("buffer_length=%lu", bufferLength));
    }
    else {
        LogWebSocketApiMessage("WinHttpWebSocketReceive", "websocket-in", endpoint, type, result, nullptr, 0, FormatString("bytes_read=%lu buffer_length=%lu", actual, bufferLength));
    }
    return result;
}

DWORD WINAPI Hook_WinHttpWebSocketClose(HINTERNET webSocket, USHORT status, PVOID reason, DWORD reasonLength)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketClose(webSocket, status, reason, reasonLength));
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(webSocket));
    LogEvent("WinHttpWebSocketClose", "websocket-close-out", endpoint, reasonLength, FormatString("status=%hu", status), {}, reason, reasonLength);
    DWORD result = Real_WinHttpWebSocketClose(webSocket, status, reason, reasonLength);
    LogEvent("WinHttpWebSocketClose", "result", endpoint, 0, result == ERROR_SUCCESS ? "ok" : FormatString("error=%lu", result));
    return result;
}

DWORD WINAPI Hook_WinHttpWebSocketShutdown(HINTERNET webSocket, USHORT status, PVOID reason, DWORD reasonLength)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketShutdown(webSocket, status, reason, reasonLength));
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(webSocket));
    LogEvent("WinHttpWebSocketShutdown", "websocket-shutdown", endpoint, reasonLength, FormatString("status=%hu", status), {}, reason, reasonLength);
    DWORD result = Real_WinHttpWebSocketShutdown(webSocket, status, reason, reasonLength);
    LogEvent("WinHttpWebSocketShutdown", "result", endpoint, 0, result == ERROR_SUCCESS ? "ok" : FormatString("error=%lu", result));
    return result;
}

DWORD WINAPI Hook_WinHttpWebSocketQueryCloseStatus(HINTERNET webSocket, USHORT* status, PVOID reason, DWORD reasonLength, DWORD* reasonLengthConsumed)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWebSocketQueryCloseStatus(webSocket, status, reason, reasonLength, reasonLengthConsumed));
    DWORD result = Real_WinHttpWebSocketQueryCloseStatus(webSocket, status, reason, reasonLength, reasonLengthConsumed);
    DWORD actual = reasonLengthConsumed ? *reasonLengthConsumed : 0;
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(webSocket));
    LogEvent(
        "WinHttpWebSocketQueryCloseStatus",
        "websocket-close-in",
        endpoint,
        actual,
        result == ERROR_SUCCESS ? FormatString("status=%hu", status ? *status : 0) : FormatString("error=%lu", result),
        FormatString("reason_buffer=%lu", reasonLength),
        reason,
        result == ERROR_SUCCESS && reason && actual > 0 ? actual : 0);
    return result;
}

BOOL WINAPI Hook_WinHttpCloseHandle(HINTERNET handle)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpCloseHandle(handle));
    HttpHandleInfo info = GetHandleInfo(handle);
    BOOL result = Real_WinHttpCloseHandle(handle);
    LogEvent("WinHttpCloseHandle", "close", EndpointFromHttpInfo(info), 0, result ? "ok" : "failed");
    RemoveHandle(handle);
    return result;
}

// ===================================================================
// Hook Functions - WinINet
// ===================================================================

HINTERNET WINAPI Hook_InternetOpenA(LPCSTR agent, DWORD accessType, LPCSTR proxy, LPCSTR proxyBypass, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_InternetOpenA(agent, accessType, proxy, proxyBypass, flags));
    HINTERNET session = Real_InternetOpenA(agent, accessType, proxy, proxyBypass, flags);
    LogEvent("InternetOpenA", "open", "?", 0, session ? "ok" : "failed", FormatString("agent=%s", agent ? agent : ""));
    return session;
}

HINTERNET WINAPI Hook_InternetOpenW(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR proxyBypass, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_InternetOpenW(agent, accessType, proxy, proxyBypass, flags));
    HINTERNET session = Real_InternetOpenW(agent, accessType, proxy, proxyBypass, flags);
    LogEvent("InternetOpenW", "open", "?", 0, session ? "ok" : "failed", FormatString("agent=%s", WideToUtf8(agent).c_str()));
    return session;
}

HINTERNET WINAPI Hook_InternetConnectA(HINTERNET session, LPCSTR serverName, INTERNET_PORT serverPort, LPCSTR userName, LPCSTR password, DWORD service, DWORD flags, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_InternetConnectA(session, serverName, serverPort, userName, password, service, flags, context));
    HINTERNET connection = Real_InternetConnectA(session, serverName, serverPort, userName, password, service, flags, context);
    HttpHandleInfo info;
    info.kind = "wininet-connect";
    info.host = serverName ? serverName : "";
    info.port = serverPort;
    info.secure = (flags & INTERNET_FLAG_SECURE) != 0;
    TrackHandle(connection, info);
    LogEvent("InternetConnectA", "connect", EndpointFromHttpInfo(info), 0, connection ? "ok" : "failed", FormatString("service=%lu secure=%s user=%s", service, info.secure ? "yes" : "no", userName ? "<provided>" : ""));
    return connection;
}

HINTERNET WINAPI Hook_InternetConnectW(HINTERNET session, LPCWSTR serverName, INTERNET_PORT serverPort, LPCWSTR userName, LPCWSTR password, DWORD service, DWORD flags, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_InternetConnectW(session, serverName, serverPort, userName, password, service, flags, context));
    HINTERNET connection = Real_InternetConnectW(session, serverName, serverPort, userName, password, service, flags, context);
    HttpHandleInfo info;
    info.kind = "wininet-connect";
    info.host = WideToUtf8(serverName);
    info.port = serverPort;
    info.secure = (flags & INTERNET_FLAG_SECURE) != 0;
    TrackHandle(connection, info);
    LogEvent("InternetConnectW", "connect", EndpointFromHttpInfo(info), 0, connection ? "ok" : "failed", FormatString("service=%lu secure=%s user=%s", service, info.secure ? "yes" : "no", userName ? "<provided>" : ""));
    return connection;
}

HINTERNET WINAPI Hook_HttpOpenRequestA(HINTERNET connection, LPCSTR verb, LPCSTR objectName, LPCSTR version, LPCSTR referrer, LPCSTR* acceptTypes, DWORD flags, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_HttpOpenRequestA(connection, verb, objectName, version, referrer, acceptTypes, flags, context));
    HINTERNET request = Real_HttpOpenRequestA(connection, verb, objectName, version, referrer, acceptTypes, flags, context);
    HttpHandleInfo parent = GetHandleInfo(connection);
    HttpHandleInfo info = parent;
    info.kind = "wininet-request";
    info.method = verb ? verb : "";
    info.path = objectName ? objectName : "";
    info.secure = (flags & INTERNET_FLAG_SECURE) != 0;
    TrackHandle(request, info);
    LogEvent("HttpOpenRequestA", "open", EndpointFromHttpInfo(info), 0, request ? "ok" : "failed", FormatString("method=%s secure=%s", info.method.c_str(), info.secure ? "yes" : "no"));
    return request;
}

HINTERNET WINAPI Hook_HttpOpenRequestW(HINTERNET connection, LPCWSTR verb, LPCWSTR objectName, LPCWSTR version, LPCWSTR referrer, LPCWSTR* acceptTypes, DWORD flags, DWORD_PTR context)
{
    SOCKETU_GUARD_RETURN(Real_HttpOpenRequestW(connection, verb, objectName, version, referrer, acceptTypes, flags, context));
    HINTERNET request = Real_HttpOpenRequestW(connection, verb, objectName, version, referrer, acceptTypes, flags, context);
    HttpHandleInfo parent = GetHandleInfo(connection);
    HttpHandleInfo info = parent;
    info.kind = "wininet-request";
    info.method = WideToUtf8(verb);
    info.path = WideToUtf8(objectName);
    info.secure = (flags & INTERNET_FLAG_SECURE) != 0;
    TrackHandle(request, info);
    LogEvent("HttpOpenRequestW", "open", EndpointFromHttpInfo(info), 0, request ? "ok" : "failed", FormatString("method=%s secure=%s", info.method.c_str(), info.secure ? "yes" : "no"));
    return request;
}

BOOL WINAPI Hook_HttpSendRequestA(HINTERNET request, LPCSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength)
{
    SOCKETU_GUARD_RETURN(Real_HttpSendRequestA(request, headers, headersLength, optional, optionalLength));
    HttpHandleInfo info = GetHandleInfo(request);
    std::string endpoint = EndpointFromHttpInfo(info);
    std::string headerText = AnsiString(headers, headersLength);
    if (TextContainsWebSocketUpgrade(headerText)) {
        info.webSocketUpgrade = true;
        TrackHandle(request, info);
    }
    LogHeaders("HttpSendRequestA", endpoint, headerText);
    if (optional && optionalLength > 0) {
        LogEvent("HttpSendRequestA", "out", endpoint, optionalLength, FormatString("method=%s", info.method.c_str()), {}, optional, optionalLength);
    }
    else {
        LogEvent("HttpSendRequestA", "out", endpoint, 0, FormatString("method=%s", info.method.c_str()));
    }
    return Real_HttpSendRequestA(request, headers, headersLength, optional, optionalLength);
}

BOOL WINAPI Hook_HttpSendRequestW(HINTERNET request, LPCWSTR headers, DWORD headersLength, LPVOID optional, DWORD optionalLength)
{
    SOCKETU_GUARD_RETURN(Real_HttpSendRequestW(request, headers, headersLength, optional, optionalLength));
    HttpHandleInfo info = GetHandleInfo(request);
    std::string endpoint = EndpointFromHttpInfo(info);
    std::string headerText = WideToUtf8(headers, headersLength == static_cast<DWORD>(-1) ? -1 : static_cast<int>(headersLength));
    if (TextContainsWebSocketUpgrade(headerText)) {
        info.webSocketUpgrade = true;
        TrackHandle(request, info);
    }
    LogHeaders("HttpSendRequestW", endpoint, headerText);
    if (optional && optionalLength > 0) {
        LogEvent("HttpSendRequestW", "out", endpoint, optionalLength, FormatString("method=%s", info.method.c_str()), {}, optional, optionalLength);
    }
    else {
        LogEvent("HttpSendRequestW", "out", endpoint, 0, FormatString("method=%s", info.method.c_str()));
    }
    return Real_HttpSendRequestW(request, headers, headersLength, optional, optionalLength);
}

BOOL WINAPI Hook_HttpQueryInfoA(HINTERNET request, DWORD infoLevel, LPVOID buffer, LPDWORD bufferLength, LPDWORD index)
{
    SOCKETU_GUARD_RETURN(Real_HttpQueryInfoA(request, infoLevel, buffer, bufferLength, index));
    BOOL result = Real_HttpQueryInfoA(request, infoLevel, buffer, bufferLength, index);
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    if (result && buffer && bufferLength && !(infoLevel & HTTP_QUERY_FLAG_NUMBER)) {
        LogHeaders("HttpQueryInfoA", endpoint, std::string(static_cast<const char*>(buffer), *bufferLength));
    }
    else {
        LogEvent("HttpQueryInfoA", "headers", endpoint, bufferLength ? *bufferLength : 0, result ? "ok" : FormatString("failed=%lu", GetLastError()), FormatString("level=0x%08lX", infoLevel));
    }
    return result;
}

BOOL WINAPI Hook_HttpQueryInfoW(HINTERNET request, DWORD infoLevel, LPVOID buffer, LPDWORD bufferLength, LPDWORD index)
{
    SOCKETU_GUARD_RETURN(Real_HttpQueryInfoW(request, infoLevel, buffer, bufferLength, index));
    BOOL result = Real_HttpQueryInfoW(request, infoLevel, buffer, bufferLength, index);
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    if (result && buffer && bufferLength && !(infoLevel & HTTP_QUERY_FLAG_NUMBER)) {
        DWORD chars = *bufferLength / sizeof(wchar_t);
        LogHeaders("HttpQueryInfoW", endpoint, WideToUtf8(static_cast<LPCWSTR>(buffer), static_cast<int>(chars)));
    }
    else {
        LogEvent("HttpQueryInfoW", "headers", endpoint, bufferLength ? *bufferLength : 0, result ? "ok" : FormatString("failed=%lu", GetLastError()), FormatString("level=0x%08lX", infoLevel));
    }
    return result;
}

BOOL WINAPI Hook_InternetReadFile(HINTERNET file, LPVOID buffer, DWORD bytesToRead, LPDWORD bytesRead)
{
    SOCKETU_GUARD_RETURN(Real_InternetReadFile(file, buffer, bytesToRead, bytesRead));
    BOOL result = Real_InternetReadFile(file, buffer, bytesToRead, bytesRead);
    DWORD read = bytesRead ? *bytesRead : 0;
    HttpHandleInfo info = GetHandleInfo(file);
    std::string endpoint = EndpointFromHttpInfo(info);
    if (result && read > 0) {
        LogEvent("InternetReadFile", "in", endpoint, read, "ok", {}, buffer, read);
        if (info.webSocketUpgrade) {
            LogWebSocketWireFrames("InternetReadFile", "in", endpoint, buffer, read);
        }
    }
    else {
        LogEvent("InternetReadFile", "in", endpoint, read, result ? "ok" : "failed");
    }
    return result;
}

BOOL WINAPI Hook_InternetWriteFile(HINTERNET file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten)
{
    SOCKETU_GUARD_RETURN(Real_InternetWriteFile(file, buffer, bytesToWrite, bytesWritten));
    HttpHandleInfo info = GetHandleInfo(file);
    std::string endpoint = EndpointFromHttpInfo(info);
    LogEvent("InternetWriteFile", "out", endpoint, bytesToWrite, "before-call", {}, buffer, bytesToWrite);
    if (info.webSocketUpgrade) {
        LogWebSocketWireFrames("InternetWriteFile", "out", endpoint, buffer, bytesToWrite);
    }
    BOOL result = Real_InternetWriteFile(file, buffer, bytesToWrite, bytesWritten);
    LogEvent("InternetWriteFile", "result", endpoint, bytesWritten ? *bytesWritten : 0, result ? "ok" : "failed");
    return result;
}

BOOL WINAPI Hook_InternetCloseHandle(HINTERNET handle)
{
    SOCKETU_GUARD_RETURN(Real_InternetCloseHandle(handle));
    HttpHandleInfo info = GetHandleInfo(handle);
    BOOL result = Real_InternetCloseHandle(handle);
    LogEvent("InternetCloseHandle", "close", EndpointFromHttpInfo(info), 0, result ? "ok" : "failed");
    RemoveHandle(handle);
    return result;
}

// ===================================================================
// Hook Functions - Schannel TLS
// ===================================================================

SECURITY_STATUS WINAPI Hook_EncryptMessage(PCtxtHandle context, ULONG qop, PSecBufferDesc message, ULONG sequenceNo)
{
    SOCKETU_GUARD_RETURN(Real_EncryptMessage(context, qop, message, sequenceNo));
    if (message) {
        for (ULONG i = 0; i < message->cBuffers; ++i) {
            SecBuffer& buffer = message->pBuffers[i];
            if (buffer.BufferType == SECBUFFER_DATA && buffer.pvBuffer && buffer.cbBuffer > 0) {
                LogEvent("EncryptMessage", "tls-out", "?", buffer.cbBuffer, "before-call", {}, buffer.pvBuffer, buffer.cbBuffer);
                ObserveSchannelWebSocketPayload(context, "EncryptMessage", "tls-out", "schannel", buffer.pvBuffer, buffer.cbBuffer);
            }
        }
    }
    return Real_EncryptMessage(context, qop, message, sequenceNo);
}

SECURITY_STATUS WINAPI Hook_DecryptMessage(PCtxtHandle context, PSecBufferDesc message, ULONG sequenceNo, PULONG qop)
{
    SOCKETU_GUARD_RETURN(Real_DecryptMessage(context, message, sequenceNo, qop));
    SECURITY_STATUS status = Real_DecryptMessage(context, message, sequenceNo, qop);
    if (status == SEC_E_OK && message) {
        for (ULONG i = 0; i < message->cBuffers; ++i) {
            SecBuffer& buffer = message->pBuffers[i];
            if (buffer.BufferType == SECBUFFER_DATA && buffer.pvBuffer && buffer.cbBuffer > 0) {
                LogEvent("DecryptMessage", "tls-in", "?", buffer.cbBuffer, "ok", {}, buffer.pvBuffer, buffer.cbBuffer);
                ObserveSchannelWebSocketPayload(context, "DecryptMessage", "tls-in", "schannel", buffer.pvBuffer, buffer.cbBuffer);
            }
        }
    }
    else {
        LogEvent("DecryptMessage", "tls-in", "?", 0, FormatString("status=0x%08lX", status));
    }
    return status;
}

// ===================================================================
// Hook Functions - OpenSSL / BoringSSL / Dynamic DLL Loading
// ===================================================================

int WINAPI Hook_SSL_read(void* ssl, void* buffer, int count)
{
    SOCKETU_GUARD_RETURN(Real_SSL_read(ssl, buffer, count));
    int result = Real_SSL_read(ssl, buffer, count);
    if (result > 0) {
        LogEvent("SSL_read", "tls-in", "openssl", result, "ok", {}, buffer, static_cast<size_t>(result));
        ObserveOpenSslWebSocketPayload(ssl, "SSL_read", "tls-in", "openssl", buffer, static_cast<size_t>(result));
    }
    else {
        LogEvent("SSL_read", "tls-in", "openssl", result);
    }
    return result;
}

int WINAPI Hook_SSL_write(void* ssl, const void* buffer, int count)
{
    SOCKETU_GUARD_RETURN(Real_SSL_write(ssl, buffer, count));
    LogEvent("SSL_write", "tls-out", "openssl", count, "before-call", {}, buffer, count > 0 ? static_cast<size_t>(count) : 0);
    if (count > 0) {
        ObserveOpenSslWebSocketPayload(ssl, "SSL_write", "tls-out", "openssl", buffer, static_cast<size_t>(count));
    }
    int result = Real_SSL_write(ssl, buffer, count);
    LogEvent("SSL_write", "result", "openssl", result);
    return result;
}

int WINAPI Hook_SSL_read_ex(void* ssl, void* buffer, size_t count, size_t* readBytes)
{
    SOCKETU_GUARD_RETURN(Real_SSL_read_ex(ssl, buffer, count, readBytes));
    int result = Real_SSL_read_ex(ssl, buffer, count, readBytes);
    size_t actual = readBytes ? *readBytes : 0;
    if (result == 1 && actual > 0) {
        LogEvent("SSL_read_ex", "tls-in", "openssl", static_cast<long long>(actual), "ok", {}, buffer, actual);
        ObserveOpenSslWebSocketPayload(ssl, "SSL_read_ex", "tls-in", "openssl", buffer, actual);
    }
    else {
        LogEvent("SSL_read_ex", "tls-in", "openssl", static_cast<long long>(actual), FormatString("result=%d", result));
    }
    return result;
}

int WINAPI Hook_SSL_write_ex(void* ssl, const void* buffer, size_t count, size_t* written)
{
    SOCKETU_GUARD_RETURN(Real_SSL_write_ex(ssl, buffer, count, written));
    LogEvent("SSL_write_ex", "tls-out", "openssl", static_cast<long long>(count), "before-call", {}, buffer, count);
    if (count > 0) {
        ObserveOpenSslWebSocketPayload(ssl, "SSL_write_ex", "tls-out", "openssl", buffer, count);
    }
    int result = Real_SSL_write_ex(ssl, buffer, count, written);
    LogEvent("SSL_write_ex", "result", "openssl", written ? static_cast<long long>(*written) : 0, FormatString("result=%d", result));
    return result;
}

int Hook_luaL_loadbufferx(void* state, const char* buffer, size_t size, const char* name, const char* mode)
{
    SOCKETU_GUARD_RETURN(Real_luaL_loadbufferx(state, buffer, size, name, mode));
    LogEvent("luaL_loadbufferx", "script", "lua-runtime", static_cast<long long>(size), "lua", FormatString("chunk=%s mode=%s", name ? name : "?", mode ? mode : "?"), buffer, size);
    return Real_luaL_loadbufferx(state, buffer, size, name, mode);
}

int Hook_luaL_loadbuffer(void* state, const char* buffer, size_t size, const char* name)
{
    SOCKETU_GUARD_RETURN(Real_luaL_loadbuffer(state, buffer, size, name));
    LogEvent("luaL_loadbuffer", "script", "lua-runtime", static_cast<long long>(size), "lua", FormatString("chunk=%s", name ? name : "?"), buffer, size);
    return Real_luaL_loadbuffer(state, buffer, size, name);
}

int Hook_luaL_loadstring(void* state, const char* text)
{
    SOCKETU_GUARD_RETURN(Real_luaL_loadstring(state, text));
    size_t size = text ? strlen(text) : 0;
    LogEvent("luaL_loadstring", "script", "lua-runtime", static_cast<long long>(size), "lua", {}, text, size);
    return Real_luaL_loadstring(state, text);
}

int Hook_lua_pcallk(void* state, int nargs, int nresults, int errfunc, intptr_t ctx, void* k)
{
    SOCKETU_GUARD_RETURN(Real_lua_pcallk(state, nargs, nresults, errfunc, ctx, k));
    LogEvent("lua_pcallk", "script", "lua-runtime", 0, "lua", FormatString("nargs=%d nresults=%d errfunc=%d", nargs, nresults, errfunc));
    return Real_lua_pcallk(state, nargs, nresults, errfunc, ctx, k);
}

void __fastcall Hook_GraalDecryptScript(void* destStruct, void* nameArg, int a3, void* a4, int a5, void* a6)
{
    SOCKETU_GUARD_RETURN((Real_GraalDecryptScript(destStruct, nameArg, a3, a4, a5, a6), void()));
    std::string scriptName = ReadGraalStringWrapper(nameArg);
    LogEvent("GraalDecryptScript", "script-decrypt-enter", scriptName.empty() ? "graal-runtime" : scriptName, 0, "gs2", FormatString("dest=%p name_arg=%p a3=%d a4=%p a5=%d a6=%p", destStruct, nameArg, a3, a4, a5, a6));
    Real_GraalDecryptScript(destStruct, nameArg, a3, a4, a5, a6);

    void* bytecode = nullptr;
    SafeReadValue(destStruct, bytecode);
    LogGraalBytecode("GraalDecryptScript", bytecode, scriptName, "on_leave decrypted");
}

void __fastcall Hook_GraalExecScript(void* a1, void* a2, int a3, void* a4, void* a5)
{
    SOCKETU_GUARD_RETURN((Real_GraalExecScript(a1, a2, a3, a4, a5), void()));
    std::string objectName = ReadGraalStringWrapper(a2);
    LogGraalBytecode("GraalExecScript", a5, objectName, FormatString("a1=%p a2=%p a3=%d a4=%p", a1, a2, a3, a4));
    Real_GraalExecScript(a1, a2, a3, a4, a5);
}

void __fastcall Hook_GraalBindBytecode(void* scriptObject, void* bytecode)
{
    SOCKETU_GUARD_RETURN((Real_GraalBindBytecode(scriptObject, bytecode), void()));
    LogGraalBytecode("GraalBindBytecode", bytecode, "script-object", FormatString("script_object=%p", scriptObject));
    Real_GraalBindBytecode(scriptObject, bytecode);
}

int64_t __fastcall Hook_GraalEventCall(void* object, void* eventName, const char* format, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9)
{
    SOCKETU_GUARD_RETURN(Real_GraalEventCall(object, eventName, format, a4, a5, a6, a7, a8, a9));
    std::string event = ReadGraalStringWrapper(eventName);
    LogEvent(
        "GraalEventCall",
        "script-event-call",
        event.empty() ? "graal-runtime" : event,
        0,
        "gs2",
        FormatString("object=%p event_arg=%p format=%s args=[%s,%s,%s,%s,%s,%s]", object, eventName, format ? format : "?", HexAddress(a4).c_str(), HexAddress(a5).c_str(), HexAddress(a6).c_str(), HexAddress(a7).c_str(), HexAddress(a8).c_str(), HexAddress(a9).c_str()));
    return Real_GraalEventCall(object, eventName, format, a4, a5, a6, a7, a8, a9);
}

void* __fastcall Hook_GraalFindObject(void* context, void* objectNameArg)
{
    SOCKETU_GUARD_RETURN(Real_GraalFindObject(context, objectNameArg));
    std::string objectName = ReadGraalStringWrapper(objectNameArg);
    void* result = Real_GraalFindObject(context, objectNameArg);
    LogEvent("GraalFindObject", "script-object-find", objectName.empty() ? "graal-runtime" : objectName, 0, result ? "found-or-created" : "null", FormatString("context=%p name_arg=%p result=%p", context, objectNameArg, result));
    return result;
}

void* __fastcall Hook_GraalFindInTable(void* tableRoot, int hash, void* nameArg)
{
    SOCKETU_GUARD_RETURN(Real_GraalFindInTable(tableRoot, hash, nameArg));
    std::string name = ReadGraalStringWrapper(nameArg);
    void* result = Real_GraalFindInTable(tableRoot, hash, nameArg);
    LogEvent("GraalFindInTable", "script-function-lookup", name.empty() ? "graal-runtime" : name, 0, result ? "found" : "missing", FormatString("table=%p hash=0x%08X name_arg=%p result=%p", tableRoot, static_cast<unsigned>(hash), nameArg, result));
    return result;
}

void* __fastcall Hook_GraalExecEvent(void* eventBlock, void* arg)
{
    SOCKETU_GUARD_RETURN(Real_GraalExecEvent(eventBlock, arg));
    LogEvent("GraalExecEvent", "script-event-exec", "graal-runtime", 0, "gs2", FormatString("event_block=%p arg=%p", eventBlock, arg));
    return Real_GraalExecEvent(eventBlock, arg);
}

int64_t __fastcall Hook_GraalOpCall(void* vmContext, void* eventArg)
{
    SOCKETU_GUARD_RETURN(Real_GraalOpCall(vmContext, eventArg));
    std::string event = ReadGraalStringWrapper(eventArg);
    LogEvent("GraalOpCall", "script-op-call", event.empty() ? "graal-runtime" : event, 0, "gs2", FormatString("vm_context=%p event_arg=%p", vmContext, eventArg));
    return Real_GraalOpCall(vmContext, eventArg);
}

void* __fastcall Hook_GraalLookupFunction(void* tableOrObject, void* nameArg)
{
    SOCKETU_GUARD_RETURN(Real_GraalLookupFunction(tableOrObject, nameArg));
    std::string name = ReadGraalStringWrapper(nameArg);
    void* result = Real_GraalLookupFunction(tableOrObject, nameArg);
    LogEvent("GraalLookupFunction", "script-function-lookup", name.empty() ? "graal-runtime" : name, 0, result ? "found" : "missing", FormatString("table_or_object=%p name_arg=%p result=%p", tableOrObject, nameArg, result));
    return result;
}

void __fastcall Hook_GraalResolveVariable(void* variant, void* activeContext)
{
    SOCKETU_GUARD_RETURN((Real_GraalResolveVariable(variant, activeContext), void()));
    int beforeType = -1;
    SafeReadValue(variant, beforeType);
    Real_GraalResolveVariable(variant, activeContext);
    int afterType = -1;
    SafeReadValue(variant, afterType);
    std::string value;
    if (afterType == 2) {
        value = ReadGraalStringWrapper(variant);
    }
    LogEvent("GraalResolveVariable", "script-value-resolve", "graal-runtime", static_cast<long long>(value.size()), "gs2", FormatString("variant=%p context=%p type=%d->%d", variant, activeContext, beforeType, afterType), value.data(), value.size());
}

bool InstallDynamicHook(HMODULE module, const char* name, LPVOID hook, LPVOID* original)
{
    if (!module || !name || !hook || !original || !g_MinHookInitialized.load()) {
        return false;
    }

    LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, name));
    if (!target) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_DynamicHookMutex);
    if (g_DynamicHookTargets.find(target) != g_DynamicHookTargets.end()) {
        return false;
    }

    MH_STATUS createStatus = MH_CreateHook(target, hook, original);
    if (createStatus != MH_OK && createStatus != MH_ERROR_ALREADY_CREATED) {
        LogMessage("Dynamic hook failed: %s -> %s", name, MH_StatusToString(createStatus));
        return false;
    }

    MH_STATUS enableStatus = MH_EnableHook(target);
    if (enableStatus != MH_OK && enableStatus != MH_ERROR_ENABLED) {
        LogMessage("Dynamic hook enable failed: %s -> %s", name, MH_StatusToString(enableStatus));
        return false;
    }

    g_DynamicHookTargets.insert(target);
    LogMessage("Dynamic hook enabled: %s", name);
    return true;
}

bool InstallDynamicHookAtAddress(LPVOID target, const char* name, LPVOID hook, LPVOID* original)
{
    if (!target || !name || !hook || !original || !g_MinHookInitialized.load()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_DynamicHookMutex);
    if (g_DynamicHookTargets.find(target) != g_DynamicHookTargets.end()) {
        return false;
    }

    MH_STATUS createStatus = MH_CreateHook(target, hook, original);
    if (createStatus != MH_OK && createStatus != MH_ERROR_ALREADY_CREATED) {
        LogMessage("Dynamic RVA hook failed: %s target=%p -> %s", name, target, MH_StatusToString(createStatus));
        return false;
    }

    MH_STATUS enableStatus = MH_EnableHook(target);
    if (enableStatus != MH_OK && enableStatus != MH_ERROR_ENABLED) {
        LogMessage("Dynamic RVA hook enable failed: %s target=%p -> %s", name, target, MH_StatusToString(enableStatus));
        return false;
    }

    g_DynamicHookTargets.insert(target);
    LogMessage("Dynamic RVA hook enabled: %s target=%p", name, target);
    return true;
}

LPVOID RvaTarget(HMODULE module, uintptr_t rva)
{
    if (!module || rva == 0) {
        return nullptr;
    }
    return reinterpret_cast<unsigned char*>(module) + rva;
}

void TryInstallOpenSslHooks(HMODULE module)
{
    if (!module) {
        return;
    }

    if (!Real_SSL_read) {
        InstallDynamicHook(module, "SSL_read", reinterpret_cast<LPVOID>(Hook_SSL_read), reinterpret_cast<LPVOID*>(&Real_SSL_read));
    }
    if (!Real_SSL_write) {
        InstallDynamicHook(module, "SSL_write", reinterpret_cast<LPVOID>(Hook_SSL_write), reinterpret_cast<LPVOID*>(&Real_SSL_write));
    }
    if (!Real_SSL_read_ex) {
        InstallDynamicHook(module, "SSL_read_ex", reinterpret_cast<LPVOID>(Hook_SSL_read_ex), reinterpret_cast<LPVOID*>(&Real_SSL_read_ex));
    }
    if (!Real_SSL_write_ex) {
        InstallDynamicHook(module, "SSL_write_ex", reinterpret_cast<LPVOID>(Hook_SSL_write_ex), reinterpret_cast<LPVOID*>(&Real_SSL_write_ex));
    }
}

bool GetModuleImageInfo(HMODULE module, IMAGE_NT_HEADERS** ntHeaders, std::string* moduleName)
{
    if (!module || !ntHeaders) {
        return false;
    }

    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<unsigned char*>(module) + dosHeader->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (moduleName) {
        char path[MAX_PATH] = {};
        if (GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
            const char* name = PathFindFileNameA(path);
            *moduleName = name ? name : path;
        }
        else {
            *moduleName = FormatString("module@%p", module);
        }
    }

    *ntHeaders = nt;
    return true;
}

void ScanModuleScriptExports(HMODULE module)
{
    if (!g_Config.scriptExportScan || !module) {
        return;
    }

    IMAGE_NT_HEADERS* nt = nullptr;
    std::string moduleName;
    if (!GetModuleImageInfo(module, &nt, &moduleName) || !IsLikelyGameModuleName(moduleName)) {
        return;
    }

    IMAGE_DATA_DIRECTORY exportDirectoryData = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectoryData.VirtualAddress == 0 || exportDirectoryData.Size == 0) {
        return;
    }

    auto* base = reinterpret_cast<unsigned char*>(module);
    auto* exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportDirectoryData.VirtualAddress);
    auto* names = reinterpret_cast<DWORD*>(base + exportDirectory->AddressOfNames);
    auto* ordinals = reinterpret_cast<WORD*>(base + exportDirectory->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<DWORD*>(base + exportDirectory->AddressOfFunctions);

    int logged = 0;
    for (DWORD i = 0; i < exportDirectory->NumberOfNames && logged < g_Config.maxScriptExportLogs; ++i) {
        const char* exportName = reinterpret_cast<const char*>(base + names[i]);
        if (!exportName || !IsLikelyScriptExportName(exportName)) {
            continue;
        }

        WORD ordinalIndex = ordinals[i];
        DWORD functionRva = functions[ordinalIndex];
        void* functionAddress = base + functionRva;
        std::string exportKind = DetectScriptKindFromText(exportName);
        if (exportKind.empty()) {
            exportKind = "script-export";
        }

        LogEvent(
            "ScriptExportScan",
            "script-export",
            moduleName,
            0,
            exportKind,
            FormatString(
                "module_base=%p export=%s ordinal=%u rva=%s va=%s",
                module,
                exportName,
                static_cast<unsigned>(exportDirectory->Base + ordinalIndex),
                HexAddress(functionRva).c_str(),
                HexAddress(reinterpret_cast<uintptr_t>(functionAddress)).c_str()));
        logged++;
    }

    if (logged > 0) {
        LogEvent("ScriptExportScan", "script-export-summary", moduleName, logged, "ok", FormatString("module_base=%p export_count=%lu", module, exportDirectory->NumberOfNames));
    }
}

void ScanAsciiScriptStringsInSection(HMODULE module, const std::string& moduleName, IMAGE_SECTION_HEADER* section, int& logged)
{
    if (!section || logged >= g_Config.maxScriptStringLogs) {
        return;
    }

    auto* base = reinterpret_cast<unsigned char*>(module);
    DWORD virtualSize = section->Misc.VirtualSize;
    DWORD rawSize = section->SizeOfRawData;
    DWORD sectionSize = virtualSize != 0 ? virtualSize : rawSize;
    if (sectionSize == 0 || sectionSize > 64u * 1024u * 1024u) {
        return;
    }

    const unsigned char* start = base + section->VirtualAddress;
    const unsigned char* end = start + sectionSize;
    const unsigned char* current = start;
    while (current < end && logged < g_Config.maxScriptStringLogs) {
        while (current < end && !std::isprint(*current)) {
            current++;
        }

        const unsigned char* textStart = current;
        while (current < end && (std::isprint(*current) || *current == '\t')) {
            current++;
        }

        size_t length = static_cast<size_t>(current - textStart);
        if (length >= 5 && length <= 1024) {
            std::string text(reinterpret_cast<const char*>(textStart), length);
            std::string scriptKind = DetectScriptKindFromText(text);
            if (scriptKind.empty()) {
                scriptKind = DetectScriptKindFromPath(text);
            }

            if (!scriptKind.empty()) {
                char sectionName[9] = {};
                memcpy(sectionName, section->Name, 8);
                DWORD rva = static_cast<DWORD>(textStart - base);
                LogEvent(
                    "ScriptStringScan",
                    "script-string",
                    moduleName,
                    static_cast<long long>(length),
                    scriptKind,
                    FormatString("module_base=%p section=%s rva=%s", module, sectionName, HexAddress(rva).c_str()),
                    text.data(),
                    text.size());
                logged++;
            }
        }

        current++;
    }
}

void ScanModuleScriptStrings(HMODULE module)
{
    if (!g_Config.scriptStringScan || !module) {
        return;
    }

    IMAGE_NT_HEADERS* nt = nullptr;
    std::string moduleName;
    if (!GetModuleImageInfo(module, &nt, &moduleName) || !IsLikelyGameModuleName(moduleName)) {
        return;
    }

    auto* firstSection = IMAGE_FIRST_SECTION(nt);
    int logged = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && logged < g_Config.maxScriptStringLogs; ++i) {
        IMAGE_SECTION_HEADER* section = &firstSection[i];
        DWORD characteristics = section->Characteristics;
        bool readableData = (characteristics & IMAGE_SCN_MEM_READ) != 0 &&
            ((characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 || (characteristics & IMAGE_SCN_CNT_CODE) != 0);
        if (readableData) {
            ScanAsciiScriptStringsInSection(module, moduleName, section, logged);
        }
    }

    if (logged > 0) {
        LogEvent("ScriptStringScan", "script-string-summary", moduleName, logged, "ok", FormatString("module_base=%p", module));
    }
}

void ScanModuleForScriptDetails(HMODULE module)
{
    if (!module) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_DynamicHookMutex);
        if (g_ScriptScannedModules.find(module) != g_ScriptScannedModules.end()) {
            return;
        }
        g_ScriptScannedModules.insert(module);
    }

    ScanModuleScriptExports(module);
    ScanModuleScriptStrings(module);
}

void TryInstallGraalProbes(HMODULE module)
{
    if (!ShouldProbeGraalModule(module)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_DynamicHookMutex);
        if (g_GraalProbeModules.find(module) != g_GraalProbeModules.end()) {
            return;
        }
        g_GraalProbeModules.insert(module);
    }

    std::string moduleName = ModuleNameFromHandle(module);
    LogEvent(
        "GraalProbe",
        "script-probe-enable",
        moduleName,
        0,
        "gs2",
        FormatString(
            "module_base=%p decrypt=%s exec=%s bind=%s event=%s find_object=%s find_table=%s exec_event=%s op_call=%s lookup=%s resolve=%s context=%s xor_key=%s",
            module,
            HexAddress(g_Config.graalDecryptScriptRva).c_str(),
            HexAddress(g_Config.graalExecScriptRva).c_str(),
            HexAddress(g_Config.graalBindBytecodeRva).c_str(),
            HexAddress(g_Config.graalEventCallRva).c_str(),
            HexAddress(g_Config.graalFindObjectRva).c_str(),
            HexAddress(g_Config.graalFindInTableRva).c_str(),
            HexAddress(g_Config.graalExecEventRva).c_str(),
            HexAddress(g_Config.graalOpCallRva).c_str(),
            HexAddress(g_Config.graalLookupFunctionRva).c_str(),
            HexAddress(g_Config.graalResolveVariableRva).c_str(),
            HexAddress(g_Config.graalGlobalContextRva).c_str(),
            HexAddress(g_Config.graalXorKeyRva).c_str()));

    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalDecryptScriptRva), "GraalDecryptScript", reinterpret_cast<LPVOID>(Hook_GraalDecryptScript), reinterpret_cast<LPVOID*>(&Real_GraalDecryptScript));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalExecScriptRva), "GraalExecScript", reinterpret_cast<LPVOID>(Hook_GraalExecScript), reinterpret_cast<LPVOID*>(&Real_GraalExecScript));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalBindBytecodeRva), "GraalBindBytecode", reinterpret_cast<LPVOID>(Hook_GraalBindBytecode), reinterpret_cast<LPVOID*>(&Real_GraalBindBytecode));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalEventCallRva), "GraalEventCall", reinterpret_cast<LPVOID>(Hook_GraalEventCall), reinterpret_cast<LPVOID*>(&Real_GraalEventCall));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalFindObjectRva), "GraalFindObject", reinterpret_cast<LPVOID>(Hook_GraalFindObject), reinterpret_cast<LPVOID*>(&Real_GraalFindObject));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalFindInTableRva), "GraalFindInTable", reinterpret_cast<LPVOID>(Hook_GraalFindInTable), reinterpret_cast<LPVOID*>(&Real_GraalFindInTable));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalExecEventRva), "GraalExecEvent", reinterpret_cast<LPVOID>(Hook_GraalExecEvent), reinterpret_cast<LPVOID*>(&Real_GraalExecEvent));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalOpCallRva), "GraalOpCall", reinterpret_cast<LPVOID>(Hook_GraalOpCall), reinterpret_cast<LPVOID*>(&Real_GraalOpCall));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalLookupFunctionRva), "GraalLookupFunction", reinterpret_cast<LPVOID>(Hook_GraalLookupFunction), reinterpret_cast<LPVOID*>(&Real_GraalLookupFunction));
    InstallDynamicHookAtAddress(RvaTarget(module, g_Config.graalResolveVariableRva), "GraalResolveVariable", reinterpret_cast<LPVOID>(Hook_GraalResolveVariable), reinterpret_cast<LPVOID*>(&Real_GraalResolveVariable));
    ScanGraalScriptManager(module, "probe-install");
}

void TryInstallScriptRuntimeHooks(HMODULE module)
{
    if (!module) {
        return;
    }

    ScanModuleForScriptDetails(module);
    TryInstallGraalProbes(module);

    if (!Real_luaL_loadbufferx) {
        InstallDynamicHook(module, "luaL_loadbufferx", reinterpret_cast<LPVOID>(Hook_luaL_loadbufferx), reinterpret_cast<LPVOID*>(&Real_luaL_loadbufferx));
    }
    if (!Real_luaL_loadbuffer) {
        InstallDynamicHook(module, "luaL_loadbuffer", reinterpret_cast<LPVOID>(Hook_luaL_loadbuffer), reinterpret_cast<LPVOID*>(&Real_luaL_loadbuffer));
    }
    if (!Real_luaL_loadstring) {
        InstallDynamicHook(module, "luaL_loadstring", reinterpret_cast<LPVOID>(Hook_luaL_loadstring), reinterpret_cast<LPVOID*>(&Real_luaL_loadstring));
    }
    if (!Real_lua_pcallk) {
        InstallDynamicHook(module, "lua_pcallk", reinterpret_cast<LPVOID>(Hook_lua_pcallk), reinterpret_cast<LPVOID*>(&Real_lua_pcallk));
    }
}

void ScanLoadedModulesForOpenSsl()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            HMODULE module = GetModuleHandleW(entry.szModule);
            TryInstallOpenSslHooks(module);
            TryInstallScriptRuntimeHooks(module);
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

HMODULE WINAPI Hook_LoadLibraryA(LPCSTR fileName)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryA(fileName));
    HMODULE module = Real_LoadLibraryA(fileName);
    TryInstallOpenSslHooks(module);
    TryInstallScriptRuntimeHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR fileName)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryW(fileName));
    HMODULE module = Real_LoadLibraryW(fileName);
    TryInstallOpenSslHooks(module);
    TryInstallScriptRuntimeHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryExA(fileName, file, flags));
    HMODULE module = Real_LoadLibraryExA(fileName, file, flags);
    TryInstallOpenSslHooks(module);
    TryInstallScriptRuntimeHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryExW(fileName, file, flags));
    HMODULE module = Real_LoadLibraryExW(fileName, file, flags);
    TryInstallOpenSslHooks(module);
    TryInstallScriptRuntimeHooks(module);
    return module;
}

// ===================================================================
// Hook Table / Initialization
// ===================================================================

struct HookEntry {
    const wchar_t* dll;
    const char* func;
    LPVOID* original;
    LPVOID hook;
};

static std::vector<HookEntry> g_HookTable = {
    { L"kernel32.dll", "LoadLibraryA",        reinterpret_cast<LPVOID*>(&Real_LoadLibraryA),       reinterpret_cast<LPVOID>(Hook_LoadLibraryA) },
    { L"kernel32.dll", "LoadLibraryW",        reinterpret_cast<LPVOID*>(&Real_LoadLibraryW),       reinterpret_cast<LPVOID>(Hook_LoadLibraryW) },
    { L"kernel32.dll", "LoadLibraryExA",      reinterpret_cast<LPVOID*>(&Real_LoadLibraryExA),     reinterpret_cast<LPVOID>(Hook_LoadLibraryExA) },
    { L"kernel32.dll", "LoadLibraryExW",      reinterpret_cast<LPVOID*>(&Real_LoadLibraryExW),     reinterpret_cast<LPVOID>(Hook_LoadLibraryExW) },
    { L"kernel32.dll", "CreateFileA",         reinterpret_cast<LPVOID*>(&Real_CreateFileA),        reinterpret_cast<LPVOID>(Hook_CreateFileA) },
    { L"kernel32.dll", "CreateFileW",         reinterpret_cast<LPVOID*>(&Real_CreateFileW),        reinterpret_cast<LPVOID>(Hook_CreateFileW) },
    { L"kernel32.dll", "ReadFile",            reinterpret_cast<LPVOID*>(&Real_ReadFile),           reinterpret_cast<LPVOID>(Hook_ReadFile) },
    { L"kernel32.dll", "CloseHandle",         reinterpret_cast<LPVOID*>(&Real_CloseHandle),        reinterpret_cast<LPVOID>(Hook_CloseHandle) },
    { L"kernel32.dll", "CreateFileMappingA",  reinterpret_cast<LPVOID*>(&Real_CreateFileMappingA), reinterpret_cast<LPVOID>(Hook_CreateFileMappingA) },
    { L"kernel32.dll", "CreateFileMappingW",  reinterpret_cast<LPVOID*>(&Real_CreateFileMappingW), reinterpret_cast<LPVOID>(Hook_CreateFileMappingW) },
    { L"kernel32.dll", "MapViewOfFile",       reinterpret_cast<LPVOID*>(&Real_MapViewOfFile),      reinterpret_cast<LPVOID>(Hook_MapViewOfFile) },
    { L"kernel32.dll", "MapViewOfFileEx",     reinterpret_cast<LPVOID*>(&Real_MapViewOfFileEx),    reinterpret_cast<LPVOID>(Hook_MapViewOfFileEx) },
    { L"kernel32.dll", "UnmapViewOfFile",     reinterpret_cast<LPVOID*>(&Real_UnmapViewOfFile),    reinterpret_cast<LPVOID>(Hook_UnmapViewOfFile) },
    { L"kernel32.dll", "GetOverlappedResult", reinterpret_cast<LPVOID*>(&Real_GetOverlappedResult), reinterpret_cast<LPVOID>(Hook_GetOverlappedResult) },
    { L"kernel32.dll", "GetQueuedCompletionStatus", reinterpret_cast<LPVOID*>(&Real_GetQueuedCompletionStatus), reinterpret_cast<LPVOID>(Hook_GetQueuedCompletionStatus) },
    { L"kernel32.dll", "GetQueuedCompletionStatusEx", reinterpret_cast<LPVOID*>(&Real_GetQueuedCompletionStatusEx), reinterpret_cast<LPVOID>(Hook_GetQueuedCompletionStatusEx) },

    { L"ws2_32.dll",  "WSASocketW",          reinterpret_cast<LPVOID*>(&Real_WSASocketW),         reinterpret_cast<LPVOID>(Hook_WSASocketW) },
    { L"ws2_32.dll",  "WSASocketA",          reinterpret_cast<LPVOID*>(&Real_WSASocketA),         reinterpret_cast<LPVOID>(Hook_WSASocketA) },
    { L"ws2_32.dll",  "bind",                reinterpret_cast<LPVOID*>(&Real_bind),               reinterpret_cast<LPVOID>(Hook_bind) },
    { L"ws2_32.dll",  "listen",              reinterpret_cast<LPVOID*>(&Real_listen),             reinterpret_cast<LPVOID>(Hook_listen) },
    { L"ws2_32.dll",  "accept",              reinterpret_cast<LPVOID*>(&Real_accept),             reinterpret_cast<LPVOID>(Hook_accept) },
    { L"ws2_32.dll",  "connect",             reinterpret_cast<LPVOID*>(&Real_connect),            reinterpret_cast<LPVOID>(Hook_connect) },
    { L"ws2_32.dll",  "WSAConnect",          reinterpret_cast<LPVOID*>(&Real_WSAConnect),         reinterpret_cast<LPVOID>(Hook_WSAConnect) },
    { L"ws2_32.dll",  "send",                reinterpret_cast<LPVOID*>(&Real_send),               reinterpret_cast<LPVOID>(Hook_send) },
    { L"ws2_32.dll",  "recv",                reinterpret_cast<LPVOID*>(&Real_recv),               reinterpret_cast<LPVOID>(Hook_recv) },
    { L"ws2_32.dll",  "sendto",              reinterpret_cast<LPVOID*>(&Real_sendto),             reinterpret_cast<LPVOID>(Hook_sendto) },
    { L"ws2_32.dll",  "recvfrom",            reinterpret_cast<LPVOID*>(&Real_recvfrom),           reinterpret_cast<LPVOID>(Hook_recvfrom) },
    { L"ws2_32.dll",  "WSASend",             reinterpret_cast<LPVOID*>(&Real_WSASend),            reinterpret_cast<LPVOID>(Hook_WSASend) },
    { L"ws2_32.dll",  "WSARecv",             reinterpret_cast<LPVOID*>(&Real_WSARecv),            reinterpret_cast<LPVOID>(Hook_WSARecv) },
    { L"ws2_32.dll",  "WSAIoctl",            reinterpret_cast<LPVOID*>(&Real_WSAIoctl),           reinterpret_cast<LPVOID>(Hook_WSAIoctl) },
    { L"ws2_32.dll",  "WSAGetOverlappedResult", reinterpret_cast<LPVOID*>(&Real_WSAGetOverlappedResult), reinterpret_cast<LPVOID>(Hook_WSAGetOverlappedResult) },
    { L"ws2_32.dll",  "shutdown",            reinterpret_cast<LPVOID*>(&Real_shutdown),           reinterpret_cast<LPVOID>(Hook_shutdown) },
    { L"ws2_32.dll",  "closesocket",         reinterpret_cast<LPVOID*>(&Real_closesocket),        reinterpret_cast<LPVOID>(Hook_closesocket) },
    { L"ws2_32.dll",  "getaddrinfo",         reinterpret_cast<LPVOID*>(&Real_getaddrinfo),        reinterpret_cast<LPVOID>(Hook_getaddrinfo) },
    { L"ws2_32.dll",  "GetAddrInfoW",        reinterpret_cast<LPVOID*>(&Real_GetAddrInfoW),       reinterpret_cast<LPVOID>(Hook_GetAddrInfoW) },

    { L"winhttp.dll", "WinHttpOpen",         reinterpret_cast<LPVOID*>(&Real_WinHttpOpen),        reinterpret_cast<LPVOID>(Hook_WinHttpOpen) },
    { L"winhttp.dll", "WinHttpConnect",      reinterpret_cast<LPVOID*>(&Real_WinHttpConnect),     reinterpret_cast<LPVOID>(Hook_WinHttpConnect) },
    { L"winhttp.dll", "WinHttpOpenRequest",  reinterpret_cast<LPVOID*>(&Real_WinHttpOpenRequest), reinterpret_cast<LPVOID>(Hook_WinHttpOpenRequest) },
    { L"winhttp.dll", "WinHttpSendRequest",  reinterpret_cast<LPVOID*>(&Real_WinHttpSendRequest), reinterpret_cast<LPVOID>(Hook_WinHttpSendRequest) },
    { L"winhttp.dll", "WinHttpReceiveResponse", reinterpret_cast<LPVOID*>(&Real_WinHttpReceiveResponse), reinterpret_cast<LPVOID>(Hook_WinHttpReceiveResponse) },
    { L"winhttp.dll", "WinHttpQueryHeaders", reinterpret_cast<LPVOID*>(&Real_WinHttpQueryHeaders), reinterpret_cast<LPVOID>(Hook_WinHttpQueryHeaders) },
    { L"winhttp.dll", "WinHttpReadData",     reinterpret_cast<LPVOID*>(&Real_WinHttpReadData),    reinterpret_cast<LPVOID>(Hook_WinHttpReadData) },
    { L"winhttp.dll", "WinHttpWriteData",    reinterpret_cast<LPVOID*>(&Real_WinHttpWriteData),   reinterpret_cast<LPVOID>(Hook_WinHttpWriteData) },
    { L"winhttp.dll", "WinHttpSetOption",    reinterpret_cast<LPVOID*>(&Real_WinHttpSetOption),   reinterpret_cast<LPVOID>(Hook_WinHttpSetOption) },
    { L"winhttp.dll", "WinHttpWebSocketCompleteUpgrade", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketCompleteUpgrade), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketCompleteUpgrade) },
    { L"winhttp.dll", "WinHttpWebSocketSend", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketSend), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketSend) },
    { L"winhttp.dll", "WinHttpWebSocketReceive", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketReceive), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketReceive) },
    { L"winhttp.dll", "WinHttpWebSocketClose", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketClose), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketClose) },
    { L"winhttp.dll", "WinHttpWebSocketShutdown", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketShutdown), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketShutdown) },
    { L"winhttp.dll", "WinHttpWebSocketQueryCloseStatus", reinterpret_cast<LPVOID*>(&Real_WinHttpWebSocketQueryCloseStatus), reinterpret_cast<LPVOID>(Hook_WinHttpWebSocketQueryCloseStatus) },
    { L"winhttp.dll", "WinHttpCloseHandle",  reinterpret_cast<LPVOID*>(&Real_WinHttpCloseHandle), reinterpret_cast<LPVOID>(Hook_WinHttpCloseHandle) },

    { L"wininet.dll", "InternetOpenA",       reinterpret_cast<LPVOID*>(&Real_InternetOpenA),      reinterpret_cast<LPVOID>(Hook_InternetOpenA) },
    { L"wininet.dll", "InternetOpenW",       reinterpret_cast<LPVOID*>(&Real_InternetOpenW),      reinterpret_cast<LPVOID>(Hook_InternetOpenW) },
    { L"wininet.dll", "InternetConnectA",    reinterpret_cast<LPVOID*>(&Real_InternetConnectA),   reinterpret_cast<LPVOID>(Hook_InternetConnectA) },
    { L"wininet.dll", "InternetConnectW",    reinterpret_cast<LPVOID*>(&Real_InternetConnectW),   reinterpret_cast<LPVOID>(Hook_InternetConnectW) },
    { L"wininet.dll", "HttpOpenRequestA",    reinterpret_cast<LPVOID*>(&Real_HttpOpenRequestA),   reinterpret_cast<LPVOID>(Hook_HttpOpenRequestA) },
    { L"wininet.dll", "HttpOpenRequestW",    reinterpret_cast<LPVOID*>(&Real_HttpOpenRequestW),   reinterpret_cast<LPVOID>(Hook_HttpOpenRequestW) },
    { L"wininet.dll", "HttpSendRequestA",    reinterpret_cast<LPVOID*>(&Real_HttpSendRequestA),   reinterpret_cast<LPVOID>(Hook_HttpSendRequestA) },
    { L"wininet.dll", "HttpSendRequestW",    reinterpret_cast<LPVOID*>(&Real_HttpSendRequestW),   reinterpret_cast<LPVOID>(Hook_HttpSendRequestW) },
    { L"wininet.dll", "HttpQueryInfoA",      reinterpret_cast<LPVOID*>(&Real_HttpQueryInfoA),     reinterpret_cast<LPVOID>(Hook_HttpQueryInfoA) },
    { L"wininet.dll", "HttpQueryInfoW",      reinterpret_cast<LPVOID*>(&Real_HttpQueryInfoW),     reinterpret_cast<LPVOID>(Hook_HttpQueryInfoW) },
    { L"wininet.dll", "InternetReadFile",    reinterpret_cast<LPVOID*>(&Real_InternetReadFile),   reinterpret_cast<LPVOID>(Hook_InternetReadFile) },
    { L"wininet.dll", "InternetWriteFile",   reinterpret_cast<LPVOID*>(&Real_InternetWriteFile),  reinterpret_cast<LPVOID>(Hook_InternetWriteFile) },
    { L"wininet.dll", "InternetCloseHandle", reinterpret_cast<LPVOID*>(&Real_InternetCloseHandle), reinterpret_cast<LPVOID>(Hook_InternetCloseHandle) },

    { L"secur32.dll", "EncryptMessage",      reinterpret_cast<LPVOID*>(&Real_EncryptMessage),     reinterpret_cast<LPVOID>(Hook_EncryptMessage) },
    { L"secur32.dll", "DecryptMessage",      reinterpret_cast<LPVOID*>(&Real_DecryptMessage),     reinterpret_cast<LPVOID>(Hook_DecryptMessage) },
};

DWORD WINAPI InitHooks(LPVOID)
{
    LoadConfig();
    CreateDebugConsole();
    OpenLogFiles();

    LogMessage("=== SocketUniversal network hook loading ===");
    LogMessage(
        "config dump=%s max_bytes=%d headers=%s redact=%s console=%s jsonl=%s pipe=%s websocket(capture=%s frames=%s frame_limit=%d preview=%d) scripts(file=%s exports=%s strings=%s graal=%s module=%s) rotate=%llu/%d log=%s jsonl_file=%s pipe_name=%s",
        g_Config.dumpData ? "on" : "off",
        g_Config.maxDumpBytes,
        g_Config.logHttpHeaders ? "on" : "off",
        g_Config.redact ? "on" : "off",
        g_Config.console ? "on" : "off",
        g_Config.jsonl ? "on" : "off",
        g_Config.namedPipe ? "on" : "off",
        g_Config.webSocketCapture ? "on" : "off",
        g_Config.webSocketFrameScan ? "on" : "off",
        g_Config.maxWebSocketFramesPerBuffer,
        g_Config.maxWebSocketFramePreviewBytes,
        g_Config.scriptFileCapture ? "on" : "off",
        g_Config.scriptExportScan ? "on" : "off",
        g_Config.scriptStringScan ? "on" : "off",
        g_Config.graalProbes ? "on" : "off",
        g_Config.graalModuleFilter.c_str(),
        g_Config.rotateBytes,
        g_Config.rotateFiles,
        g_Config.logPath.c_str(),
        g_Config.jsonlPath.c_str(),
        g_Config.pipeName.c_str());

    if (!g_Config.loggingEnabled) {
        LogMessage("process filter did not match; hooks will pass through with logging disabled");
    }

    MH_STATUS initStatus = MH_Initialize();
    if (initStatus != MH_OK) {
        LogMessage("MH_Initialize failed: %s", MH_StatusToString(initStatus));
        return 0;
    }
    g_MinHookInitialized = true;

    int created = 0;
    for (const HookEntry& entry : g_HookTable) {
        HMODULE module = GetModuleHandleW(entry.dll);
        if (!module) {
            module = LoadLibraryW(entry.dll);
        }

        std::string dllName = WideToUtf8(entry.dll);
        if (!module) {
            LogMessage("LoadLibrary failed: %s error=%lu", dllName.c_str(), GetLastError());
            continue;
        }

        LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, entry.func));
        if (!target) {
            LogMessage("GetProcAddress failed: %s!%s error=%lu", dllName.c_str(), entry.func, GetLastError());
            continue;
        }

        MH_STATUS createStatus = MH_CreateHook(target, entry.hook, entry.original);
        if (createStatus == MH_OK) {
            LogMessage("Hook created: %s!%s", dllName.c_str(), entry.func);
            created++;
        }
        else if (createStatus == MH_ERROR_ALREADY_CREATED) {
            LogMessage("Hook already created: %s!%s", dllName.c_str(), entry.func);
        }
        else {
            LogMessage("Hook failed: %s!%s -> %s", dllName.c_str(), entry.func, MH_StatusToString(createStatus));
        }
    }

    MH_STATUS enableStatus = MH_EnableHook(MH_ALL_HOOKS);
    if (enableStatus == MH_OK) {
        g_HooksEnabled = true;
        ScanLoadedModulesForOpenSsl();
        LogMessage("=== SocketUniversal network hook loaded: %d hooks enabled ===", created);
    }
    else {
        LogMessage("MH_EnableHook failed: %s", MH_StatusToString(enableStatus));
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_Module = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, InitHooks, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_ShuttingDown = true;

        if (g_HooksEnabled.load()) {
            MH_DisableHook(MH_ALL_HOOKS);
            g_HooksEnabled = false;
        }

        if (g_MinHookInitialized.load()) {
            MH_Uninitialize();
            g_MinHookInitialized = false;
        }

        CloseLogFiles();
        CloseNamedPipe();
    }

    return TRUE;
}
