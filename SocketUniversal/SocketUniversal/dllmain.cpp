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
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
    bool redact = true;
    bool jsonl = true;
    bool namedPipe = true;
    bool loggingEnabled = true;
    int maxDumpBytes = 4096; // Set SOCKETUNIVERSAL_MAX_DUMP_BYTES=0 for no cap.
    unsigned long long rotateBytes = 10ull * 1024ull * 1024ull;
    int rotateFiles = 5;
    DWORD threadFilter = 0;
    std::string processFilter;
    std::string logPath;
    std::string jsonlPath;
    std::string pipeName = R"(\\.\pipe\SocketUniversal)";
};

struct HttpHandleInfo {
    std::string kind;
    std::string host;
    INTERNET_PORT port = 0;
    std::string method;
    std::string path;
    bool secure = false;
};

struct PayloadPreview {
    std::string text;
    std::string hex;
    size_t previewBytes = 0;
    bool textLike = false;
    bool truncated = false;
    bool redacted = false;
};

struct OverlappedOperation {
    std::string api;
    std::string endpoint;
    bool inbound = false;
    std::vector<WSABUF> buffers;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine = nullptr;
};

static RuntimeConfig g_Config;
static HMODULE g_Module = nullptr;
static FILE* g_LogFile = nullptr;
static FILE* g_JsonlFile = nullptr;
static HANDLE g_Pipe = INVALID_HANDLE_VALUE;
static bool g_PipeConnected = false;
static std::mutex g_LogMutex;
static std::mutex g_StateMutex;
static std::mutex g_DynamicHookMutex;
static std::atomic<bool> g_MinHookInitialized{ false };
static std::atomic<bool> g_HooksEnabled{ false };
static std::atomic<bool> g_ShuttingDown{ false };

static std::unordered_map<SOCKET, std::string> g_SocketToHost;
static std::unordered_map<HINTERNET, HttpHandleInfo> g_HandleInfo;
static std::unordered_map<LPWSAOVERLAPPED, OverlappedOperation> g_OverlappedOps;
static std::unordered_set<LPVOID> g_DynamicHookTargets;
static thread_local int g_HookDepth = 0;

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

void WriteHumanLine(const std::string& message)
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
            fputs(line.c_str(), console);
            fflush(console);
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
    g_Config.redact = ParseBoolEnv("SOCKETUNIVERSAL_REDACT", true);
    g_Config.jsonl = ParseBoolEnv("SOCKETUNIVERSAL_JSONL", true);
    g_Config.namedPipe = ParseBoolEnv("SOCKETUNIVERSAL_PIPE", true);
    g_Config.maxDumpBytes = ParseIntEnv("SOCKETUNIVERSAL_MAX_DUMP_BYTES", 4096);
    g_Config.rotateBytes = ParseUllEnv("SOCKETUNIVERSAL_ROTATE_BYTES", 10ull * 1024ull * 1024ull);
    g_Config.rotateFiles = ParseIntEnv("SOCKETUNIVERSAL_ROTATE_FILES", 5);
    g_Config.threadFilter = ParseDwordEnv("SOCKETUNIVERSAL_THREAD_FILTER", 0);
    g_Config.processFilter = Trim(GetEnvString("SOCKETUNIVERSAL_PROCESS_FILTER"));
    g_Config.logPath = Trim(GetEnvString("SOCKETUNIVERSAL_LOG_FILE"));
    g_Config.jsonlPath = Trim(GetEnvString("SOCKETUNIVERSAL_JSONL_FILE"));
    g_Config.pipeName = Trim(GetEnvString("SOCKETUNIVERSAL_PIPE_NAME"));

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

    return std::string(host) + ":" + port;
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
    std::lock_guard<std::mutex> lock(g_StateMutex);
    auto it = g_SocketToHost.find(socket);
    return it != g_SocketToHost.end() ? it->second : "?";
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

// ===================================================================
// Structured event logging
// ===================================================================

void WriteEventJson(
    const char* api,
    const char* direction,
    const std::string& endpoint,
    long long bytes,
    const std::string& status,
    const std::string& detail,
    const PayloadPreview* payload)
{
    std::ostringstream json;
    json << "{";
    json << "\"timestamp\":\"" << JsonEscape(Timestamp()) << "\",";
    json << "\"pid\":" << GetCurrentProcessId() << ",";
    json << "\"tid\":" << GetCurrentThreadId() << ",";
    json << "\"api\":\"" << JsonEscape(api ? api : "") << "\",";
    json << "\"direction\":\"" << JsonEscape(direction ? direction : "") << "\",";
    json << "\"endpoint\":\"" << JsonEscape(endpoint) << "\",";
    json << "\"bytes\":" << bytes << ",";
    json << "\"status\":\"" << JsonEscape(status) << "\",";
    json << "\"detail\":\"" << JsonEscape(detail) << "\"";

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
    const std::string& status = {},
    const std::string& detail = {},
    const void* payloadData = nullptr,
    size_t payloadLength = 0)
{
    if (!ShouldLog()) {
        return;
    }

    PayloadPreview payload = BuildPayloadPreview(payloadData, payloadLength);

    std::string message = FormatString(
        "%s %s bytes=%lld endpoint=%s",
        api ? api : "?",
        direction ? direction : "?",
        bytes,
        endpoint.empty() ? "?" : endpoint.c_str());

    if (!status.empty()) {
        message += " status=" + status;
    }

    if (!detail.empty()) {
        message += " " + detail;
    }

    WriteHumanLine(message);

    if (payload.previewBytes > 0) {
        std::string prefix = FormatString(
            "  payload preview=%zu%s%s",
            payload.previewBytes,
            payload.truncated ? " truncated" : "",
            payload.redacted ? " redacted" : "");
        WriteHumanLine(prefix);

        if (!payload.text.empty()) {
            WriteHumanLine("  text: " + payload.text);
        }

        if (!payload.hex.empty()) {
            WriteHumanLine("  hex: " + payload.hex);
        }
    }

    WriteEventJson(api, direction, endpoint, bytes, status, detail, payload.previewBytes > 0 ? &payload : nullptr);
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
    payload.redacted = redacted != headers;
    WriteEventJson(api, "headers", endpoint, static_cast<long long>(headers.size()), "ok", "headers", &payload);
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

void TrackOverlappedOperation(
    LPWSAOVERLAPPED overlapped,
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
    return Real_send(socket, buffer, length, flags);
}

int WINAPI Hook_recv(SOCKET socket, char* buffer, int length, int flags)
{
    SOCKETU_GUARD_RETURN(Real_recv(socket, buffer, length, flags));
    int result = Real_recv(socket, buffer, length, flags);
    if (result > 0) {
        LogEvent("recv", "in", SocketEndpoint(socket), result, FormatString("flags=%d", flags), {}, buffer, static_cast<size_t>(result));
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
    if (overlapped) {
        TrackOverlappedOperation(overlapped, "WSASend", endpoint, false, buffers, bufferCount, completionRoutine);
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
        TrackOverlappedOperation(overlapped, "WSARecv", endpoint, true, buffers, bufferCount, completionRoutine);
    }
    int result = Real_WSARecv(socket, buffers, bufferCount, bytesReceived, flags, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    DWORD received = bytesReceived ? *bytesReceived : 0;

    if (result == 0 && received > 0 && buffers) {
        DWORD remaining = received;
        for (DWORD i = 0; i < bufferCount && remaining > 0; ++i) {
            DWORD chunk = buffers[i].len < remaining ? buffers[i].len : remaining;
            if (buffers[i].buf && chunk > 0) {
                LogEvent("WSARecv", "in", endpoint, chunk, "buffer", FormatString("index=%lu", i), buffers[i].buf, chunk);
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
        if (overlapped) {
            TrackOverlappedOperation(overlapped, "WSASendMsg", endpoint, false, message->lpBuffers, message->dwBufferCount, completionRoutine);
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
        TrackOverlappedOperation(overlapped, "WSARecvMsg", endpoint, true, message->lpBuffers, message->dwBufferCount, completionRoutine);
    }

    int result = Real_WSARecvMsg(socket, message, bytesReceived, overlapped, completionRoutine ? Hook_WSACompletionRoutine : nullptr);
    DWORD received = bytesReceived ? *bytesReceived : 0;
    if (result == 0 && received > 0 && message) {
        DWORD remaining = received;
        for (DWORD i = 0; i < message->dwBufferCount && remaining > 0; ++i) {
            DWORD chunk = message->lpBuffers[i].len < remaining ? message->lpBuffers[i].len : remaining;
            if (message->lpBuffers[i].buf && chunk > 0) {
                LogEvent("WSARecvMsg", "in", endpoint, chunk, "buffer", FormatString("index=%lu", i), message->lpBuffers[i].buf, chunk);
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
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    if (result && read > 0) {
        LogEvent("WinHttpReadData", "in", endpoint, read, "ok", {}, buffer, read);
    }
    else {
        LogEvent("WinHttpReadData", "in", endpoint, read, result ? "ok" : "failed");
    }
    return result;
}

BOOL WINAPI Hook_WinHttpWriteData(HINTERNET request, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten)
{
    SOCKETU_GUARD_RETURN(Real_WinHttpWriteData(request, buffer, bytesToWrite, bytesWritten));
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(request));
    LogEvent("WinHttpWriteData", "out", endpoint, bytesToWrite, "before-call", {}, buffer, bytesToWrite);
    BOOL result = Real_WinHttpWriteData(request, buffer, bytesToWrite, bytesWritten);
    LogEvent("WinHttpWriteData", "result", endpoint, bytesWritten ? *bytesWritten : 0, result ? "ok" : "failed");
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
    LogHeaders("HttpSendRequestA", endpoint, AnsiString(headers, headersLength));
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
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(file));
    if (result && read > 0) {
        LogEvent("InternetReadFile", "in", endpoint, read, "ok", {}, buffer, read);
    }
    else {
        LogEvent("InternetReadFile", "in", endpoint, read, result ? "ok" : "failed");
    }
    return result;
}

BOOL WINAPI Hook_InternetWriteFile(HINTERNET file, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten)
{
    SOCKETU_GUARD_RETURN(Real_InternetWriteFile(file, buffer, bytesToWrite, bytesWritten));
    std::string endpoint = EndpointFromHttpInfo(GetHandleInfo(file));
    LogEvent("InternetWriteFile", "out", endpoint, bytesToWrite, "before-call", {}, buffer, bytesToWrite);
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
    int result = Real_SSL_write_ex(ssl, buffer, count, written);
    LogEvent("SSL_write_ex", "result", "openssl", written ? static_cast<long long>(*written) : 0, FormatString("result=%d", result));
    return result;
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
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

HMODULE WINAPI Hook_LoadLibraryA(LPCSTR fileName)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryA(fileName));
    HMODULE module = Real_LoadLibraryA(fileName);
    TryInstallOpenSslHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR fileName)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryW(fileName));
    HMODULE module = Real_LoadLibraryW(fileName);
    TryInstallOpenSslHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR fileName, HANDLE file, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryExA(fileName, file, flags));
    HMODULE module = Real_LoadLibraryExA(fileName, file, flags);
    TryInstallOpenSslHooks(module);
    return module;
}

HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR fileName, HANDLE file, DWORD flags)
{
    SOCKETU_GUARD_RETURN(Real_LoadLibraryExW(fileName, file, flags));
    HMODULE module = Real_LoadLibraryExW(fileName, file, flags);
    TryInstallOpenSslHooks(module);
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
        "config dump=%s max_bytes=%d headers=%s redact=%s console=%s jsonl=%s pipe=%s rotate=%llu/%d log=%s jsonl_file=%s pipe_name=%s",
        g_Config.dumpData ? "on" : "off",
        g_Config.maxDumpBytes,
        g_Config.logHttpHeaders ? "on" : "off",
        g_Config.redact ? "on" : "off",
        g_Config.console ? "on" : "off",
        g_Config.jsonl ? "on" : "off",
        g_Config.namedPipe ? "on" : "off",
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
