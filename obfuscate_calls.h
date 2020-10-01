#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#define RESOLVE_NAME_MAX 4096
#define RESOLVE_REL_CALC(x,y) ((LPBYTE)x + y)

#define PROCESSENTRY32 PROCESSENTRY32W
#define PPROCESSENTRY32 PPROCESSENTRY32W
#define LPPROCESSENTRY32 LPPROCESSENTRY32W

typedef HMODULE(WINAPI* _GetModuleHandleW)(LPCWSTR);
typedef BOOL(WINAPI* _OpenProcessToken)(
	HANDLE  ProcessHandle,
	DWORD   DesiredAccess,
	PHANDLE TokenHandle
	);
typedef HANDLE(WINAPI* _GetCurrentProcess)();
typedef BOOL(WINAPI* _LookupPrivilegeValueA)(
	_In_opt_ LPCSTR lpSystemName,
	_In_     LPCSTR lpName,
	_Out_    PLUID   lpLuid
	);
typedef BOOL(WINAPI* _AdjustTokenPrivileges)(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength
	);
typedef DWORD(WINAPI* _GetModuleFileName)(
	HMODULE hModule,
	LPWSTR   lpFilename,
	DWORD   nSize
	);
typedef HANDLE(WINAPI* _CreateToolhelp32Snapshot)(
	DWORD dwFlags,
	DWORD th32ProcessID
	);
typedef BOOL(WINAPI* _Process32FirstW)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* _Process32NextW)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* _CloseHandle)(HANDLE);
typedef HANDLE(WINAPI* _OpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);
typedef HMODULE(WINAPI* _GetModuleHandleW)(
	LPCWSTR lpModuleName
	);
typedef FARPROC(WINAPI* _GetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);
typedef LPVOID(WINAPI* _VirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);
typedef BOOL(WINAPI* _WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);
typedef HANDLE(WINAPI* _CreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	);
typedef LSTATUS(WINAPI* _RegCreateKeyW)(
	HKEY hKey,
	LPCWSTR lpSubKey,
	PHKEY phkResult
	);
typedef LSTATUS(WINAPI* _RegSetValueExW)(
	HKEY hKey,
	LPCWSTR lpValueName,
	DWORD Reserved,
	DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
	DWORD cbData
	);
typedef HANDLE(WINAPI* _CreateFileW)(
	_In_ LPCWSTR lpFileName,
	_In_ DWORD dwDesiredAccess,
	_In_ DWORD dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_ DWORD dwCreationDisposition,
	_In_ DWORD dwFlagsAndAttributes,
	_In_opt_ HANDLE hTemplateFile
	);
typedef BOOL(WINAPI*
	_ReadFile)(
		_In_ HANDLE hFile,
		_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
		_In_ DWORD nNumberOfBytesToRead,
		_Out_opt_ LPDWORD lpNumberOfBytesRead,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
typedef BOOL
(WINAPI*
	_WriteFile)(
		_In_ HANDLE hFile,
		_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
		_In_ DWORD nNumberOfBytesToWrite,
		_Out_opt_ LPDWORD lpNumberOfBytesWritten,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);

typedef BOOL
(WINAPI* _DeleteFileA)
(
	LPCSTR lpFileName
	);

#define TH32CS_SNAPPROCESS  0x00000002

typedef struct RESOLVE_ENTRY {
	CONST UINT32 u32Hash;
	LPCWSTR cszwMod;
	PVOID lpAddr;
} RESOLVE_ENTRY, * PRESOLVE_ENTRY;

typedef struct RESOLVE_TABLE {
	RESOLVE_ENTRY reEntries[];
} RESOLVE_TABLE, * PRESOLVE_TABLE;

BOOL resolve_find(PRESOLVE_ENTRY pEntry);
BOOL resolve_init(PRESOLVE_TABLE pTbl, SIZE_T uCount);
UINT32 resolve_hash_name(LPCSTR cszName);

