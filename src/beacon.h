/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 */

/* data API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);

/* format API */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_PENDING     0x16
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void   BeaconPrintf(int type, char * fmt, ...);
DECLSPEC_IMPORT void   BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void   BeaconErrorD(int msg, int arg);
DECLSPEC_IMPORT void   BeaconErrorDD(int msg, int arg, int arg2);
DECLSPEC_IMPORT void   BeaconErrorNA(int msg);
DECLSPEC_IMPORT void   BeaconDebug(char * fmt, ...);

/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Spawn and Inject */
//DECLSPEC_IMPORT void   BeaconSpawnJob(int type, int wait, int offset, char * payload, int payload_length, char * argument, int argument_length, char * description, int description_length, BOOL x86, BOOL ignoreToken);
//DECLSPEC_IMPORT void   BeaconInject(HANDLE handle, char * shellcode, int shellcode_length, int shellcode_offset, char * arguments, int argument_length);

/* Execute Programs */
//DECLSPEC_IMPORT BOOL   BeaconExecute(char * command, int commandlength, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD flags, BOOL ignoreToken);
//DECLSPEC_IMPORT void   BeaconExecuteCleanup(PROCESS_INFORMATION * pi);

/* Job related APIs */
//DECLSPEC_IMPORT void   BeaconWatchHandle(HANDLE readme, DWORD pid, DWORD type, char * description);
//DECLSPEC_IMPORT void   BeaconWatchPipe(char * pipe, DWORD pid, DWORD type, char * description);

/* Win32 APIs */
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid);
DECLSPEC_IMPORT BOOL      APIENTRY ADVAPI32$CheckTokenMembership(HANDLE hToken, PSID pSid, PBOOL isMember);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$CreateProcessWithLogonW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL      APIENTRY ADVAPI32$CreateRestrictedToken(HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD, PLUID_AND_ATTRIBUTES, DWORD, PSID_AND_ATTRIBUTES, PHANDLE);
DECLSPEC_IMPORT SC_HANDLE WINAPI   ADVAPI32$CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$DeleteService(SC_HANDLE hService);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT PVOID     WINAPI   ADVAPI32$FreeSid(PSID pSid);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT PDWORD    WINAPI   ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT PUCHAR    WINAPI   ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT SC_HANDLE WINAPI   ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegOpenCurrentUser(REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LSTATUS   APIENTRY ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$RevertToSelf();
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI   ADVAPI32$StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors);

DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetCurrentDirectoryW(DWORD, LPWSTR);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime);
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetModuleFileNameA(HMODULE, LPSTR, DWORD);
DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT UINT     WINAPI   KERNEL32$GetSystemWindowsDirectoryA(LPSTR, UINT);
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetLastError();
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetProcessId(HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$GetTickCount();
DECLSPEC_IMPORT HLOCAL   WINAPI   KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL   WINAPI   KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$Process32First(HANDLE, void *);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$Process32Next(HANDLE, void *);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$ProcessIdToSessionId(DWORD, DWORD *);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$SetFileTime(HANDLE hFile, CONST FILETIME *lpCreationTime, CONST FILETIME *lpLastAccessTime, CONST FILETIME *lpLastWriteTime);
DECLSPEC_IMPORT VOID     WINAPI   KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT LPVOID   WINAPI   KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT DWORD    WINAPI   KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);

DECLSPEC_IMPORT DWORD    WINAPI   NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
DECLSPEC_IMPORT DWORD    WINAPI   NETAPI32$NetApiBufferFree(LPVOID);

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation, ObjectNameInformation, ObjectTypeInformation, ObjectAllTypesInformation, ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

DECLSPEC_IMPORT NTSTATUS NTAPI    NTDLL$NtDuplicateObject(HANDLE, HANDLE *, HANDLE, HANDLE *, ACCESS_MASK, BOOLEAN, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI    NTDLL$NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI    NTDLL$NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI   NTDLL$RtlAdjustPrivilege(ULONG Privilege, BOOL Enable, BOOL CurrentThread, PULONG pPreviousState);
DECLSPEC_IMPORT BOOLEAN  NTAPI    NTDLL$RtlEqualUnicodeString(void *, void *, BOOLEAN);
DECLSPEC_IMPORT VOID     NTAPI    NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);

DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CLSIDFromString(wchar_t * lpsz, LPCLSID pclsid);
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CoGetObject(wchar_t *, BIND_OPTS *, REFIID, void **ppv);
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT  WINAPI   OLE32$IIDFromString(wchar_t * lpsz, LPIID lpiid);

DECLSPEC_IMPORT NTSTATUS NTAPI    SECUR32$LsaCallAuthenticationPackage(HANDLE, ULONG, PVOID, ULONG, PVOID, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS NTAPI    SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI    SECUR32$LsaDeregisterLogonProcess(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI    SECUR32$LsaLookupAuthenticationPackage(HANDLE, void *, PULONG);

DECLSPEC_IMPORT BOOL     WINAPI   SHELL32$ShellExecuteExA(LPSHELLEXECUTEINFOA);
