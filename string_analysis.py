import sys


RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m' 
CYAN = "\033[36m"
END = "\033[0m"


banner="""
███████ ████████ ██████  ██ ███    ██  ██████       █████  ███    ██  █████  ██      ██    ██ ███████ ██ ███████ 
██         ██    ██   ██ ██ ████   ██ ██           ██   ██ ████   ██ ██   ██ ██       ██  ██  ██      ██ ██      
███████    ██    ██████  ██ ██ ██  ██ ██   ███     ███████ ██ ██  ██ ███████ ██        ████   ███████ ██ ███████ 
     ██    ██    ██   ██ ██ ██  ██ ██ ██    ██     ██   ██ ██  ██ ██ ██   ██ ██         ██         ██ ██      ██ 
███████    ██    ██   ██ ██ ██   ████  ██████      ██   ██ ██   ████ ██   ██ ███████    ██    ███████ ██ ███████
"""
print(f"{CYAN}{banner}")
print(f">>>{CYAN} By Rishi Prakash")


mal_api = [
'CreateToolhelp32Snapshot', 'EnumDeviceDrivers', 'EnumProcesses', 'EnumProcessModules', 'EnumProcessModulesEx', 'FindFirstFileA', 'FindNextFileA', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetModuleBaseNameA', 'GetSystemDefaultLangId', 'GetVersionExA', 'GetWindowsDirectoryA', 'IsWoW64Process', 'Module32First', 'Module32Next', 'Process32First', 'Process32Next', 'ReadProcessMemory', 'Thread32First', 'Thread32Next', 'GetSystemDirectoryA', 'GetSystemTime', 'ReadFile', 'GetComputerNameA', 'VirtualQueryEx', 'GetProcessIdOfThread', 'GetProcessId', 'GetCurrentThread', 'GetCurrentThreadId', 'GetThreadId', 'GetThreadInformation', 'GetCurrentProcess', 'GetCurrentProcessId', 'SearchPathA', 'GetFileTime', 'GetFileAttributesA', 'LookupPrivilegeValueA', 'LookupAccountNameA', 'GetCurrentHwProfileA', 'GetUserNameA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegQueryInfoKeyA', 'RegQueryMultipleValuesA', 'RegQueryValueExA', 'NtQueryDirectoryFile', 'NtQueryInformationProcess', 'NtQuerySystemEnvironmentValueEx', 'EnumDesktopWindows', 'EnumWindows', 'NetShareEnum', 'NetShareGetInfo', 'NetShareCheck', 'GetAdaptersInfo', 'PathFileExistsA', 'GetNativeSystemInfo', 'RtlGetVersion', 'GetIpNetTable', 'GetLogicalDrives', 'GetDriveTypeA', 'RegEnumKeyA', 'WNetEnumResourceA', 'WNetCloseEnum', 'FindFirstUrlCacheEntryA', 'FindNextUrlCacheEntryA', 'WNetAddConnection2A', 'WNetAddConnectionA', 'EnumResourceTypesA', 'EnumResourceTypesExA', 'GetSystemTimeAsFileTime', 'GetThreadLocale', 'EnumSystemLocalesA', 'CreateFileMappingA', 'CreateProcessA', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'GetModuleHandleA', 'GetProcAddress', 'GetThreadContext', 'HeapCreate', 'LoadLibraryA', 'LoadLibraryExA', 'LocalAlloc', 'MapViewOfFile', 'MapViewOfFile2', 'MapViewOfFile3', 'MapViewOfFileEx', 'OpenThread', 'Process32First', 'Process32Next', 'QueueUserAPC', 'ReadProcessMemory', 'ResumeThread', 'SetProcessDEPPolicy', 'SetThreadContext', 'SuspendThread', 'Thread32First', 'Thread32Next', 'Toolhelp32ReadProcessMemory', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'VirtualAllocExNuma', 'VirtualAlloc2', 'VirtualAlloc2FromApp', 'VirtualAllocFromApp', 'VirtualProtectFromApp', 'CreateThread', 'WaitForSingleObject', 'OpenProcess', 'OpenFileMappingA', 'GetProcessHeap', 'GetProcessHeaps', 'HeapAlloc', 'HeapReAlloc', 'GlobalAlloc', 'AdjustTokenPrivileges', 'CreateProcessAsUserA', 'OpenProcessToken', 'CreateProcessWithTokenW', 'NtAdjustPrivilegesToken', 'NtAllocateVirtualMemory', 'NtContinue', 'NtCreateProcess', 'NtCreateProcessEx', 'NtCreateSection', 'NtCreateThread', 'NtCreateThreadEx', 'NtCreateUserProcess', 'NtDuplicateObject', 'NtMapViewOfSection', 'NtOpenProcess', 'NtOpenThread', 'NtProtectVirtualMemory', 'NtQueueApcThread', 'NtQueueApcThreadEx', 'NtQueueApcThreadEx2', 'NtReadVirtualMemory', 'NtResumeThread', 'NtUnmapViewOfSection', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'NtWriteVirtualMemory', 'RtlCreateHeap', 'LdrLoadDll', 'RtlMoveMemory', 'RtlCopyMemory', 'SetPropA', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx', 'KeInsertQueueApc', 'Wow64SetThreadContext', 'NtSuspendProcess', 'NtResumeProcess', 'DuplicateToken', 'NtReadVirtualMemoryEx', 'CreateProcessInternal', 'EnumSystemLocalesA', 'UuidFromStringA', 'DebugActiveProcessStop', 'CreateFileMappingA', 'DeleteFileA', 'GetModuleHandleA', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryExA', 'LoadResource', 'SetEnvironmentVariableA', 'SetFileTime', 'Sleep', 'WaitForSingleObject', 'SetFileAttributesA', 'SleepEx', 'NtDelayExecution', 'NtWaitForMultipleObjects', 'NtWaitForSingleObject', 'CreateWindowExA', 'RegisterHotKey', 'timeSetEvent', 'IcmpSendEcho', 'WaitForSingleObjectEx', 'WaitForMultipleObjects', 'WaitForMultipleObjectsEx', 'SetWaitableTimer', 'CreateTimerQueueTimer', 'CreateWaitableTimer', 'SetWaitableTimer', 'SetTimer', 'Select', 'ImpersonateLoggedOnUser', 'SetThreadToken', 'DuplicateToken', 'SizeOfResource', 'LockResource', 'CreateProcessInternal', 'TimeGetTime', 'EnumSystemLocalesA', 'UuidFromStringA', 'CryptProtectData', 'AttachThreadInput', 'CallNextHookEx', 'GetAsyncKeyState', 'GetClipboardData', 'GetDC', 'GetDCEx', 'GetForegroundWindow', 'GetKeyboardState', 'GetKeyState', 'GetMessageA', 'GetRawInputData', 'GetWindowDC', 'MapVirtualKeyA', 'MapVirtualKeyExA', 'PeekMessageA', 'PostMessageA', 'PostThreadMessageA', 'RegisterHotKey', 'RegisterRawInputDevices', 'SendMessageA', 'SendMessageCallbackA', 'SendMessageTimeoutA', 'SendNotifyMessageA', 'SetWindowsHookExA', 'SetWinEventHook', 'UnhookWindowsHookEx', 'BitBlt', 'StretchBlt', 'GetKeynameTextA', 'WinExec', 'FtpPutFileA', 'HttpOpenRequestA', 'HttpSendRequestA', 'HttpSendRequestExA', 'InternetCloseHandle', 'InternetOpenA', 'InternetOpenUrlA', 'InternetReadFile', 'InternetReadFileExA', 'InternetWriteFile', 'URLDownloadToFile', 'URLDownloadToCacheFile', 'URLOpenBlockingStream', 'URLOpenStream', 'Accept', 'Bind', 'Connect', 'Gethostbyname', 'Inet_addr', 'Recv', 'Send', 'WSAStartup', 'Gethostname', 'Socket', 'WSACleanup', 'Listen', 'ShellExecuteA', 'ShellExecuteExA', 'DnsQuery_A', 'DnsQueryEx', 'WNetOpenEnumA', 'FindFirstUrlCacheEntryA', 'FindNextUrlCacheEntryA', 'InternetConnectA', 'InternetSetOptionA', 'WSASocketA', 'Closesocket', 'WSAIoctl', 'ioctlsocket', 'HttpAddRequestHeaders', 'CreateToolhelp32Snapshot', 'GetLogicalProcessorInformation', 'GetLogicalProcessorInformationEx', 'GetTickCount', 'OutputDebugStringA', 'CheckRemoteDebuggerPresent', 'Sleep', 'GetSystemTime', 'GetComputerNameA', 'SleepEx', 'IsDebuggerPresent', 'GetUserNameA', 'NtQueryInformationProcess', 'ExitWindowsEx', 'FindWindowA', 'FindWindowExA', 'GetForegroundWindow', 'GetTickCount64', 'QueryPerformanceFrequency', 'QueryPerformanceCounter', 'GetNativeSystemInfo', 'RtlGetVersion', 'GetSystemTimeAsFileTime', 'CountClipboardFormats', 'CryptAcquireContextA', 'EncryptFileA', 'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey', 'CryptSetKeyParam', 'CryptGetHashParam', 'CryptSetKeyParam', 'CryptDestroyKey', 'CryptGenRandom', 'DecryptFileA', 'FlushEfsCache', 'GetLogicalDrives', 'GetDriveTypeA', 'CryptStringToBinary', 'CryptBinaryToString', 'CryptReleaseContext', 'CryptDestroyHash', 'EnumSystemLocalesA', 'CryptProtectData', 'ConnectNamedPipe', 'CopyFileA', 'CreateFileA', 'CreateMutexA', 'CreateMutexExA', 'DeviceIoControl', 'FindResourceA', 'FindResourceExA', 'GetModuleBaseNameA', 'GetModuleFileNameA', 'GetModuleFileNameExA', 'GetTempPathA', 'IsWoW64Process', 'MoveFileA', 'MoveFileExA', 'PeekNamedPipe', 'WriteFile', 'TerminateThread', 'CopyFile2', 'CopyFileExA', 'CreateFile2', 'GetTempFileNameA', 'TerminateProcess', 'SetCurrentDirectory', 'FindClose', 'SetThreadPriority', 'UnmapViewOfFile', 'ControlService', 'ControlServiceExA', 'CreateServiceA', 'DeleteService', 'OpenSCManagerA', 'OpenServiceA', 'RegOpenKeyA', 'RegOpenKeyExA', 'StartServiceA', 'StartServiceCtrlDispatcherA', 'RegCreateKeyExA', 'RegCreateKeyA', 'RegSetValueExA', 'RegSetKeyValueA', 'RegDeleteValueA', 'RegOpenKeyExA', 'RegEnumKeyExA', 'RegEnumValueA', 'RegGetValueA', 'RegFlushKey', 'RegGetKeySecurity', 'RegLoadKeyA', 'RegLoadMUIStringA', 'RegOpenCurrentUser', 'RegOpenKeyTransactedA', 'RegOpenUserClassesRoot', 'RegOverridePredefKey', 'RegReplaceKeyA', 'RegRestoreKeyA', 'RegSaveKeyA', 'RegSaveKeyExA', 'RegSetKeySecurity', 'RegUnLoadKeyA', 'RegConnectRegistryA', 'RegCopyTreeA', 'RegCreateKeyTransactedA', 'RegDeleteKeyA', 'RegDeleteKeyExA', 'RegDeleteKeyTransactedA', 'RegDeleteKeyValueA', 'RegDeleteTreeA', 'RegDeleteValueA', 'RegCloseKey', 'NtClose', 'NtCreateFile', 'NtDeleteKey', 'NtDeleteValueKey', 'NtMakeTemporaryObject', 'NtSetContextThread', 'NtSetInformationProcess', 'NtSetInformationThread', 'NtSetSystemEnvironmentValueEx', 'NtSetValueKey', 'NtShutdownSystem', 'NtTerminateProcess', 'NtTerminateThread', 'RtlSetProcessIsCritical', 'DrawTextExA', 'GetDesktopWindow', 'SetClipboardData', 'SetWindowLongA', 'SetWindowLongPtrA', 'OpenClipboard', 'SetForegroundWindow', 'BringWindowToTop', 'SetFocus', 'ShowWindow', 'NetShareSetInfo', 'NetShareAdd', 'NtQueryTimer', 'GetIpNetTable', 'GetLogicalDrives', 'GetDriveTypeA', 'CreatePipe', 'RegEnumKeyA', 'WNetOpenEnumA', 'WNetEnumResourceA', 'WNetAddConnection2A', 'CallWindowProcA', 'NtResumeProcess', 'lstrcatA', 'ImpersonateLoggedOnUser', 'SetThreadToken', 'SizeOfResource', 'LockResource', 'UuidFromStringA']


print("======================= API analysis ======================================")
arguments = sys.argv


try:

	file = open(arguments[1],"r")
	for i in file:
		for j in mal_api:
			if j in i:
				print(f"{RED}{j}")
	file.close()


	print(f"{CYAN}======================= EXE file analysis ======================================")
	file1 = open(arguments[1],"r")
	for j in file1:
		if "exe" in j:
			print(f"{RED} {j}",end="")
	file1.close()


	print(f"{CYAN}======================= All files analysis ======================================")
	file = open(arguments[1],"r")
	for i in file:
		if "." in i:
			dot_index = i.index(".")
			if i[dot_index-1].isalpha() and i[dot_index+1].isalpha():
				print(f"{RED} {i}",end="")

	file.close()


	print(f"{CYAN}======================= URL analysis ======================================")
	file = open(arguments[1],"r")
	for i in file:
		if "http" in i or "https" in i or "ftp" in i:
			print(f"{RED} {i}",end="")

	file.close()

except:
	print(f"{RED}Syntax: python3 string_analysis.py strings.txt")
	if ".txt" in arguments[1]:
		print(f"{RED}{arguments[1]}: File not found!!!")

