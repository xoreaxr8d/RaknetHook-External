#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>

/*
	VCLIB | JAN 2026 | VOLXPHY
	PROCESS CLASS

*/

class CProcess {
private:
	std::string processName;
	DWORD processId{};
	HANDLE hProc{};

	DWORD GetPidByWindow(const std::string& windowName);
	DWORD GetPidByProcess(const std::string& processName); 

	DWORD GetPid();
	HANDLE GetHandle(const DWORD desiredAccess);

public:
	// METHOD 1 : WindowName
	CProcess(const std::string& procName, const DWORD desiredAccess = PROCESS_ALL_ACCESS) : processName(procName) {
		processId = GetPid();
		if (!processId) return;
		hProc = GetHandle(desiredAccess);
	};
	// METHOD 2 : PID
	CProcess(const DWORD pid, const DWORD desiredAccess = PROCESS_ALL_ACCESS) : processId(pid) {
		if (!processId) return;
		hProc = GetHandle(desiredAccess);
	};
	~CProcess() {
		processName.clear();
		CloseHandle(hProc);
	};

	DWORD pid() { return processId; };
	HANDLE handle() { return hProc; };
	uint64_t GetModuleBaseAddress(const std::string& modName);
	uint64_t GetRemoteModuleProc(uint64_t modBase, const std::string& exFuncName);
	bool GetSection(uintptr_t mod, const std::string& sectionName, PIMAGE_SECTION_HEADER secHeader);
	void Suspend(bool param);
};