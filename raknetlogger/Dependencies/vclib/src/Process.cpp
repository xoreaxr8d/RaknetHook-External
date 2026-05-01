#include "vclib/process.h"
#include "vclib/syscall.h"

#include <Psapi.h>
#include <TlHelp32.h>

DWORD CProcess::GetPidByWindow(const std::string& windowName) {
	HWND h = FindWindowA(nullptr, windowName.c_str());
	if (!h) return 0;
	DWORD pid;
	GetWindowThreadProcessId(h, &pid);
	return pid;
}

DWORD CProcess::GetPidByProcess(const std::string& processName) {
    DWORD processes[1024], cbNeeded, processCount;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
        return 0;
    processCount = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < processCount; i++) {
        if (processes[i] == 0) continue;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (!hProcess) continue;
        char szProcessName[MAX_PATH] = { 0 };
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameA(hProcess, hMod, szProcessName, sizeof(szProcessName));
            if (_stricmp(szProcessName, processName.c_str()) == 0) {
                DWORD pid = processes[i];
                CloseHandle(hProcess);
                return pid;
            }
        }
        CloseHandle(hProcess);
    }
    return 0;
}

DWORD CProcess::GetPid() {
    if (processName.empty()) return 0;
    DWORD pid;
    return (pid = GetPidByWindow(processName)) || (pid = GetPidByProcess(processName)) ? pid : 0;
}

HANDLE CProcess::GetHandle(const DWORD desiredAccess) {
    if (!processId) return nullptr;
    HANDLE hProcess = nullptr;
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)processId;
    clientId.UniqueThread = nullptr;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    NTSTATUS status = Syscall::NtOpenProcess(
        &hProcess,
        desiredAccess,
        &objAttr,
        &clientId
    );
    return NT_SUCCESS(status) ? hProcess : nullptr;
}

uint64_t CProcess::GetModuleBaseAddress(const std::string& modName) {
    if (!hProc || !processId) return 0x0;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(hProc, hMods[i], szModName, sizeof(szModName))) {
                if (_stricmp(szModName, modName.c_str()) == 0) {
                    return (uint64_t)hMods[i];
                }
            }
        }
    }

    return 0x0;
}

void CProcess::Suspend(bool suspend) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (suspend)
                        SuspendThread(hThread);
                    else
                        ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
}


uint64_t CProcess::GetRemoteModuleProc(uint64_t modBase, const std::string& exFuncName) {
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProc, (LPCVOID)modBase, &dosHeader, sizeof(dosHeader), nullptr)) {
        return 0;
    }

    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr)) {
        return 0;
    }

    const auto& exportDirData = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.VirtualAddress == 0 || exportDirData.Size == 0) {
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + exportDirData.VirtualAddress), &exportDir, sizeof(exportDir), nullptr)) {
        return 0;
    }

    std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);

    if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + exportDir.AddressOfNames), nameRVAs.data(), sizeof(DWORD) * nameRVAs.size(), nullptr) ||
        !ReadProcessMemory(hProc, (LPCVOID)(modBase + exportDir.AddressOfNameOrdinals), ordinals.data(), sizeof(WORD) * ordinals.size(), nullptr) ||
        !ReadProcessMemory(hProc, (LPCVOID)(modBase + exportDir.AddressOfFunctions), functionRVAs.data(), sizeof(DWORD) * functionRVAs.size(), nullptr)) {
        return 0;
    }

    char nameBuffer[256];
    for (size_t i = 0; i < nameRVAs.size(); ++i) {
        if (!ReadProcessMemory(hProc, (LPCVOID)(modBase + nameRVAs[i]), nameBuffer, sizeof(nameBuffer), nullptr))
            continue;

        if (strcmp(nameBuffer, exFuncName.c_str()) == 0) {
            WORD ordinal = ordinals[i];
            if (ordinal >= functionRVAs.size()) {
                return 0;
            }

            return modBase + functionRVAs[ordinal];
        }
    }

    return 0;
}


bool CProcess::GetSection(uintptr_t mod, const std::string& sectionName, PIMAGE_SECTION_HEADER secHeader) {
    IMAGE_DOS_HEADER dosHeader{};
    ReadProcessMemory(hProc, (PVOID)mod, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    uintptr_t ntHeadersAddr = mod + dosHeader.e_lfanew;
    IMAGE_NT_HEADERS ntHeaders{};
    ReadProcessMemory(hProc, (PVOID)ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr);
    WORD numOfSections = ntHeaders.FileHeader.NumberOfSections;

    uintptr_t firstSectionAddr = ntHeadersAddr + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

    std::vector<IMAGE_SECTION_HEADER> sections(numOfSections);
    ReadProcessMemory(hProc, (PVOID)firstSectionAddr, sections.data(), numOfSections * sizeof(IMAGE_SECTION_HEADER), nullptr);

    for (int i = 0; i < numOfSections; ++i) {
        if (strncmp((const char*)sections[i].Name, sectionName.c_str(), IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *secHeader = sections[i];
            return true;
        }
    }

    return false;
}