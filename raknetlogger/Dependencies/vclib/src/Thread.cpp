#include "vclib/thread.h"
#include "vclib/syscall.h"

#include <memory>


MODULEINFO CThread::GetLocalModule() {
	MODULEINFO modInf{};
	HMODULE hMod = GetModuleHandleA(nullptr);
	if (hMod) {
		GetModuleInformation((HANDLE)-1, hMod, &modInf, sizeof(modInf));
	}
	return modInf;
}

void* CThread::ConvertAddress(const void* address, const void* oldBase, const void* newBase) {
	return (void*)((uintptr_t)(address)-(uintptr_t)(oldBase)+(uintptr_t)(newBase));
}

bool CThread::AllocateRemoteImage(const MODULEINFO& local, void*& remoteAlloc) {
    if (!remoteAlloc) {
        remoteAlloc = VirtualAllocEx(hProc, nullptr, local.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteAlloc)
            return false;
    }
    VirtualProtectEx(hProc, remoteAlloc, local.SizeOfImage, PAGE_EXECUTE_READWRITE, nullptr);
    if (!WriteProcessMemory(hProc, remoteAlloc, local.lpBaseOfDll, local.SizeOfImage, nullptr)) {
        VirtualFreeEx(hProc, remoteAlloc, 0, MEM_RELEASE);
        return false;
    }
    return true;
}

bool CThread::CreateThreadPool(void* function) {
    PROCESS_HANDLE_SNAPSHOT_INFORMATION* Handles = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(new BYTE[100000]);
    
    NTSTATUS status = Syscall::NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)51,
        Handles,
        100000,
        nullptr
    );
    if (!NT_SUCCESS(status))
        return false;
    std::unique_ptr<BYTE[]> typeInfoBuffer = std::make_unique<BYTE[]>(10000);
    OBJECT_TYPE_INFORMATION* typeInfo =
        (OBJECT_TYPE_INFORMATION*)(typeInfoBuffer.get());

    HANDLE completionHandle = nullptr;
    for (DWORD i = 0; i < Handles->NumberOfHandles; i++) {
        HANDLE duplicatedHandle = nullptr;
        if (DuplicateHandle(hProc, (HANDLE)(i),
            GetCurrentProcess(), &duplicatedHandle,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {

            if (NT_SUCCESS(Syscall::NtQueryObject(duplicatedHandle, (OBJECT_INFORMATION_CLASS)2, typeInfo, 10000, nullptr)) &&
                wcscmp(L"IoCompletion", typeInfo->TypeName.Buffer) == 0) {
                completionHandle = duplicatedHandle;
                break;
            }
            else CloseHandle(duplicatedHandle);
        }
    }
    if (!completionHandle) {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi;
    PTP_DIRECT remoteDirectAddress = nullptr;
    PBYTE searchAddress = nullptr;
    SIZE_T minCaveSize = sizeof(TP_DIRECT);

    while (VirtualQueryEx(hProc, searchAddress, &mbi, sizeof(mbi))) {
        searchAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT &&
            mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize >= minCaveSize) {

            BYTE buffer[4096];
            SIZE_T bytesRead;
            PBYTE regionAddress = (PBYTE)mbi.BaseAddress;

            for (SIZE_T offset = 0; offset <= mbi.RegionSize - minCaveSize; offset += sizeof(buffer)) {
                SIZE_T readSize = min(sizeof(buffer), mbi.RegionSize - offset - minCaveSize + 1);
                if (!ReadProcessMemory(hProc, regionAddress + offset, buffer, readSize, &bytesRead)) {
                    break;
                }

                for (SIZE_T i = 0; i <= bytesRead - minCaveSize; i++) {
                    bool isCave = true;
                    for (SIZE_T j = 0; j < minCaveSize; j++) {
                        if (buffer[i + j] != 0) {
                            isCave = false;
                            break;
                        }
                    }

                    if (isCave) {
                        remoteDirectAddress = (PTP_DIRECT)(regionAddress + offset + i);
                        break;
                    }
                }

                if (remoteDirectAddress) break;
            }
        }

        if (remoteDirectAddress) break;
    }

    if (!remoteDirectAddress) {
        CloseHandle(completionHandle);
        return false;
    }
    TP_DIRECT direct = { 0 };
    direct.Callback = static_cast<TP_DIRECT*>(function);
    if (!WriteProcessMemory(hProc, remoteDirectAddress, &direct,
        sizeof(TP_DIRECT), nullptr)) {
        printf("Failed to write TP_DIRECT structure to target process, error 0x%X\n", GetLastError());
        CloseHandle(completionHandle);
        return false;
    }

    using Tdih = NTSTATUS(NTAPI*)(
        HANDLE IoCompletionHandle,
        PVOID KeyContext,
        PVOID ApcContext,
        NTSTATUS IoStatus,
        ULONG_PTR IoStatusInformation
    );
    auto dih = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetIoCompletion");
    Tdih zwDih = (Tdih)(dih);

    status = zwDih(completionHandle, remoteDirectAddress, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        CloseHandle(completionHandle);
        return false;
    }
    CloseHandle(completionHandle);
    return true;
}

uint64_t CThread::CreateRemoteThread(const PVOID function, uint64_t location) {
    MODULEINFO local = GetLocalModule();
    if (!local.lpBaseOfDll || !local.SizeOfImage)
        return false;

    void* remoteAlloc = (PVOID)location;
    if (!AllocateRemoteImage(local, remoteAlloc))
        return false;

    void* adjusted = ConvertAddress(function, local.lpBaseOfDll, remoteAlloc);
    CreateThreadPool(adjusted);
    return (uint64_t)remoteAlloc;
}

bool CThread::CreateRemoteThread(const std::vector<uint8_t>& shellcode, uint64_t location) {
    MODULEINFO local = GetLocalModule();
    if (!local.lpBaseOfDll || !local.SizeOfImage)
        return false;
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProc, (PVOID)location, shellcode.data(),
        shellcode.size(), &bytesWritten) || bytesWritten != shellcode.size()) {
        return false;
    }

    return CreateThreadPool((PVOID)location);
}