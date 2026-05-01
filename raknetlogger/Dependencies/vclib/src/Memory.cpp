#include "vclib/memory.h"
#include "vclib/syscall.h"
#include "vclib/process.h"

#undef min
#undef max
#include <algorithm>
#include <Psapi.h>
#include <sstream>


bool CMemory::ProtectVirtualMemory(const uint64_t virtualAddress, SIZE_T regionSize, DWORD protection, PDWORD oldProtect) {
	NTSTATUS status;
	PVOID target = (PVOID)virtualAddress;
	status = Syscall::NtProtectVirtualMemory(
		pProc->handle(),
		&target,
		&regionSize,
		(ULONG)protection,
		(PULONG)oldProtect
	);
	return (status == 0);
}

bool CMemory::ReadVirtualMemory(const uint64_t virtualAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesRead) {
	NTSTATUS status;
	status = Syscall::NtReadVirtualMemory(pProc->handle(), (PVOID)virtualAddress, buffer, size, bytesRead);
	return (status == 0);
}

bool CMemory::WriteVirtualMemory(const uint64_t virtualAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten) {
	NTSTATUS status;
	status = Syscall::NtWriteVirtualMemory(pProc->handle(), (PVOID)virtualAddress, buffer, size, bytesWritten);
	return (status == 0);
}

bool CMemory::Patch(uint64_t virtualAddress, const std::vector<uint8_t>& bytes) {
	SIZE_T patchSize = bytes.size();
	std::vector<uint8_t> original(patchSize);
	if (!ReadVirtualMemory(virtualAddress, original.data(), patchSize))
		return false;
	savedPatches.emplace_back(SPatch{ virtualAddress, original });
	DWORD old;
	ProtectVirtualMemory(virtualAddress, bytes.size(), PAGE_EXECUTE_READWRITE, &old);
	if (!WriteVirtualMemory(virtualAddress, (PVOID)bytes.data(), bytes.size()))
		return false;
	ProtectVirtualMemory(virtualAddress, bytes.size(), old, &old);
	return true;
}

void CMemory::RestorePatches(uint64_t virtualAddress) {
	if (virtualAddress == RESTORE_ALL) {
		for (const auto& patch : savedPatches) {
			DWORD oldProtect;
			ProtectVirtualMemory(patch.va, patch.original.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
			WriteVirtualMemory(patch.va, (PVOID)patch.original.data(), patch.original.size());
			ProtectVirtualMemory(patch.va, patch.original.size(), oldProtect, &oldProtect);
		}
		savedPatches.clear();
	}
	else {
		auto it = std::find_if(savedPatches.begin(), savedPatches.end(),
			[virtualAddress](const auto& patch) { return patch.va == virtualAddress; });

		if (it != savedPatches.end()) {
			DWORD oldProtect;
			ProtectVirtualMemory(it->va, it->original.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
			WriteVirtualMemory(it->va, it->original.data(), it->original.size());
			ProtectVirtualMemory(it->va, it->original.size(), oldProtect, &oldProtect);
			savedPatches.erase(it);
		}
	}
}

bool CMemory::RemapMemory(uint64_t base, size_t size) {
	std::vector<uint8_t> old(size);
	ReadVirtualMemory(base, old.data(), size);

	if (NT_ERROR(Syscall::NtUnmapViewOfSection(pProc->handle(), (PVOID)base)))
		return false;
	if (!VirtualAllocEx(pProc->handle(), (PVOID)base, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
		return false;
	WriteVirtualMemory(base, old.data(), size);
	return true;
}

std::vector<uint8_t> parsePattern(const std::string& pattern) {
	std::vector<uint8_t> bytes;
	std::istringstream iss(pattern);
	std::string token;
	while (iss >> token) {
		if (token == "?" || token == "??") {
			bytes.push_back(0xFF);
		}
		else {
			bytes.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
		}
	}
	return bytes;
}
bool matchesPattern(const uint8_t* data, const std::vector<uint8_t>& pattern, size_t offset) {
	for (size_t i = 0; i < pattern.size(); ++i) {
		if (pattern[i] != 0xFF && data[offset + i] != pattern[i]) {
			return false;
		}
	}
	return true;
}
uintptr_t CMemory::SigScan(const std::string& pattern, uintptr_t base) {
	if (!pProc || !pProc->handle()) return 0;

	auto bytes = parsePattern(pattern);
	if (bytes.empty()) return 0;

	std::vector<uint8_t> buffer(4096);
	MEMORY_BASIC_INFORMATION mbi;

	uintptr_t addr = base;
	if (base == 0) {
		addr = 0x10000;
	}

	while (VirtualQueryEx(pProc->handle(), reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT &&
			(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))) {
			uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
			for (uintptr_t scanAddr = (uintptr_t)mbi.BaseAddress; scanAddr + bytes.size() <= regionEnd; scanAddr += 4096) {
				SIZE_T toRead = std::min<SIZE_T>(4096UL, regionEnd - scanAddr);
				SIZE_T bytesRead;
				if (ReadProcessMemory(pProc->handle(), reinterpret_cast<LPCVOID>(scanAddr), buffer.data(), toRead, &bytesRead)) {
					for (size_t i = 0; i <= bytesRead - bytes.size(); ++i) {
						if (matchesPattern(buffer.data(), bytes, i)) {
							return scanAddr + i;
						}
					}
				}
			}
		}
		addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
		if (addr > 0x7FFFFFFF0000ULL) break;
	}
	return 0;
}

