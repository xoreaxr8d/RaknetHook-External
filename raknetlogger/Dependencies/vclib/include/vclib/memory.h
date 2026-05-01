#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#define RESTORE_ALL 0x0

class CProcess;
struct SPatch {
	uintptr_t va;
	std::vector<uint8_t> original;
};

class CMemory {
private:
	std::shared_ptr<CProcess> pProc;
	std::vector<SPatch> savedPatches;

public:
	CMemory(std::shared_ptr<CProcess> proc) : pProc(proc) {};
	~CMemory() {};

	bool ReadVirtualMemory(const uint64_t virtualAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesRead = nullptr);
	bool WriteVirtualMemory(const uint64_t virtualAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten = nullptr);
	bool ProtectVirtualMemory(const uint64_t virtualAddress, SIZE_T regionSize, DWORD protection, PDWORD oldProtect);
	
	template <typename T>
	T Read(uint64_t virtualAddress) {
		T buf{};
		ReadVirtualMemory(virtualAddress, &buf, sizeof(T));
		return buf;
	}
	template <typename T>
	void Write(uint64_t virtualAddress, T value) {
		WriteVirtualMemory(virtualAddress, &value, sizeof(T));
	}

	bool Patch(uint64_t virtualAddress, const std::vector<uint8_t>& bytes);
	void RestorePatches(uint64_t virtualAddress = RESTORE_ALL);
	bool RemapMemory(uint64_t base, size_t size);

	uintptr_t SigScan(const std::string& pattern, uintptr_t base = 0x0);

};