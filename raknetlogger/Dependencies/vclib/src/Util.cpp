#include "vclib/util.h"

#include <vector>
#include <Psapi.h>
#include <TlHelp32.h>
#include <sstream>
#include <aclapi.h>
#include <sddl.h>

uint64_t Util::ReadFileD(const std::string& filePath) {
	void* handle = CreateFileA(filePath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!handle) return 0;
	DWORD fileSize = GetFileSize(handle, 0);
	PVOID buffer = VirtualAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ReadFile(handle, buffer, fileSize, 0, FALSE) || *reinterpret_cast<int*>(buffer) != 9460301) {
		CloseHandle(handle);
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}
	CloseHandle(handle);
	return (uint64_t)buffer;
}

PIMAGE_NT_HEADERS Util::GetMappingHeader(uint64_t base) {
	PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(base);
	return PIMAGE_NT_HEADERS(base + dosHeader->e_lfanew);
}

void Util::ReplaceShellcode(std::vector<BYTE>& data, uint64_t searchValue, uint64_t replaceValue) {
	const BYTE movPrefix = 0x48;
	const BYTE movPrefix2 = 0x49;
	const BYTE movBaseOpcode = 0xB8;
	const size_t instructionSize = 10;
	for (size_t i = 0; i <= data.size() - instructionSize; ++i) {
		if ((data[i] == movPrefix || data[i] == movPrefix2) && data[i + 1] >= movBaseOpcode && data[i + 1] <= movBaseOpcode + 7) {
			uint64_t imm = *(uint64_t*)(&data[i + 2]);
			uint32_t offset = *(uint32_t*)(&data[i + 2]);
			if (imm - offset == searchValue) {
				uintptr_t newValue = replaceValue + offset;
				std::memcpy(&data[i + 2], &newValue, sizeof(newValue));
			}
		}

		uint64_t immQ = *(uint64_t*)(&data[i + 1]);
		uint32_t immO = *(uint32_t*)(&data[i + 1]);
		if ((data[i] == 0xA1 || data[i] == 0xA2 || data[i] == 0xA3) && immQ - immO == searchValue) {
			uintptr_t newValue = replaceValue + immO;
			std::memcpy(&data[i + 1], &newValue, sizeof(newValue));
		}
	}
}

std::vector<BYTE> Util::ExtractShellcode(uintptr_t func) {
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((void*)func, &mbi, sizeof(mbi));
	size_t functionSize = mbi.RegionSize;
	std::vector<BYTE> shellcode;
	for (size_t i = 0; i < functionSize; ++i) {
		BYTE value = *(BYTE*)(func + i);
		shellcode.push_back(value);

		if (value == 0xCC && *(BYTE*)(func + i + 1) == 0xCC && *(BYTE*)(func + i + 2) == 0xCC) {
			break;
		}
	}
	return shellcode;
}

void Util::SetFilePerms(const char* path, bool allowAccess) {
	PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
	PACL dacl = nullptr;

	LPCWSTR sddlString = allowAccess
		? L"D:(D;;FA;;;WD)"
		: L"D:(A;;FA;;;WD)";

	wchar_t widePath[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddlString,
		SDDL_REVISION_1,
		&securityDescriptor,
		nullptr)) {
		return;
	}

	BOOL daclPresent = FALSE;
	BOOL daclDefaulted = FALSE;
	GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl, &daclDefaulted);

	SetNamedSecurityInfoW(
		widePath,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		nullptr,
		nullptr,
		dacl,
		nullptr);

	LocalFree(securityDescriptor);
}