#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>


class Util {
private:


public:
	static uint64_t ReadFileD(const std::string& filePath);
	static PIMAGE_NT_HEADERS GetMappingHeader(uint64_t base);
	static void ReplaceShellcode(std::vector<BYTE>& data, uint64_t searchValue, uint64_t replaceValue);
	static std::vector<BYTE> ExtractShellcode(uintptr_t func);
	static void SetFilePerms(const char* path, bool admin);
};