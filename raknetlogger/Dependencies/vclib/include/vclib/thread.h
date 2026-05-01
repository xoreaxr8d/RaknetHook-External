#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <Psapi.h>
#include <vector>


class CThread {
private:
	HANDLE hProc;

	MODULEINFO GetLocalModule();
	void* ConvertAddress(const void* address, const void* oldBase, const void* newBase);
	bool AllocateRemoteImage(const MODULEINFO& local, void*& remoteAlloc);
	bool CreateThreadPool(void* function);

public:
	CThread(HANDLE h) : hProc(h) {};
	
	uint64_t CreateRemoteThread(const PVOID function, uint64_t location);
	bool CreateRemoteThread(const std::vector<uint8_t>& shellcode, uint64_t location);
};