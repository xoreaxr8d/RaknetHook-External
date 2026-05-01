#pragma once
#include <iostream>
#include <Windows.h>

#include "vclib/vclib.h"

class Instance {
private:
	CProcess* rbx;
	CMemory* mem;

	uintptr_t robloxBase;

public:
	Instance(CProcess* prc, CMemory* cm) : rbx(prc), mem(cm) {
		robloxBase = rbx->GetModuleBaseAddress("RobloxPlayerBeta.exe");
		if (!robloxBase) return;
	};
	~Instance() {
		
	}

	uintptr_t GetJobByName(const std::string& jobName);

	std::string ReadString(uintptr_t address);

};