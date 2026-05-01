#include <iostream>
#include <Windows.h>
#include <memory>

#include "Essentials/Logs.h"
#include "Update.h"
#include "vclib/vclib.h"

#include "Instance/Instance.h"





int64_t Raknet_Send_Hook(
	int64_t* thisPtr,
	int64_t* bitStream,
	int priority,
	int reliability,
	char orderingChannel,
	int64_t* systemIdentifier,
	char broadcast,
	int shift
) {
	auto ctx = (HookContext*)0x1000000000; // mov reg, 01000000000h
	uintptr_t realBitStream = bitStream[0];
	uint8_t* packetBytes = *reinterpret_cast<uint8_t**>(realBitStream + Update::RaknetInternal::bitStream_PacketBytes);
	uint32_t packetSize = *reinterpret_cast<uint32_t*>(realBitStream + Update::RaknetInternal::bitStream_PacketSize);

	memcpy(ctx->data.packetBytes, packetBytes, 256);
	ctx->data.packetSize = packetSize;
	ctx->data.pc = false;


	return ctx->fOriginal_RS(
		thisPtr,
		bitStream,
		priority,
		reliability,
		orderingChannel,
		systemIdentifier,
		broadcast,
		shift
	);
}



int main()
{
	SetConsoleTitleA("Raknet Packet Logger");
	Log::info("Made By Volx");
	// "Net Peer Send"
	auto rbx = std::make_shared<CProcess>("RobloxPlayerBeta.exe", PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION);
	auto mem = std::make_unique<CMemory>(rbx);
	if (!rbx->pid()) {
		Log::error("Roblox not found!");
		std::cin.get();
		return 1;
	}
	Log::info("Roblox : %d", rbx->pid());

	Instance* i = new Instance(rbx.get(), mem.get());
	uintptr_t packetJob = i->GetJobByName("Net Peer Send(Network_SendOutgoing;Ugc)");
	Log::warn("Packet Job : %llx", packetJob);
	delete i;

	uintptr_t RakPeer = mem->Read<uintptr_t>(packetJob + Update::RakPeer);
	Log::warn("RakPeer: %llx", RakPeer);

	uintptr_t sharedMemory = (uintptr_t)VirtualAllocEx(
		rbx->handle(),
		nullptr,
		sizeof(HookContext),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	

	uintptr_t hookSpace = rbx->GetModuleBaseAddress("winsta.dll") + 0x1000;
	mem->ProtectVirtualMemory(hookSpace, 0x1000, PAGE_EXECUTE_READWRITE, &Globals::op);


	uintptr_t originalVtable = mem->Read<uintptr_t>(RakPeer);
	uintptr_t originalRaknetSend = mem->Read<uintptr_t>(originalVtable + (Update::rnsndvtidx*sizeof(uintptr_t)));

	uintptr_t newVtable = hookSpace + 0x2000;
	mem->ProtectVirtualMemory(newVtable, 0x1000, PAGE_EXECUTE_READWRITE, &Globals::op);
	for (uintptr_t i = 0x0; i < 250 * sizeof(uintptr_t); i += 0x8)
		mem->Write<uintptr_t>(newVtable + i, mem->Read<uintptr_t>(originalVtable + i));

	mem->Write<uintptr_t>(newVtable + (Update::rnsndvtidx*sizeof(uintptr_t)), hookSpace);

	HookContext localView;
	localView.fOriginal_RS = (tRaknet_Send)originalRaknetSend;

	mem->Write(sharedMemory, localView);


	auto shellcode = Util::ExtractShellcode((uintptr_t)Raknet_Send_Hook);
	Util::ReplaceShellcode(shellcode, 0x1000000000, sharedMemory);
	mem->WriteVirtualMemory(hookSpace, shellcode.data(), shellcode.size());
	mem->Write<uintptr_t>(RakPeer, newVtable);


	while (true) {
		Sleep(1);
		PacketData cur = mem->Read<PacketData>(sharedMemory + offsetof(HookContext, data));
		if (cur.pc) continue;
		mem->Write<bool>(sharedMemory + offsetof(HookContext, data) + offsetof(PacketData, pc), false);
		printf("Packet Data (%d): \n", cur.packetSize);

		for (int i = 0; i <= cur.packetSize; ++i) {
			printf("%02llx ", cur.packetBytes[i]);

			if (i == cur.packetSize) printf("\n");
		}

		printf("ASCII: ");
		for (int i = 0; i <= cur.packetSize; ++i) {
			unsigned char byte = static_cast<unsigned char>(cur.packetBytes[i]);
			printf("%c", std::isprint(byte) ? byte : '.');
		}
		printf("\n\n");
		
	}

	return 0;
}
