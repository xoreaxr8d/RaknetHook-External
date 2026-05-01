#pragma once
#include <iostream>
#include <Windows.h>

enum class RaknetPacketType {
	RBX_PHYSICS_PACKET = 0x1B,

};
using tRaknet_Send = int64_t(__fastcall*)(
	int64_t* thisPtr,
	int64_t* bitStream,
	int priority, 
	int reliability,
	char orderingChannel,
	int64_t* systemIdentifier, 
	char broadcast, 
	int shift
);


struct PacketData {
	uint32_t packetSize; // 0x8
	uint8_t packetBytes[256]; // 0xC

	bool pc; // 0x10C
};

struct HookContext {
	tRaknet_Send fOriginal_RS;
	PacketData data; // 0x8
};

namespace Update {
	inline uintptr_t rawTaskScheduler = 0x7CF5400;
	inline uintptr_t jobName = 0x18;
	inline uintptr_t jobClassName = 0x108;
	inline uintptr_t jobEnd = 0xD0;
	inline uintptr_t jobStart = 0xC8;

	inline uintptr_t RakPeer = 0x1D0;
	inline int rnsndvtidx = 20;

	namespace RaknetInternal {
		inline uintptr_t bitStream_PacketBytes = 0x10; // *array
		inline uintptr_t bitStream_PacketSize = 0x30;

	}

	namespace Hyperion {
		inline uintptr_t Bitmap = 0xDA8550;
	}
}

namespace Globals {
	inline DWORD op;
}