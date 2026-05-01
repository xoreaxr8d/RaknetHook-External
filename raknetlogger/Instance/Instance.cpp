#include "Instance.h"


#include "../Update.h"

std::string Instance::ReadString(uintptr_t address) {
    std::string result;
    result.reserve(204);
    for (int offset = 0; offset < 200; offset++) {
        char character = mem->Read<char>(address + offset);
        if (character == 0) break;
        result.push_back(character);
    }
    return result;
}



uintptr_t Instance::GetJobByName(const std::string& jobName) {
	uintptr_t scheduler = mem->Read<uintptr_t>(robloxBase + Update::rawTaskScheduler);
	if (!scheduler) return 0x0;

	uintptr_t jobList = mem->Read<uintptr_t>(scheduler + Update::jobStart);
    for (int i = 0; i < 2560; i++) {
        uintptr_t jobPtrAddr = jobList + i * sizeof(uintptr_t);
        uintptr_t jobPtr = mem->Read<uintptr_t>(jobPtrAddr);
        if (!jobPtr) continue;

        uintptr_t namePtr = mem->Read<uintptr_t>(jobPtr + Update::jobClassName);
        if (!namePtr) continue;


        std::string str = ReadString(jobPtr + Update::jobClassName);
        if (strcmp(str.c_str(), jobName.c_str()) == 0) {
            return jobPtr;
        }


    }


}