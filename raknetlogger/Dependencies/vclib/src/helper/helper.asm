PUBLIC NtOpenProcess
PUBLIC NtWriteVirtualMemory
PUBLIC NtReadVirtualMemory
PUBLIC NtProtectVirtualMemory
PUBLIC NtAllocateVirtualMemory
PUBLIC NtQueryVirtualMemory
PUBLIC NtUnmapViewOfSection
PUBLIC NtQuerySystemInformation
PUBLIC NtQueryObject

.data
	NtOpenProcessSysId				dd 026h
	NtWriteVirtualMemorySysId		dd 03Ah
	NtReadVirtualMemorySysId		dd 03Fh
	NtProtectVirtualMemorySysId		dd 050h
	NtAllocateVirtualMemorySysId	dd 018h
	NtQueryVirtualMemorySysId		dd 023h
	NtUnmapViewOfSectionSysId		dd 02Ah
	NtQuerySystemInformationSysId	dd 036h
	NtQueryObjectSysId				dd 010h



.code
	NtOpenProcess PROC
		mov r10, rcx
		mov eax, NtOpenProcessSysId
		syscall
		ret	
	NtOpenProcess ENDP

	NtWriteVirtualMemory PROC
		mov r10, rcx
		mov eax, NtWriteVirtualMemorySysId
		syscall
		ret	
	NtWriteVirtualMemory ENDP

	NtReadVirtualMemory PROC
		mov r10, rcx
		mov eax, NtReadVirtualMemorySysId
		syscall
		ret	
	NtReadVirtualMemory ENDP

	NtProtectVirtualMemory PROC
		mov r10, rcx
		mov eax, NtProtectVirtualMemorySysId
		syscall
		ret	
	NtProtectVirtualMemory ENDP

	NtAllocateVirtualMemory PROC
		mov r10, rcx
		mov eax, NtAllocateVirtualMemorySysId
		syscall
		ret	
	NtAllocateVirtualMemory ENDP

	NtQueryVirtualMemory PROC
		mov r10, rcx
		mov eax, NtQueryVirtualMemorySysId
		syscall
		ret	
	NtQueryVirtualMemory ENDP

	NtUnmapViewOfSection PROC
		mov r10, rcx
		mov eax, NtUnmapViewOfSectionSysId
		syscall
		ret	
	NtUnmapViewOfSection ENDP

	NtQuerySystemInformation PROC
		mov r10, rcx
		mov eax, NtQuerySystemInformationSysId
		syscall
		ret	
	NtQuerySystemInformation ENDP

	NtQueryObject PROC
		mov r10, rcx
		mov eax, NtQueryObjectSysId
		syscall
		ret	
	NtQueryObject ENDP

END