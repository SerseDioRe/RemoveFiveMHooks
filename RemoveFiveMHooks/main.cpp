#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

//InsideExploit is gay

void PatchEx(BYTE* dst, BYTE* src, unsigned int size, HANDLE hProcess) {
	DWORD oldprotect;
	VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	WriteProcessMemory(hProcess, dst, src, size, nullptr);
	VirtualProtectEx(hProcess, dst, size, oldprotect, &oldprotect);
}

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName) {
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_stricmp(modEntry.szModule, modName)) {
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

DWORD GetProcId(const char* processName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);
		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_stricmp(procEntry.szExeFile, processName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

int main()
{
	DWORD PID = 0;

	while (!PID)
	{
		std::cout << "PROCESS NOT FOUND\n";
		PID = GetProcId("FiveM_GTAProcess.exe");

		Sleep(30);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (!hProc)
	{
		exit(EXIT_FAILURE);
	}

	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "ntdll.dll"),      "NtProtectVirtualMemory")), (BYTE*)"\x4C\x8B\xD1\xB8\x50\x00\x00\x00\xF6\x04\x25\x08\x03\xFE\x7F\x01", 16, hProc);
	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "kernel32.dll"),   "BaseThreadInitThunk")),    (BYTE*)"\x48\x83\xEC\x28\x85\xC9", 6, hProc);
	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "kernel32.dll"),   "LoadLibraryExW")),         (BYTE*)"\x48\xFF\x25\x11\x67\x06\x00\xCC", 8, hProc);
	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "KernelBase.dll"), "LoadLibraryExW")),         (BYTE*)"\x40\x55\x53\x57\x48\x8B\xEC", 7, hProc);
	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "ntdll.dll"),      "LdrLoadDll")),             (BYTE*)"\x48\x89\x5C\x24\x10", 5, hProc);
	PatchEx((BYTE*)(GetProcAddress((HMODULE)GetModuleBaseAddress(PID, "ntdll.dll"),      "NtOpenFile")),             (BYTE*)"\x4C\x8B\xD1\xB8\x33\x00\x00\x00\xF6\x04\x25\x08\x03\xFE\x7F\x01", 16, hProc);

	CloseHandle(hProc);

	return 0;
}
