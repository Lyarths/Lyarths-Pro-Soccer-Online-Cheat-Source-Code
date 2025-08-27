#include <iostream>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>  
#include <winternl.h>  

// process name'den process id'yi alıyor
DWORD ProcessIdAl(const char* UygulamaIsim) {
    DWORD ProcessId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 ProcessEntry;
        ProcessEntry.dwSize = sizeof(ProcessEntry);

        if (Process32First(hSnap, &ProcessEntry)) {
            do {
                if (!_strcmpi(ProcessEntry.szExeFile, UygulamaIsim)) {
                    ProcessId = ProcessEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &ProcessEntry));
        }
    }
    CloseHandle(hSnap);
    return ProcessId;
}

// pointer zinciri okuma
uintptr_t PointerZinciriOku(HANDLE hProc, DWORD64 ptr, const std::vector<unsigned int>& offsets) {
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i) {
        if (!ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(DWORD64), nullptr)) {
            std::cout << "Pointerlari okumada hata var!! hata cıkıs: " << addr << std::endl;
            std::cout << "Eger bu hatayi aldiysan benle iletisime gec, discord: 9.9.9.9.9" << std::endl;
            return 0; 
        }
        addr += offsets[i];
    }
    return addr;
}

int main() {
    const char* OyunIsim = "ProSoccerOnline-Win64-Shipping.exe";
    // pid alir
    DWORD ProcessID = ProcessIdAl(OyunIsim);
    if (ProcessID == 0) {
        std::cout << "Process ID alimi basarisiz!" << std::endl;
        std::cout << "Eger bu hatayi aldiysan benle iletisime gec, discord: 9.9.9.9.9" << std::endl;
        return 1;
    }
    std::cout << "Process ID: " << ProcessID << std::endl;
    // handle alir
    HANDLE OyunHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
    if (!OyunHandle) {
        std::cout << "handle erisimi basarisiz!" << std::endl;
        std::cout << "Eger bu hatayi aldiysan benle iletisime gec, discord: 9.9.9.9.9" << std::endl;
        return 1;
    }

    // base addresi alir
    PROCESS_BASIC_INFORMATION pbi;
    ULONG Size = 0;
    typedef NTSTATUS(NTAPI* pNtQueryInfo)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    pNtQueryInfo NtQueryInformationProcess =
        (pNtQueryInfo)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess(OyunHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &Size) != 0) {
        std::cout << "NtQueryInformationProcess basarisiz!" << std::endl;
        std::cout << "Eger bu hatayi aldiysan benle iletisime gec, discord: 9.9.9.9.9" << std::endl;
        return 1;
    }

    PPEB PEB = pbi.PebBaseAddress;
    DWORD64 BaseAdress = 0;
    DWORD64 HedefAdress = (DWORD64)PEB + 0x10;
    ReadProcessMemory(OyunHandle, (LPCVOID)HedefAdress, &BaseAdress, sizeof(DWORD64), nullptr);

    std::cout << "Base Address: 0x" << std::hex << BaseAdress << std::endl;

    // pointer zinciriii
    std::vector<unsigned int> offsets = { 0x0, 0xA0, 0x6C8 };

    float yeniStamina = 999999.f;
    std::cout << "Aga stamina hilesi aktif. Her V tusuna bastiginda stamina dolacak!" << std::endl;

    while (true) {
        if (GetAsyncKeyState('V') & 0x8000) {
          
        
        uintptr_t finalAddr = PointerZinciriOku(OyunHandle, BaseAdress + 0x04611A38, offsets);

        if (finalAddr) {
            WriteProcessMemory(OyunHandle, (LPVOID)finalAddr, &yeniStamina, sizeof(yeniStamina), nullptr);
        }
        }
        Sleep(10); // 10ms de bir yenilicek 
    }

    CloseHandle(OyunHandle);
    return 0;
}
// By Lyarths
// Discord: 9.9.9.9.9
// Eğer ne yaptığınızı bilmiyorsanız kodda mantıksız bir değişiklik yapmayınız!
