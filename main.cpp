#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <psapi.h>
#include <ntstatus.h>

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    PSIZE_T NumberOfBytesRead
    );

bool SetSeDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

void GeneratePattern(HANDLE hProcess, uintptr_t address, SIZE_T patternSize) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "Falha ao carregar ntdll.dll" << std::endl;
        return;
    }

    auto NtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemory_t>(
        GetProcAddress(hNtdll, "NtQueryVirtualMemory"));
    auto NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(
        GetProcAddress(hNtdll, "NtReadVirtualMemory"));

    if (!NtQueryVirtualMemory || !NtReadVirtualMemory) {
        std::cerr << "Falha ao obter endereços de NtQueryVirtualMemory ou NtReadVirtualMemory" << std::endl;
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T bytesRead;

    if (!NT_SUCCESS(NtQueryVirtualMemory(hProcess, reinterpret_cast<PVOID>(address), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr))) {
        std::cerr << "Falha ao consultar a memória." << std::endl;
        return;
    }

    std::vector<BYTE> buffer(mbi.RegionSize);
    if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))) {
        std::cerr << "Falha ao ler a memória." << std::endl;
        return;
    }

    SIZE_T offset = address - reinterpret_cast<uintptr_t>(mbi.BaseAddress);

    if (offset + patternSize > buffer.size()) {
        std::cerr << "Tamanho do padrão excede os limites da região de memória." << std::endl;
        return;
    }

    std::ostringstream oss;
    for (SIZE_T i = 0; i < patternSize; ++i) {
        if (buffer[offset + i] == 0x00) {
            oss << "? ";
        }
        else {
            oss << std::hex << std::uppercase << (buffer[offset + i] < 0x10 ? "0" : "") << static_cast<int>(buffer[offset + i]) << " ";
        }
    }

    std::cout << "Pattern gerado: " << oss.str() << std::endl;
}

int main() {
    if (!SetSeDebugPrivilege()) {
        std::cerr << "Falha ao definir SeDebugPrivilege." << std::endl;
        return 1;
    }

    DWORD pid;
    uintptr_t address;
    SIZE_T patternSize;

    std::cout << "Digite o PID do processo: ";
    std::cin >> pid;

    std::cout << "Digite o endereço de memória (hex): ";
    std::cin >> std::hex >> address;

    std::cout << "Digite o tamanho do padrão: ";
    std::cin >> patternSize;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Falha ao abrir o processo. Código de erro: " << GetLastError() << std::endl;
        return 1;
    }

    GeneratePattern(hProcess, address, patternSize);

    CloseHandle(hProcess);
    return 0;
}