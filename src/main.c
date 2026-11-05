#include <stdio.h>
#include <windows.h>
#include "../include/sysgate.h"

int main(void) {
    printf("[*] SysGate baslatiliyor (PEB parsing)...\n");
    if (!SysGateInitialize()) {
        printf("[-] Hata: ntdll okunamadi veya syscall gadget bulunamadi.\n");
        return -1;
    }

    printf("[+] ntdll.dll adresi   : 0x%p\n", (void*)g_SysGateTable.NtdllBase);
    printf("[+] 'syscall; ret' adr : 0x%p\n", (void*)g_SysGateTable.SyscallGadgetAddress);
    printf("[+] Toplam Zw fonksiyon: %u\n\n", g_SysGateTable.Count);

    // hash
    uint32_t hashAlloc   = SysGateComputeHash("NtAllocateVirtualMemory");
    uint32_t hashProtect = SysGateComputeHash("NtProtectVirtualMemory");
    uint32_t hashFree    = SysGateComputeHash("NtFreeVirtualMemory");

    uint16_t ssnAlloc   = SysGateGetSSNByHash(hashAlloc);
    uint16_t ssnProtect = SysGateGetSSNByHash(hashProtect);
    uint16_t ssnFree    = SysGateGetSSNByHash(hashFree);

    printf("[*] Dinamik SSN Cozumleri:\n");
    printf("    -> NtAllocateVirtualMemory : SSN = 0x%04X\n", ssnAlloc);
    printf("    -> NtProtectVirtualMemory  : SSN = 0x%04X\n", ssnProtect);
    printf("    -> NtFreeVirtualMemory     : SSN = 0x%04X\n\n", ssnFree);

    if (ssnAlloc == 0xFFFF || ssnProtect == 0xFFFF || ssnFree == 0xFFFF) {
        printf("[-] SSN degerlerinden biri bulunamadi!\n");
        return -1;
    }

    // indirect syscall
    printf("[*] Indirect syscall ile bellek ayriliyor (NtAllocateVirtualMemory)...\n");

    PVOID pBaseAddress = NULL;
    SIZE_T uRegionSize = 0x1000; // 4096 byte
    HANDLE hProcess = (HANDLE)(intptr_t)-1; // process handle

    NTSTATUS status = SysGateDispatch(
        ssnAlloc,
        SysGateGetGadgetAddress(),
        6,
        (uintptr_t)hProcess,
        (uintptr_t)&pBaseAddress,
        (uintptr_t)0,
        (uintptr_t)&uRegionSize,
        (uintptr_t)(MEM_COMMIT | MEM_RESERVE),
        (uintptr_t)PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtAllocateVirtualMemory basarisiz: 0x%08X\n", status);
        return -1;
    }

    printf("[+] Bellek ayrildi: 0x%p (Boyut: 0x%llX)\n", pBaseAddress, (unsigned long long)uRegionSize);

    uint8_t testPattern[] = { 0x90, 0x90, 0xC3 }; // nop, nop, ret
    memcpy(pBaseAddress, testPattern, sizeof(testPattern));
    printf("[+] Bellek alanina test verisi yazildi.\n");

    // 2) PAGE_READWRITE -> PAGE_EXECUTE_READ
    printf("[*] Bellek korumasi degistiriliyor (NtProtectVirtualMemory)...\n");
    ULONG oldProtect = 0;
    SIZE_T uProtectSize = 0x1000;

    status = SysGateDispatch(
        ssnProtect,
        SysGateGetGadgetAddress(),
        5,
        (uintptr_t)hProcess,
        (uintptr_t)&pBaseAddress,
        (uintptr_t)&uProtectSize,
        (uintptr_t)PAGE_EXECUTE_READ,
        (uintptr_t)&oldProtect
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtProtectVirtualMemory basarisiz: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Bellek korumasi guncellendi (Eski koruma: 0x%04X)\n", oldProtect);

    // 3) Bellek Temizleme
    printf("[*] Bellek serbest birakiliyor (NtFreeVirtualMemory)...\n");
    SIZE_T uFreeSize = 0;

    status = SysGateDispatch(
        ssnFree,
        SysGateGetGadgetAddress(),
        4,
        (uintptr_t)hProcess,
        (uintptr_t)&pBaseAddress,
        (uintptr_t)&uFreeSize,
        (uintptr_t)MEM_RELEASE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtFreeVirtualMemory basarisiz: 0x%08X\n", status);
        return -1;
    }

    printf("[+] Bellek basariyla serbest birakildi.\n\n");
    printf("[✓] Tum dolayli syscall testleri basariyla gecti (STATUS_SUCCESS).\n");

    return 0;
}
