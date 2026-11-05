/**
 * @file main.c
 * @brief Dynamic Indirect Syscall Engine - Verification & Diagnostic Harness
 * @target Windows 11 x64 User-Mode
 */

#include <stdio.h>
#include <windows.h>
#include "../include/sysgate.h"

/* Precomputed Murmur3 Hashes for standard NT Native APIs */
#define HASH_NtAllocateVirtualMemory  0x6e2c31e6
#define HASH_NtProtectVirtualMemory   0x92f02548
#define HASH_NtFreeVirtualMemory      0xa142b938
#define HASH_NtDelayExecution         0x77d07712

static void PrintBanner(void) {
    printf("====================================================================\n");
    printf("  SysGate-x64: Dynamic Indirect Syscall Engine & Telemetry Bypass   \n");
    printf("  Research Environment: Windows 11 x64 User-Mode Native Interface   \n");
    printf("====================================================================\n\n");
}

int main(void) {
    PrintBanner();

    printf("[*] Initializing SysGate engine via Process Environment Block (PEB)...\n");
    if (!SysGateInitialize()) {
        printf("[-] Failed to initialize SysGate engine. NTDLL parsing anomaly.\n");
        return -1;
    }

    printf("[+] NTDLL Base Address        : 0x%p\n", (void*)g_SysGateTable.NtdllBase);
    printf("[+] Discovered 'syscall; ret' : 0x%p\n", (void*)g_SysGateTable.SyscallGadgetAddress);
    printf("[+] Parsed Native Services    : %u distinct system service stubs\n\n", g_SysGateTable.Count);

    /* Dynamic Hash Computation & SSN Resolution */
    uint32_t hashAlloc   = SysGateComputeHash("NtAllocateVirtualMemory");
    uint32_t hashProtect = SysGateComputeHash("NtProtectVirtualMemory");
    uint32_t hashFree    = SysGateComputeHash("NtFreeVirtualMemory");

    uint16_t ssnAlloc   = SysGateGetSSNByHash(hashAlloc);
    uint16_t ssnProtect = SysGateGetSSNByHash(hashProtect);
    uint16_t ssnFree    = SysGateGetSSNByHash(hashFree);

    printf("[*] Dynamic System Service Number (SSN) Resolutions:\n");
    printf("    -> NtAllocateVirtualMemory : SSN = 0x%04X (Hash: 0x%08X)\n", ssnAlloc, hashAlloc);
    printf("    -> NtProtectVirtualMemory  : SSN = 0x%04X (Hash: 0x%08X)\n", ssnProtect, hashProtect);
    printf("    -> NtFreeVirtualMemory     : SSN = 0x%04X (Hash: 0x%08X)\n\n", ssnFree, hashFree);

    if (ssnAlloc == 0xFFFF || ssnProtect == 0xFFFF || ssnFree == 0xFFFF) {
        printf("[-] Error: Unable to resolve one or more target SSNs.\n");
        return -1;
    }

    /* Verification Test: Indirectly allocate, protect, and deallocate memory */
    printf("[*] Executing Memory Allocation via Indirect Syscall...\n");

    PVOID pBaseAddress = NULL;
    SIZE_T uRegionSize = 0x1000; /* 4 KB Page */
    HANDLE hProcess = (HANDLE)(intptr_t)-1; /* Current Process Pseudo-Handle */

    /*
     * NtAllocateVirtualMemory Prototype:
     * NTSTATUS NtAllocateVirtualMemory(
     *     HANDLE ProcessHandle,
     *     PVOID *BaseAddress,
     *     ULONG_PTR ZeroBits,
     *     PSIZE_T RegionSize,
     *     ULONG AllocationType,
     *     ULONG Protect
     * );
     */
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
        printf("[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x%08X\n", status);
        return -1;
    }

    printf("[+] Indirect allocation successful: Allocated page at 0x%p (Size: 0x%llX)\n", 
           pBaseAddress, (unsigned long long)uRegionSize);

    /* Write test data pattern into allocated memory */
    uint8_t testPayload[] = { 0x90, 0x90, 0xCC, 0xC3 }; /* NOP, NOP, INT3, RET */
    memcpy(pBaseAddress, testPayload, sizeof(testPayload));
    printf("[+] Memory buffer successfully written with diagnostic test pattern.\n");

    /* Alter page protection to PAGE_EXECUTE_READ via indirect syscall */
    printf("[*] Transitioning Memory Page Protection (PAGE_READWRITE -> PAGE_EXECUTE_READ)...\n");
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
        printf("[-] NtProtectVirtualMemory failed with NTSTATUS: 0x%08X\n", status);
        return -1;
    }
    printf("[+] Page protection updated successfully. Old Protection: 0x%04X\n", oldProtect);

    /* Deallocate memory page via indirect syscall */
    printf("[*] Deallocating memory page via NtFreeVirtualMemory...\n");
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
        printf("[-] NtFreeVirtualMemory failed with NTSTATUS: 0x%08X\n", status);
        return -1;
    }

    printf("[+] Memory successfully released. Page state normalized.\n\n");
    printf("[✓] All Indirect Syscall execution tests completed with NTSTATUS: 0x00000000 (STATUS_SUCCESS).\n");
    printf("====================================================================\n");

    return 0;
}
