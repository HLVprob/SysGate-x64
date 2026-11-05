#include "../include/sysgate.h"
#include <stdio.h>

SYSGATE_TABLE g_SysGateTable = { 0 };

typedef struct _CUSTOM_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} CUSTOM_UNICODE_STRING;

typedef struct _CUSTOM_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    CUSTOM_UNICODE_STRING FullDllName;
    CUSTOM_UNICODE_STRING BaseDllName;
} CUSTOM_LDR_DATA_TABLE_ENTRY, *PCUSTOM_LDR_DATA_TABLE_ENTRY;

// Basit string hash fonksiyonu (Murmur3 mantigi)
uint32_t SysGateComputeHash(const char* string) {
    if (!string) return 0;
    
    uint32_t hash = SYSGATE_HASH_SEED;
    while (*string) {
        hash ^= (uint8_t)(*string);
        hash *= 0x5bd1e995;
        hash ^= hash >> 15;
        string++;
    }
    return hash;
}

// GetModuleHandle yerine PEB üzerinden ntdll base adresini bulur
static uintptr_t GetNtdllBaseFromPEB(void) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHeader = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pHeader->Flink;

    while (pCurrent != pHeader) {
        PCUSTOM_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurrent, CUSTOM_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Buffer != NULL) {
            PWSTR name = pEntry->BaseDllName.Buffer;
            // Case-insensitive kontrol
            if ((name[0] == L'n' || name[0] == L'N') &&
                (name[1] == L't' || name[1] == L'T') &&
                (name[2] == L'd' || name[2] == L'D') &&
                (name[3] == L'l' || name[3] == L'L') &&
                (name[4] == L'l' || name[4] == L'L')) {
                return (uintptr_t)pEntry->DllBase;
            }
        }
        pCurrent = pCurrent->Flink;
    }
    return 0;
}

// ntdll .text section icinde 'syscall; ret' (0F 05 C3) byte dizisini arar
static uintptr_t FindSyscallGadget(uintptr_t ntdllBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(ntdllBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        // Sadece calistirilabilir kod bolumunde ara
        if ((pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (pSec[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            
            uint8_t* pStart = (uint8_t*)(ntdllBase + pSec[i].VirtualAddress);
            size_t size = pSec[i].Misc.VirtualSize;

            for (size_t offset = 0; offset + 2 < size; offset++) {
                if (pStart[offset] == 0x0F && pStart[offset + 1] == 0x05 && pStart[offset + 2] == 0xC3) {
                    return (uintptr_t)(pStart + offset);
                }
            }
        }
    }
    return 0;
}

// qsort icin fonksiyon adresi karsilastirici
static int CompareSysgateEntries(const void* a, const void* b) {
    const SYSGATE_ENTRY* ea = (const SYSGATE_ENTRY*)a;
    const SYSGATE_ENTRY* eb = (const SYSGATE_ENTRY*)b;
    if (ea->FunctionAddress < eb->FunctionAddress) return -1;
    if (ea->FunctionAddress > eb->FunctionAddress) return 1;
    return 0;
}

// Engine'i baslatir: EAT parse eder, adres siralamasiyla SSN bulur, gadget arar
bool SysGateInitialize(void) {
    uintptr_t ntdllBase = GetNtdllBaseFromPEB();
    if (!ntdllBase) return false;

    g_SysGateTable.NtdllBase = ntdllBase;
    g_SysGateTable.SyscallGadgetAddress = FindSyscallGadget(ntdllBase);
    if (!g_SysGateTable.SyscallGadgetAddress) return false;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(ntdllBase + pDos->e_lfanew);
    
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return false;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(ntdllBase + exportRva);
    DWORD* pAddressOfFunctions = (DWORD*)(ntdllBase + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)(ntdllBase + pExport->AddressOfNames);
    WORD*  pAddressOfNameOrdinals = (WORD*)(ntdllBase + pExport->AddressOfNameOrdinals);

    uint32_t trackedCount = 0;

    // 1. Adim: ntdll export tablosundaki Zw* stublarini topla
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* funcName = (const char*)(ntdllBase + pAddressOfNames[i]);
        if (funcName[0] == 'Z' && funcName[1] == 'w') {
            WORD ordinal = pAddressOfNameOrdinals[i];
            uintptr_t funcAddr = ntdllBase + pAddressOfFunctions[ordinal];

            if (trackedCount < SYSGATE_MAX_ENTRIES) {
                // Nt ile arayabilmek icin ismin basini Nt olarak hashle
                char ntName[128];
                ntName[0] = 'N';
                ntName[1] = 't';
                int charIdx = 2;
                while (funcName[charIdx] && charIdx < 127) {
                    ntName[charIdx] = funcName[charIdx];
                    charIdx++;
                }
                ntName[charIdx] = '\0';

                g_SysGateTable.Entries[trackedCount].Hash = SysGateComputeHash(ntName);
                g_SysGateTable.Entries[trackedCount].FunctionAddress = funcAddr;
                g_SysGateTable.Entries[trackedCount].SSN = 0;
                trackedCount++;
            }
        }
    }

    // 2. Adim: Adreslere gore kucukten buyuge sirala.
    // Windows x64'te ntdll'deki syscall stublari SSN sirasina gore siralanir.
    // Bu yontem fonksiyonun ilk byte'lari hooklanmis olsa bile dogru SSN'i verir.
    qsort(g_SysGateTable.Entries, trackedCount, sizeof(SYSGATE_ENTRY), CompareSysgateEntries);

    for (uint32_t i = 0; i < trackedCount; i++) {
        g_SysGateTable.Entries[i].SSN = (uint16_t)i;
    }

    g_SysGateTable.Count = trackedCount;
    return true;
}

uint16_t SysGateGetSSNByHash(uint32_t functionHash) {
    for (uint32_t i = 0; i < g_SysGateTable.Count; i++) {
        if (g_SysGateTable.Entries[i].Hash == functionHash) {
            return g_SysGateTable.Entries[i].SSN;
        }
    }
    return (uint16_t)0xFFFF;
}

uintptr_t SysGateGetGadgetAddress(void) {
    return g_SysGateTable.SyscallGadgetAddress;
}
