/**
 * @file sysgate.h
 * @brief Dynamic Indirect Syscall Engine Header
 * @target Windows 11 x64 User-Mode
 */

#ifndef SYSGATE_H
#define SYSGATE_H

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>

#define SYSGATE_MAX_ENTRIES 512
#define SYSGATE_HASH_SEED   0x5BD1E995

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#pragma pack(push, 1)

/**
 * @brief Represents an individual resolved Native System Service descriptor.
 */
typedef struct _SYSGATE_ENTRY {
    uint32_t Hash;             /**< Function name 32-bit hash */
    uint16_t SSN;              /**< Resolved System Service Number */
    uintptr_t FunctionAddress; /**< Virtual address in ntdll memory space */
} SYSGATE_ENTRY, *PSYSGATE_ENTRY;

/**
 * @brief Global execution table managing parsed system services and execution gadgets.
 */
typedef struct _SYSGATE_TABLE {
    uintptr_t NtdllBase;                 /**< Base address of loaded ntdll.dll */
    uintptr_t SyscallGadgetAddress;      /**< Pointer to 'syscall; ret' sequence in ntdll */
    uint32_t Count;                      /**< Total tracked system services */
    SYSGATE_ENTRY Entries[SYSGATE_MAX_ENTRIES];
} SYSGATE_TABLE, *PSYSGATE_TABLE;

#pragma pack(pop)

/* Global engine context */
extern SYSGATE_TABLE g_SysGateTable;

/**
 * @brief Asynchronous/Direct MASM x64 low-level dispatcher.
 * Adheres strictly to the Microsoft x64 Calling Convention.
 */
extern NTSTATUS SysGateDispatch(
    uint16_t ssn,
    uintptr_t gadget_addr,
    uint32_t arg_count,
    ...
);

/* Engine Initialization & Discovery API */
bool SysGateInitialize(void);
uint16_t SysGateGetSSNByHash(uint32_t functionHash);
uintptr_t SysGateGetGadgetAddress(void);
uint32_t SysGateComputeHash(const char* string);

/* Macro for dynamic indirect invocation */
#define SYSGATE_CALL(funcHash, argCount, ...) \
    SysGateDispatch(SysGateGetSSNByHash(funcHash), SysGateGetGadgetAddress(), argCount, __VA_ARGS__)

#endif /* SYSGATE_H */
