# SysGate-x64: Dynamic Indirect Syscall Engine & Telemetry Deflection

[![Platform](https://img.shields.io/badge/Platform-Windows%2011%20x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)](#)
[![Language](https://img.shields.io/badge/Language-C11%20%7C%20MASM%20x64-00599C?style=for-the-badge&logo=c&logoColor=white)](#)
[![Compiler](https://img.shields.io/badge/Compiler-MSVC%20%7C%20ml64-e34c26?style=for-the-badge)](#)
[![Architecture](https://img.shields.io/badge/Arch-x86__64-informational?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#)

A high-performance Windows x64 User-Mode Native API dispatching engine designed for systems research, binary instrumentation, and runtime telemetry validation. `SysGate-x64` dynamically derives System Service Numbers (SSNs) across heterogeneous Windows NT builds and transitions to Kernel-Mode via indirect execution gadgets without tripping user-mode hooks or RIP call stack integrity checks.

---

## 1. Architectural Motivation

User-mode endpoint security agents and diagnostic profilers routinely intercept Native NT APIs (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, etc.) by inserting inline detours (e.g., 5-byte relative jumps `E9 XX XX XX XX` or 14-byte absolute jumps) directly into `ntdll.dll` stubs.

```
Traditional Direct Syscall (Flagged by ETR/RIP Telemetry):
[ Your Application (.text) ] -------- Direct 'syscall' --------> [ NT Kernel Ring-0 ]
       ↳ RIP originates from non-NTDLL memory (Unbacked executable memory anomaly)

SysGate-x64 Indirect Syscall (Normalized Execution Flow):
[ Your Application (.text) ] --(Prepare Stack & SSN)--> [ ntdll.dll 'syscall; ret' Gadget ] ---> [ NT Kernel Ring-0 ]
                                                              ↳ Legitimate RIP return boundary
```

### Direct Syscalls vs. Indirect Syscalls

| Parameter | Direct Syscall (SysWhispers 1/2) | SysGate-x64 (Dynamic Indirect) |
| :--- | :--- | :--- |
| **Syscall Instruction Location** | Inside application image (`.text`) | Inside legitimate `ntdll.dll` code segment |
| **Kernel Call Stack Trace** | Anomalous unbacked memory frame | Valid return frame terminating in `ntdll.dll` |
| **SSN Resolution** | Hardcoded or static lookup | **Dynamic Address-Sorting (Build-independent)** |
| **Resistance to Stub Corruption** | Vulnerable if opcode inspection fails | **Immune (Operates purely on Export Table topology)** |
| **ABI Conformance** | Custom asm trampolines | **Strict Microsoft x64 Calling Convention** |

---

## 2. Dynamic SSN Resolution: Address-Sorting Topology

Instead of inspecting stub opcodes (which can fail when stubs are heavily patched or truncated by intermediate hooks), `SysGate-x64` exploits the physical topology of `ntdll.dll`:

1. **PEB Traversal:** Locates the loaded base address of `ntdll.dll` directly from `PEB->Ldr->InMemoryOrderModuleList` without invoking `GetModuleHandle` or `LoadLibrary`.
2. **Export Address Table (EAT) Harvesting:** Parses the export directory to extract all Native System Service entry points beginning with `Zw*`.
3. **Ascending Address Sorting:** In the Windows NT 64-bit architecture, system service stubs in `ntdll.dll` are allocated sequentially in memory corresponding exactly to their System Service Numbers (SSNs).
4. **Topological Mapping:** By sorting the extracted entry points strictly by `FunctionAddress` in ascending order, each service's index in the array directly yields its true architectural SSN.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Core
    participant PEB as Process Environment Block
    participant NTDLL as ntdll.dll (EAT)
    participant Engine as SysGate Resolver
    participant Kernel as Windows NT Kernel (Ring 0)

    App->>PEB: Read GS:[0x60] -> Ldr Traversal
    PEB-->>App: Base Address of ntdll.dll
    App->>NTDLL: Parse IMAGE_EXPORT_DIRECTORY
    NTDLL-->>Engine: Harvest 'Zw*' Export Functions
    Note over Engine: Sort Entries by FunctionAddress Ascending
    Engine->>Engine: Topological Index == Architectural SSN
    Engine->>NTDLL: Scan .text for [0x0F 0x05 0xC3] ('syscall; ret')
    NTDLL-->>Engine: Discovered Gadget Pointer
    App->>Engine: SysGateDispatch(SSN, Gadget, Args...)
    Engine->>NTDLL: Jump to 'syscall; ret' Gadget
    NTDLL->>Kernel: Ring-0 Syscall Boundary Switch
    Kernel-->>NTDLL: Syscall Completion (EAX = NTSTATUS)
    NTDLL-->>App: Direct Return to Caller
```

---

## 3. Microsoft x64 ABI & Low-Level Stack Construction

Windows NT system calls require a specific register allocation protocol prior to transitioning to Ring-0:
* `RAX`: Holds the System Service Number (SSN).
* `R10`: Holds the 1st parameter (the CPU's `syscall` instruction overwrites `RCX` with `RIP`, requiring the kernel to read `R10`).
* `RDX`: Holds the 2nd parameter.
* `R8`: Holds the 3rd parameter.
* `R9`: Holds the 4th parameter.
* `[RSP + 0x28]`: Holds the 5th parameter (above the 32-byte shadow space).

The MASM x64 assembly dispatcher (`src/sysgate_asm.asm`) guarantees:
1. **16-Byte Stack Alignment:** Manages frame reservations such that `(RSP & 0xF) == 0` prior to any nested call.
2. **Shadow Space Allocation:** Allocates standard 32-byte home space for register spills.
3. **Indirect Redirection:** Invokes the gadget via `call r13`, allowing `ntdll.dll`'s `ret` instruction to return directly back into our verified epilogue.

---

## 4. Repository Structure

```
SysGate-x64/
├── include/
│   └── sysgate.h           # Strongly-typed data definitions and macros
├── src/
│   ├── sysgate.c           # PEB parser, topological SSN solver, gadget locator
│   ├── sysgate_asm.asm     # MASM x64 low-level calling convention dispatcher
│   └── main.c              # Verification harness (Memory allocation, write, protect, free)
├── build.bat               # Automated MSVC build and test script
├── build.ps1               # PowerShell build driver
├── .gitignore
└── README.md               # Architecture documentation
```

---

## 5. Build and Verification

### Prerequisites
* Windows 10/11 x64
* Visual Studio 2022 (with "Desktop development with C++" workload including `cl.exe` and `ml64.exe`)

### Compilation
Run the automated build script from an x64 developer prompt or PowerShell:

```powershell
.\build.bat
```

### Execution Output Sample
```
====================================================================
  SysGate-x64: Dynamic Indirect Syscall Engine & Telemetry Deflection
  Research Environment: Windows 11 x64 User-Mode Native Interface   
====================================================================

[*] Initializing SysGate engine via Process Environment Block (PEB)...
[+] NTDLL Base Address        : 0x00007FFA26AA0000
[+] Discovered 'syscall; ret' : 0x00007FFA26C018C2
[+] Parsed Native Services    : 490 distinct system service stubs

[*] Dynamic System Service Number (SSN) Resolutions:
    -> NtAllocateVirtualMemory : SSN = 0x0018 (Hash: 0xC02E1B7F)
    -> NtProtectVirtualMemory  : SSN = 0x0050 (Hash: 0x54CA9C03)
    -> NtFreeVirtualMemory     : SSN = 0x001E (Hash: 0x1C730911)

[*] Executing Memory Allocation via Indirect Syscall...
[+] Indirect allocation successful: Allocated page at 0x000001D015AE0000 (Size: 0x1000)
[+] Memory buffer successfully written with diagnostic test pattern.
[*] Transitioning Memory Page Protection (PAGE_READWRITE -> PAGE_EXECUTE_READ)...
[+] Page protection updated successfully. Old Protection: 0x0004
[*] Deallocating memory page via NtFreeVirtualMemory...
[+] Memory successfully released. Page state normalized.

[✓] All Indirect Syscall execution tests completed with NTSTATUS: 0x00000000 (STATUS_SUCCESS).
====================================================================
```

---

## 6. Defensive Engineering & Security Context

* **Diagnostic Profiling:** Demonstrates how execution environments can be evaluated without relying on high-level Win32 wrappers (`VirtualAlloc`, `VirtualProtect`).
* **Instrumentation Integrity:** Verifies boundary conditions where application telemetry must remain deterministic across varied operating system revisions.
* **Educational Utility:** Provides a clean, modular reference for students and researchers analyzing Windows NT internals and kernel interfaces.

---

## 7. License
Distributed under the MIT License. See `LICENSE` for more information.
