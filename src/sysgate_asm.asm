;=============================================================================
; @file sysgate_asm.asm
; @brief Microsoft x64 Low-Level Indirect Syscall Dispatcher
; @target Windows 11 x64 User-Mode (ml64 / MSVC)
;=============================================================================

.code

;-----------------------------------------------------------------------------
; NTSTATUS SysGateDispatch(
;     uint16_t  ssn,            ; RCX
;     uintptr_t gadget_addr,    ; RDX
;     uint32_t  arg_count,      ; R8
;     uintptr_t arg1,           ; R9
;     ...                       ; [RSP + 28h], [RSP + 30h], etc.
; );
;-----------------------------------------------------------------------------
SysGateDispatch PROC
    ; Preserve non-volatile registers used for argument mapping
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Save dispatch control variables
    mov r12, rcx        ; r12 = SSN
    mov r13, rdx        ; r13 = Syscall Gadget Pointer ('syscall; ret')
    mov r14, r8         ; r14 = Argument count
    mov r15, r9         ; r15 = Syscall Arg 1

    ; Determine stack space needed for arguments 5..N
    ; Maximum supported stack args: 12. We allocate a safe frame of 160 bytes (0A0h)
    ; Ensures 16-byte stack alignment:
    ; (rbp is 16-byte aligned before call, pushed 7 regs = 56 bytes (odd),
    ; sub rsp, 0A8h -> 56 + 168 = 224 (divisible by 16) -> perfectly aligned!
    sub rsp, 0A8h

    ; Copy stack arguments (Syscall Arg 5 onwards)
    ; Caller's Syscall Arg 5 is at [rbp + 10h + 28h + 18h] = [rbp + 50h]
    ; Let's verify caller's stack layout relative to rbp:
    ; [rbp]       = old rbp
    ; [rbp + 08h] = return address to caller
    ; [rbp + 10h] = shadow slot 1 (RCX - ssn)
    ; [rbp + 18h] = shadow slot 2 (RDX - gadget)
    ; [rbp + 20h] = shadow slot 3 (R8  - count)
    ; [rbp + 28h] = shadow slot 4 (R9  - arg1)
    ; [rbp + 30h] = Syscall Arg 2
    ; [rbp + 38h] = Syscall Arg 3
    ; [rbp + 40h] = Syscall Arg 4
    ; [rbp + 48h] = Syscall Arg 5
    ; [rbp + 50h] = Syscall Arg 6
    ; [rbp + 58h] = Syscall Arg 7
    ; [rbp + 60h] = Syscall Arg 8
    ; [rbp + 68h] = Syscall Arg 9
    ; [rbp + 70h] = Syscall Arg 10

    ; Copy Arg 5 -> [rsp + 20h] (Shadow space is 0..1Fh, stack args start at 20h)
    mov rax, [rbp + 48h]
    mov [rsp + 20h], rax

    ; Copy Arg 6 -> [rsp + 28h]
    mov rax, [rbp + 50h]
    mov [rsp + 28h], rax

    ; Copy Arg 7 -> [rsp + 30h]
    mov rax, [rbp + 58h]
    mov [rsp + 30h], rax

    ; Copy Arg 8 -> [rsp + 38h]
    mov rax, [rbp + 60h]
    mov [rsp + 38h], rax

    ; Copy Arg 9 -> [rsp + 40h]
    mov rax, [rbp + 68h]
    mov [rsp + 40h], rax

    ; Copy Arg 10 -> [rsp + 48h]
    mov rax, [rbp + 70h]
    mov [rsp + 48h], rax

    ; Setup registers for Windows x64 Syscall ABI:
    ; R10 = Syscall Arg 1 (RCX replacement for kernel transition)
    ; RDX = Syscall Arg 2
    ; R8  = Syscall Arg 3
    ; R9  = Syscall Arg 4
    ; RAX = System Service Number (SSN)

    mov r10, r15            ; Arg 1
    mov rdx, [rbp + 30h]    ; Arg 2
    mov r8,  [rbp + 38h]    ; Arg 3
    mov r9,  [rbp + 40h]    ; Arg 4
    mov eax, r12d           ; RAX = SSN

    ; Indirect call into ntdll's 'syscall; ret' sequence
    ; Return address on stack will point to the label below within our module.
    call r13

    ; Clean up stack frame
    add rsp, 0A8h

    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    ret
SysGateDispatch ENDP

END
