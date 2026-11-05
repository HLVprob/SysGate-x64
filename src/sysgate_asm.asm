; @file sysgate_asm.asm
; @brief microsoft x64 low level indirect syscall dispatcher
; @target win 11 x64 ring 3 (ml64 / MSVC)

.code

; NTSTATUS SysGateDispatch(
;     uint16_t  ssn,            ; RCX
;     uintptr_t gadget_addr,    ; RDX
;     uint32_t  arg_count,      ; R8
;     uintptr_t arg1,           ; R9
;     ...                       ; [RSP + 28h], [RSP + 30h], etc.
; );
SysGateDispatch PROC

    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov r12, rcx        ; r12 = ssn
    mov r13, rdx        ; r13 = 'syscall; ret'
    mov r14, r8         ; r14 = arguman count
    mov r15, r9         ; r15 = syscall arg 1

    sub rsp, 0A8h

    ; [rbp + 10h + 28h + 18h] = [rbp + 50h]
    ; [rbp]       = eski rbp
    ; [rbp + 08h] = return address to caller
    ; [rbp + 10h] = shadow slot 1 (RCX - ssn)
    ; [rbp + 18h] = shadow slot 2 (RDX - gadget)
    ; [rbp + 20h] = shadow slot 3 (R8  - count)
    ; [rbp + 28h] = shadow slot 4 (R9  - arg1)
    ; [rbp + 30h] = syscall arg 2
    ; [rbp + 38h] = syscall arg 3
    ; [rbp + 40h] = syscall arg 4
    ; [rbp + 48h] = syscall arg 5
    ; [rbp + 50h] = syscall arg 6
    ; [rbp + 58h] = syscall arg 7
    ; [rbp + 60h] = syscall arg 8
    ; [rbp + 68h] = syscall arg 9
    ; [rbp + 70h] = syscall arg 10

    ; [rsp + 20h]
    mov rax, [rbp + 48h]
    mov [rsp + 20h], rax

    ; [rsp + 28h]
    mov rax, [rbp + 50h]
    mov [rsp + 28h], rax

    ; [rsp + 30h]
    mov rax, [rbp + 58h]
    mov [rsp + 30h], rax

    ; [rsp + 38h]
    mov rax, [rbp + 60h]
    mov [rsp + 38h], rax

    ; [rsp + 40h]
    mov rax, [rbp + 68h]
    mov [rsp + 40h], rax

    ; [rsp + 48h]
    mov rax, [rbp + 70h]
    mov [rsp + 48h], rax

    ; R10 = syscall arg 1
    ; RDX = syscall arg 2
    ; R8  = syscall arg 3
    ; R9  = syscall arg 4
    ; RAX = ssn

    mov r10, r15            ; arg 1
    mov rdx, [rbp + 30h]    ; arg 2
    mov r8,  [rbp + 38h]    ; arg 3
    mov r9,  [rbp + 40h]    ; arg 4
    mov eax, r12d           ; RAX = SSN

    call r13

    add rsp, 0A8h

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

