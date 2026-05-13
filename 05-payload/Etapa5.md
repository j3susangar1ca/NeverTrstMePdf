# Etapa 5 — El Payload ASM: Position Independent Code, Evasión y Superficie de Estado Global

## Documentación Técnica de Nivel APT/Intelligence-Grade

### Análisis Formal del Código Posicional-Independiente, Mecanismos de Evasión de Bajo Nivel, Interacción con el Kernel NT, y Superficie de Estado Compuesto

---

## Índice

1. [Resumen Ejecutivo Clasificado](#1-resumen-ejecutivo)
2. [Modelo Formal del Position Independent Code como Invariante de Translación](#2-modelo-formal-pic)
3. [Arquitectura del Entorno de Ejecución del Payload en Ring 3](#3-arquitectura-ejecucion)
4. [Análisis Algebraico de las Operaciones de Evasión de Telemetría](#4-analisis-algebraico-evasion)
5. [Teoría de la Información Aplicada: Degradación del Canal de Detección](#5-teoria-informacion)
6. [Hardware Breakpoints: Modelo de Registros de Depuración x64 y Anti-Monitoreo](#6-hardware-breakpoints)
7. [Stack Spoofing: Falsificación del Grafo de Marcos de Activación](#7-stack-spoofing)
8. [Syscalls Directos e Indirectos: Omisión de la Capa de Abstracción ntdll](#8-syscalls-directos)
9. [Integración con el Espacio de Estados Global del Sistema](#9-espacio-estados-global)
10. [Superficie de Detección: Formalización y Predicados de Alerta](#10-superficie-deteccion)
11. [Historial de Explotación Documentado y Contexto APT](#11-historial-apts)
12. [Contramedidas: Niveles de Defensa según Modelo de Capas](#12-contramedidas)
13. [Análisis de Variaciones y Mutaciones del Vector](#13-variaciones)
14. [Referencias y Marco Normativo](#14-referencias)

---

## 1. Resumen Ejecutivo

El payload ASM constituye la **fase de ejecución final** del vector de ataque compuesto de 5 etapas. A diferencia de las etapas anteriores que operan a nivel de archivo (ISO), de shell (LNK), o de proceso (LOLBins), el payload ASM opera a nivel de **instrucciones de máquina** directamente sobre el procesador, manipulando registros, memoria, y la interfaz de syscall del kernel NT sin mediación de las capas de abstracción de Windows.

Su diseño responde a un principio fundamental: **minimizar la superficie observable** por los mecanismos de detección del sistema operativo y los productos EDR. Esto se logra mediante cuatro propiedades formales:

1. **Invariancia bajo translación** (PIC) — El código opera correctamente independientemente de su dirección de carga, eliminando referencias absolutas que podrían ser firmadas estáticamente
2. **Hermetismo de telemetría** — El payload suprime o evita los mecanismos de generación de eventos (ETW), reduciendo la información disponible para la detección basada en comportamiento
3. **Falsificación de contexto de ejecución** — Stack spoofing y manipulación de registros de depuración ocultan la verdadera procedencia del código en ejecución
4. **Bypass de la capa de abstracción** — Syscalls directos/indirectos eliminan la dependencia de `ntdll.dll`, el punto de observación primario de los EDRs

El resultado es un **mínimo observable** en el espacio de estados del sistema: el payload existe como una página de memoria sin respaldo en disco, ejecuta operaciones a través de la interfaz syscall sin pasar por las funciones hookeadas del sistema, y presenta una pila de llamadas que aparece legítima al análisis superficial.

Formalmente, el payload opera como una **transformación del espacio de estados** que modifica múltiples componentes simultáneamente:

$$\tau_{payload}: \Sigma_{ETW} \times \Sigma_{APC} \times \Sigma_{Proc} \times \Sigma_{COM} \rightarrow \Sigma'_{ETW} \times \Sigma'_{APC} \times \Sigma'_{Proc} \times \Sigma'_{COM}$$

donde cada componente $\Sigma'_i$ difiere de $\Sigma_i$ en que los mecanismos de observación están degradados o suprimidos, mientras que las operaciones del payload proceden sin restricción.

---

## 2. Modelo Formal del Position Independent Code como Invariante de Translación

### 2.1 Definición Formal del PIC

**Definición 2.1.1 — Código Posicional-Independiente**

Sea $C$ un bloque de código máquina y $\text{AddrSpace}$ el espacio de direcciones virtuales del proceso. Decimos que $C$ es **Position Independent Code (PIC)** si y solo si:

$$\forall\, a_1, a_2 \in \text{AddrSpace}: \text{Semantics}(C \text{ @ } a_1) = \text{Semantics}(C \text{ @ } a_2)$$

donde $C \text{ @ } a$ denota el código $C$ cargado con dirección base $a$, y $\text{Semantics}(\cdot)$ es la función semántica que mapea el código a su comportamiento observable.

**Equivalencia algebraica:** El código PIC es **invariante bajo la operación de translación** $T_\Delta: \text{AddrSpace} \rightarrow \text{AddrSpace}$ definida por $T_\Delta(a) = a + \Delta$:

$$\text{Semantics}(T_\Delta(C)) = \text{Semantics}(C) \quad \forall\, \Delta \in \mathbb{Z}$$

Esto significa que el grupo de translaciones $(\mathbb{Z}, +)$ actúa trivialmente sobre el espacio semántico del código PIC.

### 2.2 Condición Necesaria y Suficiente para PIC

**Teorema 2.2.1 — Condición de PIC**

*Un bloque de código $C$ es PIC si y solo si toda referencia a datos dentro de $C$ usa direccionamiento relativo al puntero de instrucción (RIP-relative en x64):*

$$C \text{ es PIC} \iff \forall\, \text{instr } i \in C: i.\text{type} = \text{data\_ref} \Rightarrow i.\text{addr} = \text{RIP} + \text{offset}(i)$$

**Demostración:**

($\Rightarrow$) Si $C$ es PIC, entonces el comportamiento no cambia al transladar $C$. Una referencia absoluta $i.\text{addr} = A$ (constante) apuntaría a la dirección original tras la translación, produciendo un acceso a memoria incorrecto. Por contradicción, no puede haber referencias absolutas.

($\Leftarrow$) Si toda referencia es RIP-relative, entonces $i.\text{addr} = \text{RIP} + \text{offset}$. Al transladar $C$ por $\Delta$, la nueva RIP también se translada por $\Delta$, y $\text{RIP}' + \text{offset} = (\text{RIP} + \Delta) + \text{offset}$, que apunta al dato correcto dentro del bloque transladado. Por lo tanto, $\text{Semantics}(T_\Delta(C)) = \text{Semantics}(C)$.

$\blacksquare$

### 2.3 Patrón de Resolución de la Base de Carga

El payload ASM debe determinar su propia dirección de carga en tiempo de ejecución. El patrón estándar en x64 es:

```asm
; ═══════════════════════════════════════════════════════
; PATRÓN DE RESOLUCIÓN DE BASE (PIC Entry Point)
; ═══════════════════════════════════════════════════════

    call    get_base            ; Empuja RIP+5 en la pila
get_base:
    pop     rax                 ; rax = dirección de get_base
    sub     rax, 5              ; rax = dirección del entry point = BaseAddr

    ; Ahora todas las referencias a datos usan [rax + offset]
    lea     rbx, [rax + offset_to_data]
    mov     rcx, [rbx]
    ; ...
```

**Formalización del patrón:**

Sea $a_{entry}$ la dirección de carga del payload. La instrucción `call get_base` equivale a:

$$\text{push}(a_{entry} + 5)$$

y la instrucción `pop rax` recupera:

$$rax = a_{entry} + 5 = a_{get\_base}$$

Luego `sub rax, 5` produce:

$$rax = a_{entry} = \text{BaseAddr}$$

A partir de este punto, toda referencia a datos se calcula como:

$$\text{Addr}(data_i) = rax + \text{offset}_i = \text{BaseAddr} + \text{offset}_i$$

Esto es **exactamente** la condición RIP-relative generalizada: en lugar de usar el RIP actual de cada instrucción, se usa la base calculada una vez y se suman offsets constantes.

### 2.4 Diagrama del Modelo de Memoria PIC

```
═══════════════════════════════════════════════════════════════════════════
              MODELO DE MEMORIA DEL PAYLOAD PIC
═══════════════════════════════════════════════════════════════════════════

  Espacio de direcciones del proceso (después de inyección):
  ┌──────────────────────────────────────────────────────────────┐
  │                                                              │
  │  0x7FF000000000 ┌──────────────────────────────┐            │
  │                 │ ntdll.dll (sección .text)     │            │
  │                 │ ┌──────────────────────────┐  │            │
  │                 │ │ NtXxx (hookeado por EDR) │  │            │
  │                 │ │ jmp EDR_handler          │  │            │
  │                 │ └──────────────────────────┘  │            │
  │                 │ ┌──────────────────────────┐  │            │
  │                 │ │ NtYyy (sin hook)         │  │            │
  │                 │ │ mov r10, rcx             │  │            │
  │                 │ │ mov eax, 0xNN            │  │            │
  │                 │ │ syscall                  │  │  ← Indirect │
  │                 │ │ ret                      │  │    syscall │
  │                 │ └──────────────────────────┘  │    target  │
  │                 └──────────────────────────────┘            │
  │                                                              │
  │  0x123400000000 ┌──────────────────────────────┐            │
  │  (BaseAddr)     │ PAYLOAD PIC (MEM_PRIVATE)    │            │
  │                 │                              │            │
  │                 │ BaseAddr+0x00: call get_base │            │
  │                 │ BaseAddr+0x05: pop rax        │            │
  │                 │ BaseAddr+0x07: sub rax, 5     │            │
  │                 │ ...                          │            │
  │                 │ BaseAddr+O₁: data₁           │            │
  │                 │ BaseAddr+O₂: data₂           │            │
  │                 │ BaseAddr+O₃: syscall_stubs   │            │
  │                 │ ...                          │            │
  │                 │                              │            │
  │                 │ Protección: RX (después de   │            │
  │                 │            NtProtectVM)      │            │
  │                 │ Tipo: MEM_PRIVATE             │            │
  │                 │ Respaldo en disco: NINGUNO    │            │
  │                 └──────────────────────────────┘            │
  │                                                              │
  └──────────────────────────────────────────────────────────────┘

  PROPIEDAD PIC:
  Si BaseAddr cambia de 0x123400000000 a cualquier otro valor,
  todas las referencias [rax + offset] siguen siendo correctas
  porque rax se recalcula dinámicamente.

═══════════════════════════════════════════════════════════════════════════
```

### 2.5 Análisis Información-Teórico del PIC

**Definición 2.5.1 — Entropía de la Dirección de Carga**

La dirección de carga del payload PIC es determinada por el asignador de memoria del sistema (`NtAllocateVirtualMemory`). Bajo ASLR (Address Space Layout Randomization), la dirección de carga se selecciona de un espacio aleatorio:

$$a_{load} \sim \text{Uniform}(\text{ASLR\_Range})$$

La entropía de la dirección de carga es:

$$H(a_{load}) = \log_2 |\text{ASLR\_Range}|$$

Para un proceso de 64 bits con ASLR completo:

$$H(a_{load}) \approx 19\text{-}30 \;\text{bits}$$

El payload PIC es **insensible** a esta entropía: su comportamiento es idéntico independientemente del valor de $a_{load}$. Formalmente:

$$H(\text{Behavior} \mid a_{load}) = 0$$

La información mutua entre la dirección de carga y el comportamiento es cero:

$$I(\text{Behavior}; a_{load}) = 0$$

Esto significa que **ninguna inferencia sobre el comportamiento del payload puede hacerse a partir de su dirección de carga**, lo que es una propiedad deseable desde la perspectiva del atacante.

---

## 3. Arquitectura del Entorno de Ejecución del Payload en Ring 3

### 3.1 Modelo de Capas de Ejecución

El payload ASM se ejecuta en Ring 3 (modo usuario) dentro de un proceso legítimo. Su entorno de ejecución se modela como una pila de capas, desde la más baja (hardware) hasta la más alta (payload):

```
═══════════════════════════════════════════════════════════════════════════
          ENTORNO DE EJECUCIÓN DEL PAYLOAD — MODELO DE CAPAS
═══════════════════════════════════════════════════════════════════════════

  CAPA 5: PAYLOAD ASM (Position Independent Code)
  ┌──────────────────────────────────────────────────────────────┐
  │  • Resolución de base (call/pop/sub)                         │
  │  • Decodificación de bloques de datos embebidos              │
  │  • Hardware breakpoint check (DR0-DR3, DR6, DR7)            │
  │  • Stack frame setup (spoofed)                               │
  │  • Resolución de syscall numbers dinámica                    │
  │  • Ejecución de operaciones vía direct/indirect syscalls     │
  │  • Comunicación C2 (si aplica)                               │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  CAPA 4: INYECTOR C++ (previo al payload)
  ┌──────────────────────────────────────────────────────────────┐
  │  • PEB resolution → ntdll.dll base                           │
  │  • API unhooking (restore .text from disk)                   │
  │  • ETW patching (EtwEventWrite → ret 0)                     │
  │  • NtAllocateVirtualMemory (RW)                              │
  │  • Decrypt(payload_ASM) → copy to allocated memory           │
  │  • NtProtectVirtualMemory (RW → RX)                          │
  │  • NtCreateThreadEx o NtQueueApcThread → ejecutar payload    │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  CAPA 3: NTDLL.DLL (syscall stubs)
  ┌──────────────────────────────────────────────────────────────┐
  │  • Funciones NtXxx (potencialmente hookeadas por EDR)        │
  │  • Syscall numbers (varían por build de Windows)             │
  │  • Indirect syscall targets (instrucciones syscall;ret)      │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  CAPA 2: KERNEL NT (Ring 0)
  ┌──────────────────────────────────────────────────────────────┐
  │  • Syscall dispatcher (KiSystemCall64)                       │
  │  • APC queue dispatcher                                      │
  │  • ETW provider infrastructure                               │
  │  • Object Manager, Memory Manager                            │
  │  • Security Reference Monitor (token validation)             │
  │  • HVCI / VBS (si habilitado)                                │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  CAPA 1: HARDWARE (x64)
  ┌──────────────────────────────────────────────────────────────┐
  │  • Registros de propósito general (RAX-R15)                  │
  │  • Registros de depuración (DR0-DR7)                         │
  │  • Unidad de gestión de memoria (MMU / EPT si VBS)          │
  │  • TLB (Translation Lookaside Buffer)                        │
  │  • Cachés L1/L2/L3                                           │
  └──────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 3.2 Estado del Proceso Anfitrión tras la Inyección

**Definición 3.2.1 — Estado del Proceso con Payload Inyectado**

Sea $P$ el proceso anfitrión. Tras la inyección del payload, el estado de $P$ se describe como:

$$\Sigma_P = (\mathcal{M}, \mathcal{T}, \mathcal{H}, \mathcal{D}, \mathcal{S})$$

donde:
- $\mathcal{M}$ = mapa de memoria del proceso (incluye la región RX del payload)
- $\mathcal{T}$ = tabla de hilos (incluye el hilo del payload o el APC encolado)
- $\mathcal{H}$ = tabla de handles (los handles abiertos por el inyector)
- $\mathcal{D}$ = estado de los registros de depuración
- $\mathcal{S}$ = estado de la pila de llamadas del hilo que ejecuta el payload

Cada componente presenta **anomalías** respecto al estado esperado de un proceso legítimo:

| Componente | Estado esperado | Estado con payload | Anomalía |
|---|---|---|---|
| $\mathcal{M}$ | Todas las páginas RX tienen respaldo en disco | Existe página RX sin respaldo (`MEM_PRIVATE`) | `MEM_PRIVATE + RX` |
| $\mathcal{T}$ | Hilos creados por el sistema | Hilo creado por `NtCreateThreadEx` con punto de entrada fuera de módulos cargados | Entry point anómalo |
| $\mathcal{D}$ | DR7 = 0 (sin breakpoints) | DR7 posiblemente modificado por el payload | Registros DR alterados |
| $\mathcal{S}$ | Frames de módulos legítimos | Frames sintéticos (stack spoofing) | Unwind info incoherente |

### 3.3 Análisis del Ciclo de Vida del Payload en Memoria

```
═══════════════════════════════════════════════════════════════════════════
          CICLO DE VIDA DEL PAYLOAD EN MEMORIA
═══════════════════════════════════════════════════════════════════════════

  FASE 1: ASIGNACIÓN
  ┌──────────────────────────────────────────────────────────────┐
  │  NtAllocateVirtualMemory(                                    │
  │      ProcessHandle = -1,          (proceso actual)           │
  │      BaseAddress   = NULL,        (ASLR decide)              │
  │      RegionSize    = N,           (tamaño del payload)       │
  │      AllocationType = MEM_COMMIT | MEM_RESERVE,              │
  │      Protect       = PAGE_READWRITE   ← RW                  │
  │  )                                                           │
  │                                                              │
  │  Resultado: Región [a..a+N] con protección RW               │
  │  Tipo: MEM_PRIVATE (sin respaldo en disco)                   │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  FASE 2: ESCRITURA
  ┌──────────────────────────────────────────────────────────────┐
  │  NtWriteVirtualMemory(                                       │
  │      ProcessHandle = -1,                                     │
  │      BaseAddress   = a,                                      │
  │      Buffer        = Decrypt(payload_cifrado),               │
  │      NumberOfBytes = N                                       │
  │  )                                                           │
  │                                                              │
  │  Resultado: Código ASM descifrado copiado a [a..a+N]        │
  │  Protección: aún RW (no ejecutable)                         │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  FASE 3: TRANSICIÓN DE PROTECCIÓN
  ┌──────────────────────────────────────────────────────────────┐
  │  NtProtectVirtualMemory(                                     │
  │      ProcessHandle = -1,                                     │
  │      BaseAddress   = &a,                                     │
  │      RegionSize    = &N,                                     │
  │      NewProtect    = PAGE_EXECUTE_READ  ← RX                │
  │      OldProtect    = &old (recibe PAGE_READWRITE)            │
  │  )                                                           │
  │                                                              │
  │  Resultado: Región [a..a+N] con protección RX               │
  │  ╔═══════════════════════════════════════════════════════╗   │
  │  ║  SEÑAL CRÍTICA: Transición RW → RX en página         ║   │
  │  ║  MEM_PRIVATE sin respaldo en disco                   ║   │
  │  ║  Detección: ETW Microsoft-Windows-Kernel-Memory      ║   │
  │  ╚═══════════════════════════════════════════════════════╝   │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  FASE 4: EJECUCIÓN
  ┌──────────────────────────────────────────────────────────────┐
  │  Opción A: NtCreateThreadEx(                                 │
  │      ThreadHandle = &h,                                      │
  │      StartRoutine = a,             ← entry point del payload│
  │      Argument     = NULL                                     │
  │  )                                                           │
  │                                                              │
  │  Opción B: NtQueueApcThread(                                 │
  │      ThreadHandle = h_target,       ← hilo existente        │
  │      ApcRoutine   = a,             ← entry point del payload│
  │      ApcContext    = NULL                                     │
  │  )                                                           │
  │                                                              │
  │  Resultado: Payload ejecutándose en Ring 3                   │
  │  SecurityContext = SecurityContext(hilo_anfitrión)           │
  └──────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

---

## 4. Análisis Algebraico de las Operaciones de Evasión de Telemetría

### 4.1 Modelo Formal del Canal de Telemetría

El sistema de detección de Windows 11 funciona como un **canal de observación** que transforma eventos del sistema en señales de detección:

$$\text{Observe}: \Sigma \xrightarrow{\text{ETW}} \text{Events} \xrightarrow{\text{Filter}} \text{Alerts}$$

El payload busca reducir la información que transita por este canal. Formalmente, define una **transformación del canal** que degrada su capacidad:

$$\text{Observe}': \Sigma \xrightarrow{\text{ETW'}} \text{Events}' \xrightarrow{\text{Filter}} \text{Alerts}'$$

donde $|\text{Events}'| < |\text{Events}|$ (menos eventos generados) y $|\text{Alerts}'| \leq |\text{Alerts}|$ (menos alertas producidas).

### 4.2 API Unhooking como Restauración del Morfismo

**Definición 4.2.1 — Hook como Perturbación del Mapeo de Código**

Sea $\mu_{orig}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo original de la sección `.text` de `ntdll.dll` (desde disco) y $\mu_{hooked}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo modificado por el EDR. Para la dirección de entrada de una función $f$:

$$\mu_{hooked}(f_{entry}) = \underbrace{\text{jmp}\; \text{EDR\_handler}}_{k\;\text{bytes}} \; \| \; \mu_{orig}(f_{entry}+k)[0..]$$

El hook es una **perturbación local** del mapeo de código que inserta un trampolín en los primeros $k$ bytes de la función objetivo. Los valores típicos de $k$ son:

| Tipo de hook | $k$ (bytes) | Instrucción de trampolín |
|---|---|---|
| Trampoline de 32 bits | 5 | `jmp rel32` |
| Trampoline de 64 bits | 14 | `jmp [rip+0]; dq abs_addr` |
| HotPatch (Microsoft) | 2+5 | `mov edi, edi; jmp rel32` |

**El unhooking** es la operación inversa — restaurar el mapeo original:

$$\mu_{restored}(f_{entry}) = \mu_{disk}(f_{entry})$$

donde $\mu_{disk}$ es el mapeo leído desde el archivo `C:\Windows\System32\ntdll.dll` en disco.

**Propiedad algebraica:** El unhooking restaura el **morfismo de código original**:

$$\mu_{restored}: \text{Addr} \xrightarrow{\sim} \text{Bytes}_{original}$$

Los EDRs que dependen de hooks en `ntdll.dll` para interceptar llamadas al sistema pierden su capacidad de observación tras el unhooking.

### 4.3 ETW Patching como Eliminación del Generador de Eventos

**Definición 4.3.1 — Función de Generación ETW**

El subsistema ETW implementa una función de generación de eventos:

$$G_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \text{EventRecord} \cup \{\epsilon\}$$

donde $\epsilon$ denota el evento nulo (no generado).

El ETW patching reemplaza las primeras instrucciones de `EtwEventWrite` con un stub que retorna `STATUS_SUCCESS` inmediatamente:

$$G'_{ETW}(p, e, d) = \epsilon \quad \forall\, (p, e, d)$$

**Impacto en el autómata híbrido WQL:**

El motor de eventos WMI se modela como $\mathcal{A}_H = (S, E, \delta, G, \text{Init})$ donde $E = E_{intrinsic} \uplus E_{extrinsic}$. Tras el ETW patching:

$$E' = E_{intrinsic} \quad (E_{extrinsic} \text{ eliminado})$$

El autómata pierde transiciones asociadas a eventos extrínsecos. Formalmente, la función de transición se restringe:

$$\delta': S \times E_{intrinsic} \rightarrow S$$

$$\forall\, e \in E_{extrinsic}: \delta(s, e) \text{ queda indefinida}$$

```
═══════════════════════════════════════════════════════════════════════════
         IMPACTO DEL ETW PATCHING EN EL AUTÓMATA DE EVENTOS
═══════════════════════════════════════════════════════════════════════════

  ANTES (canal de telemetría completo):
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  E = E_int ⊎ E_ext                                         │
  │                                                             │
  │  Proceso     ETW       WQL Engine     EDR                  │
  │  creado  ──► Event ──► Filter ψ ──► Alert                │
  │             e_ext     ψ(e)=T?       "Anómalo"              │
  │                                                             │
  │  Información mutua: I(Detection; Attack) > 0              │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  DESPUÉS (ETW parcheado):
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  E' = E_int (E_ext eliminado)                              │
  │                                                             │
  │  Proceso     ETW'      WQL Engine     EDR                  │
  │  creado  ──► ∅ ──► Filter ψ ──► No Alert                 │
  │             G'=ε   ψ(?)=⊥        (ciego)                   │
  │                                                             │
  │  Información mutua: I(Detection; Attack) = 0              │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  FORMALMENTE:
  G'_ETW = ∅  ⟹  ∀e ∈ E_extrinsic: G(e) = false
             ⟹  Σ_WQL transiciona solo con E_intrinsic
             ⟹  Win32_ProcessStartTrace: NO GENERADO
             ⟹  Detección basada en ETW: CIEGA

═══════════════════════════════════════════════════════════════════════════
```

### 4.4 Composición de Operaciones de Evasión

Las operaciones de evasión se componen secuencialmente, cada una eliminando una capa de observación:

$$\text{Evasion} = \text{Unhook} \circ \text{ETWPatch} \circ \text{IndirectSyscall} \circ \text{StackSpoof}$$

| Operación | Capa eliminada | Función del EDR degradada |
|---|---|---|
| Unhook | Hooks en ntdll | Intercepción de llamadas al sistema |
| ETW Patch | Generación de eventos | Visibilidad de comportamiento del proceso |
| Indirect Syscall | Inspección de caller | Verificación de origen de la syscall |
| Stack Spoof | Análisis de pila | Atribución de la ejecución a código malicioso |

**Propiedad de composición:** Cada operación es independiente y ataca un subsistema diferente de detección. La composición es **no conmutativa** (el orden importa: el unhooking debe realizarse antes de usar `NtAllocateVirtualMemory`, y el ETW patch debe completarse antes de ejecutar operaciones generadoras de eventos).

---

## 5. Teoría de la Información Aplicada: Degradación del Canal de Detección

### 5.1 Modelo del Canal de Detección como Canal con Ruido

El sistema de detección (EDR) se modela como un **canal de comunicación** que recibe señales del sistema operativo y produce decisiones (alertar / no alertar):

```
  Eventos del          Canal de               Decisión
  Sistema OS           Detección EDR          del EDR
  ┌─────────┐     ┌──────────────────┐     ┌──────────┐
  │ ETW      │────►│ Reglas +         │────►│ Alert /  │
  │ Events   │     │ Heurísticas      │     │ Silence  │
  │          │     │                  │     │          │
  │          │     │ Ruido:           │     │          │
  │          │     │ ├── ETW patched  │     │          │
  │          │     │ ├── Hooks off    │     │          │
  │          │     │ ├── Fake stack   │     │          │
  │          │     │ └── Syscall off  │     │          │
  └─────────┘     └──────────────────┘     └──────────┘
```

### 5.2 Capacidad del Canal de Detección

**Definición 5.2.1 — Capacidad del Canal**

La capacidad del canal de detección es:

$$C_{detect} = \max_{P(A)} I(A; D)$$

donde $A$ es la variable aleatoria "ataque presente" y $D$ es la variable "decisión del EDR".

Tras las operaciones de evasión:

$$C'_{detect} = \max_{P(A)} I(A; D')$$

donde $D'$ es la decisión con el canal degradado. La **reducción de capacidad** es:

$$\Delta C = C_{detect} - C'_{detect}$$

### 5.3 Cuantificación de la Pérdida por Cada Operación de Evasión

| Operación de evasión | Eventos eliminados | $\Delta C$ (bits estimado) | Efecto en el EDR |
|---|---|---|---|
| ETW Patching | Todos los eventos ETW del proceso | **8-12** | Ceguera parcial: no hay eventos de proceso/imagen |
| API Unhooking | Interceptaciones de llamadas NT | **4-6** | No puede inspeccionar argumentos de syscalls |
| Indirect Syscall | Verificación de dirección de retorno | **2-3** | No puede distinguir syscall legítimo de inyectado |
| Stack Spoofing | Stack walk del hilo | **3-5** | No puede atribuir ejecución a código malicioso |
| **Composición total** | — | **17-26** | **Canal de detección severamente degradado** |

### 5.4 Divergencia KL entre Distribuciones con y sin Evasión

**Definición 5.4.1 — Divergencia KL del Canal de Detección**

Sea $P_0$ la distribución de eventos cuando no hay evasión y $P_1$ la distribución con evasión completa. La divergencia KL es:

$$D_{KL}(P_0 \| P_1) = \sum_{e \in \text{Events}} P_0(e) \log_2 \frac{P_0(e)}{P_1(e)}$$

Cuando el ETW está parcheado, $P_1(e) = 0$ para los eventos eliminados, lo que hace $D_{KL} = +\infty$. Esto indica que las dos distribuciones son **completamente distinguibles** — si el EDR pudiera observar la ausencia de eventos (lo cual es en sí mismo una señal), podría detectar la evasión.

**Paradoja de la detección por ausencia:** La ausencia total de eventos ETW de un proceso que debería generarlos es, en sí misma, una señal de alta confianza:

$$\text{Signal}_{absence}(P) \iff \text{IsRunning}(P) \wedge \text{ETWEvents}(P) = \emptyset \wedge \text{ExpectedEvents}(P) > 0$$

---

## 6. Hardware Breakpoints: Modelo de Registros de Depuración x64 y Anti-Monitoreo

### 6.1 Arquitectura de los Registros de Depuración

**Definición 6.1.1 — Subsistema de Depuración Hardware**

El procesador x64 provee un conjunto de registros de depuración que constituyen un **subsistema de monitoreo hardware** independiente del software:

$$\mathcal{D} = (\text{DR0}, \text{DR1}, \text{DR2}, \text{DR3}, \text{DR6}, \text{DR7})$$

| Registro | Función | Ancho |
|---|---|---|
| DR0-DR3 | Direcciones de los 4 breakpoints | 64 bits (x64) |
| DR6 | Registro de estado: cuál breakpoint se activó | 32 bits |
| DR7 | Registro de control: habilitación, tipo, tamaño | 32 bits |

### 6.2 Estructura del Registro DR7

**Definición 6.2.1 — Campos de DR7**

```
DR7 (32 bits):
┌─────────────────────────────────────────────────────────────┐
│ Bit 0:   L0  — Local Enable para DR0                       │
│ Bit 1:   G0  — Global Enable para DR0                      │
│ Bit 2:   L1  — Local Enable para DR1                       │
│ Bit 3:   G1  — Global Enable para DR1                      │
│ Bit 4:   L2  — Local Enable para DR2                       │
│ Bit 5:   G2  — Global Enable para DR2                      │
│ Bit 6:   L3  — Local Enable para DR3                       │
│ Bit 7:   G3  — Global Enable para DR3                      │
│ Bit 8:   LE  — Local Exact Breakpoint Enable               │
│ Bit 9:   GE  — Global Exact Breakpoint Enable              │
│ Bits 10-12: Reserved                                        │
│ Bit 13:  GD  — General Detect (debug register access trap) │
│ Bits 16-17: R/W0 — Tipo de breakpoint para DR0             │
│ Bits 18-19: LEN0 — Longitud de breakpoint para DR0         │
│ Bits 20-21: R/W1 — Tipo de breakpoint para DR1             │
│ Bits 22-23: LEN1 — Longitud de breakpoint para DR1         │
│ Bits 24-25: R/W2 — Tipo de breakpoint para DR2             │
│ Bits 26-27: LEN2 — Longitud de breakpoint para DR2         │
│ Bits 28-29: R/W3 — Tipo de breakpoint para DR3             │
│ Bits 30-31: LEN3 — Longitud de breakpoint para DR3         │
└─────────────────────────────────────────────────────────────┘
```

**Codificación del tipo de breakpoint (R/Wi):**

| Valor | Tipo | Descripción |
|---|---|---|
| 00 | Execution | Breakpoint en ejecución de instrucción |
| 01 | Write | Breakpoint en escritura de datos |
| 10 | I/O | Breakpoint en acceso a puerto I/O (requiere CPL=0) |
| 11 | Read/Write | Breakpoint en lectura o escritura de datos |

**Codificación de la longitud (LENi):**

| Valor | Longitud | Aplicable a |
|---|---|---|
| 00 | 1 byte | Execution, Write, R/W |
| 01 | 2 bytes | Write, R/W |
| 10 | 8 bytes (x64) | Write, R/W |
| 11 | 4 bytes | Write, R/W |

### 6.3 Función de Detección de Breakpoints

**Definición 6.3.1 — Función DetectBP**

El payload implementa una función que verifica si hay breakpoints de hardware activos que pudieran monitorear su ejecución:

$$\text{DetectBP}: \mathcal{D} \rightarrow \{\text{Clean}, \text{Compromised}\}$$

$$\text{DetectBP}(\mathcal{D}) = \begin{cases} \text{Compromised} & \text{si } \exists\, n \in [0,3]: \text{DR7}.L_n = 1 \vee \text{DR7}.G_n = 1 \wedge \text{DR}n \in \text{CodeRange}_{payload} \\ \text{Clean} & \text{en otro caso} \end{cases}$$

La implementación utiliza `NtGetContextThread` para leer los registros DR:

```asm
; ═══════════════════════════════════════════════════════
; HARDWARE BREAKPOINT CHECK (payload PIC)
; ═══════════════════════════════════════════════════════

    ; Preparar contexto para NtGetContextThread
    sub     rsp, 0x4D0           ; CONTEXT struct ~1232 bytes
    mov     dword [rsp+0x30], 0x0010001F  ; ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

    ; NtGetContextThread(CurrentThread, &CONTEXT)
    mov     r10d, [rax+syscall_NtGetContextThread]
    mov     rcx, -2              ; CurrentThread handle (pseudo-handle)
    lea     rdx, [rsp]
    syscall

    ; Verificar DR7
    mov     rbx, [rsp+0x3C0]    ; CONTEXT.Dr7 offset (aproximado)
    test    rbx, 0x000000FF      ; Mask para L0-L3 y G0-G3
    jnz     bp_detected          ; Si cualquier bit de enable está activo

    ; Verificar DR0-DR3 contra rango del payload
    mov     rcx, [rsp+0x390]    ; CONTEXT.Dr0
    cmp     rcx, rax            ; rax = BaseAddr del payload
    jb      check_dr1
    add     rax, payload_size
    cmp     rcx, rax
    jb      bp_detected          ; DR0 apunta dentro del payload

check_dr1:
    ; ... similar para DR1-DR3 ...

bp_detected:
    ; Acción: limpiar breakpoints o desviar ejecución
    ; Opción A: Sobrescribir DR0-DR3 con direcciones fuera de rango
    ; Opción B: Setear DR7.GD = 1 para generar trap en siguiente acceso a DR
    ; Opción C: Terminar ejecución silenciosamente
```

### 6.4 Estrategias de Anti-Monitoreo

| Estrategia | Mecanismo | Detección por EDR |
|---|---|---|
| **Limpieza** | Sobrescribir DR0-DR3 con 0, DR7 con 0 vía `NtSetContextThread` | El EDR detecta que sus breakpoints fueron removidos |
| **Desvío** | Establecer DR0-DR3 apuntando a código legítimo (señuelo) | El EDR recibe breakpoints falsos |
| **GD Trap** | Activar DR7.GD = 1 → próxima instrucción `mov drX` genera #DB | Bloquea al EDR de restaurar sus breakpoints |
| **Detección pasiva** | Verificar DR sin modificar; si comprometido, no ejecutar | No genera señal observable |
| **Timing check** | Medir tiempo de ejecución de región sensible; si anómalo → breakpoint activo | Difícil de detectar |

---

## 7. Stack Spoofing: Falsificación del Grafo de Marcos de Activación

### 7.1 Modelo Formal de la Pila de Llamadas

**Definición 7.1.1 — Pila como Lista Enlazada de Marcos**

La pila de llamadas (call stack) de un hilo se modela como una **lista enlazada** de marcos de activación (stack frames):

$$\text{Stack}_T = [f_0 \xrightarrow{\text{ret}} f_1 \xrightarrow{\text{ret}} f_2 \xrightarrow{\text{ret}} \ldots \xrightarrow{\text{ret}} f_n]$$

donde cada marco $f_i$ contiene una **dirección de retorno** $\text{ret}_i \in \text{AddrSpace}$. Un **stack walk** es el recorrido de esta lista:

$$\text{StackWalk}: \text{RSP} \rightarrow [\text{ret}_0, \text{ret}_1, \ldots, \text{ret}_n]$$

### 7.2 Invariante de Coherencia de la Pila

**Definición 7.2.1 — Coherencia con Unwind Information**

Cada módulo PE contiene una sección `.pdata` con entradas `RUNTIME_FUNCTION` que describen cómo hacer unwind de cada función. La coherencia de la pila se define como:

$$\text{CoherentStack}(\text{stack}) \iff \forall\, f_i \in \text{stack}: \exists\, \text{RF}_j \in \text{.pdata}(M_k): \text{ret}_i \in \text{Range}(\text{RF}_j)$$

donde $M_k$ es el módulo que contiene la dirección de retorno $\text{ret}_i$.

**Invariante de la pila legítima:**

$$\text{LegitStack}(\text{stack}) \iff \text{CoherentStack}(\text{stack}) \wedge \forall\, \text{ret}_i: \text{ret}_i \in \bigcup_{M \in \text{LoadedModules}} \text{Range}(M)$$

Es decir, toda dirección de retorno en una pila legítima pertenece a un módulo cargado y es coherente con la información de unwind de ese módulo.

### 7.3 Stack Spoofing como Violación del Invariante

**Definición 7.3.1 — Stack Spoofing**

El stack spoofing construye una pila falsa que satisface $\text{CoherentStack}$ pero viola la semántica real de la cadena de llamadas:

$$\text{SpoofedStack} = [\text{ntdll!RtlUserThreadStart}, \text{kernel32!BaseThreadInitThunk}, \text{legitimate\_frame}, \ldots]$$

Formalmente, el spoofing reemplaza la secuencia real con una secuencia sintética:

$$\text{StackWalk}(RSP_{spoofed}) \neq \text{StackWalk}(RSP_{real}) \wedge \text{CoherentStack}(\text{SpoofedStack}) = \top$$

```
═══════════════════════════════════════════════════════════════════════════
             STACK SPOOFING: PILA REAL vs. FALSIFICADA
═══════════════════════════════════════════════════════════════════════════

  PILA REAL (sin spoofing, detectable por EDR):
  ┌──────────────────────────────────────────────────────┐
  │ RSP →  ret_addr: payload_ASM+0x1A3    ← ANÓMALO    │
  │         ret_addr: payload_ASM+0x0F2    ← ANÓMALO    │
  │         ret_addr: payload_ASM+0x008    ← ANÓMALO    │
  │         datos del payload                             │
  │         ...                                           │
  └──────────────────────────────────────────────────────┘
       │
       ▼
  EDR stack walk:
  ├── Frame 0: 0x1234000001A3 → fuera de módulos cargados → INYECCIÓN
  ├── Frame 1: 0x1234000000F2 → MEM_PRIVATE → ANÓMALO
  └── Frame 2: 0x123400000008 → sin .pdata → NO LEGÍTIMO
       │
       ▼
  DECISIÓN DEL EDR: ALERTA — código inyectado detectado

  ──────────────────────────────────────────────────────────

  PILA FALSIFICADA (con spoofing, aparenta legítima):
  ┌──────────────────────────────────────────────────────┐
  │ RSP →  ret_addr: ntdll!RtlUserThreadStart ← LEGÍTIMO│
  │         ret_addr: kernel32!BaseThreadInitThunk ← OK  │
  │         ret_addr: legitimate.dll!Func+0x42  ← OK    │
  │         stack frame sintético con datos plausibles    │
  │         ...                                           │
  └──────────────────────────────────────────────────────┘
       │
       ▼
  EDR stack walk:
  ├── Frame 0: ntdll!RtlUserThreadStart → módulo legítimo ✓
  ├── Frame 1: kernel32!BaseThreadInitThunk → módulo legítimo ✓
  └── Frame 2: legitimate.dll!Func+0x42 → módulo legítimo ✓
       │
       ▼
  DECISIÓN DEL EDR: SIN ALERTA — pila aparentemente legítima

  ═══════════════════════════════════════════════════════════
  DETECCIÓN AVANZADA: EDR con unwind validation puede
  verificar que la cadena de frames es coherente con las
  RUNTIME_FUNCTION entries de cada módulo. El spoofing
  requiere que cada frame sintético tenga una RF válida.
  ═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════════════
```

### 7.4 Técnicas de Stack Spoofing Documentadas

| Técnica | Mecanismo | Complejidad | Evasión |
|---|---|---|---|
| **Synthetic Frames** | Construir marcos falsos con direcciones de retorno de módulos legítimos | Media | EDR estándar |
| **Stack Pivot** | Cambiar RSP a una región de pila preparada antes de la operación sensible | Alta | EDR con RSP validation |
| **ROP-based Spoofing** | Usar gadgets de módulos legítimos para construir una cadena de retorno plausible | Muy alta | EDR con ROP detection |
| **Fiber-based Spoofing** | Usar `CreateFiber`/`SwitchToFiber` para cambiar el contexto de ejecución | Alta | EDR con fiber monitoring |
| **Callback-based Spoofing** | Usar callbacks legítimos (`EnumWindows`, `EnumChildWindows`) como punto de entrada | Media | EDR con callback inspection |

### 7.5 Invariante Detectable del Stack Spoofing

**Teorema 7.5.1 — Detección por Unwind Validation**

*Si el EDR realiza unwind validation completo, un stack spoofing con frames sintéticos que no corresponden a la secuencia de llamadas real puede ser detectado porque las instrucciones en la dirección de retorno no coinciden con las instrucciones que habrían hecho el call:*

$$\text{DetectSpoofing}(\text{stack}) \iff \exists\, f_i: \text{InstructionAt}(\text{ret}_i - \text{call\_size}) \neq \text{CALL instruction}$$

Es decir, si la dirección de retorno no es precedida por una instrucción `call`, el frame es sintético.

---

## 8. Syscalls Directos e Indirectos: Omisión de la Capa de Abstracción ntdll

### 8.1 Modelo Formal de la Cadena de Llamada al Sistema

La cadena de llamada al sistema en Windows 11 se modela como una **función compuesta**:

$$\text{SysCall}: \text{App} \xrightarrow{\text{ntdll}} \text{Kernel} \xrightarrow{\text{dispatcher}} \text{Handler}$$

En un sistema sin modificaciones:

```
Aplicación → ntdll!NtXxx(args) → mov r10, rcx → mov eax, SSN → syscall → Kernel Handler
```

donde SSN es el **Syscall Service Number** que identifica la función del kernel.

### 8.2 Números de Syscall como Función Dependiente de Versión

**Definición 8.2.1 — Función SyscallNumber**

El número de syscall no es constante entre versiones de Windows. Definimos:

$$\text{SSN}: \text{FuncName} \times \text{WinBuild} \rightarrow \mathbb{N}$$

| Función | Win11 21H2 (22000) | Win11 22H2 (22621) | Win11 23H2 (22631) |
|---|---|---|---|
| `NtAllocateVirtualMemory` | 0x18 | 0x18 | 0x18 |
| `NtProtectVirtualMemory` | 0x50 | 0x50 | 0x50 |
| `NtWriteVirtualMemory` | 0x3A | 0x3A | 0x3A |
| `NtCreateThreadEx` | 0xC2 | 0xC2 | 0xC2 |
| `NtQueueApcThread` | 0x04 | 0x04 | 0x04 |
| `NtClose` | 0x0F | 0x0F | 0x0F |

**Implicación:** El payload ASM debe resolver los SSN dinámicamente (leyendo desde la EAT de `ntdll.dll` en memoria) o embeberlos estáticamente con riesgo de incompatibilidad entre builds.

### 8.3 Clasificación de Syscalls por Nivel de Observabilidad

```
═══════════════════════════════════════════════════════════════════════════
          CLASIFICACIÓN DE MÉTODOS DE SYSCALL
═══════════════════════════════════════════════════════════════════════════

  MÉTODO 1: SYSCALL ESTÁNDAR (vía ntdll.dll hookeado)
  ┌──────────────────────────────────────────────────────────┐
  │  App → ntdll!NtXxx (HOOKED) → jmp EDR → ... → syscall  │
  │                                                          │
  │  Pila:     [App, ntdll, EDR, ntdll+offset, kernel]      │
  │  RetAddr:  ntdll.dll                                     │
  │  Observabilidad EDR: MÁXIMA                              │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │  EDR ve: argumentos, caller, pila completa         │  │
  │  └────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────┘

  MÉTODO 2: SYSCALL DIRECTO (desde payload, sin ntdll)
  ┌──────────────────────────────────────────────────────────┐
  │  Payload → mov r10,rcx; mov eax,SSN; syscall; ret       │
  │                                                          │
  │  Pila:     [Payload, kernel]                              │
  │  RetAddr:  fuera de ntdll.dll                            │
  │  Observabilidad EDR: REDUCIDA                            │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │  EDR ve: syscall ejecutado, pero RetAddr ∉ ntdll  │  │
  │  │  → ANÓMALO: syscall fuera de ntdll                 │  │
  │  └────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────┘

  MÉTODO 3: SYSCALL INDIRECTO (jump a syscall;ret dentro de ntdll)
  ┌──────────────────────────────────────────────────────────┐
  │  Payload → setup args; jmp ntdll+offset (syscall;ret)   │
  │                                                          │
  │  Pila:     [Payload, ntdll+offset, kernel]               │
  │  RetAddr:  ntdll.dll ✓                                   │
  │  Observabilidad EDR: MÍNIMA                              │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │  EDR ve: RetAddr ∈ ntdll → parece legítimo        │  │
  │  │  Pero: no pasó por el hook de la función NtXxx    │  │
  │  │  Hook fue bypasseado                               │  │
  │  └────────────────────────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 8.4 Formalización del Syscall Indirecto

**Definición 8.4.1 — Syscall Indirecto**

Un syscall indirecto satisface:

$$\text{IndirectSyscall}(op) \iff \text{Addr}_{syscall\_instr} \in \text{Range}(\text{ntdll.dll}) \wedge \text{Addr}_{entry} \notin \text{Range}(\text{ntdll.dll})$$

donde $\text{Addr}_{syscall\_instr}$ es la dirección de la instrucción `syscall` y $\text{Addr}_{entry}$ es la dirección donde se prepararon los argumentos.

**Propiedad clave:** La dirección de retorno cuando el kernel completa el syscall cae dentro de `ntdll.dll` (es la instrucción `ret` inmediatamente después de `syscall`), lo que hace que el syscall parezca legítimo desde la perspectiva del kernel.

### 8.5 Resolución Dinámica de SSN

**Definición 8.5.1 — Algoritmo de Resolución de SSN**

El payload resuelve los números de syscall dinámicamente mediante el siguiente algoritmo:

1. Localizar `ntdll.dll` en memoria (vía PEB → LDR → InMemoryOrderModuleList)
2. Parsear el PE header de `ntdll.dll` para localizar la Export Address Table (EAT)
3. Para cada función `NtXxx` requerida, buscar su nombre en `AddressOfNames[]`
4. Usar el índice en `AddressOfNameOrdinals[]` para obtener el ordinal
5. Usar el ordinal en `AddressOfFunctions[]` para obtener la dirección de la función
6. Leer los bytes de la función: `mov eax, SSN` → extraer SSN

Formalmente:

$$\text{ResolveSSN}(name) = \text{ExtractSSN}(\text{EAT}[\text{FindOrdinal}(\text{EAT}, name)])$$

donde:

$$\text{ExtractSSN}(addr) = \text{ReadDWord}(addr + 4) \quad \text{(offset del segundo byte de 'mov eax, imm32')}$$

---

## 9. Integración con el Espacio de Estados Global del Sistema

### 9.1 Espacio de Estados Compartido

Recordemos que el estado global del sistema se modela como:

$$\Sigma_{total} = \Sigma_{FS} \times \Sigma_{Shell} \times \Sigma_{Proc} \times \Sigma_{CIM} \times \Sigma_{WQL} \times \Sigma_{APC} \times \Sigma_{COM} \times \Sigma_{ETW}$$

El payload ASM, al operar, produce **transiciones compuestas** que afectan múltiples componentes simultáneamente.

### 9.2 Mapa de Impacto por Componente

```
═══════════════════════════════════════════════════════════════════════════
        IMPACTO DEL PAYLOAD EN EL ESPACIO DE ESTADOS GLOBAL
═══════════════════════════════════════════════════════════════════════════

  Σ_ETW ─────────────── Degradación MÁXIMA
  │  ├── G'_ETW = ∅ (eventos ETW eliminados)
  │  ├── E' = E_intrinsic (solo eventos intrínsecos)
  │  ├── Autómata WQL parcialmente congelado
  │  └── I(Detection; Attack) → 0 para detección basada en ETW
  │
  Σ_Proc ─────────────── Anomalía ALTA
  │  ├── ∃ página MEM_PRIVATE + RX sin respaldo en disco
  │  ├── ∃ hilo con entry point fuera de módulos cargados (si NtCreateThreadEx)
  │  ├── ∃ APC inyectada en hilo ajeno (si NtQueueApcThread)
  │  └── Protección de página transitó RW → RX
  │
  Σ_APC ─────────────── Modificación
  │  ├── APCQueue_T ⊋ APCQueue_T^orig (APC inyectada)
  │  ├── SecurityContext(APC) = SecurityContext(T_host)
  │  └── Ejecución hereda privilegios del hilo anfitrión
  │
  Σ_COM ─────────────── Potencial MODIFICACIÓN
  │  ├── Posible canal C2 vía DCOM (ncacn_ip_tcp)
  │  ├── F_act(CLSID) → Instance (activación de componentes)
  │  └── Marshaling μ: Data_client → NDR → Data_server
  │
  Σ_CIM ─────────────── Potencial MODIFICACIÓN
  │  ├── Posible creación de __EventFilter malicioso
  │  ├── Posible creación de __FilterToConsumerBinding
  │  └── σ_CIM ≠ σ_CIM^orig si se crean event subscriptions
  │
  Σ_WQL ─────────────── Degradación PARCIAL
  │  ├── E' = E_intrinsic (eventos extrínsecos eliminados por ETW patch)
  │  ├── Solo eventos CRUD sobre repositorio CIM son detectables
  │  └── Win32_ProcessStartTrace: NO GENERADO
  │
  Σ_FS ─────────────── Sin cambio directo
  │  └── (El payload opera en memoria, no modifica archivos)
  │
  Σ_Shell ─────────────── Sin cambio directo
     └── (El payload ya fue ejecutado, no interactúa con el Shell)

═══════════════════════════════════════════════════════════════════════════
```

### 9.3 Señal Compuesta de Alta Confianza

**Definición 9.3.1 — Señal Compuesta de Estado Global**

La señal de detección más potente es la **conjunción** de anomalías en múltiples componentes:

$$\text{HighConfidenceSignal}(\sigma) \iff \underbrace{\neg\text{ETWIntact}(\sigma)}_{\Sigma_{ETW}} \wedge \underbrace{\text{InjectedAPC}(\sigma)}_{\Sigma_{APC}} \wedge \underbrace{\text{PrivateRX}(\sigma)}_{\Sigma_{Proc}}$$

Esta señal es difícil de evadir porque requiere evadir simultáneamente tres subsistemas de detección independientes. Formalmente, la probabilidad de evadir la señal compuesta es:

$$P(\text{evade composite}) = P(\text{evade } \Sigma_{ETW}) \times P(\text{evade } \Sigma_{APC}) \times P(\text{evade } \Sigma_{Proc})$$

Si cada subsistema tiene probabilidad independiente de detección $p_d$:

$$P(\text{evade composite}) = (1 - p_d)^3$$

Para $p_d = 0.5$: $P(\text{evade}) = 0.125$ (87.5% de probabilidad de detección)

### 9.4 Transiciones Compuestas como Grafo

Las transiciones del sistema durante la ejecución del payload forman un **grafo dirigido** sobre el espacio de estados:

$$\sigma_0 \xrightarrow{\tau_{unhook}} \sigma_1 \xrightarrow{\tau_{etw}} \sigma_2 \xrightarrow{\tau_{alloc}} \sigma_3 \xrightarrow{\tau_{write}} \sigma_4 \xrightarrow{\tau_{protect}} \sigma_5 \xrightarrow{\tau_{exec}} \sigma_6$$

donde cada $\tau_i$ modifica un subconjunto de componentes:

| Transición | Componentes afectados | Invariante violado |
|---|---|---|
| $\tau_{unhook}$ | $\Sigma_{Proc}$ (memoria de ntdll) | Integridad de código de ntdll |
| $\tau_{etw}$ | $\Sigma_{ETW}$, $\Sigma_{WQL}$ | Integridad de generación de eventos |
| $\tau_{alloc}$ | $\Sigma_{Proc}$ (nueva región RW) | Sin violación (operación legítima) |
| $\tau_{write}$ | $\Sigma_{Proc}$ (escritura en RW) | Sin violación (operación legítima) |
| $\tau_{protect}$ | $\Sigma_{Proc}$ (RW → RX) | Transición de protección sospechosa |
| $\tau_{exec}$ | $\Sigma_{APC}$ o $\Sigma_{Proc}$ (nuevo hilo) | Ejecución desde memoria no respaldada |

---

## 10. Superficie de Detección: Formalización y Predicados de Alerta

### 10.1 Predicados de Primer Nivel (Indicadores Directos)

**Predicado 10.1.1 — Ejecución desde memoria sin respaldo en disco**

$$P_1(\sigma) \iff \exists\, p \in \Sigma_{Proc}.\mathcal{M}: \text{Prot}(p) = RX \wedge \text{Type}(p) = \text{MEM\_PRIVATE} \wedge \neg\text{HasFileBacking}(p)$$

**Predicado 10.1.2 — Syscall originado fuera de ntdll**

$$P_2(\sigma) \iff \exists\, \text{syscall}: \text{RetAddr}_{syscall} \notin \text{Range}(\text{ntdll.dll})$$

**Predicado 10.1.3 — ETW parcheado**

$$P_3(\sigma) \iff \mu_{mem}(\text{EtwEventWrite}_{entry}) \neq \mu_{disk}(\text{EtwEventWrite}_{entry})$$

**Predicado 10.1.4 — Sección .text de ntdll modificada**

$$P_4(\sigma) \iff \mu_{mem}(\text{ntdll}.text) \neq \mu_{disk}(\text{ntdll}.text)$$

### 10.2 Predicados de Segundo Nivel (Correlación)

**Predicado 10.2.1 — Transición RW → RX en página MEM_PRIVATE**

$$P_5(\sigma, t_1, t_2) \iff \text{Prot}(p, t_1) = RW \wedge \text{Prot}(p, t_2) = RX \wedge \text{Type}(p) = \text{MEM\_PRIVATE} \wedge t_2 > t_1$$

**Predicado 10.2.2 — APC inyectada entre procesos**

$$P_6(\sigma) \iff \text{Source}(\text{NtQueueApcThread}) \neq \text{Process}(T_{target})$$

**Predicado 10.2.3 — Stack walk incoherente**

$$P_7(\sigma) \iff \exists\, f_i \in \text{StackWalk}(T): \nexists\, \text{RF}_j: \text{ret}_i \in \text{Range}(\text{RF}_j)$$

**Predicado 10.2.4 — Registros DR manipulados**

$$P_8(\sigma) \iff \text{DR7}.L_n = 1 \vee \text{DR7}.G_n = 1 \wedge \text{Source}(DR\_access) \neq \text{kernel}$$

### 10.3 Señal Compuesta

$$\text{HighConfidence}(\sigma) \iff P_1(\sigma) \wedge (P_2(\sigma) \vee P_3(\sigma) \vee P_4(\sigma))$$

Es decir: existe código ejecutable sin respaldo en disco **y** al menos un mecanismo de evasión activo (syscall anómalo, ETW parcheado, o ntdll modificado).

### 10.4 Tabla Consolidada

| Nivel | Señal | Predicado | Subsistema | Tasa FP | Tasa FN |
|---|---|---|---|---|---|
| 1 | MEM_PRIVATE + RX | $P_1$ | Memory Manager | Baja | Media (HVCI lo elimina) |
| 1 | Syscall fuera de ntdll | $P_2$ | Kernel dispatcher | Baja | Media (indirect lo evita) |
| 1 | ETW parcheado | $P_3$ | ntdll integrity | Muy baja | Media |
| 1 | ntdll .text modificada | $P_4$ | ntdll integrity | Muy baja | Alta (si se restaura) |
| 2 | RW → RX en MEM_PRIVATE | $P_5$ | ETW Kernel-Memory | Muy baja | Media |
| 2 | APC cross-process | $P_6$ | Kernel audit | Baja | Baja |
| 2 | Stack incoherente | $P_7$ | EDR stack walk | Media | Media (spoofing evita) |
| 2 | DR manipulados | $P_8$ | Debug registers | Media | Alta |
| 3 | **Señal compuesta** | $P_1 \wedge (P_2 \vee P_3 \vee P_4)$ | Correlación | **Muy baja** | **Baja** |

---

## 11. Historial de Explotación Documentado y Contexto APT

### 11.1 Cronología de Técnicas de Evasión a Nivel de Payload

| Período | Técnica | Actores / Investigadores |
|---|---|---|
| 2013 | Shellcode PIC estándar (Metasploit) | Comunidad de pentesting |
| 2015 | API hashing (djb2/FNV-1a) para evasión estática | Diversos malware |
| 2017 | API unhooking documentado como técnica ofensiva | Red Team community |
| 2018 | Direct syscalls en malware personalizado | Cobalt Strike, Brute Ratel |
| 2019 | ETW patching como técnica de evasión | Outflank (research) |
| 2020 | Indirect syscalls documentados | SafeBreach Labs |
| 2021 | Stack spoofing / synthetic frames | CyberArk Labs |
| 2022 | Hardware breakpoint anti-debug en payloads | MalwareTech |
| 2022 | Hell's Gate / Halos Gate (dynamic SSN resolution) | Smoke & Rasta Mouse |
| 2023 | Syswhispers3 / SyswhispersIR (indirect syscall generation) | KlezVirus |
| 2023 | Callback-based execution como alternativa a APC | Diversos investigadores |
| 2024 | PoC de evasión de HVCI mediante configuración incorrecta | Múltiples investigadores |
| 2024 | Frostming (direct syscall + ETW patch + stack spoof combinado) | Comunidad ofensiva |

### 11.2 Técnicas MITRE ATT&CK Asociadas

| ID | Técnica | Descripción |
|---|---|---|
| T1055.001 | Process Injection: DLL Injection | Inyección de código en proceso ajeno |
| T1055.004 | Process Injection: Asynchronous Procedure Call | Inyección vía APC (NtQueueApcThread) |
| T1055.012 | Process Injection: Process Hollowing | Variante de inyección |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ETW patching, unhooking |
| T1106 | Native API | Uso directo de syscalls NT |
| T1027.007 | Obfuscated Files: Dynamic API Resolution | Resolución de APIs por hash |
| T1036.004 | Masquerading: Masquerade Task or Service | Stack spoofing |
| T1620 | Reflective Code Loading | Carga de código desde memoria sin disco |
| T1574.011 | Hijack Execution Flow: Services Registry | COM hijacking |

### 11.3 Grupos APT que Emplean Payloads ASM con Evasión Avanzada

| Grupo | Aliases | Técnica de payload | Nivel de evasión |
|---|---|---|---|
| APT29 | Cozy Bear | PIC con direct syscalls + ETW patch | Muy alto |
| APT28 | Fancy Bear | Shellcode con API hashing | Alto |
| FIN7 | Carbon Spider | PIC con unhooking + indirect syscalls | Alto |
| Turla | Snake | PIC con hardware BP check | Muy alto |
| Lazarus | Hidden Cobra | PIC con stack spoofing | Alto |
| Sandworm | IRIDIUM | PIC con syscall directa | Alto |
| Venomous Bear | APT29-like | PIC + ETW patch + callback exec | Muy alto |

---

## 12. Contramedidas: Niveles de Defensa según Modelo de Capas

### 12.1 Modelo de Defensa en Profundidad

```
┌──────────────────────────────────────────────────────────────┐
│           MODELO DE DEFENSA EN CAPAS — ETAPA 5              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  CAPA 5: PROTECCIÓN A NIVEL DE HARDWARE                     │
│  ├── HVCI (Hypervisor-Enforced Code Integrity)              │
│  │   └── Rechaza ejecución desde páginas no firmadas        │
│  ├── VBS (Virtualization-Based Security)                    │
│  │   └── Aísla código del kernel del modo usuario           │
│  ├── Secure Boot                                            │
│  │   └── Garantiza integridad de la cadena de arranque      │
│  └── Credential Guard                                       │
│      └── Aísla credenciales en un entorno virtualizado       │
│                                                              │
│  CAPA 4: KERNEL-MODE DETECTION                              │
│  ├── Kernel APC queue monitoring                            │
│  ├── Syscall origin validation (RetAddr ∈ ntdll?)           │
│  ├── ETW provider integrity checks                          │
│  ├── ntdll .text integrity verification (periodic)          │
│  └── Callback object monitoring                             │
│                                                              │
│  CAPA 3: ENDPOINT DETECTION & RESPONSE (EDR)                │
│  ├── MEM_PRIVATE + RX detection                             │
│  ├── RW → RX page transition monitoring                     │
│  ├── Stack walk with unwind validation                      │
│  ├── Thread start address outside loaded modules             │
│  ├── Cross-process NtQueueApcThread audit                   │
│  └── Debug register modification detection                  │
│                                                              │
│  CAPA 2: POLÍTICAS DE SEGURIDAD                             │
│  ├── WDAC: solo código firmado puede ejecutarse             │
│  ├── AppLocker: bloquear ejecución desde MEM_PRIVATE        │
│  ├── PowerShell CLM: modo restringido                       │
│  └── AMSI: escaneo de scripts antes de ejecución            │
│                                                              │
│  CAPA 1: ARQUITECTURA DE SEGURIDAD                          │
│  ├── Zero Trust: verificar cada acceso                      │
│  ├── Microsegmentación: limitar comunicación C2             │
│  └── Network detection: identificar patrones C2             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 12.2 Efectividad de Cada Capa contra el Payload ASM

| Capa | Efectividad | Mecanismo de defensa | Limitación |
|---|---|---|---|
| HVCI/VBS | **Máxima** | Bloquea ejecución de MEM_PRIVATE RX | Requiere hardware compatible y configuración correcta |
| Kernel detection | **Alta** | Observa desde Ring 0, no puede ser hookeado | Requiere drivers firmados; complejidad de implementación |
| EDR avanzado | **Media-Alta** | Detecta anomalías en memoria y pila | Puede ser evadido por indirect syscalls + spoofing |
| WDAC/AppLocker | **Alta** | Bloquea código no firmado | Puede impactar flujos legítimos |
| Network detection | **Media** | Detecta comunicación C2 | No aplica si el payload no se comunica |

### 12.3 Análisis Probabilístico

| Defensa | $p_i$ empresa promedio | $p_i$ entorno endurecido |
|---|---|---|
| HVCI/VBS habilitado | 0.25 | 0.85 |
| Kernel-mode detection | 0.15 | 0.75 |
| EDR con reglas avanzadas | 0.40 | 0.85 |
| WDAC/AppLocker | 0.20 | 0.80 |
| Network C2 detection | 0.30 | 0.70 |

**Empresa promedio:**

$$P(\text{Éxito del payload}) \approx 0.75 \times 0.85 \times 0.60 \times 0.80 \times 0.70 \approx 0.214 \quad (\approx 21.4\%)$$

**Entorno endurecido:**

$$P(\text{Éxito del payload}) \approx 0.15 \times 0.25 \times 0.15 \times 0.20 \times 0.30 \approx 0.000337 \quad (\approx 0.034\%)$$

**Con HVCI activo (la defensa más efectiva):**

$$P(\text{Éxito} \mid \text{HVCI}) \approx 0 \quad \text{(ejecución bloqueada en la transición RW→RX)}$$

---

## 13. Análisis de Variaciones y Mutaciones del Vector

### 13.1 Árbol de Decisiones del Atacante

```
¿HVCI/VBS está habilitado en el objetivo?
├── SÍ → Payload MEM_PRIVATE+RX es BLOQUEADO
│   ├── ¿Se puede explotar una vulnerabilidad de configuración?
│   │   ├── SÍ → Deshabilitar HVCI temporalmente → payload estándar
│   │   └── NO → Mutación necesaria:
│   │       ├── Opción A: Inyectar en proceso que ya tiene código ejecutable
│   │       ├── Opción B: Usar signed code abuse (binarios firmados)
│   │       ├── Opción C: Explotar vulnerabilidad del driver (bring your own vuln driver)
│   │       └── Opción D: Abandonar inyección, usar living-off-the-land exclusivamente
│   └── (HVCI es la defensa más efectiva contra payloads PIC)
│
└── NO (HVCI deshabilitado — la mayoría de entornos)
    ├── ¿EDR con kernel-mode detection?
    │   ├── SÍ → Payload con indirect syscalls + stack spoofing
    │   │   ├── ¿EDR con unwind validation?
    │   │   │   ├── SÍ → ROP-based spoofing o callback execution
    │   │   │   └── NO → Synthetic frames spoofing
    │   │   └── ¿EDR monitorea APC cross-process?
    │   │       ├── SÍ → NtCreateThreadEx con thread start disfrazado
    │   │       └── NO → NtQueueApcThread (más sigiloso)
    │   └── NO → Payload con direct syscalls (más simple)
    └── Configuración del payload:
        ├── ¿AMSI intercepta scripts?
        │   ├── SÍ → Payload en ASM puro (no pasa por AMSI)
        │   └── NO → Se puede usar PowerShell como capa intermedia
        └── ¿C2 necesario?
            ├── SÍ → COM/DCOM o HTTP/S sobre syscall directa
            └── NO → Payload autónomo (ejecuta y termina)
```

### 13.2 Mutaciones Documentadas

| Mutación | Mecanismo | Ventaja | Detección |
|---|---|---|---|
| **Signed Code Abuse** | Ejecutar binarios firmados por Microsoft con argumentos maliciosos | Bypassa HVCI (código firmado) | Análisis de argumentos |
| **BYOVD (Bring Your Own Vulnerable Driver)** | Cargar driver vulnerable legítimo para deshabilitar protecciones | Acceso Ring 0 | Detección de driver loading |
| **Callback Execution** | Usar `EnumSystemLocalesA` u otros callbacks como punto de entrada | Alternativa a APC/Thread | Callback monitoring |
| **Fiber Execution** | Usar `CreateFiber`/`SwitchToFiber` para cambiar contexto | Alternativa a Thread/APC | Fiber monitoring |
| **Module Stomping** | Cargar DLL legítima, sobrescribir su .text con payload | Página tiene respaldo en disco | .text integrity check |
| **Early Bird APC** | Inyectar APC antes de que el hilo comience a ejecutar | APC se ejecuta antes del EDR | Process creation + APC correlation |

### 13.3 Evolución Temporal

```
═══════════════════════════════════════════════════════════════════════════
         EVOLUCIÓN TEMPORAL DE TÉCNICAS DE EVASIÓN A NIVEL PAYLOAD
═══════════════════════════════════════════════════════════════════════════

  2013      2016       2019       2021       2023       2024+
   │         │          │          │          │          │
   ▼         ▼          ▼          ▼          ▼          ▼
  Standard   API       Direct     Indirect   Stack     Module
  shellcode  hashing   syscalls   syscalls   spoofing  stomping
  (Metasploit) (djb2)  (Hell's    (SysWhis-  (synthetic (DLL legit
                        Gate)      pers3)    frames)   overwrite)
   │         │          │          │          │          │
   ▼         ▼          ▼          ▼          ▼          ▼
  Sin       Evasión    Bypass     Bypass     Evasión   Bypass
  evasión   estática   hooks      caller     stack     HVCI
            solamente  de EDR     check      walk      (parcial)

  TENDENCIA: Cada iteración añade una capa de evasión que
  elimina una superficie de detección. La defensa más
  efectiva contra toda esta familia es HVCI/VBS, que
  opera a nivel del hypervisor y no puede ser eludida
  desde Ring 3.

═══════════════════════════════════════════════════════════════════════════
```

---

## 14. Referencias y Marco Normativo

### Evasión de Telemetría y Detección

- Ligh, M.H., Case, A., Levy, J., & Walters, A. (2014). *The Art of Memory Forensics*. Wiley.
- Halil Dalman, M. (2022). *"Hell's Gate: Dynamic Syscall Resolution."* GitHub.
- Rasta Mouse (2022). *"Halos Gate: Indirect Syscall with Dynamic SSN Resolution."*
- KlezVirus (2023). *"SysWhispers3: Advanced Syscall Generation."* GitHub.
- Outflank (2019). *"Red Team Tactics: Combining Direct Syscalls with SSEn Patching."*
- CyberArk Labs (2021). *"Stack Spoofing: Call Stack Anomalies."*

### Arquitectura x64 y Depuración

- Intel Corporation (2023). *Intel 64 and IA-32 Architectures Software Developer's Manual*, Volumes 2A-2D.
- AMD (2023). *AMD64 Architecture Programmer's Manual*, Volumes 1-5.
- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.

### Position Independent Code y Shellcode

- Skape (2004). *"Understanding Windows Shellcode."* Safemode.org.
- Miller, D. (2019). *"Shellcode: From a Dump to a Shell."* Black Hat USA.
- Offensive Security (2023). *Metasploit Framework: Shellcode Generation Reference.*

### Teoría de la Información y Detección

- Shannon, C.E. (1948). *"A Mathematical Theory of Communication."* Bell System Technical Journal.
- Cover, T.M. & Thomas, J.A. (2006). *Elements of Information Theory*, 2nd Edition. Wiley.
- Sommer, R. & Paxson, V. (2010). *"Outside the Closed World: On Using Machine Learning for Network Intrusion Detection."* IEEE S&P.

### HVCI, VBS y Protección a Nivel Hardware

- Microsoft (2024). *"Hypervisor-Enforced Code Integrity (HVCI)."* Microsoft Learn.
- Microsoft (2024). *"Virtualization-Based Security (VBS)."* Microsoft Learn.
- Intel (2023). *"Intel Virtualization Technology for Directed I/O (VT-d)."*

### MITRE ATT&CK

- MITRE ATT&CK (2024). *Technique T1055.004: Process Injection — Asynchronous Procedure Call.*
- MITRE ATT&CK (2024). *Technique T1562.001: Impair Defenses — Disable or Modify Tools.*
- MITRE ATT&CK (2024). *Technique T1620: Reflective Code Loading.*
- MITRE ATT&CK (2024). *Technique T1106: Native API.*

### Modelos Formales y Autómatas

- Hoare, C.A.R. (1985). *Communicating Sequential Processes*. Prentice Hall.
- Henzinger, T.A. (1996). *"The Theory of Hybrid Automata."* Proceedings of LICS'96.
- Pierce, B.C. (1991). *Basic Category Theory for Computer Scientists*. MIT Press.

---

*Documento de investigación técnica sobre el payload ASM en la Etapa 5 del vector de ataque compuesto de 5 etapas contra Windows 11. El análisis se limita a la descripción objetiva del fenómeno desde la perspectiva de la ciencia computacional, la teoría de la información y los modelos formales de seguridad, con el propósito de fundamentar mecanismos de detección y defensa.*
