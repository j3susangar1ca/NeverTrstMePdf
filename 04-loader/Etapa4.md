# Etapa 4 — El Cargador C++: Evasión de Telemetría y el Mecanismo APC

## Documentación Técnica de Nivel APT/Intelligence-Grade

### Análisis Formal de Resolución de APIs, Unhooking, ETW Patching, Indirect Syscalls, Inyección de Memoria, y el Mecanismo de Procedimientos Asíncronos del Kernel NT

---

## Índice

1. [Resumen Ejecutivo Clasificado](#1-resumen-ejecutivo)
2. [Marco Formal: El Cargador como Máquina de Estados de Evasión](#2-marco-formal)
3. [Resolución de la PEB: Grafo Acíclico de Resolución de Módulos](#3-resolucion-peb)
4. [Export Address Table y Resolución de APIs por Hash](#4-eat-resolucion)
5. [API Unhooking: Restauración de la Integridad de Código](#5-api-unhooking)
6. [ETW Patching: Supresión de la Función de Generación de Telemetría](#6-etw-patching)
7. [Indirect Syscalls: Redirección del Punto de Transición Ring 3→Ring 0](#7-indirect-syscalls)
8. [Gestión de Memoria: Allocación, Cifrado, Inyección y Cambio de Permisos](#8-gestion-memoria)
9. [El Mecanismo APC: Formalización en CSP y Teoría de Concurrencia](#9-mecanismo-apc)
10. [Especificación Formal de NtQueueApcThread y NtCreateThreadEx](#10-especificacion-syscalls)
11. [KAPC: Estructura Interna y Modelo Algebraico](#11-kapc-estructura)
12. [Comparación Formal de Métodos de Inyección](#12-comparacion-metodos)
13. [COM/DCOM como Superficie de Interacción con WMI y Persistencia](#13-com-dcom)
14. [Superficie de Detección: Predicados Multi-Capa y Correlación](#14-superficie-deteccion)
15. [Historial de Explotación APT y Contexto Operacional](#15-historial-apts)
16. [Contramedidas por Capa y Análisis de Efectividad](#16-contramedidas)
17. [Mutaciones y Evolución Post-Detección](#17-mutaciones)
18. [Referencias y Marco Normativo](#18-referencias)

---

## 1. Resumen Ejecutivo

La Etapa 4 constituye el **núcleo técnico del vector de ataque**, el punto donde el control sobre el sistema operativo se transfiere desde los binarios legítimos del host (Etapas 1-3) al código del atacante. Su función es triple: **preparar un entorno de ejecución "limpio"** desactivando los mecanismos de telemetría que el EDR utiliza para observar la actividad del proceso; **alojar el payload final** (ASM, Etapa 5) en memoria con los permisos adecuados; y **establecer el hilo o la cola APC** desde la cual el payload se ejecutará.

El cargador opera bajo una restricción fundamental: **todo su código debe residir dentro de un binario legítimo** (el proceso de PowerShell, cmd.exe, o rundll32 que la Etapa 3 invocó) y debe ejecutarse **antes de que el EDR procese la alerta** generada por la creación del proceso (ventana de oportunidad identificada en la Etapa 3: $L \in [1, 50]$ ms para suscripciones WMI, $L \in [10, 100]$ μs para callbacks ETW directos).

Las operaciones del cargador se descomponen en siete primitivas computacionales, cada una con una superficie de detección formalmente definida y un mecanismo de evasión correspondiente:

| Primitiva              | Función                               | Superficie de detección                    | Mecanismo de evasión                                         |
| ---------------------- | ------------------------------------- | ------------------------------------------ | ------------------------------------------------------------ |
| Resolución PEB         | Localizar ntdll.dll en memoria        | Accesos a PEB desde código no estándar     | Código embebido en sección legítima                          |
| Parseo EAT             | Resolver funciones por hash           | Strings de nombres de función              | Hashes embebidos, no strings                                 |
| API Unhooking          | Restaurar código original de ntdll    | Lectura de ntdll.dll desde disco           | Indirect syscalls para operaciones de lectura                |
| ETW Patching           | Deshabilitar generación de telemetría | Escritura en sección .text de ntdll        | Parcheo mínimo (bytes), verificación periódica de integridad |
| Indirect Syscalls      | Evitar hooks en puntos de transición  | Direcciones de retorno fuera de ntdll      | Saltos a gadgets dentro de ntdll                             |
| Gestión de Memoria     | Allocar, cifrar, escribir, proteger   | Transiciones RW→RX sin respaldo en disco   | Páginas con respaldo en section headers legítimos            |
| Inyección (APC/Thread) | Ejecutar payload en contexto adecuado | Creación de hilos, inyección cross-process | APC en hilo existente, thread context manipulation           |

---

## 2. Marco Formal: El Cargador como Máquina de Estados de Evasión

### 2.1 Definición de la Máquina de Estados

El cargador C++ se modela como un **autómata finito determinista con emisión** (Mealy machine):

$$\mathcal{M}_{loader} = (Q, \Sigma, \Gamma, \delta, \lambda, q_0)$$

donde:

- $Q = \{q_0, q_1, q_2, q_3, q_4, q_5, q_6, q_7, q_8, q_F\}$ es el conjunto de estados
- $\Sigma$ es el alfabeto de entrada (resultados de operaciones del sistema)
- $\Gamma$ es el alfabeto de salida (operaciones de evasión ejecutadas)
- $\delta: Q \times \Sigma \rightarrow Q$ es la función de transición
- $\lambda: Q \times \Sigma \rightarrow \Gamma$ es la función de emisión
- $q_0$ es el estado inicial

### 2.2 Diagrama de Estados del Cargador

```
═══════════════════════════════════════════════════════════════════
        AUTÓMATA DE ESTADOS DEL CARGADOR C++
═══════════════════════════════════════════════════════════════════

  q₀ ─────────────────────────────────────────────────────────→ q₁
  (Inicio)              Resolver PEB → ntdll base               │
                        Parsear DOS/NT headers                  │
                        Localizar Export Directory               │
                                                                ▼
  q₁ ─────────────────────────────────────────────────────────→ q₂
                        Resolver funciones por hash             │
                        NtAllocateVirtualMemory                 │
                        NtProtectVirtualMemory                  │
                        NtWriteVirtualMemory                    │
                        NtCreateThreadEx                        │
                        NtQueueApcThread                        │
                                                                ▼
  q₂ ─────────────────────────────────────────────────────────→ q₃
                        API Unhooking                           │
                        Leer ntdll.dll desde disco              │
                        Restaurar sección .text                 │
                                                                ▼
  q₃ ─────────────────────────────────────────────────────────→ q₄
                        ETW Patching                            │
                        Sobrescribir EtwEventWrite              │
                        mov eax, 0; ret                         │
                                                                ▼
  q₄ ─────────────────────────────────────────────────────────→ q₅
                        Configurar Indirect Syscalls             │
                        Resolver gadgets syscall;ret en ntdll   │
                        Preparar trampolín de salto              │
                                                                ▼
  q₅ ─────────────────────────────────────────────────────────→ q₆
                        Alloc RW memory (NtAllocateVirtualMemory)│
                        Descifrar payload ASM (AES/RC4)          │
                        Escribir payload (NtWriteVirtualMemory)  │
                                                                ▼
  q₆ ─────────────────────────────────────────────────────────→ q₇
                        Cambiar permisos RW → RX                │
                        (NtProtectVirtualMemory)                 │
                                                                ▼
  q₇ ─────────────────────────────────────────────────────────→ q₈
                        Inyección del payload                    │
                        ├── Opción A: NtCreateThreadEx           │
                        └── Opción B: NtQueueApcThread           │
                                                                ▼
  q₈ ─────────────────────────────────────────────────────────→ q_F
                        Limpieza de artefactos                   │
                        Liberación de buffers temporales         │
                        Retorno al código legítimo del host      │
                                                                ▼
  q_F (Fin: payload ejecutándose autónomamente)

═══════════════════════════════════════════════════════════════════
```

### 2.3 Especificación Formal de Transiciones

$$\delta(q_0, \text{PEB\_located}) = q_1 \quad \lambda(q_0, \text{PEB\_located}) = \text{ParseHeaders}$$

$$\delta(q_1, \text{APIs\_resolved}) = q_2 \quad \lambda(q_1, \text{APIs\_resolved}) = \text{HashMapLookup}$$

$$\delta(q_2, \text{ntdll\_restored}) = q_3 \quad \lambda(q_2, \text{ntdll\_restored}) = \text{OverwriteText}$$

$$\delta(q_3, \text{ETW\_patched}) = q_4 \quad \lambda(q_3, \text{ETW\_patched}) = \text{PatchEtwEventWrite}$$

$$\delta(q_4, \text{gadgets\_ready}) = q_5 \quad \lambda(q_4, \text{gadgets\_ready}) = \text{SetupTrampoline}$$

$$\delta(q_5, \text{memory\_written}) = q_6 \quad \lambda(q_5, \text{memory\_written}) = \text{DecryptAndWrite}$$

$$\delta(q_6, \text{perms\_changed}) = q_7 \quad \lambda(q_6, \text{perms\_changed}) = \text{SetRX}$$

$$\delta(q_7, \text{thread\_created}) = q_8 \quad \lambda(q_7, \text{thread\_created}) = \text{Inject}$$

$$\delta(q_8, \text{cleanup\_done}) = q_F \quad \lambda(q_8, \text{cleanup\_done}) = \text{ReleaseTempBuffers}$$

### 2.4 Invariantes del Cargador

**Invariante 1 — Integridad de la cadena:**

$$\forall\, i \in [0, 8]: \delta(q_i, \sigma_i) = q_{i+1} \Rightarrow \text{NoError}(\sigma_i)$$

Si cualquier operación falla (por ejemplo, `NtAllocateVirtualMemory` retorna un error), el cargador debe abortar sin dejar artefactos detectables.

**Invariante 2 — Sigilo temporal:**

$$\sum_{i=0}^{8} T(q_i \rightarrow q_{i+1}) < L_{detection}$$

El tiempo total de ejecución del cargador debe ser menor que la latencia de detección del EDR.

**Invariante 3 — Ausencia de artefactos persistentes:**

$$\nexists\, f \in \mathcal{F}_{disk}: \text{Created}(f) \wedge \text{Contains}(f, \text{payload})$$

El payload no debe residir en disco en ningún momento (o si lo hace, debe eliminarse antes de que el EDR lo inspeccione).

---

## 3. Resolución de la PEB: Grafo Acíclico de Resolución de Módulos

### 3.1 El Process Environment Block como Nodo Raíz

**Definición 3.1.1 — PEB como Nodo del Grafo de Resolución**

El Process Environment Block (PEB) es la estructura central del espacio de direcciones de un proceso en Windows NT. Es el nodo raíz de un **grafo dirigido acíclico** (DAG) de resolución de módulos:

$$G_{PEB} = (V, E_{resolve})$$

donde:

- $V = \{\text{PEB}, \text{PEB\_LDR\_DATA}, \text{LDR\_DATA\_TABLE\_ENTRY}_1, \ldots, \text{DllBase}, \text{ExportTable}\}$
- $E_{resolve}$ son las aristas de resolución de punteros entre nodos

### 3.2 Cadena de Resolución Arquitectónica

El PEB es accesible vía un registro arquitectónico dependiente de la arquitectura:

| Arquitectura | Registro | Offset | Expresión            |
| ------------ | -------- | ------ | -------------------- |
| x86          | FS       | 0x30   | `mov eax, fs:[0x30]` |
| x64          | GS       | 0x60   | `mov rax, gs:[0x60]` |

**La cadena completa de resolución en x64 se expresa como una composición de funciones de acceso:**

$$\text{Resolve}: \text{ArchReg} \xrightarrow{\text{offset}} \text{PEB} \xrightarrow{+0x18} \text{Ldr} \xrightarrow{+0x20} \text{InMemoryOrderModuleList} \xrightarrow{\text{walk}} \text{DllBase}$$

### 3.3 Estructuras de Datos Involucradas

#### 3.3.1 PEB (Process Environment Block)

```
PEB (x64, parcial):
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size  Field                                         │
│ 0x00    1     InheritedAddressSpace                         │
│ 0x01    1     ReadImageFileExecOptions                      │
│ 0x02    1     BeingDebugged                                 │  ← Anti-debug check
│ 0x03    1     BitField                                      │
│ 0x08    8     Mutant                                        │
│ 0x10    8     ImageBaseAddress                              │  ← Base del PE principal
│ 0x18    8     Ldr → PEB_LDR_DATA*                          │  ← CRÍTICO: cadena de módulos
│ 0x20    8     ProcessParameters → RTL_USER_PROCESS_PARAMETERS*
│ ...     ...   ...                                           │
│ 0x60    1     AnsiCodePageData (o campo adicional)          │
│ ...     ...   ...                                           │
│ 0xE0    8     ApiSetMap → API_SET_NAMESPACE*                │
│ ...     ...   ...                                           │
│ 0x108   1     IsProtectedProcess                            │
│ 0x109   1     IsDynamicCodePolicyAllowed                    │  ← HVCI check
│ 0x10A   1     IsAppContainer                               │
└─────────────────────────────────────────────────────────────┘
```

#### 3.3.2 PEB_LDR_DATA

```
PEB_LDR_DATA:
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size  Field                                         │
│ 0x00    4     Length                                        │
│ 0x04    1     Initialized                                   │
│ 0x08    8     SsHandle                                      │
│ 0x10    16    InLoadOrderModuleList (LIST_ENTRY)             │  ← Lista enlazada
│ 0x20    16    InMemoryOrderModuleList (LIST_ENTRY)           │  ← CRÍTICO
│ 0x30    16    InInitializationOrderModuleList (LIST_ENTRY)   │
│ 0x40    1     EntryInProgress                               │
└─────────────────────────────────────────────────────────────┘
```

#### 3.3.3 LDR_DATA_TABLE_ENTRY

```
LDR_DATA_TABLE_ENTRY (una entrada por DLL cargada):
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size  Field                                         │
│ 0x00    16    InLoadOrderLinks (LIST_ENTRY)                  │
│ 0x10    16    InMemoryOrderLinks (LIST_ENTRY)                │
│ 0x20    16    InInitializationOrderLinks (LIST_ENTRY)        │
│ 0x30    8     DllBase → PVOID                               │  ← CRÍTICO: base address
│ 0x38    8     EntryPoint → PVOID                             │
│ 0x40    4     SizeOfImage                                    │
│ 0x44    80    FullDllName (UNICODE_STRING)                   │
│ 0x94    80    BaseDllName (UNICODE_STRING)                   │  ← "ntdll.dll"
│ ...     ...   ...                                           │
└─────────────────────────────────────────────────────────────┘
```

### 3.4 Algoritmo de Resolución de Módulo

**Algoritmo 3.4.1 — Resolución de Base de ntdll.dll**

```
ENTRADA: Ninguna (usa registro arquitectónico)
SALIDA: Base address de ntdll.dll (PVOID)

1.  rax ← gs:[0x60]                    // PEB address
2.  rax ← [rax + 0x18]                 // PEB->Ldr
3.  rdi ← [rax + 0x20]                 // Ldr->InMemoryOrderModuleList.Flink
4.  INICIO BUCLE:
5.    rsi ← rdi                         // Guardar puntero actual
6.    rax ← [rdi + 0x50]               // Entry->BaseDllName.Buffer (UNICODE_STRING.Buffer)
7.    // Comparar hash del nombre con hash("ntdll.dll")
8.    hash_actual ← FNV1a(rax)
9.    SI hash_actual == HASH_NTDLL:
10.     RETORNA [rdi + 0x30]            // Entry->DllBase
11.   FIN SI
12.   rdi ← [rdi + 0x10]               // Entry->InMemoryOrderLinks.Flink (siguiente)
13.   SI rdi == rsi:                    // Vuelta completa (lista circular)
14.     RETORNA ERROR
15.   FIN SI
16.   IR A INICIO BUCLE
```

**Formalización como recorrido de lista enlazada circular:**

Sea $L = (e_0, e_1, \ldots, e_{n-1})$ la lista circular de `LDR_DATA_TABLE_ENTRY` donde $e_{i+1} = e_i.\text{InMemoryOrderLinks.Flink}$ y $e_0 = e_{n-1}.\text{InMemoryOrderLinks.Flink}$ (circularidad). El algoritmo realiza un **búsqueda lineal con criterio de hash**:

$$\text{FindModule}(L, h_{target}) = e_k \quad \text{donde } k = \min\{i : h(\text{BaseDllName}(e_i)) = h_{target}\}$$

La complejidad es $O(n)$ donde $n$ es el número de DLLs cargadas (típicamente 30-80 en un proceso de Windows 11).

### 3.5 Diagrama del Grafo de Resolución

```
═══════════════════════════════════════════════════════════════════
              GRAFO DE RESOLUCIÓN PEB (x64)
═══════════════════════════════════════════════════════════════════

  gs:[0x60]
      │
      ▼
  ┌───────────┐     +0x18     ┌──────────────────┐
  │    PEB    │──────────────→│  PEB_LDR_DATA    │
  │           │               │                  │
  │ .Ldr ────│               │ .InMemoryOrder   │
  │ .ProcessP.│               │  ModuleList      │
  │ .BeingDbg.│               │  (LIST_ENTRY)    │
  └───────────┘               └────────┬─────────┘
                                       │ +0x20
                                       ▼
                    ┌──────────────────────────────────────┐
                    │     InMemoryOrderModuleList           │
                    │     (lista circular doblemente        │
                    │      enlazada)                        │
                    │                                       │
                    │  ┌──────┐  ┌──────┐  ┌──────┐       │
                    └──┤ENTRY1├──┤ENTRY2├──┤ENTRY3├───────┘
                       │ntdll │  │kernel│  │ ...  │
                       │.dll  │  │32.dll│       │
                       │      │  │      │       │
                       │DllBase│ │DllBase│       │
                       │=0x7FF │  │=0x7FF│       │
                       └──┬───┘  └──┬───┘  └──────┘
                          │         │
                          ▼         ▼
                    ┌──────────────────────────────────────┐
                    │     PE Header Parse                   │
                    │                                       │
                    │  DOS Header                           │
                    │    └→ e_lfanew ──→ NT Headers         │
                    │                      │                │
                    │                      ▼                │
                    │              Optional Header           │
                    │                      │                │
                    │                      ▼                │
                    │          DataDirectory[0]              │
                    │          (Export Directory)            │
                    │                      │                │
                    │                      ▼                │
                    │          Export Directory Table        │
                    │          ┌──────────────────────┐     │
                    │          │ NumberOfFunctions    │     │
                    │          │ NumberOfNames        │     │
                    │          │ AddressOfFunctions[] │     │
                    │          │ AddressOfNames[]     │──→ Func names
                    │          │ AddressOfNameOrdinals[] │  → RVA mapping
                    │          └──────────────────────┘     │
                    └──────────────────────────────────────┘
                          │
                          ▼
                    Resolución por hash:
                    FNV1a("NtAllocateVirtualMemory") == HASH_TARGET?
                          │
                          ▼
                    Función resuelta: dirección en memoria

═══════════════════════════════════════════════════════════════════
```

### 3.6 Detección de la Resolución PEB

**Señal de detección:** Un código que accede a `gs:[0x60]` (PEB) directamente, sin pasar por `kernel32!GetModuleHandle` o `kernel32!LoadLibrary`, es inusual en código legítimo compilado con herramientas estándar. La detección se basa en:

$$\text{SuspiciousPEBAccess}(code) \iff \exists\, instr \in code: instr.\text{operand} = \text{gs:[0x60]} \wedge \text{NotFromStandardCRT}(code)$$

**Limitación de la detección:** Esta señal es difícil de detectar en tiempo real porque los accesos al PEB ocurren dentro del proceso objetivo y no generan eventos ETW. Solo es detectable mediante análisis estático del código inyectado o monitoring de las operaciones que se realizan **después** de la resolución.

---

## 4. Export Address Table y Resolución de APIs por Hash

### 4.1 Estructura de la Export Directory

**Definición 4.1.1 — Export Directory Table**

La Export Directory Table del PE define la tabla de exportaciones de un módulo:

```
Export Directory Table:
┌─────────────────────────────────────────────────────────────┐
│ Offset  Size  Field                                         │
│ 0x00    4     Export Flags (0 para archivo, no resource)     │
│ 0x04    4     TimeDateStamp                                  │
│ 0x08    2     MajorVersion                                   │
│ 0x0A    2     MinorVersion                                   │
│ 0x0C    4     Name RVA → puntero al nombre del módulo       │
│ 0x10    4     OrdinalBase                                    │
│ 0x14    4     NumberOfFunctions                              │
│ 0x18    4     NumberOfNames                                  │
│ 0x1C    4     AddressOfFunctions RVA                         │
│ 0x20    4     AddressOfNames RVA                             │
│ 0x24    4     AddressOfNameOrdinals RVA                      │
└─────────────────────────────────────────────────────────────┘
```

**Las tres tablas de exportación:**

| Tabla                   | Contenido                                                        | Indexación           |
| ----------------------- | ---------------------------------------------------------------- | -------------------- |
| `AddressOfFunctions`    | Array de RVAs (Relative Virtual Addresses) a las funciones       | Por ordinal          |
| `AddressOfNames`        | Array de RVAs a los nombres de función (null-terminated strings) | Por índice de nombre |
| `AddressOfNameOrdinals` | Array de WORDs: mapeo nombre→ordinal                             | Por índice de nombre |

### 4.2 Algoritmo de Resolución por Hash

**Algoritmo 4.2.1 — Resolución de Función por Hash FNV-1a**

```
ENTRADA: Base del módulo (PVOID), hash objetivo (DWORD)
SALIDA: Dirección de la función (PVOID) o NULL

1.  Parsear DOS Header → NT Headers → Optional Header
2.  ExportDir ← OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
3.  NumNames ← ExportDir.NumberOfNames
4.  NamesRVA ← ExportDir.AddressOfNames
5.  OrdinalsRVA ← ExportDir.AddressOfNameOrdinals
6.  FuncsRVA ← ExportDir.AddressOfFunctions
7.
8.  PARA i = 0 HASTA NumNames - 1:
9.    NameRVA ← *(DWORD*)(Base + NamesRVA + i*4)
10.   NamePtr ← Base + NameRVA
11.   HashActual ← FNV1a(NamePtr)
12.
13.   SI HashActual == HashObjetivo:
14.     Ordinal ← *(WORD*)(Base + OrdinalsRVA + i*2)
15.     FuncRVA ← *(DWORD*)(Base + FuncsRVA + Ordinal*4)
16.     RETORNA Base + FuncRVA
17.   FIN SI
18. FIN PARA
19. RETORNA NULL
```

### 4.3 Función de Hash FNV-1a

**Definición 4.3.1 — FNV-1a 32-bit**

$$h_{FNV1a}(s) = \bigoplus_{n=0}^{|s|-1} \left( h_{n-1} \oplus s[n] \right) \times p$$

donde:

- $h_{-1} = \text{offset\_basis} = 2166136261$ (0x811c9dc5)
- $p = \text{FNV\_prime} = 16777619$ (0x01000193)
- $\oplus$ denota XOR bit a bit
- $\times$ denota multiplicación modular ($\mod 2^{32}$)

**Propiedades:**

- **Determinística:** $h(s_1) = h(s_2) \Rightarrow s_1 = s_2$ NO se cumple (no es inyectiva)
- **Colisiones:** Existen pares $(s_1, s_2)$ tales que $h(s_1) = h(s_2) \wedge s_1 \neq s_2$
- **Riesgo:** Un hash colisionante causaría resolución errónea de la función → crash del proceso

**Probabilidad de colisión para $n$ funciones resueltas:**

Sea $m = 2^{32}$ el espacio de hash. Usando la aproximación del cumpleaños:

$$P(\text{colisión}) \approx 1 - e^{-n^2 / (2m)}$$

Para $n = 20$ funciones:

$$P(\text{colisión}) \approx 1 - e^{-400 / (2 \times 2^{32})} \approx 1 - e^{-4.66 \times 10^{-8}} \approx 4.66 \times 10^{-8}$$

Extremadamente bajo, pero no cero. Los cargadores robustos implementan verificación de nombre post-resolución como salvaguarda.

### 4.4 Pre-resolución: El Set de Funciones Requeridas

El cargador necesita resolver un conjunto mínimo de funciones de `ntdll.dll` para completar todas sus operaciones:

**Definición 4.4.1 — Conjunto de Funciones Requeridas**

$$\mathcal{F}_{req} = \{f_1, f_2, \ldots, f_k\} \subset \text{Exports}(\text{ntdll.dll})$$

| Función                    | Uso en el cargador                                    | Syscall number (Win11 23H2) |
| -------------------------- | ----------------------------------------------------- | --------------------------- |
| `NtAllocateVirtualMemory`  | Allocar bloque RW para el payload                     | 0x18                        |
| `NtWriteVirtualMemory`     | Escribir el payload descifrado en la memoria allocada | 0x3A                        |
| `NtProtectVirtualMemory`   | Cambiar permisos de RW a RX                           | 0x50                        |
| `NtCreateThreadEx`         | Crear hilo que ejecute el payload                     | 0xC1                        |
| `NtQueueApcThread`         | Encolar APC para ejecución del payload                | 0x04                        |
| `NtClose`                  | Cerrar handles temporales                             | 0x0F                        |
| `NtCreateFile`             | Abrir ntdll.dll en disco para unhooking               | 0x55                        |
| `NtReadFile`               | Leer sección .text original desde disco               | 0x06                        |
| `NtOpenProcess`            | Abrir proceso objetivo (para inyección cross-process) | 0x26                        |
| `NtOpenThread`             | Abrir hilo objetivo (para APC injection)              | 0x07                        |
| `NtFreeVirtualMemory`      | Liberar memoria temporal                              | 0x1B                        |
| `NtQuerySystemInformation` | Consultar información del sistema (anti-debug)        | 0x36                        |

**Formalización como operación de resolución:**

$$\text{Resolve}: \mathcal{F}_{req} \times \text{Base}(\text{ntdll}) \rightarrow (\mathcal{F}_{req} \rightarrow \text{PVOID})$$

$$\text{Resolve}(\mathcal{F}_{req}, base) = \{f \mapsto \text{LookupEAT}(base, h_{FNV1a}(f)) \mid f \in \mathcal{F}_{req}\}$$

### 4.5 Detección por Strings de Nombres

**Superficie de detección:** Un binario que contiene strings como "NtAllocateVirtualMemory", "NtWriteVirtualMemory", etc. es inmediatamente sospechoso. Los cargadores evitan esto de dos maneras:

1. **Hashes embebidos:** En lugar de strings, el binario contiene los hashes FNV-1a precalculados (4 bytes cada uno)
2. **Decodificación en tiempo de ejecución:** Los nombres se reconstruyen a partir de fragments cifrados

**Formalización de la detección:**

$$\text{Suspicious}(binary) \iff \exists\, s \in \text{Strings}(binary): s \in \mathcal{N}_{suspicious}$$

$$\mathcal{N}_{suspicious} = \{"NtAllocate", "NtWrite", "NtProtect", "NtCreateThread", "NtQueueApc", \ldots\}$$

**Con hashes embebidos:**

$$\text{Suspicious}(binary) \iff \exists\, h \in \text{Dwords}(binary): h \in \mathcal{H}_{suspicious}$$

$$\mathcal{H}_{suspicious} = \{h_{FNV1a}(f) \mid f \in \mathcal{N}_{suspicious}\}$$

La detección basada en hashes tiene mayor tasa de FP (muchos valores DWORD de 4 bytes aparecen legítimamente en binarios) pero es más difícil de evadir que la detección basada en strings.

---

## 5. API Unhooking: Restauración de la Integridad de Código

### 5.1 Modelo de Hooks del EDR

**Definición 5.1.1 — Hook como Transformación Local**

Sea $\mu_{orig}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo original de la sección `.text` de `ntdll.dll` (como está en disco), y $\mu_{hooked}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo modificado por el EDR en memoria. Para una función $f$ con punto de entrada en la dirección $f_{entry}$:

$$\mu_{hooked}(f_{entry}) = \underbrace{\text{jmp}\; \text{EDR\_handler}}_{\text{5-14 bytes}} \; \| \; \underbrace{\mu_{orig}(f_{entry} + k)[k+1..]}_{\text{resto de la función}}$$

donde $k$ es el número de bytes sobrescritos por el trampolín del hook.

### 5.2 Tipos de Hooks Observados en EDRs de Producción

| Tipo de Hook                 | Mecanismo                                            | Tamaño                       | EDRs que lo usan           |
| ---------------------------- | ---------------------------------------------------- | ---------------------------- | -------------------------- |
| **Inline hook (JMP)**        | Sobrescribir primeras instrucciones con `jmp rel32`  | 5 bytes                      | CrowdStrike, SentinelOne   |
| **Inline hook (JMP + NOP)**  | JMP con NOP padding para alineación                  | 5-14 bytes                   | Carbon Black, Cylance      |
| **Trampoline hook**          | JMP a stub que preserva registros y salta al handler | 14+ bytes                    | Symantec, McAfee           |
| **IAT hook**                 | Modificar Import Address Table entry                 | 8 bytes (puntero)            | Algunos AVs legacy         |
| **EAT hook**                 | Modificar Export Address Table entry                 | 4-8 bytes (RVA)              | Raramente usado            |
| **Hardware breakpoint hook** | Usar registros DR0-DR3                               | 0 bytes (no modifica código) | EDRs avanzados, anti-debug |
| **Syscall hook (kernel)**    | Interceptar en la transición Ring 0                  | Variable                     | EDRs con componente kernel |

### 5.3 Diagrama del Estado del Código: Original vs. Hookeado vs. Restaurado

```
═══════════════════════════════════════════════════════════════════
        TRES ESTADOS DE NtAllocateVirtualMemory EN MEMORIA
═══════════════════════════════════════════════════════════════════

ESTADO 1: ORIGINAL (en disco, C:\Windows\System32\ntdll.dll)
┌─────────────────────────────────────────────────────────────────┐
│ 0x0000: 4C 8B D1                │ mov r10, rcx                  │
│ 0x0003: B8 18 00 00 00          │ mov eax, 0x18                 │
│ 0x0008: F6 04 25 08 03 FE 7F 01│ test byte ptr [7FFE0308h], 1  │
│ 0x0010: 75 03                   │ jne +3                        │
│ 0x0012: 0F 05                   │ syscall                       │
│ 0x0014: C3                      │ ret                           │
│ 0x0015: CD 2E                   │ int 2Eh                       │
│ 0x0017: C3                      │ ret                           │
└─────────────────────────────────────────────────────────────────┘

ESTADO 2: HOOKEADO (en memoria, por EDR)
┌─────────────────────────────────────────────────────────────────┐
│ 0x0000: E9 XX XX XX XX          │ jmp rel32 → EDR handler       │
│ 0x0005: [bytes sobrescritos]    │ (código original destruido)   │
│ 0x0008: ...                     │                               │
│ 0x0012: 0F 05                   │ syscall (intacto)             │
│ 0x0014: C3                      │ ret                           │
└─────────────────────────────────────────────────────────────────┘
  Observación: Los bytes 0x0000-0x0004 han sido sobrescritos
               Los bytes 0x0005+ pueden estar parcialmente dañados
               El syscall (0x0012) y ret (0x0014) permanecen intactos

ESTADO 3: RESTAURADO (por el cargador, después de unhooking)
┌─────────────────────────────────────────────────────────────────┐
│ 0x0000: 4C 8B D1                │ mov r10, rcx (restaurado)     │
│ 0x0003: B8 18 00 00 00          │ mov eax, 0x18 (restaurado)    │
│ 0x0008: F6 04 25 08 03 FE 7F 01│ test ... (restaurado)         │
│ 0x0010: 75 03                   │ jne +3 (restaurado)           │
│ 0x0012: 0F 05                   │ syscall (original)            │
│ 0x0014: C3                      │ ret                           │
│ 0x0015: CD 2E                   │ int 2Eh (restaurado)          │
│ 0x0017: C3                      │ ret                           │
└─────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 5.4 Algoritmo de Unhooking

**Algoritmo 5.4.1 — Restauración de la Sección .text**

```
ENTRADA: Base de ntdll.dll en memoria (PVOID)
SALIDA: Sección .text restaurada a estado original

1.  // Abrir ntdll.dll en disco (vía indirect syscall)
2.  hFile ← NtOpenFile("\\??\\C:\\Windows\\System32\\ntdll.dll",
3.                       GENERIC_READ, FILE_SHARE_READ)
4.
5.  // Obtener tamaño del archivo
6.  IoStatusBlock info;
7.  NtQueryInformationFile(hFile, &info, &fileInfo, sizeof(fileInfo),
8.                          FileStandardInformation)
9.  fileSize ← fileInfo.EndOfFile.LowPart
10.
11. // Allocar buffer temporal para el archivo
12. NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0,
13.                         &fileSize, MEM_COMMIT, PAGE_READWRITE)
14.
15. // Leer archivo completo en buffer
16. NtReadFile(hFile, NULL, NULL, NULL, &ioStatus,
17.            buffer, fileSize, NULL, NULL)
18.
19. // Parsear PE headers del archivo en buffer
20. dosHeader ← (PIMAGE_DOS_HEADER)buffer
21. ntHeaders ← (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew)
22. sectionHeaders ← IMAGE_FIRST_SECTION(ntHeaders)
23.
24. // Localizar sección .text
25. PARA cada section EN sectionHeaders:
26.   SI section.Name == ".text":
27.     textDiskOffset ← buffer + section.PointerToRawData
28.     textMemOffset  ← base + section.VirtualAddress
29.     textSize       ← section.SizeOfRawData
30.     SALIR DEL BUCLE
31.   FIN SI
32. FIN PARA
33.
34. // Cambiar protección de .text a RW temporalmente
35. oldProtect;
36. NtProtectVirtualMemory(NtCurrentProcess(), &textMemOffset,
37.                        &textSize, PAGE_READWRITE, &oldProtect)
38.
39. // Copiar .text original desde disco a memoria
40. memcpy(textMemOffset, textDiskOffset, textSize)
41.
42. // Restaurar protección original (RX)
43. NtProtectVirtualMemory(NtCurrentProcess(), &textMemOffset,
44.                        &textSize, oldProtect, &oldProtect)
45.
46. // Limpiar
47. NtClose(hFile)
48. NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &fileSize, MEM_RELEASE)
```

### 5.5 Análisis de Superficie de Ataque del Unhooking

**Operaciones que genera el unhooking y sus superficies de detección:**

| Operación                   | Syscall involucrado           | Señal de detección                                                                            | Dificultad de detección                       |
| --------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Abrir ntdll.dll en disco    | `NtCreateFile` / `NtOpenFile` | Minifilter: `IRP_MJ_READ` de ntdll.dll por proceso que ya lo tiene cargado                    | Media (ruidoso: muchas lecturas legítimas)    |
| Leer contenido del archivo  | `NtReadFile`                  | Monitoreo de volumen de lectura desde ntdll.dll                                               | Alta (distinguible de lecturas normales)      |
| Cambiar protección de .text | `NtProtectVirtualMemory`      | ETW: cambio de protección sobre sección .text de ntdll                                        | **Alta** (operación rara en código legítimo)  |
| Escribir en .text           | `memcpy` (user-mode)          | No genera syscall directo, pero la escritura es visible por monitoreo de integridad de código | **Alta** (EDR puede verificar periódicamente) |
| Restaurar protección        | `NtProtectVirtualMemory`      | Misma señal que arriba                                                                        | **Alta**                                      |

**Teorema 5.5.1 — Dificultad de Detección del Unhooking**

_El unhooking es la operación más detectable del cargador, ya que requiere tres operaciones de syscall (`NtCreateFile`, `NtProtectVirtualMemory` × 2) que, en combinación, son altamente anómalas:_

$$\text{SuspiciousUnhooking}(p) \iff \text{Reads}(p, \text{ntdll.dll}) \wedge \text{Modifies}(p, \text{ntdll}.text)$$

$$\wedge\; \text{HasLoaded}(p, \text{ntdll.dll})$$

_La probabilidad de que un proceso legítimo lea ntdll.dll desde disco y luego modifique su sección .text es prácticamente cero._

### 5.6 Variantes de Unhooking

**Variante 1 — Unhooking parcial:**

Solo restaurar las primeras instrucciones de las funciones que se van a usar, no toda la sección .text. Reduce la superficie de operaciones pero requiere identificar exactamente qué funciones están hookeadas.

**Variante 2 — Unhooking selectivo por syscall:**

Para cada función necesaria, leer solo los primeros $k$ bytes (el trampolín del hook) y restaurarlos individualmente.

**Variante 3 — Unhooking desde sección .text de disco mapeada:**

En lugar de leer el archivo completo, mapear ntdll.dll como una sección de memoria (`NtCreateSection` + `NtMapViewOfSection`) y copiar la sección .text desde el mapeo. Esto evita `NtReadFile` pero usa `NtCreateSection`, que también es monitoreable.

**Variante 4 — No unhook (direct syscalls):**

El enfoque más sofisticado: **no restaurar ntdll.dll en absoluto**, y en su lugar usar indirect syscalls que saltan directamente al `syscall; ret` gadget dentro de ntdll, evitando los hooks enteramente. Esto se describe en detalle en la Sección 7.

---

## 6. ETW Patching: Supresión de la Función de Generación de Telemetría

### 6.1 Event Tracing for Windows: Arquitectura Formal

**Definición 6.1.1 — Función de Generación ETW**

ETW implementa una función de generación de eventos desde el espacio de usuario:

$$G_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \text{EventRecord}$$

La función central es `EtwEventWrite` en `ntdll.dll`, que es el punto de entrada para la mayoría de los eventos ETW desde el espacio de usuario.

### 6.2 El Mecanismo de Parcheo

**Definición 6.2.1 — Parcheo de EtwEventWrite**

El ETW patching reemplaza las primeras instrucciones de `EtwEventWrite` con un stub que retorna `STATUS_SUCCESS` inmediatamente:

**Antes del parcheo:**

```
EtwEventWrite:
  0x0000: 4C 8B DC              │ mov r11, rsp
  0x0003: 49 89 5B 08           │ mov [r11+8], rbx
  0x0007: 49 89 6B 10           │ mov [r11+10h], rbp
  0x000B: 49 89 73 18           │ mov [r11+18h], rsi
  0x000F: ...                   │ (continúa)
```

**Después del parcheo:**

```
EtwEventWrite:
  0x0000: 33 C0                 │ xor eax, eax    ; eax = 0 (STATUS_SUCCESS)
  0x0002: C3                    │ ret             ; retorno inmediato
  0x0003: 90                    │ nop             ; relleno
  0x0004: 90                    │ nop
  0x0005: 90                    │ nop
  0x0006: 90                    │ nop
  0x0007: ...                   │ (código original intacto pero inalcanzable)
```

**Solo 3 bytes necesitan ser modificados:** `33 C0 C3` (xor eax,eax; ret).

**Formalización:**

$$G'_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \emptyset$$

$$G'_{ETW}(\ldots) = \text{STATUS\_SUCCESS} \quad \text{(sin generar EventRecord)}$$

### 6.3 Impacto en el Motor de Eventos WMI

**Definición 6.3.1 — Partición del Espacio de Eventos**

Recordemos que el espacio de eventos se particiona:

$$E = E_{intrinsic} \uplus E_{extrinsic}$$

donde $E_{extrinsic}$ depende de ETW para su generación. El ETW patching elimina $E_{extrinsic}$:

$$E' = E_{intrinsic}$$

**Impacto en el autómata híbrido $\mathcal{A}_H$:**

El autómata pierde transiciones. Las funciones de transición $\delta(s, e)$ quedan indefinidas para todo $e \in E_{extrinsic}$:

$$\forall\, e \in E_{extrinsic}, \forall\, s \in S: \delta(s, e) = \text{undefined}$$

El autómata se **congela parcialmente**: solo responde a eventos intrínsecos (CRUD sobre el repositorio CIM).

### 6.4 Eventos Afectados por el ETW Patching

| Evento                          | Tipo      | Depende de ETW | Afectado por patch     |
| ------------------------------- | --------- | -------------- | ---------------------- |
| `Win32_ProcessStartTrace`       | Extrinsic | Sí             | **Sí — no se genera**  |
| `Win32_ProcessStopTrace`        | Extrinsic | Sí             | **Sí — no se genera**  |
| `Win32_ThreadStartTrace`        | Extrinsic | Sí             | **Sí — no se genera**  |
| `Win32_ModuleLoadTrace`         | Extrinsic | Sí             | **Sí — no se genera**  |
| `__InstanceCreationEvent` (CIM) | Intrinsic | No             | No — sigue funcionando |
| ETW Security Events             | Extrinsic | Sí             | **Sí — no se generan** |
| Sysmon Events                   | Extrinsic | Sí             | **Sí — no se generan** |

**Consecuencia crítica:** Los EDRs que dependen de ETW para monitorear la creación de procesos, carga de módulos, y actividad de hilos pierden **toda visibilidad** sobre el proceso del atacante después del parcheo.

### 6.5 Diagrama del Impacto del ETW Patching

```
═══════════════════════════════════════════════════════════════════
        IMPACTO DEL ETW PATCHING EN EL AUTÓMATA WQL
═══════════════════════════════════════════════════════════════════

ANTES DEL PATCH:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  E = E_intrinsic ⊎ E_extrinsic                                  │
│                                                                 │
│  s₀ ──δ(s₀,e₁)──→ s₁ ──δ(s₁,e₂)──→ s₂ ──δ(s₂,e₃)──→ s₃    │
│        e₁∈E_int       e₂∈E_ext       e₃∈E_int                  │
│                                                                 │
│  El autómata transiciona con eventos de ambos tipos             │
│  Win32_ProcessStartTrace → GENERADO ✓                           │
│  Sysmon ProcessCreate → GENERADO ✓                              │
│  ETW Security Events → GENERADOS ✓                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

DESPUÉS DEL PATCH:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  E' = E_intrinsic  (E_extrinsic eliminado)                      │
│                                                                 │
│  s₀ ──δ(s₀,e₁)──→ s₁ ──✕──→ s₁ ──δ(s₁,e₃)──→ s₂            │
│        e₁∈E_int       e₂∉E'       e₃∈E_int                     │
│                      (transición                                │
│                       bloqueada)                                │
│                                                                 │
│  El autómata solo transiciona con eventos intrínsecos           │
│  Win32_ProcessStartTrace → NO GENERADO ✗                        │
│  Sysmon ProcessCreate → NO GENERADO ✗                           │
│  __InstanceCreationEvent → SOLO si es CRUD sobre CIM ✓          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

FORMALMENTE:
  G'_ETW = ∅    ⟹   ∀e ∈ E_extrinsic: G(e) = false
                  ⟹   ∀s ∈ S, e ∈ E_extrinsic: δ(s,e) indefinida
                  ⟹   Σ_WQL opera con información incompleta
                  ⟹   El EDR es parcialmente ciego

═══════════════════════════════════════════════════════════════════
```

### 6.6 Detección del ETW Patching

**Predicado de detección:**

$$\text{ETWPatched}(p) \iff \mu_{mem}(\text{EtwEventWrite}_{entry}) \neq \mu_{disk}(\text{EtwEventWrite}_{entry})$$

donde $\mu_{mem}$ es el contenido en memoria y $\mu_{disk}$ es el contenido original en disco.

**Mecanismos de detección:**

1. **Verificación periódica de integridad:** El propio EDR puede verificar periódicamente los primeros bytes de `EtwEventWrite` contra una copia conocida del original.

2. **ETW desde kernel mode:** Los eventos ETW que se generan desde el kernel (a través de callbacks de kernel providers) no pasan por `EtwEventWrite` en el espacio de usuario y, por lo tanto, no son afectados por el parcheo. Los EDRs con componente kernel pueden usar estos eventos como alternativa.

3. **Verificación de consistencia:** Un proceso que genera eventos ETW (por ejemplo, `__InstanceCreationEvent` intrínsecos) pero no genera eventos ETW extrínsecos correspondientes (como `Win32_ProcessStartTrace`) presenta una **inconsistencia detectable**:

$$\text{Inconsistency}(p) \iff \exists\, e_{intrinsic} \in E_{intrinsic} : e_{intrinsic} \text{ implica } e_{extrinsic} \in E_{extrinsic}$$

$$\wedge\; \neg\text{Exists}(e_{extrinsic})$$

---

## 7. Indirect Syscalls: Redirección del Punto de Transición Ring 3→Ring 0

### 7.1 Definición Formal

**Definición 7.1.1 — Syscall Directo**

Un **syscall directo** ejecuta la instrucción `syscall` desde una dirección fuera de `ntdll.dll`:

$$\text{DirectSyscall}: \text{Addr}_{syscall} \notin \text{Range}(\text{ntdll.dll})$$

**Definición 7.1.2 — Syscall Indirecto**

Un **syscall indirecto** lee la dirección de la instrucción `syscall; ret` desde dentro de `ntdll.dll` y salta a ella:

$$\text{IndirectSyscall}: \text{Addr}_{syscall} \in \text{Range}(\text{ntdll.dll}) \wedge \text{Addr}_{entry} \notin \text{Range}(\text{ntdll.dll})$$

### 7.2 Diagrama Comparativo

```
═══════════════════════════════════════════════════════════════════
     COMPARACIÓN: SYSCALL DIRECTO vs. INDIRECTO vs. NORMAL
═══════════════════════════════════════════════════════════════════

MÉTODO NORMAL (vía ntdll hookeado):
┌────────────┐         ┌──────────────────────────────┐
│ User Code  │────────→│ ntdll!NtAllocateVirtualMemory│
│            │         │   0x0000: jmp EDR_handler    │← Hook intercepta
│            │         │   ...                        │
│            │         │   0x0012: syscall             │
│            │         │   0x0014: ret                │
└────────────┘         └──────────────────────────────┘
  Stack: [user_code, ntdll!NtAlloc...+0]
  Detección EDR: ✓ (EDR intercepta en el jmp)

SYSCALL DIRECTO:
┌────────────┐         ┌──────────────────────────────┐
│ User Code  │────────→│ syscall; ret                 │  ← Dirección fuera
│ (stubs     │  saltar │ (embebido en código propio)  │    de ntdll
│  propios)  │         │                              │
└────────────┘         └──────────────────────────────┘
  Stack: [user_code, <dirección fuera de ntdll>]
  Detección EDR: ✓✓ (RetAddr fuera de ntdll = anomalía clara)

SYSCALL INDIRECTO:
┌────────────┐    ┌────┴─────────────────────────────┐
│ User Code  │    │ ntdll!NtAllocateVirtualMemory    │
│ (código    │───→│   0x0012: syscall                │← Salta aquí
│ propio)    │    │   0x0014: ret                    │   (después del hook)
└────────────┘    └──────────────────────────────────┘
  Stack: [user_code, ntdll!NtAlloc...+0x12]
  Detección EDR: ✗ (RetAddr DENTRO de ntdll = parece legítimo)

═══════════════════════════════════════════════════════════════════
```

### 7.3 Algoritmo de Resolución de Gadgets Syscall

**Algoritmo 7.3.1 — Localización de Gadgets `syscall; ret` en ntdll**

```
ENTRADA: Base de ntdll.dll (PVOID), tamaño de sección .text (DWORD)
SALIDA: Diccionario {función → dirección de syscall gadget}

1.  textBase ← Base + .text.VirtualAddress
2.  textSize ← .text.SizeOfRawData
3.
4.  gadgets ← {}
5.  PARA offset = 0 HASTA textSize - 2:
6.    SI *(WORD*)(textBase + offset) == 0x050F:   // opcode de syscall
7.      SI *(BYTE*)(textBase + offset + 2) == 0xC3:  // opcode de ret
8.        // Encontrado gadget syscall;ret en textBase + offset
9.        // Buscar la función a la que pertenece este offset
10.       funcAddr ← BuscarFuncionQueContiene(textBase, offset)
11.       SI funcAddr != NULL:
12.         gadgets[funcAddr] ← textBase + offset
13.       FIN SI
14.     FIN SI
15.   FIN SI
16. FIN PARA
17. RETORNA gadgets
```

**Formalización:**

$$\text{FindGadgets}(base, \text{.text}) = \{f \mapsto a \mid f \in \mathcal{F}_{req} \wedge a \in \text{Range}(f) \wedge [a, a+2] = \text{0F05C3}\}$$

donde `0F05C3` es la secuencia de bytes `syscall; ret`.

### 7.4 Mecanismo de Ejecución del Syscall Indirecto

El cargador construye una función stub que:

1. Establece los registros de argumentos (RCX, RDX, R8, R9 para los primeros 4 argumentos)
2. Establece `R10 = RCX` (convención NT syscall)
3. Establece `EAX = syscall_number` (pre-resuelto de la EAT)
4. Salta al gadget `syscall; ret` dentro de ntdll

**La clave es que el `syscall` se ejecuta dentro del rango de direcciones de ntdll.dll**, lo que hace que la dirección de retorno en el stack apunte dentro de ntdll, pareciendo legítimo para un EDR que verifique el origen del syscall.

### 7.5 Detección de Syscalls Indirectos

La detección de syscalls indirectos es significativamente más difícil que la de syscalls directos, pero existen técnicas:

**Técnica 1 — Análisis del stack frame completo:**

Un syscall indirecto deja un stack frame atípico: la función que precede al syscall no es la función completa de ntdll, sino que el retorno viene de un offset interno. Los EDRs avanzados pueden verificar que el offset de retorno corresponda a un punto de entrada válido de una función (no a un offset interno):

$$\text{ValidReturn}(addr) \iff \exists\, f \in \text{Exports}(\text{ntdll}): addr = f_{entry} + 0 \quad \text{(punto de entrada exacto)}$$

**Técnica 2 — Monitoring de kernel mode:**

El kernel puede verificar que el registro `RIP` al momento del `syscall` apunte a una ubicación esperada dentro de ntdll. Los offsets internos son anómalos.

**Técnica 3 — Control Flow Guard (CFG):**

CFG verifica que los saltos indirectos apunten a direcciones válidas de inicio de función. Un salto al medio de una función de ntdll (offset 0x12) puede ser bloqueado por CFG:

$$\text{CFG}(target) = \begin{cases} \text{Allow} & \text{si } target \in \text{ValidCallTargets} \\ \text{Block} & \text{en otro caso} \end{cases}$$

---

## 8. Gestión de Memoria: Allocación, Cifrado, Inyección y Cambio de Permisos

### 8.1 Ciclo de Vida de la Memoria del Payload

```
═══════════════════════════════════════════════════════════════════
    CICLO DE VIDA DE LA MEMORIA DEL PAYLOAD
═══════════════════════════════════════════════════════════════════

  Estado 1: PAYLOAD CIFRADO (en disco dentro del ISO, o embebido)
  ┌─────────────────────────────────────────────────────────────┐
  │ [encrypted_bytes...]                                        │
  │ Tamaño: ~4KB - 256KB típicamente                           │
  │ Cifrado: AES-256-CBC, RC4, o XOR con clave embebida       │
  └─────────────────────────────────────────────────────────────┘
                          │
                          ▼  NtAllocateVirtualMemory (RW)
  Estado 2: MEMORIA RW ASIGNADA (sin contenido útil)
  ┌─────────────────────────────────────────────────────────────┐
  │ [00 00 00 00 00 00 ... ] (página limpia)                   │
  │ Permiso: PAGE_READWRITE                                    │
  │ Tipo: MEM_PRIVATE (no respaldada en disco)                 │
  └─────────────────────────────────────────────────────────────┘
                          │
                          ▼  NtWriteVirtualMemory / memcpy
  Estado 3: PAYLOAD CIFRADO EN MEMORIA RW
  ┌─────────────────────────────────────────────────────────────┐
  │ [encrypted_bytes...] copiados a la página RW               │
  │ Permiso: PAGE_READWRITE                                    │
  │ Detectable: contenido cifrado en página RW                 │
  └─────────────────────────────────────────────────────────────┘
                          │
                          ▼  Descifrado in-situ
  Estado 4: PAYLOAD DESCIFRADO EN MEMORIA RW
  ┌─────────────────────────────────────────────────────────────┐
  │ [payload ASM ejecutable...]                                 │
  │ Permiso: PAGE_READWRITE                                    │
  │ Detectable: código ejecutable en página RW                 │
  │ Ventana de máxima exposición: entre write y protect        │
  └─────────────────────────────────────────────────────────────┘
                          │
                          ▼  NtProtectVirtualMemory (RW → RX)
  Estado 5: PAYLOAD DESCIFRADO EN MEMORIA RX (LISTO PARA EJECUTAR)
  ┌─────────────────────────────────────────────────────────────┐
  │ [payload ASM ejecutable...]                                 │
  │ Permiso: PAGE_EXECUTE_READ                                 │
  │ Tipo: MEM_PRIVATE (no respaldada en disco)                 │
  │ Anomalía: MEM_PRIVATE + RX = inyección probable            │
  └─────────────────────────────────────────────────────────────┘
                          │
                          ▼  NtCreateThreadEx / NtQueueApcThread
  Estado 6: PAYLOAD EJECUTÁNDOSE
  ┌─────────────────────────────────────────────────────────────┐
  │ Hilo/APC ejecutando código desde página MEM_PRIVATE + RX   │
  │ No hay respaldo en disco → EDR no puede verificar origen   │
  │ No hay unwind information → stack walks anómalos           │
  └─────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 8.2 Especificación Formal de NtAllocateVirtualMemory

**Definición 8.2.1 — Especificación de la Syscall**

$$\text{NtAllocateVirtualMemory}: \mathcal{H} \times \mathcal{P}^{**} \times \mathcal{N} \times \mathcal{P}^{**} \times \mathcal{T} \times \mathcal{P} \rightarrow \text{NTSTATUS}$$

donde:

- $\mathcal{H}$: Handle del proceso (típicamente `NtCurrentProcess() = -1`)
- $\mathcal{P}^{**}$: Puntero a puntero de dirección base (input/output)
- $\mathcal{N}$: ZeroBits (típicamente 0)
- $\mathcal{P}^{**}$: Puntero a tamaño de región (input/output, redondeado a página)
- $\mathcal{T}$: Tipo de asignación: `MEM_COMMIT` (0x1000), `MEM_RESERVE` (0x2000), `MEM_TOP_DOWN` (0x100000)
- $\mathcal{P}$: Protección de página: `PAGE_READWRITE` (0x04), `PAGE_EXECUTE_READ` (0x20), etc.

**Precondiciones:**

1. El handle del proceso debe tener acceso `PROCESS_VM_OPERATION`
2. La dirección base puede ser `NULL` (el sistema elige) o una dirección específica
3. El tamaño debe ser mayor que 0 (redondeado a múltiplo de página: 4KB)

**Postcondiciones:**

1. Se asigna una región de memoria virtual del tamaño especificado
2. La región tiene los permisos de página especificados
3. La región es de tipo `MEM_PRIVATE` (no mapeada desde archivo)

### 8.3 Análisis de Cifrado del Payload

**Definición 8.3.1 — Esquema de Cifrado del Payload**

Sea $P$ el payload ASM (Position Independent Code) en texto plano. El cifrado se define como:

$$C = \text{Enc}_K(P, IV)$$

donde $K$ es la clave de cifrado embebida en el cargador y $IV$ es el vector de inicialización.

| Algoritmo     | Tamaño clave            | Velocidad            | Fortaleza                      | Uso típico                        |
| ------------- | ----------------------- | -------------------- | ------------------------------ | --------------------------------- |
| AES-256-CBC   | 256 bits                | ~1 GB/s (con AES-NI) | Alta                           | Payloads grandes                  |
| RC4           | Variable (128-256 bits) | ~500 MB/s            | Media (debilidades conocidas)  | Payloads pequeños, compatibilidad |
| XOR con clave | Variable                | ~10 GB/s             | Baja (reversible trivialmente) | Ofuscación básica                 |
| ChaCha20      | 256 bits                | ~800 MB/s            | Alta                           | Alternativa moderna               |

**Propiedad de seguridad:**

$$\text{Si } K \text{ es desconocida: } H(P \mid C) = H(P)$$

Es decir, sin conocimiento de la clave, el ciphertext no revela información sobre el plaintext (seguridad perfecta del cifrado simétrico).

**Implicación para detección:** El contenido cifrado en memoria es indistinguible de datos aleatorios. La detección no puede basarse en el análisis del contenido del bloque cifrado; debe basarse en los **metadatos** de la asignación (tipo de memoria, permisos, respaldo en disco, etc.).

### 8.4 Transición de Permisos RW → RX

**Definición 8.4.1 — Transición Anómala de Permisos**

Una transición de permisos de `PAGE_READWRITE` a `PAGE_EXECUTE_READ` sobre una página de tipo `MEM_PRIVATE` es el **indicador más fuerte de inyección de código**:

$$\text{InjectionIndicator}(page) \iff \text{MemType}(page) = \text{MEM\_PRIVATE}$$

$$\wedge\; \text{OldProtect}(page) = \text{PAGE\_READWRITE}$$

$$\wedge\; \text{NewProtect}(page) = \text{PAGE\_EXECUTE\_READ}$$

$$\wedge\; \text{FileBacked}(page) = \text{FALSE}$$

**Justificación:** En código legítimo, las secciones ejecutables de un DLL o EXE se cargan directamente como `PAGE_EXECUTE_READ` (o `PAGE_EXECUTE_WRITECOPY` si hay relocations). Una página que pasa de RW a RX sin respaldo en disco es casi exclusivamente el resultado de inyección de código.

### 8.5 Secuencia Completa de Syscalls del Cargador

```
═══════════════════════════════════════════════════════════════════
    SECUENCIA COMPLETA DE SYSCALLS DEL CARGADOR C++
═══════════════════════════════════════════════════════════════════

Paso  Syscall                      Argumentos                    Propósito
────  ───────                      ──────────                    ─────────

 1    NtCreateFile                 ntdll.dll, READ              Abrir ntdll en disco
 2    NtReadFile                   buffer, size                 Leer .text original
 3    NtProtectVirtualMemory       ntdll.text, RW               Cambiar permiso .text
 4    memcpy (user-mode)           ntdll.text ← buffer          Restaurar código
 5    NtProtectVirtualMemory       ntdll.text, RX               Restaurar permiso
 6    NtClose                      handle                       Cerrar archivo
 7    NtFreeVirtualMemory          buffer                       Liberar buffer temporal
      ─── Unhooking completo ───

 8    NtProtectVirtualMemory       EtwEventWrite, RW            Desproteger EtwEventWrite
 9    memcpy (user-mode)           EtwEventWrite ← {33 C0 C3}  Parchear con xor+ret
10    NtProtectVirtualMemory       EtwEventWrite, RX            Restaurar permiso
      ─── ETW Patched ───

11    NtAllocateVirtualMemory      NULL, size, RW               Allocar bloque RW
12    NtWriteVirtualMemory         bloque ← payload_cifrado     Copiar payload cifrado
13    descifrado in-situ           bloque ^= keystream          Descifrar payload
14    NtProtectVirtualMemory       bloque, RX                   Hacer ejecutable
      ─── Payload inyectado ───

15a   NtCreateThreadEx             start_address = bloque       Crear hilo (opción A)
  ó
15b   NtQueueApcThread             thread, bloque, ctx          Encolar APC (opción B)
      ─── Ejecución iniciada ───

16    NtFreeVirtualMemory          buffers_temporales           Limpieza
      ─── Cargador termina ───

═══════════════════════════════════════════════════════════════════
```

---

## 9. El Mecanismo APC: Formalización en CSP y Teoría de Concurrencia

### 9.1 Modelo CSP del Hilo

**Definición 9.1.1 — Hilo como Proceso CSP**

Un hilo $T$ en Windows se modela como un proceso en el Cálculo de Procesos Comunicantes (CSP) de Hoare:

$$T = \text{Running} \rightarrow T' \;\Box\; \text{AlertableWait} \rightarrow \text{ProcessAPCQueue} \rightarrow T''$$

donde:

- $\text{Running}$ representa la ejecución normal del hilo
- $\text{AlertableWait}$ es el estado en el que el hilo invoca una primitiva de espera alertable
- $\text{ProcessAPCQueue}$ es la acción de drenar la cola APC antes de retornar
- $\Box$ denota elección externa (external choice)

### 9.2 La Cola APC como Canal Bufferizado

**Definición 9.2.1 — Cola APC como Canal CSP**

La cola APC de un hilo se modela como un **canal bufferizado**:

$$\text{APCQueue}_T = \text{Enqueue}.\text{APC}(f, ctx) \rightarrow \text{APCQueue}_T \;\Box\; \text{Dequeue} \rightarrow \text{APCQueue}_T$$

donde cada elemento $\text{APC}(f, ctx)$ contiene:

- $f$: dirección de la función callback (punto de entrada)
- $ctx$: puntero al contexto/parámetro pasado a la función

### 9.3 Ciclo de Vida del APC

**Definición 9.3.1 — Autómata de Estados del APC**

El ciclo de vida de un APC se modela como un autómata finito determinista:

$$\text{APC} = (\Sigma, S, s_0, \delta, F)$$

donde:

- $\Sigma = \{\text{Enqueue}, \text{AlertableWait}, \text{Dispatch}, \text{Return}\}$
- $S = \{\text{None}, \text{Queued}, \text{Delivered}, \text{Executed}, \text{Completed}\}$
- $s_0 = \text{None}$
- $F = \{\text{Completed}\}$

```
═══════════════════════════════════════════════════════════════════
        AUTÓMATA DE ESTADOS DEL APC
═══════════════════════════════════════════════════════════════════

                    EnqueueAPC
    [No Existe] ──────────────────→ [En Cola (Queued)]
         │                               │
         │                         Thread enters
         │                         alertable wait
         │                               │
         │                               ▼
         │                         [Entregado (Delivered)]
         │                               │
         │                         Kernel calls
         │                         callback f(ctx)
         │                               │
         │                               ▼
         │                         [Ejecutado (Executed)]
         │                               │
         │                           Return
         │                               │
         │                               ▼
         │                         [Completado (Completed)]
         │
         │                         Thread timeout/error
         │                               │
         └───────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

**Tabla de transiciones:**

| Estado actual | Evento          | Estado siguiente | Condición                                   |
| ------------- | --------------- | ---------------- | ------------------------------------------- |
| None          | EnqueueAPC      | Queued           | `NtQueueApcThread` exitoso                  |
| Queued        | AlertableWait   | Delivered        | Hilo entra en espera alertable              |
| Queued        | (timeout/error) | None             | Hilo termina sin entrar en espera alertable |
| Delivered     | Dispatch        | Executed         | Kernel ejecuta la función callback          |
| Executed      | Return          | Completed        | Callback retorna                            |

### 9.4 Clasificación de APCs en el Kernel NT

**Definición 9.4.1 — Tipos de APC**

El kernel NT distingue tres modos de APC:

$$\text{APCMode} \in \{\text{KernelNormal}, \text{KernelSpecial}, \text{UserMode}\}$$

**APC de Modo Kernel:**

| Tipo           | Prioridad | Uso                                              | Ejecución                |
| -------------- | --------- | ------------------------------------------------ | ------------------------ |
| Kernel Special | Máxima    | Sincronización de I/O, temporizadores del kernel | Inmediata, no bloqueable |
| Kernel Normal  | Media     | Operaciones de I/O asíncrono (IRP completion)    | En contexto de espera    |

**APC de Modo Usuario:**

| Atributo  | Descripción                                                                 |
| --------- | --------------------------------------------------------------------------- |
| Entrega   | Solo cuando el hilo entra en estado alertable                               |
| Contexto  | Se ejecuta en el contexto del hilo destino (misma pila, mismos privilegios) |
| Cola      | FIFO dentro del mismo modo                                                  |
| Seguridad | Hereda el token de seguridad del hilo anfitrión                             |

### 9.5 Jerarquía de Despacho

**Definición 9.5.1 — Orden de Despacho**

El dispatcher del kernel sigue un orden estricto al procesar las colas APC:

$$\text{DispatchOrder} = \underbrace{\text{SpecialKernelAPC}}_{\text{Prioridad máxima}} \rightarrow \underbrace{\text{NormalKernelAPC}}_{\text{Media}} \rightarrow \underbrace{\text{UserModeAPC}}_{\text{Baja}}$$

Dentro de cada categoría, el orden es FIFO estricto. Esta jerarquía garantiza que las operaciones críticas del kernel (como la finalización de I/O) no sean postergadas por APCs de modo usuario.

### 9.6 Ejecución Interleaved como Interrupción Controlada

**Definición 9.6.1 — Semántica de Ejecución APC**

La ejecución de un APC de modo usuario en el contexto de un hilo $T$ se modela como una **interrupción controlada** en la traza de ejecución:

$$\rho_T = \ldots, s_k, \underbrace{a_1^{APC}, a_2^{APC}, \ldots, a_n^{APC}}_{\text{Secuencia APC}}, s_{k+1}, \ldots$$

donde $s_k$ es el estado del hilo antes de procesar la cola APC y $s_{k+1}$ es el estado después.

**Propiedades:**

1. **Atomicidad intra-cola:** Los APCs dentro de la misma cola se ejecutan sin interleaving entre ellos:

$$\forall\, i, j: a_i^{APC}, a_j^{APC} \in \text{same\_queue} \Rightarrow \neg\text{Interleaved}(a_i, a_j)$$

2. **No atomicidad con respecto al hilo:** La ejecución APC no es atómica con respecto a la ejecución normal del hilo. El hilo se suspende, procesa los APCs, y luego continúa.

3. **Herencia de contexto de seguridad:**

$$\text{SecurityContext}(APC) = \text{SecurityContext}(T_{host})$$

### 9.7 El APC como Vector de Inyección

La inyección APC inserta un elemento en la cola de un hilo existente:

$$\text{APCQueue}_T \xrightarrow{+\text{APC}(f_{payload}, ctx)} \text{APCQueue}'_T$$

El hilo, al entrar en `AlertableWait`, procesa esta APC como si fuera una operación legítima. La función $f_{payload}$ se ejecuta con los privilegios y el token de seguridad del hilo anfitrión.

**Ventajas sobre creación de hilo:**

1. **Menor visibilidad:** La entrega de APC no genera eventos ETW de creación de hilo
2. **Contexto heredado:** No es necesario manipular el token de seguridad
3. **Ejecución temporal:** El APC se ejecuta y retorna, sin dejar un hilo persistente

**Desventajas:**

1. **Requisito de alertable wait:** El hilo destino debe entrar en estado alertable (`WaitForSingleObjectEx`, `SleepEx`, etc.)
2. **Temporalidad:** Si el hilo nunca entra en alertable wait, el APC nunca se ejecuta
3. **Interferencia:** La ejecución del APC interrumpe temporalmente el hilo destino

---

## 10. Especificación Formal de NtQueueApcThread y NtCreateThreadEx

### 10.1 NtQueueApcThread

**Definición 10.1.1 — Especificación Formal**

$$\text{NtQueueApcThread}: \mathcal{H} \times \mathcal{F} \times \mathcal{V} \times \mathcal{V} \times \mathcal{V} \rightarrow \text{NTSTATUS}$$

donde:

- $\mathcal{H}$: Handle del hilo destino (con acceso `THREAD_SET_CONTEXT`)
- $\mathcal{F}$: Dirección de la función APC (punto de entrada en el espacio de direcciones del proceso destino)
- $\mathcal{V}$: ApcContext — primer parámetro pasado a la función APC
- $\mathcal{V}$: Argument1 — segundo parámetro (SystemArgument1)
- $\mathcal{V}$: Argument2 — tercer parámetro (SystemArgument2)

**Precondiciones:**

$$\text{Pre}(\text{NtQueueApcThread}) \iff$$

1. $\text{HasAccess}(\text{caller}, T_{target}, \text{THREAD\_SET\_CONTEXT})$
2. $\text{IsValidAddr}(ApcRoutine, \text{ProcessSpace}(T_{target}))$
3. $\neg\text{IsTerminated}(T_{target})$

**Postcondiciones:**

$$\text{Post}(\text{NtQueueApcThread}) \iff$$

1. Se crea una estructura `KAPC` con:
   - $\text{ApcMode} = \text{UserMode}$
   - $\text{NormalRoutine} = ApcRoutine$
   - $\text{NormalContext} = ApcContext$
   - $\text{SystemArgument1} = Argument1$
   - $\text{SystemArgument2} = Argument2$
2. La KAPC se inserta en la cola APC de modo usuario del hilo destino
3. $\text{Inserted} = \text{TRUE}$

**Contradependencia del sistema:**

$$\text{Confía en que el emisor posee THREAD\_SET\_CONTEXT} \Rightarrow \text{hereda SecurityContext del hilo}$$

### 10.2 NtCreateThreadEx

**Definición 10.2.1 — Especificación Formal**

$$\text{NtCreateThreadEx}: \mathcal{P}^{**} \times \mathcal{A} \times \mathcal{P} \times \mathcal{H} \times \mathcal{F} \times \mathcal{P} \times \mathcal{F} \times \text{Flags} \times \mathcal{N} \times \mathcal{N} \times \mathcal{P} \rightarrow \text{NTSTATUS}$$

Parámetros relevantes:

- **ThreadHandle**: Puntero a handle de salida
- **DesiredAccess**: Acceso solicitado al hilo (`THREAD_ALL_ACCESS`, etc.)
- **ObjectAttributes**: Atributos de seguridad (típicamente `NULL`)
- **ProcessHandle**: Handle del proceso donde crear el hilo (`NtCurrentProcess()`)
- **StartRoutine**: Dirección de la función de inicio del hilo (payload)
- **Argument**: Argumento pasado a StartRoutine
- **CreateFlags**: Flags de creación:
  - `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` (0x00000001)
  - `THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH` (0x00000002)
  - `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` (0x00000004)
  - `THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR` (0x00000010)
  - `THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE` (0x00000040)

**Precondiciones:**

1. $\text{HasAccess}(\text{caller}, P_{target}, \text{PROCESS\_CREATE\_THREAD})$
2. $\text{IsValidAddr}(StartRoutine, \text{ProcessSpace}(P_{target}))$
3. La región de memoria en `StartRoutine` debe tener permisos de ejecución

**Postcondiciones:**

1. Se crea un nuevo hilo en el proceso especificado
2. El hilo comienza ejecutando `StartRoutine(Argument)`
3. Se retorna un handle al nuevo hilo

---

## 11. KAPC: Estructura Interna y Modelo Algebraico

### 11.1 Estructura del KAPC en el Kernel NT

En el kernel NT, cada APC se representa mediante la estructura `KAPC`:

```
KAPC {
    Type            : UCHAR              // ApcObject (0x12)
    SpareByte1      : UCHAR              // Reservado
    SpareByte2      : UCHAR              // Reservado
    ApcStateIndex   : UCHAR              // 0=Attached, 1=Detached
    KernelRoutine   : PKKERNEL_ROUTINE   // Siempre modo kernel
    RundownRoutine  : PKRUNDOWN_ROUTINE  // Limpieza si el hilo termina
    NormalRoutine   : PKNORMAL_ROUTINE   // Función objetivo (Ring 0 o Ring 3)
    NormalContext   : PVOID              // Contexto pasado a NormalRoutine
    SystemArgument1 : PVOID              // Argumento 1 del sistema
    SystemArgument2 : PVOID              // Argumento 2 del sistema
    ApcMode         : KPROCESSOR_MODE    // KernelMode (0) o UserMode (1)
    Inserted        : BOOLEAN            // ¿Está en la cola?
}
```

### 11.2 Modelo Algebraico del KAPC

**Definición 11.2.1 — KAPC como Tupla**

$$\text{KAPC} = (k_r, r_r, n_r, ctx, a_1, a_2, m, i)$$

donde:

- $k_r: \text{KAPC} \rightarrow \text{void}$ es la rutina kernel (siempre se ejecuta en Ring 0)
- $r_r: \text{KAPC} \rightarrow \text{void}$ es la rutina de limpieza (ejecutada si el hilo termina antes de procesar la APC)
- $n_r$ es la rutina normal (puede ser Ring 0 o Ring 3 según $m$)
- $ctx$ es el contexto pasado a $n_r$
- $a_1, a_2$ son argumentos del sistema
- $m \in \{\text{KernelMode}, \text{UserMode}\}$
- $i \in \{0, 1\}$ indica si está insertada en la cola

### 11.3 Flujo de Entrega de APC de Modo Usuario

```
═══════════════════════════════════════════════════════════════════
    FLUJO DE ENTREGA DE APC DE MODO USUARIO
═══════════════════════════════════════════════════════════════════

  PROCESO ATACANTE                    HILO LEGÍTIMO (T_host)
  ┌──────────────────────┐            ┌──────────────────────────┐
  │                      │            │ Estado: Running           │
  │ NtQueueApcThread     │            │                          │
  │ (T_handle,           │            │                          │
  │  f_payload,          ├──Enqueue──→│ APCQueue_T: [...]        │
  │  ctx)                │            │              ↓ insertar   │
  │                      │            │ APCQueue'_T: [...,       │
  │                      │            │   KAPC(m=User,           │
  │                      │            │   n_r=f_payload,         │
  └──────────────────────┘            │   ctx=ctx)]              │
                                      │                          │
                                      │ ... ejecución normal ... │
                                      │                          │
                                      │ WaitForSingleObjectEx    │
                                      │ (alertable=TRUE)         │
                                      │         │                │
                                      │         ▼                │
                                      │ KiUserApcDispatcher      │
                                      │ (ntdll.dll)              │
                                      │         │                │
                                      │         ▼                │
                                      │ Kernel entrega APC:      │
                                      │ KernelRoutine se ejecuta │
                                      │ → NormalRoutine(ctx)     │
                                      │                          │
                                      │ f_payload(ctx)           │
                                      │   ↓                      │
                                      │ Payload ASM se ejecuta   │
                                      │ con:                     │
                                      │ SecurityContext(T_host)  │
                                      │ Token(T_host)            │
                                      │ Privilegios(T_host)      │
                                      │                          │
                                      │ Payload retorna          │
                                      │         │                │
                                      │         ▼                │
                                      │ AlertableWait retorna    │
                                      │ (con STATUS_USER_APC)    │
                                      │                          │
                                      │ Continúa ejecución       │
                                      │ normal del hilo          │
                                      └──────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 11.4 Puntos de Espera Alertable

Para que el APC de modo usuario se ejecute, el hilo destino debe alcanzar un punto de espera alertable. Las funciones que constituyen tales puntos son:

| Función                                             | Modo alertable      | Tipo               |
| --------------------------------------------------- | ------------------- | ------------------ |
| `SleepEx(ms, TRUE)`                                 | Sí                  | Temporizador       |
| `WaitForSingleObjectEx(h, ms, TRUE)`                | Sí                  | Espera de objeto   |
| `WaitForMultipleObjectsEx(n, h, wait, ms, TRUE)`    | Sí                  | Espera múltiple    |
| `MsgWaitForMultipleObjectsEx(n, h, ms, mask, TRUE)` | Sí                  | Espera de mensajes |
| `SignalObjectAndWait(h1, h2, ms, TRUE)`             | Sí                  | Señal + espera     |
| `NtWaitForSingleObject(h, alertable, timeout)`      | Si `alertable=TRUE` | Nativo             |
| `NtWaitForMultipleObjects(...)`                     | Si `alertable=TRUE` | Nativo             |
| `NtDelayExecution(alertable, delay)`                | Si `alertable=TRUE` | Nativo             |
| `NtRemoveIoCompletion(...)`                         | Generalmente no     | I/O                |
| `NtReplyWaitReceivePort(...)`                       | Generalmente no     | LPC/RPC            |

**Los EDRs y procesos legítimos frecuentemente usan waits alertables**, lo que proporciona múltiples puntos de inyección. Los hilos de `explorer.exe`, `svchost.exe`, y procesos de servicios son candidatos típicos.

---

## 12. Comparación Formal de Métodos de Inyección

### 12.1 Tabla Comparativa Completa

| Dimensión                 | `NtCreateThreadEx`                          | `NtQueueApcThread`                                              | `NtMapViewOfSection`                                 | `SetThreadContext`                 |
| ------------------------- | ------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------- |
| **Modelo CSP**            | Creación de nuevo proceso $T_{new}$         | Inserción en canal existente $\text{APCQueue}_T$                | Mapeo de sección compartida                          | Modificación de contexto de hilo   |
| **Visibilidad ETW**       | Alta: genera `ThreadCreate` event           | Baja: APC delivery no genera evento ETW visible                 | Media: genera section map event                      | Media: genera context change event |
| **Contexto de seguridad** | `SecurityContext(T_{new})` = proceso actual | `SecurityContext(APC) = SecurityContext(T_{host})`              | Proceso destino                                      | Hilo destino                       |
| **Requisito previo**      | Ninguno adicional                           | $T_{host}$ debe entrar en estado alertable                      | Crear sección compartida                             | Hilo suspendido                    |
| **Detección kernel**      | `PsSetCreateProcessNotifyRoutine`           | Auditoría de `NtQueueApcThread` cross-process                   | `MmMapViewOfSection` callback                        | `NtSetContextThread` audit         |
| **Persistencia**          | Hilo dedicado (persistente)                 | Transitorio (una vez por APC)                                   | Persistente (sección mapeada)                        | Transitorio                        |
| **Resiliencia**           | Alta: hilo propio, no depende de otros      | Baja: si el hilo destino nunca entra en wait, APC no se ejecuta | Media: sección persistente pero necesitas ejecutarla | Baja: necesitas hilo suspendido    |
| **Complejidad**           | Baja                                        | Media                                                           | Alta                                                 | Alta                               |

### 12.2 Espacio de Estados de Cada Método

**NtCreateThreadEx:**

$$\tau_{Thread}: \Sigma_{Proc} \rightarrow \Sigma_{Proc}'$$

$$\Sigma_{Proc}' = \Sigma_{Proc}[\text{Threads} \mapsto \Sigma_{Proc}.\text{Threads} \cup \{T_{new}\}]$$

**NtQueueApcThread:**

$$\tau_{APC}: \Sigma_{APC} \rightarrow \Sigma_{APC}'$$

$$\Sigma_{APC}' = \Sigma_{APC}[\text{APCQueue}_{T_{target}} \mapsto \text{APCQueue}_{T_{target}} \cup \{\text{KAPC}(UserMode, f_{payload}, ctx)\}]$$

**NtMapViewOfSection:**

$$\tau_{Section}: \Sigma_{Mem} \rightarrow \Sigma_{Mem}'$$

$$\Sigma_{Mem}' = \Sigma_{Mem}[\text{Mappings}_{P_{target}} \mapsto \ldots \cup \{\text{View}(section, base, size, RX)\}]$$

---

## 13. COM/DCOM como Superficie de Interacción con WMI y Persistencia

### 13.1 WMI como Cadena de Invocación COM

Toda comunicación con el servicio WMI se realiza vía interfaces COM. Formalmente:

$$\text{Consumer} \xrightarrow{\text{COM}} \text{WMI Service} \xrightarrow{\text{WQL}} \text{CIM Repository} \xrightarrow{\text{Esent}} \text{Disk}$$

Las interfaces COM relevantes son:

| Interfaz               | IID                                      | Uso                               |
| ---------------------- | ---------------------------------------- | --------------------------------- |
| `IWbemLocator`         | `{dc12a687-737f-11cf-8820-00aa004bfe80}` | Obtener conexión al namespace WMI |
| `IWbemServices`        | `{9556dc99-828c-11cf-a37e-00aa003240c7}` | Ejecutar consultas WQL            |
| `IWbemObjectSink`      | `{7c857801-7381-11cf-8820-00aa004bfe80}` | Recibir resultados asíncronos     |
| `IEnumWbemClassObject` | `{027947e1-d731-11ce-a357-000000000001}` | Enumerar resultados               |

### 13.2 Functor de Activación COM

**Definición 13.2.1 — Activación COM**

$$\mathcal{F}_{act}: \mathbf{CLSID} \rightarrow \mathbf{Instance}$$

El SCM de COM (`combase.dll` / `rpcss.dll`) orquesta la activación:

$$\text{SCM}: \text{CLSID} \times \text{IID} \times \text{Context} \rightarrow \text{IUnknown}^*$$

### 13.3 Marshaling como Transformación Natural

**Definición 13.3.1 — Marshaling**

$$\mu: \text{Data}_{client} \rightarrow \text{WireFormat} \rightarrow \text{Data}_{server}$$

Las propiedades formales son:

- **Composición:** $\mu(g \circ f) = \mu(g) \circ \mu(f)$
- **Identidad:** $\mu(id) = id$
- **Inversibilidad:** $\mu^{-1}$ existe para tipos soportados

Esto implica que los datos que transitan por la interfaz COM de WMI son **inspeccionables** en el formato wire (NDR).

### 13.4 Descriptor de Seguridad COM

**Definición 13.4.1 — SD_COM**

$$\text{SD}_{COM} = (\text{Owner}, \text{Group}, \text{DACL}, \text{SACL})$$

Un intento de manipular el repositorio CIM (crear `__EventFilter` malicioso, por ejemplo) debe satisfacer las verificaciones de la DACL del servicio WMI.

### 13.5 Persistencia WMI como Post-Explotación

El cargador puede, como operación secundaria, crear suscripciones de eventos WMI maliciosas para persistencia:

$$\text{Persistence}_{WMI} = \text{Create}(\text{\_\_EventFilter}) + \text{Create}(\text{\_\_EventConsumer}) + \text{Create}(\text{\_\_FilterToConsumerBinding})$$

Esto crea una suscripción que ejecuta código cuando se cumplen condiciones específicas (ej: inicio de sesión, creación de proceso, etc.), proporcionando persistencia que sobrevive al reinicio del proceso actual.

---

## 14. Superficie de Detección: Predicados Multi-Capa y Correlación

### 14.1 Predicados de Detección de Primer Nivel

**Predicado 14.1.1 — Lectura de ntdll.dll desde disco**

$$P_1(p) \iff \exists\, f: \text{Reads}(p, f) \wedge \text{Path}(f) = \text{ntdll.dll} \wedge \text{HasLoaded}(p, \text{ntdll.dll})$$

_Señal:_ Un proceso que ya tiene ntdll.dll cargada vuelve a leerla desde disco. Operación extremadamente rara en código legítimo.

**Predicado 14.1.2 — Escritura en sección .text de ntdll**

$$P_2(p) \iff \exists\, a \in \text{Range}(\text{ntdll}.text): \text{Writes}(p, a) \wedge \text{Process}(a) = p$$

_Señal:_ Un proceso modifica su propia copia de la sección .text de ntdll. **Alta confianza.**

**Predicado 14.1.3 — Cambio de protección de .text de ntdll**

$$P_3(p) \iff \text{ChangesProtect}(p, \text{ntdll}.text, \text{RW}) \vee \text{ChangesProtect}(p, \text{ntdll}.text, \text{RWX})$$

_Señal:_ Un proceso solicita permisos de escritura sobre la sección .text de ntdll. **Alta confianza.**

**Predicado 14.1.4 — ETW Patching detectado**

$$P_4(p) \iff \mu_{mem}(\text{EtwEventWrite}_{entry}) \neq \mu_{disk}(\text{EtwEventWrite}_{entry})$$

_Señal:_ Los primeros bytes de `EtwEventWrite` en memoria difieren de los originales. **Máxima confianza.**

**Predicado 14.1.5 — Transición RW→RX sin respaldo en disco**

$$P_5(p) \iff \exists\, page: \text{Type}(page) = \text{MEM\_PRIVATE} \wedge \text{OldProt}(page) = \text{RW} \wedge \text{NewProt}(page) = \text{RX} \wedge \text{NoFileBack}(page)$$

_Señal:_ Una página privada cambia de lectura-escritura a lectura-ejecución sin respaldo en disco. **Máxima confianza de inyección.**

**Predicado 14.1.6 — Syscall desde fuera de ntdll**

$$P_6(p) \iff \exists\, syscall: \text{RetAddr}(syscall) \notin \text{Range}(\text{ntdll.dll})$$

_Señal:_ Un syscall ocurre desde una dirección que no pertenece a ntdll.dll. **Alta confianza de syscall directo.**

**Predicado 14.1.7 — APC cross-process**

$$P_7(p) \iff \text{Source}(NtQueueApcThread) \neq \text{Process}(T_{target})$$

_Señal:_ Una APC es encolada desde un proceso diferente al del hilo destino. **Media-Alta confianza.**

**Predicado 14.1.8 — Interacción COM sospechosa con WMI**

$$P_8(p) \iff \text{Method}(call) \in \{\text{ExecNotificationQuery}, \text{PutInstance}(\text{\_\_EventFilter}), \text{PutInstance}(\text{\_\_FilterToConsumerBinding})\}$$

_Señal:_ Un proceso realiza operaciones de creación de suscripciones de eventos WMI. **Media confianza.**

### 14.2 Señal Compuesta de Máxima Confianza

$$\text{MaxConfidence}(p) \iff \underbrace{P_1(p) \wedge P_2(p)}_{\text{Unhooking}} \wedge \underbrace{P_4(p)}_{\text{ETW Patch}} \wedge \underbrace{P_5(p)}_{\text{Inyección RW→RX}}$$

$$\vee\; \underbrace{P_5(p)}_{\text{Inyección RW→RX}} \wedge \underbrace{P_6(p) \vee P_7(p)}_{\text{Ejecución anómala}}$$

La primera rama detecta la secuencia completa del cargador: unhooking + ETW patch + inyección. La segunda rama detecta la inyección combinada con un mecanismo de ejecución anómalo.

### 14.3 Función de Confianza del Sistema

$$\mathcal{T}: \Sigma \rightarrow [0, 1]$$

$$\mathcal{T}(\sigma) = 1 - \prod_{i=1}^{k} (1 - w_i \cdot P_i(\sigma))$$

| Predicado                          | Peso $w_i$ | Justificación                             |
| ---------------------------------- | ---------- | ----------------------------------------- |
| $P_1 \wedge P_2$ (Unhooking)       | 0.90       | Secuencia altamente anómala               |
| $P_3$ (Cambio de protección .text) | 0.85       | Operación extremadamente rara             |
| $P_4$ (ETW Patching)               | 0.95       | Prácticamente exclusivo de malware        |
| $P_5$ (RW→RX sin respaldo)         | 0.95       | Indicador casi inequívoco de inyección    |
| $P_6$ (Syscall fuera de ntdll)     | 0.80       | Fuerte indicador de evasión               |
| $P_7$ (APC cross-process)          | 0.70       | Anómalo pero posible en software legítimo |
| $P_8$ (WMI manipulation)           | 0.60       | Posible en administración legítima        |

### 14.4 Tabla Consolidada de Detección

| Señal                        | Predicado                              | Subsistema                 | FP estimada             | Efectividad |
| ---------------------------- | -------------------------------------- | -------------------------- | ----------------------- | ----------- |
| Lectura de ntdll desde disco | $P_1$                                  | Minifilter IRP_MJ_READ     | Media                   | Alta        |
| Escritura en .text de ntdll  | $P_2$                                  | Protección de página       | Muy baja                | Muy alta    |
| Cambio de protección .text   | $P_3$                                  | ETW protection change      | Muy baja                | Muy alta    |
| ETW Patching                 | $P_4$                                  | Verificación de integridad | Muy baja                | Máxima      |
| RW→RX sin respaldo           | $P_5$                                  | ETW Kernel-Memory          | Muy baja                | Máxima      |
| Syscall fuera de ntdll       | $P_6$                                  | Kernel caller inspection   | Baja                    | Alta        |
| APC cross-process            | $P_7$                                  | Auditoría syscall          | Media                   | Media-Alta  |
| WMI manipulation             | $P_8$                                  | COM proxy monitoring       | Media                   | Media       |
| **Señal compuesta**          | $P_1 \wedge P_2 \wedge P_4 \wedge P_5$ | Multi-subsystem            | **Extremadamente baja** | **Máxima**  |

---

## 15. Historial de Explotación APT y Contexto Operacional

### 15.1 Evolución de Técnicas de Inyección por Período

| Período   | Técnica dominante                                                 | Actores                                | Limitaciones de detección                           |
| --------- | ----------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------- |
| 2015-2017 | `CreateRemoteThread` + `WriteProcessMemory`                       | APT28, APT29, Lazarus                  | Fácil de detectar (cross-process thread creation)   |
| 2017-2019 | `NtCreateThreadEx` con syscall directo                            | Cobalt Strike, APT41                   | Detección por syscall desde fuera de ntdll          |
| 2019-2021 | `NtQueueApcThread` + indirect syscalls                            | APT29, Carbanak                        | Más difícil de detectar; requiere kernel monitoring |
| 2021-2023 | Unhooking + ETW Patch + indirect syscalls + APC                   | Emotet, IcedID, APT29                  | EDRs pierden visibilidad completa                   |
| 2023-2024 | Stack spoofing + hardware breakpoints + direct kernel interaction | Ransomware-as-a-Service, APT avanzados | Requiere hypervisor-level detection                 |

### 15.2 Documentación de Técnicas por Actor

**APT29 (Cozy Bear):**

- Documentado usando `NtQueueApcThread` para inyección en procesos legítimos
- Combina unhooking de ntdll con ETW patching
- Usa indirect syscalls para evitar detección por EDR

**Cobalt Strike:**

- Framework comercial de red teaming ampliamente adoptado
- Soporta múltiples técnicas de inyección: `CreateThread`, `NtCreateThreadEx`, APC injection, `SetThreadContext`
- Beacon payload es Position Independent Code (PIC) cargado en memoria

**Emotet / TrickBot / IcedID:**

- Loader C++ con unhooking de ntdll
- ETW patching para evadir Sysmon y EDR
- APC injection para ejecución de payload

**APT41 (Winnti):**

- Uso de `NtQueueApcThread` con thread targeting
- Combinación con COM hijacking para persistencia
- ETW patching selectivo (solo proveedores de seguridad)

### 15.3 Técnicas de Evasión del Cargador por Nivel de Sofisticación

```
═══════════════════════════════════════════════════════════════════
    NIVELES DE SOFISTICACIÓN DEL CARGADOR C++
═══════════════════════════════════════════════════════════════════

NIVEL 1: BÁSICO
├── Resolución PEB → ntdll base
├── Parseo EAT → resolución por strings
├── NtAllocateVirtualMemory (RW)
├── memcpy payload cifrado
├── NtProtectVirtualMemory (RW → RX)
├── NtCreateThreadEx (hilo dedicado)
└── Sin evasión de EDR
  → Detectable por: ETW, EDR con monitoreo básico

NIVEL 2: INTERMEDIO
├── Resolución PEB → ntdll base
├── Parseo EAT → resolución por hash (FNV-1a)
├── API Unhooking (restaurar ntdll)
├── ETW Patching (EtwEventWrite)
├── NtAllocateVirtualMemory (RW)
├── Descifrado de payload (AES/RC4)
├── NtProtectVirtualMemory (RW → RX)
├── NtCreateThreadEx (hilo dedicado)
└── Evasión parcial de EDR
  → Detectable por: lectura de ntdll desde disco, RW→RX

NIVEL 3: AVANZADO
├── Todo lo del nivel 2
├── Indirect syscalls (evitar hooks sin unhooking completo)
├── NtQueueApcThread (en lugar de NtCreateThreadEx)
├── Thread targeting (inyección en hilo de proceso legítimo)
├── Limpieza de artefactos
└── Evasión significativa de EDR
  → Detectable por: kernel monitoring, verificación de integridad

NIVEL 4: ÉLITE
├── Todo lo del nivel 3
├── Stack spoofing (falsificación de pila durante syscall)
├── Hardware breakpoints como anti-monitoreo
├── Syscall numbers dinámicos (resolución desde ntdll en memoria)
├── Chifrado de código de evasión en tiempo de ejecución
├── Anti-sandbox (detección de entornos de análisis)
├── Polimorfismo del cargador (mutación entre ejecuciones)
└── Evasión avanzada
  → Requiere: hypervisor-level detection, VBS/HVCI

═══════════════════════════════════════════════════════════════════
```

---

## 16. Contramedidas por Capa y Análisis de Efectividad

### 16.1 Modelo de Defensa en Profundidad

```
┌─────────────────────────────────────────────────────────────────────┐
│     CONTRAMEDIDAS CONTRA EL CARGADOR C++ Y EL MECANISMO APC       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  CAPA 6: HYPERVISOR-LEVEL PROTECTION                               │
│  ├── VBS (Virtualization-Based Security)                           │
│  │   → Credencial Guard, Device Guard                              │
│  ├── HVCI (Hypervisor-protected Code Integrity)                    │
│  │   → Solo código firmado puede ejecutarse                        │
│  │   → Páginas MEM_PRIVATE + RX = bloqueadas                      │
│  │   → Payload ASM sin firma digital = no ejecutable               │
│  └── Kernel DMA Protection                                         │
│      → Protección contra acceso directo a memoria                  │
│                                                                     │
│  CAPA 5: EDR AVANZADO CON COMPONENTE KERNEL                        │
│  ├── Kernel callbacks (PsSetCreateProcessNotifyRoutineEx)          │
│  ├── Minifilter drivers (IRP monitoring)                           │
│  ├── ETW kernel providers (no afectados por user-mode patch)       │
│  ├── Verificación periódica de integridad de ntdll                 │
│  ├── Detección de ETW patching                                     │
│  ├── Detección de transiciones RW→RX                               │
│  └── Stack walking avanzado                                        │
│                                                                     │
│  CAPA 4: EDR USER-MODE                                              │
│  ├── Monitoreo de llamadas a NtProtectVirtualMemory                │
│  ├── Detección de cambios de protección en secciones ejecutables   │
│  ├── Detección de NtCreateThreadEx con argumentos anómalos         │
│  └── Monitoreo de NtQueueApcThread cross-process                   │
│                                                                     │
│  CAPA 3: RESTRICCIÓN DE PRIVILEGIOS                                 │
│  ├── AppLocker/WDAC: restringir qué procesos pueden inyectar       │
│  ├── Constrained Language Mode: limitar capacidades de PowerShell  │
│  ├── ASR rules: bloquear inyección de código                       │
│  └── Group Policy: restringir acceso a APIs de inyección           │
│                                                                     │
│  CAPA 2: HARDWARE SECURITY                                          │
│  ├── TPM 2.0: medición de integridad del arranque                  │
│  ├── Secure Boot: verificar firmas de código en arranque           │
│  └── Intel CET / AMD Shadow Stack: protección de pila              │
│                                                                     │
│  CAPA 1: MONITOREO COMPORTAMENTAL                                   │
│  ├── Machine Learning sobre secuencias de syscalls                 │
│  ├── Análisis de patrones de acceso a memoria                      │
│  ├── Correlación multi-evento (ETW + WMI + kernel)                 │
│  └── Alertas compuestas multi-predicado                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 16.2 Efectividad de HVCI contra el Vector

HVCI es la contramedida más efectiva contra el cargador porque opera a nivel de hypervisor:

$$\text{HVCI}(page) = \begin{cases} \text{Allow} & \text{si } \text{PageSignature}(page) \in \text{TrustedSignatures} \\ \text{Block} & \text{en otro caso} \end{cases}$$

**Impacto en el cargador:**

| Operación del cargador         | ¿Funciona con HVCI?                                              |
| ------------------------------ | ---------------------------------------------------------------- |
| Resolución PEB                 | Sí (no requiere ejecución de código no firmado)                  |
| Parseo EAT                     | Sí                                                               |
| API Unhooking                  | Parcial (no puede escribir en .text si el hypervisor lo protege) |
| ETW Patching                   | **No** — no puede modificar código de ntdll firmado              |
| NtAllocateVirtualMemory (RW)   | Sí                                                               |
| NtProtectVirtualMemory (RW→RX) | **No** — MEM_PRIVATE + RX bloqueado por HVCI                     |
| Payload ASM execution          | **No** — código no firmado no ejecutable                         |

**Conclusión:** Con HVCI activo, el vector de ataque se bloquea en la Etapa 4 sin posibilidad de evasión significativa, ya que el payload ASM no puede ejecutarse desde una página no firmada.

### 16.3 Análisis Probabilístico de Defensa

$$P(\text{Éxito del cargador}) = \prod_{i=1}^{n} (1 - p_i)$$

| Defensa                           | $p_i$ (empresa promedio) | $p_i$ (entorno endurecido) |
| --------------------------------- | ------------------------ | -------------------------- |
| HVCI/VBS                          | 0.30                     | 0.90                       |
| EDR con componente kernel         | 0.50                     | 0.95                       |
| ETW integrity checking            | 0.20                     | 0.80                       |
| NtProtectVirtualMemory monitoring | 0.40                     | 0.90                       |
| APC cross-process monitoring      | 0.25                     | 0.75                       |
| ASR rules (code injection)        | 0.20                     | 0.80                       |
| Intel CET / Shadow Stack          | 0.10                     | 0.60                       |

**Empresa promedio:**

$$P(\text{Éxito}) \approx 0.70 \times 0.50 \times 0.80 \times 0.60 \times 0.75 \times 0.80 \times 0.90 \approx 0.091 \quad (\approx 9.1\%)$$

**Entorno endurecido:**

$$P(\text{Éxito}) \approx 0.10 \times 0.05 \times 0.20 \times 0.10 \times 0.25 \times 0.20 \times 0.40 \approx 0.000002 \quad (\approx 0.0002\%)$$

---

## 17. Mutaciones y Evolución Post-Detección

### 17.1 Tendencias de Mutación

**Mutación 1 — Abandono de unhooking en favor de direct syscalls:**

```
2021: Unhooking completo de ntdll → ETW Patch → inyección
2023: Sin unhooking → direct syscalls con números pre-resueltos → inyección
2024: Indirect syscalls con stack spoofing → sin unhooking ni ETW patch
```

**Mutación 2 — Migración de user-mode a kernel-mode:**

```
2021: Todo en user-mode (cargador C++ + payload ASM)
2023: Cargador en user-mode → payload ejecuta en kernel-mode
      (vía vulnerabilidades de driver, BYOVD - Bring Your Own Vulnerable Driver)
2024: Payload opera directamente desde kernel-mode
      (EDR completamente eludido en user-mode)
```

**Mutación 3 — Uso de técnicas de memoria legítima:**

```
2021: MEM_PRIVATE + RW → RX (inyección clásica)
2023: Module Stomping (sobrescribir código de un DLL legítimo cargado)
      → La ejecución ocurre dentro de una sección firmada
2024: Ghosting / Phantom DLL Hollowing
      → Carga de DLL legítima, reemplazo de contenido antes de que el
        loader lo procese
```

**Mutación 4 — Callback hooks en lugar de inyección directa:**

```
2021: Crear hilo → ejecutar payload
2023: Registrar callback en ntdll (vía vectored exception handler)
      → Payload se ejecuta cuando ocurre la excepción
2024: Manipular thread context de hilos existentes
      → NtSetContextThread redirige RIP al payload
      → Sin crear hilos, sin encolar APCs
```

### 17.2 Carrera Armamentista: Cargador vs. EDR

```
═══════════════════════════════════════════════════════════════════
    CARRERA ARMAMENTISTA: CARGADOR C++ vs. EDR
═══════════════════════════════════════════════════════════════════

  2018: Cargador usa CreateRemoteThread + WriteProcessMemory
        │
        ▼
  2018: EDR detecta cross-process thread creation
        │
        ▼
  2019: Cargador usa NtCreateThreadEx (syscall directo)
        │
        ▼
  2019: EDR detecta syscall desde fuera de ntdll
        │
        ▼
  2020: Cargador usa unhooking + indirect syscalls
        │
        ▼
  2020: EDR monitorea lecturas de ntdll desde disco
        │
        ▼
  2021: Cargador añade ETW patching
        │
        ▼
  2021: EDR usa kernel-mode ETW (no afectado por user-mode patch)
        │
        ▼
  2022: Cargador usa APC injection + indirect syscalls
        │
        ▼
  2022: EDR monitorea NtQueueApcThread cross-process
        │
        ▼
  2023: Cargador usa module stomping + stack spoofing
        │
        ▼
  2023: EDR usa HVCI para bloquear ejecución desde páginas no firmadas
        │
        ▼
  2024: Cargador usa BYOVD + kernel-mode execution
        │
        ▼
  2024: EDR monitorea carga de drivers + firma de código
        │
        ▼
  ... (carrera continúa)

═══════════════════════════════════════════════════════════════════
```

---

## 18. Referencias y Marco Normativo

### Sistemas Operativos y Kernel NT

- Russinovich, M., Solomon, D., & Ionescu, A. (2021). _Windows Internals_, 7th Edition. Microsoft Press.
- Nebbett, G. (2000). _Windows NT/2000 Native API Reference._ Sams Publishing.
- Yason, M. (2019). _Windows 10 x64 Ring 0 to Ring 3 Internals._ OFFSEC.

### Evasión de Telemetría y Detección

- Ligh, M.H., Case, A., Levy, J., & Walters, A. (2014). _The Art of Memory Forensics._ Wiley.
- MalwareTech (2023). _"EDR Evasion Techniques: A Taxonomy."_ Black Hat USA.
- Tal, L. (2019). _"AMSI Bypass: A Review of Techniques."_ Black Hat Europe.
- Bohannon, D. (2018). _"Invoke-Obfuscation: PowerShell Obfuscation."_ DerbyCon.
- Reveng Project (2022). _"Indirect Syscalls in Malware: Detection and Evasion."_
- Elastic Security Labs (2023). _"Unhooking: Detection Techniques."_

### Teoría de Concurrencia y CSP

- Hoare, C.A.R. (1985). _Communicating Sequential Processes._ Prentice Hall.
- Schneider, S. (1999). _Concurrent and Real-Time Systems: The CSP Approach._ Wiley.
- Milner, R. (1989). _Communication and Concurrency._ Prentice Hall.

### Modelo CIM, WMI y WQL

- DMTF (2023). _Common Information Model (CIM) Infrastructure Specification_, DSP0004.
- Golomshtok, A. (2007). _WMI Essentials for Automating Windows Management._ Sams Publishing.

### COM/DCOM y Distribución

- Box, D. (1998). _Essential COM._ Addison-Wesley.
- Brown, N. & Kindel, C. (1998). _Distributed Component Object Model Protocol._ Microsoft.

### Análisis de Campañas APT

- Mandiant (2022). _"APT29 and Novel Delivery Mechanisms."_
- Recorded Future (2023). _"LOLBin Evolution: From Convenience to Evasion."_
- CrowdStrike (2023). _"eCrime and Nation-State Tactics: Loader Evolution."_
- SentinelOne (2023). _"The Loader Arms Race: Anatomy of Modern Droppers."_

### MITRE ATT&CK

- MITRE ATT&CK (2024). _T1055: Process Injection._
- MITRE ATT&CK (2024). _T1055.004: Asynchronous Procedure Call._
- MITRE ATT&CK (2024). _T1562.001: Impair Defenses — Disable or Modify Tools._
- MITRE ATT&CK (2024). _T1562.006: Impair Defenses — Indicator Blocking._
- MITRE ATT&CK (2024). _T1622: Debugger Evasion._
- MITRE ATT&CK (2024). _T1218: System Binary Proxy Execution._

### Teoría de la Información

- Shannon, C.E. (1948). _"A Mathematical Theory of Communication."_ Bell System Technical Journal.
- Cover, T.M. & Thomas, J.A. (2006). _Elements of Information Theory_, 2nd Edition. Wiley.

### Álgebra y Teoría de Categorías

- Pierce, B.C. (1991). _Basic Category Theory for Computer Scientists._ MIT Press.
- Mac Lane, S. (1998). _Categories for the Working Mathematician_, 2nd Edition. Springer.

### Seguridad de Hardware

- Intel (2024). _Control-flow Enforcement Technology Specification._ Intel Architecture.
- Microsoft (2024). _Virtualization-Based Security (VBS) and HVCI._ Microsoft Learn.

---

_Documento de investigación técnica sobre los mecanismos de evasión de telemetría implementados por el cargador C++, incluyendo resolución de APIs, unhooking, ETW patching, indirect syscalls, gestión de memoria, y el mecanismo de Procedimientos Asíncronos del kernel NT. El análisis se limita a la descripción objetiva del fenómeno desde la perspectiva de la ciencia computacional, la teoría de concurrencia, y los modelos formales de seguridad, con el propósito de fundamentar mecanismos de detección y defensa._
