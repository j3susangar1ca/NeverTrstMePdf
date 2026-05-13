# Etapa 1 — El Contenedor ISO: Bypass del Mark-of-the-Web

## Documentación Técnica de Nivel APT/Intelligence-Grade

### Análisis Formal del Mecanismo, Superficies de Ataque, Teoría de la Información, y Marcos de Detección

---

## Índice

1. [Resumen Ejecutivo Clasificado](#1-resumen-ejecutivo)
2. [Modelo Formal del Mark-of-the-Web como Sistema de Atribución de Confianza](#2-modelo-formal-motw)
3. [Arquitectura del Subsistema de Montaje y la Brecha Estructural](#3-arquitectura-montaje)
4. [Análisis Algebraico de la Violación de Propagación Transitiva](#4-analisis-algebraico)
5. [Teoría de la Información Aplicada: Pérdida de Entropía de Confianza](#5-teoria-informacion)
6. [El Sistemas de Archivos ISO 9660/UDF como Vector de Contención](#6-sistemas-archivos)
7. [Ingeniería del Atributo FILE_ATTRIBUTE_HIDDEN como Mecanismo de Selección](#7-atributo-hidden)
8. [Análisis de la Cadena de Confianza Rota: Del Contenedor al Contenido](#8-cadena-confianza)
9. [Superficie de Detección: Formalización y Predicados de Alerta](#9-superficie-deteccion)
10. [Historial de Explotación Documentado y Contexto APT](#10-historial-apts)
11. [Contramedidas: Niveles de Defensa según Modelo de Capas](#11-contramedidas)
12. [Análisis de Variaciones y Mutaciones del Vector](#12-variaciones)
13. [Referencias y Marco Normativo](#13-referencias)

---

## 1. Resumen Ejecutivo

El Mark-of-the-Web (MotW) constituye el **mecanismo primario de atribución de confianza** de Windows para contenido proveniente de fuentes remotas. Su función es etiquetar archivos descargados con una marca de zona de seguridad que desencadena inspección diferencial por parte de SmartScreen, AMSI, y las políticas de ejecución de PowerShell.

El bypass mediante contenedores ISO explota una **discontinuidad arquitectónica** en la cadena de propagación de atributos de seguridad: el subsistema de montaje de imágenes de disco (`vhdmp.sys` / `vdrvroot.sys`) proyecta sistemas de archivos que no soportan Alternate Data Streams (ADS) NTFS como volúmenes virtuales, sin sintetizar el atributo de zona heredado del contenedor. El resultado es que los archivos internos al contenedor montado carecen de toda marca de zona, quedando exentos de inspección agravada por SmartScreen y AMSI.

Esta brecha no es un defecto de codificación sino una **incompatibilidad de modelos de datos** entre el esquema de atributos NTFS y los sistemas de archivos ópticos (ISO 9660, UDF). Su persistencia desde Windows XP hasta Windows 11 21H2, y su corrección parcial en 22H2, la convierten en una de las vulnerabilidades de diseño más explotadas por actores de amenaza avanzada entre 2021 y 2024.

---

## 2. Modelo Formal del Mark-of-the-Web como Sistema de Atribución de Confianza

### 2.1 Definición del Mecanismo MotW

El Mark-of-the-Web es un mecanismo de **atribución de zona de seguridad** implementado sobre el subsistema NTFS mediante Alternate Data Streams (ADS). Formalmente:

**Definición 2.1.1 — Función de Atribución de Zona**

Sea $\mathcal{F}$ el conjunto de archivos en un volumen y $\mathcal{Z} = \{0, 1, 2, 3, 4\}$ el conjunto de zonas de seguridad:

| Zona | Valor | Descripción |
|---|---|---|
| Local Machine | 0 | Contenido local, máxima confianza |
| Local Intranet | 1 | Red corporativa interna |
| Trusted Sites | 2 | Sitios marcados como confiables por el usuario |
| Internet | 3 | Contenido de Internet, confianza restringida |
| Restricted Sites | 4 | Sitios marcados como restringidos |

La función de atribución de zona es:

$$\text{ZoneAttrib}: \mathcal{F} \rightarrow \mathcal{Z} \cup \{\bot\}$$

donde $\text{ZoneAttrib}(f) = \bot$ indica que el archivo $f$ no posee atributo de zona.

### 2.2 Implementación del Attachment Execution Service (AES)

La implementación de esta función depende del **Attachment Execution Service (AES)**, componente de `shlwapi.dll` que escribe el ADS `Zone.Identifier` como flujo NTFS alternativo:

```
Zone.Identifier ADS = {
    [ZoneTransfer]
    ZoneId      ∈ Z            ; Valor de zona
    ReferrerUrl ∈ {0,1}^*      ; URL de referencia (opcional)
    HostUrl     ∈ {0,1}^*      ; URL de origen (opcional)
    LastWriterPackageFamilyName ∈ {0,1}^*  ; Win10+
    SmartScreen ∈ {0,1}^*      ; Nivel de SmartScreen (Win11+)
    Flags       ∈ N            ; Flags adicionales (Win11+)
}
```

El ADS se almacena como un flujo de datos NTFS asociado al archivo principal:

```
archivo.iso                  → flujo principal (datos del ISO)
archivo.iso:Zone.Identifier  → flujo alternativo (metadatos de zona)
```

### 2.3 Consumidores del Atributo de Zona

El atributo de zona es consultado por múltiples subsistemas de seguridad:

| Consumidor | Mecanismo | Efecto de ZoneId=3 |
|---|---|---|
| **SmartScreen** (`smartscreen.exe`) | Verificación reputacional contra base de datos Microsoft | Bloqueo o advertencia antes de ejecución |
| **AMSI** (`amsi.dll`) | Antimalware Scan Interface — inspección de contenido dinámico | Escaneo agravado de scripts y binarios |
| **PowerShell** | `Set-ExecutionPolicy RemoteSigned` | Bloqueo de scripts sin firma digital |
| **Office Protected View** | Modo de apertura restrictivo para documentos | Apertura en sandbox con macros deshabilitadas |
| **Windows Explorer** | Barra de advertencia "este archivo proviene de otro equipo" | Banner de advertencia al usuario |
| **Attachment Manager** | Control de ejecución de adjuntos | Advertencia antes de abrir |

**Predicado formal del bloqueo:**

$$\text{ShouldBlock}(f) \iff \text{ZoneAttrib}(f) = 3 \wedge \text{IsExecutable}(f) \wedge \text{HasNoReputation}(f)$$

### 2.4 Anatomía de la Evaluación de SmartScreen

Cuando un archivo con $\text{ZoneAttrib}(f) = 3$ es ejecutado, Windows invoca el flujo de evaluación de SmartScreen:

```
[1] Usuario ejecuta archivo
        │
        ▼
[2] Shell32.dll verifica Zone.Identifier ADS
        │
        ├── ZoneId = ∅ → Ejecución directa (sin inspección)
        │
        └── ZoneId = 3 → Invocar SmartScreen
                │
                ▼
        [3] smartscreen.exe consulta AppRep
                │
                ├── Hash conocido + buena reputación → Permitir
                ├── Hash desconocido → Bloquear (alta confianza)
                └── Hash conocido + mala reputación → Bloquear
```

**La eficacia de SmartScreen depende críticamente de la presencia del ADS.** Sin `Zone.Identifier`, el flujo se detiene en el paso [2] y la ejecución procede sin inspección.

---

## 3. Arquitectura del Subsistema de Montaje y la Brecha Estructural

### 3.1 Arquitectura del Driver de Montaje

Windows 11 soporta el montaje nativo de imágenes ISO y VHD a través de la siguiente pila de drivers:

```
┌─────────────────────────────────────────┐
│  User Mode                               │
│  ┌─────────────────────────────────┐    │
│  │  Explorer.exe (doble clic)      │    │
│  │  → shell32.dll → MountVolume    │    │
│  └──────────┬──────────────────────┘    │
│             │ IOCTL_MOUNTDEV_POINT       │
│             ▼                             │
├─────────────────────────────────────────┤
│  Kernel Mode                             │
│  ┌─────────────────────────────────┐    │
│  │  vdrvroot.sys                    │    │
│  │  (Virtual Drive Root Driver)     │    │
│  │  → Enumera dispositivos virtuales│    │
│  └──────────┬──────────────────────┘    │
│             │                             │
│  ┌──────────▼──────────────────────┐    │
│  │  vhdmp.sys                       │    │
│  │  (VHD/ISO Mount Point Driver)    │    │
│  │  → Parsea ISO 9660 / UDF         │    │
│  │  → Proyecta como volumen NTFS    │    │
│  │  → Asigna letra de unidad        │    │
│  └──────────┬──────────────────────┘    │
│             │                             │
│  ┌──────────▼──────────────────────┐    │
│  │  NTFS.sys / FAT/exFAT            │    │
│  │  (Puede o no estar involucrado)  │    │
│  │  → ISO 9660/UDF no es NTFS      │    │
│  │  → Driver propio de proyección   │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

### 3.2 El Flujo de Descarga y Atribución

Cuando un archivo `.iso` es descargado desde Internet (por ejemplo, mediante un navegador), el flujo es:

```
[1] Navegador descarga "archivo.iso"
        │
        ▼
[2] Attachment Execution Service (AES) interviene
        │
        ├── AES.writeADS(archivo.iso, "Zone.Identifier")
        │     Content: [ZoneTransfer]\nZoneId=3\nReferrerUrl=...
        │
        ├── ZoneAttrib(archivo.iso) = 3  ✓
        │
        ▼
[3] Archivo almacenado en disco con ADS
        │
        ├── archivo.iso           ← datos del ISO
        ├── archivo.iso:Zone.Identifier  ← ADS con ZoneId=3
        │
        ▼
[4] Usuario hace doble clic en archivo.iso
        │
        ▼
[5] Shell invoca montaje: vhdmp.sys procesa el ISO
        │
        ▼
[6] Volumen virtual montado como unidad (ej: E:\)
        │
        ▼
[7] Archivos internos visibles en Explorer
        │
        ├── E:\factura.pdf.lnk    ← ¿Zone.Identifier?
        ├── E:\documento.pdf       ← ¿Zone.Identifier?
        └── E:\datos\              ← ¿Zone.Identifier?
```

### 3.3 La Brecha: No-Propagación del ADS al Volumen Montado

**El punto de fallo está entre los pasos [5] y [7].**

El driver `vhdmp.sys` proyecta el sistema de archivos del ISO (ISO 9660 o UDF) como un volumen accesible. Sin embargo:

1. **ISO 9660/UDF no soportan ADS**: Los sistemas de archivos ISO 9660 y UDF no tienen el concepto de flujos de datos alternativos. Son sistemas de archivos planos con metadatos limitados (nombre, tamaño, fecha, flags).

2. **El driver no sintetiza ADS**: `vhdmp.sys` no genera un ADS `Zone.Identifier` sintético para los archivos proyectados a partir de la zona del contenedor.

3. **NTFS no interviene**: El volumen montado no es un volumen NTFS real. Es una proyección del driver que emula un sistema de archivos accesible vía la API de Windows, pero sin las capacidades extendidas de NTFS.

**Formalización del problema:**

Sea $\text{Proj}: \mathcal{F}_{ISO} \rightarrow \mathcal{F}_{virtual}$ la función de proyección que mapea archivos del ISO a archivos accesibles en el volumen montado. Se verifica que:

$$\text{ZoneAttrib}(\text{Proj}(f)) = \bot \quad \forall f \in \mathcal{F}_{ISO}$$

independientemente de:

$$\text{ZoneAttrib}(\text{Contenedor}(f)) = 3$$

### 3.4 Análisis del Flujo de Datos a Nivel de Driver

A nivel de kernel, el flujo de montaje de un ISO sigue esta secuencia de operaciones:

```
[1] NtCreateFile("\\??\\C:\\Users\\...\\archivo.iso", GENERIC_READ)
        │
        ▼
[2] IOCTL_STORAGE_LOAD_VIRTUAL_CD (a través de vdrvroot.sys)
        │
        ▼
[3] vhdmp.sys:
    ├── NtReadFile → leer header del ISO (primeros 32KB)
    ├── Parsear System Area (sectores 0-15)
    ├── Localizar Primary Volume Descriptor (sector 16)
    ├── Parsear Directory Records
    ├── Crear Device Object para el volumen virtual
    └── Registrar volumen en el Object Manager
        │
        ▼
[4] IopMountVolume → el I/O Manager asigna letra de unidad
        │
        ▼
[5] PnP Manager notifica: GUID_DEVINTERFACE_VOLUME
        │
        ▼
[6] Shell recibe notificación y muestra contenido en Explorer
```

**En ningún punto de esta cadena se verifica ni se propaga el atributo de zona del archivo `.iso` a los archivos internos.**

### 3.5 Diagrama de la Brecha Estructural

```
┌─────────────────────────────────────────────────────────────────┐
│               FLUJO DE ATRIBUCIÓN MotW                          │
│               BRECHA ESTRUCTURAL EN MONTAJE ISO                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Descarga desde Internet                                       │
│          │                                                      │
│          ▼                                                      │
│   ┌─────────────────────────────────────┐                       │
│   │  AES (shlwapi.dll)                  │                       │
│   │  ZoneAttrib(iso) = 3                │                       │
│   │  Escribe ADS: Zone.Identifier       │                       │
│   │  sobre archivo.iso (NTFS)           │                       │
│   └──────────┬──────────────────────────┘                       │
│              │                                                   │
│     ┌────────┴────────┐                                         │
│     │                 │                                         │
│     ▼                 ▼                                          │
│  NTFS Nativo      Montaje ISO                                   │
│  (Copia manual)   (vhdmp.sys)                                   │
│     │                 │                                          │
│     ▼                 ▼                                          │
│  ┌──────────┐   ┌──────────────────────────────────────────┐    │
│  │Propagación│   │  NO Propagación                          │    │
│  │Transitiva│   │                                           │    │
│  │Correcta  │   │  ISO 9660/UDF ≠ NTFS                    │    │
│  │          │   │  No existe capacidad de ADS en FS fuente │    │
│  │Zona(f)=3 │   │  vhdmp.sys no sintetiza ADS              │    │
│  │          │   │                                           │    │
│  │SmartScreen│   │  ZoneAttrib(f_hijo) = ⊥                 │    │
│  │interviene│   │                                           │    │
│  │          │   │  SmartScreen NO interviene                │    │
│  │          │   │  PowerShell NO bloquea                    │    │
│  │          │   │  Explorer NO muestra advertencia          │    │
│  │          │   │  AMSI NO se activa por zona               │    │
│  └──────────┘   └──────────────────────────────────────────┘    │
│                                                                 │
│   VULNERABILIDAD: ¬PPT  ∃f ⊑ c : ZoneAttrib(f) = ⊥            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Análisis Algebraico de la Violación de Propagación Transitiva

### 4.1 Relación de Contención Archivística

**Definición 4.1.1 — Relación de Contención**

Sea $\sqsubseteq \;\subseteq \mathcal{F} \times \mathcal{F}$ la relación "está archivado dentro de". Para un contenedor ISO $c$ y un archivo contenido $f$, escribimos $f \sqsubseteq c$.

**Propiedades:**

- **Reflexiva:** $\forall f: f \sqsubseteq f$
- **Transitiva:** $f_1 \sqsubseteq f_2 \wedge f_2 \sqsubseteq f_3 \Rightarrow f_1 \sqsubseteq f_3$
- **Antisimétrica:** $f_1 \sqsubseteq f_2 \wedge f_2 \sqsubseteq f_1 \Rightarrow f_1 = f_2$

El par $(\mathcal{F}, \sqsubseteq)$ forma un **preorden parcial** (partial order).

### 4.2 Propiedad de Propagación Transitiva (PPT)

**Definición 4.2.1 — PPT**

En un volumen NTFS nativo, se espera que la función de atribución de zona satisfaga:

$$\text{PPT}: \forall f_1, f_2 \in \mathcal{F}: f_1 \sqsubseteq f_2 \wedge \text{ZoneAttrib}(f_2) \neq \bot \Rightarrow \text{ZoneAttrib}(f_1) = \text{ZoneAttrib}(f_2)$$

En NTFS nativo, esta propiedad se cumple porque los ADS se heredan por copia y por la operación de "marca de herencia" del AES al extraer archivos.

### 4.3 Teorema de Violación de la PPT

**Teorema 4.3.1 — Violación de la PPT en Volúmenes Montados desde ISO**

*Sea $c$ un contenedor ISO con $\text{ZoneAttrib}(c) = 3$. Sea $V_c$ el volumen virtual montado desde $c$ por el driver `vhdmp.sys`. Entonces:*

$$\exists\, f \in V_c : f \sqsubseteq c \wedge \text{ZoneAttrib}(f) = \bot$$

**Demostración (esquema):**

1. El AES escribe `Zone.Identifier` exclusivamente como ADS NTFS sobre el archivo `.iso`.
2. El driver `vhdmp.sys` proyecta el sistema de archivos ISO 9660/UDF como volumen virtual.
3. ISO 9660/UDF no soporta ADS NTFS (no es NTFS); el sistema de archivos proyectado carece de la capacidad de almacenar flujos alternativos.
4. El subsistema NTFS no intercepta el montaje para propagar el ADS del contenedor a los archivos proyectados.
5. Por lo tanto: $\text{ZoneAttrib}(f) = \bot$ para todo $f$ en el volumen montado.

$\blacksquare$

### 4.4 Morfismo de Preórdenes y su Ruptura

La función de atribución de zona en un volumen NTFS es un **morfismo de preórdenes**:

$$\text{ZoneAttrib}: (\mathcal{F}_{NTFS}, \sqsubseteq) \rightarrow (\mathcal{Z}, =)$$

que preserva la relación de orden: si $f_1 \sqsubseteq f_2$, entonces $\text{ZoneAttrib}(f_1) = \text{ZoneAttrib}(f_2)$.

En un volumen ISO montado, esta función **deja de ser un morfismo**:

$$\text{ZoneAttrib}_{ISO}: (\mathcal{F}_{ISO}, \sqsubseteq) \rightarrow (\mathcal{Z} \cup \{\bot\}, =)$$

La estructura algebraica se rompe: la relación de contención $\sqsubseteq$ se preserva en el dominio (los archivos siguen estando "dentro" del ISO), pero la función de atribución mapea todo a $\bot$.

### 4.5 Implicaciones del Morfismo Roto

La ruptura del morfismo tiene consecuencias en cascada para toda la cadena de evaluación de confianza:

```
Morfo roto
    │
    ▼
ZoneAttrib(f) = ⊥ para f ∈ ISO montado
    │
    ├──→ SmartScreen: ShouldBlock(f) = FALSE (no hay zona → no hay evaluación)
    ├──→ AMSI: ScanDepth = Normal (sin zona → sin escaneo agravado)
    ├──→ PowerShell: RemoteSigned = N/A (no hay zona → no hay bloqueo)
    ├──→ Explorer: ShowWarning = FALSE (no hay zona → no hay banner)
    └──→ Attachment Manager: AllowExecution = TRUE
```

**Definición 4.5.1 — Cadena de Evaluación de Confianza**

Sea $\mathcal{E} = (e_1, e_2, \ldots, e_n)$ la cadena de evaluaciones de seguridad que se activan cuando un archivo tiene zona atribuida. Definimos la **función de activación**:

$$\alpha: \mathcal{Z} \cup \{\bot\} \rightarrow \mathcal{P}(\mathcal{E})$$

$$\alpha(z) = \begin{cases} \{e_1, e_2, \ldots, e_n\} & \text{si } z = 3 \text{ (todas las evaluaciones activas)} \\ \{e_i\}_{i \in I_z} & \text{si } z \in \{0, 1, 2, 4\} \text{ (subconjunto)} \\ \emptyset & \text{si } z = \bot \text{ (ninguna evaluación)} \end{cases}$$

La explotación del vector consiste en transformar el valor de zona de $3$ a $\bot$, reduciendo $\alpha(3)$ a $\alpha(\bot) = \emptyset$.

---

## 5. Teoría de la Información Aplicada: Pérdida de Entropía de Confianza

### 5.1 Entropía del Sistema de Zonas

**Definición 5.1.1 — Entropía de Shannon del Espacio de Zonas**

La entropía del espacio de zonas de seguridad es:

$$H(Z) = -\sum_{z \in \mathcal{Z}} P(z) \log_2 P(z)$$

Bajo distribución uniforme sobre $|\mathcal{Z}| = 5$ zonas:

$$H(Z) = \log_2 5 \approx 2.32 \;\text{bits}$$

### 5.2 Entropía Condicional en NTFS Nativo vs. ISO Montado

**Definición 5.2.1 — Entropía Condicional de la Zona dado el Archivo**

$$H(Z \mid F) = -\sum_{f \in \mathcal{F}} P(f) \sum_{z \in \mathcal{Z}} P(z \mid f) \log_2 P(z \mid f)$$

En NTFS nativo, dado el archivo, la zona está **determinada** por herencia (PPT se cumple):

$$H(Z \mid F_{NTFS}) = 0$$

En un volumen ISO montado, la zona del archivo es **independiente** del contenedor (PPT se viola):

$$H(Z \mid F_{ISO}) = H(Z) \approx 2.32 \;\text{bits}$$

### 5.3 Ganancia de Entropía por No-Propagación

**Teorema 5.3.1 — Ganancia de Entropía**

$$\Delta H = H(Z \mid F_{ISO}) - H(Z \mid F_{NTFS}) = H(Z) - 0 = H(Z) \approx 2.32 \;\text{bits/archivo}$$

Esta ganancia de entropía representa la **incertidumbre introducida** por la no-propagación. Para el sistema de detección, esto se traduce en una pérdida de información: el EDR ya no puede determinar la zona de un archivo dentro de un ISO montado solo inspeccionando el contenedor.

### 5.4 Información Mutua entre Contenedor y Contenido

**Definición 5.4.1 — Información Mutua**

La información mutua entre la zona del contenedor $Z_c$ y la zona del archivo contenido $Z_f$ es:

$$I(Z_c; Z_f) = H(Z_c) - H(Z_c \mid Z_f)$$

En NTFS nativo (con propagación):

$$I(Z_c; Z_f)_{NTFS} = H(Z_c) \quad \text{(zona del contenido determinada completamente por el contenedor)}$$

En volumen ISO montado (sin propagación):

$$I(Z_c; Z_f)_{ISO} = 0 \quad \text{(zona del contenido independiente del contenedor)}$$

**La información mutua cae de $H(Z_c) \approx 2.32$ bits a $0$ bits.** Esta es la **destrucción total de información de confianza** en la transición del contenedor al contenido montado.

### 5.5 Implicaciones para la Detección

Desde la perspectiva de la teoría de la información, un mecanismo de detección que dependa de la zona de los archivos internos a un ISO montado recibe **cero información** sobre la confianza del contenedor padre. Esto significa que:

$$I(\text{Detección}; \text{Ataque})_{ISO} = 0$$

si la detección depende exclusivamente del atributo de zona de los archivos internos. El detector debe buscar señales **fuera del mecanismo de zona** para compensar esta pérdida de información:

$$I(\text{Detección}'; \text{Ataque}) > 0 \quad \text{donde Detección'} = f(\text{montaje}, \text{estructura}, \text{heurísticas})$$

---

## 6. El Sistema de Archivos ISO 9660/UDF como Vector de Contención

### 6.1 Estructura de ISO 9660

ISO 9660 es un sistema de archivos de solo lectura diseñado para medios ópticos. Su estructura interna define un conjunto finito de metadatos por archivo:

**Definición 6.1.1 — Registro de Directorio ISO 9660**

Cada archivo/directorio en ISO 9660 se describe mediante un **Directory Record** de longitud variable:

```
Offset  Size   Field
------  ----   -----
0       1      Length of Directory Record (LEN_DR)
1       1      Extended Attribute Record Length
2       8      Location of Extent (LBA, little-endian + big-endian)
10      8      Data Length (little-endian + big-endian)
18      7      Recording Date and Time
25      1      File Flags
26      1      File Unit Size
27      1      Interleave Gap Size
28      4      Volume Sequence Number
32      1      Length of File Identifier (LEN_FI)
33      LEN_FI  File Identifier
33+LEN_FI  1   Padding Field (if LEN_FI is even)
```

### 6.2 File Flags de ISO 9660 y la Traducción a Windows

El byte de **File Flags** (offset 25) contiene los siguientes bits:

| Bit | Nombre | Significado en ISO 9660 | Traducción Windows |
|---|---|---|---|
| 0 | Hidden | Archivo oculto | `FILE_ATTRIBUTE_HIDDEN` (0x02) |
| 1 | Directory | Es directorio | `FILE_ATTRIBUTE_DIRECTORY` (0x10) |
| 2 | Associated File | Archivo asociado | No traducido directamente |
| 3 | Record | Información en formato de registro | No traducido |
| 4 | Protection | Permisos definidos | Parcialmente traducido |
| 5-7 | Reserved | Reservado (deben ser 0) | Ignorados |

**Observación crítica:** El bit de archivo oculto (bit 0) es el único metadato de visibilidad disponible en ISO 9660. No existe ningún campo para atributos extendidos NTFS, ADS, o información de zona de seguridad.

### 6.3 Estructura de UDF (Universal Disk Format)

UDF es un sucesor de ISO 9660 con más flexibilidad. Sin embargo, aunque UDF soporta atributos extendidos (Extended Attributes), estos están diseñados para POSIX-like permissions y timestamps, **no para ADS de NTFS**:

```
UDF Extended Attributes:
  - POSIX File Permissions (owner, group, other)
  - POSIX File Times (access, modification, creation)
  - Application Use Extended Attribute
  - Implementation Use Extended Attribute
```

Ninguno de estos campos puede transportar un ADS `Zone.Identifier`. La función de proyección del driver `vhdmp.sys` traduce los atributos UDF a atributos NTFS equivalentes (`FILE_ATTRIBUTE_READONLY`, `FILE_ATTRIBUTE_HIDDEN`, etc.) pero no puede crear ADS desde metadatos que no existen en el formato fuente.

### 6.4 Tabla de Comparación de Capacidades de Metadatos

| Capacidad | NTFS | ISO 9660 | UDF |
|---|---|---|---|
| Nombre de archivo | Hasta 255 chars Unicode | 8.3 o hasta 222 chars (Level 3) | Hasta 255 chars Unicode |
| Tamaño | 64-bit | 32-bit (4GB max) | 64-bit |
| Timestamps | Creation, Modified, Accessed, MFT Modified | Recording Date/Time (un solo campo) | Creation, Modified, Accessed, Attribute Modified |
| Permisos | ACL (DACL/SACL) | Bit de protección (5 bits) | POSIX-like permissions |
| ADS (Alternate Data Streams) | **Sí** (múltiples flujos por archivo) | **No** | **No** |
| Extended Attributes | **Sí** (EA completa) | **No** | Limitados (no NTFS-compatible) |
| Zona de seguridad | **Sí** (vía ADS Zone.Identifier) | **No** | **No** |
| Compressão | Sí (LZNT1) | No | No (requiere VAT) |
| Cifrado | Sí (EFS) | No | No |

**Conclusión:** Ningún sistema de archivos óptico soporta la capacidad de almacenar atributos de zona de seguridad. Esto es una **limitación fundamental del formato**, no una omisión corregible en el driver de montaje.

---

## 7. Ingeniería del Atributo FILE_ATTRIBUTE_HIDDEN como Mecanismo de Selección

### 7.1 Función de Visibilidad

**Definición 7.1.1 — Función de Visibilidad**

Windows traduce el bit 0 de los File Flags de ISO 9660 al atributo `FILE_ATTRIBUTE_HIDDEN` (0x02). Definimos:

$$\text{Vis}: \mathcal{F} \rightarrow \{\text{Visible}, \text{Hidden}\}$$

$$\text{Vis}(f) = \begin{cases} \text{Hidden} & \text{si } f.\text{Attributes} \wedge \text{FILE\_ATTRIBUTE\_HIDDEN} \neq 0 \\ \text{Visible} & \text{en otro caso} \end{cases}$$

### 7.2 Filtro de Visualización del Explorador

La configuración predeterminada del Explorador de Windows implementa un **filtro de visibilidad**:

$$\text{ExplorerView} = \{f \in \mathcal{F} \mid \text{Vis}(f) = \text{Visible}\}$$

Esto significa que al abrir un ISO montado, el usuario solo ve los archivos visibles. Los archivos con `FILE_ATTRIBUTE_HIDDEN` están presentes en el volumen pero **no se renderizan** en la interfaz.

### 7.3 Ratio de Ocultamiento

**Definición 7.3.1 — Ratio de Ocultamiento**

Sea $\mathcal{F}_{ISO}$ el conjunto de todos los archivos en el ISO. Definimos el ratio de ocultamiento:

$$\rho_{hide} = \frac{|\mathcal{F}_{hidden}|}{|\mathcal{F}_{ISO}|}$$

donde $\mathcal{F}_{hidden} = \{f \in \mathcal{F}_{ISO} \mid \text{Vis}(f) = \text{Hidden}\}$.

**Análisis heurístico:**

| Tipo de ISO | $\rho_{hide}$ típico | Interpretación |
|---|---|---|
| ISO de instalación de software legítimo | $\rho_{hide} \approx 0.0 - 0.1$ | Pocos o ningún archivo oculto |
| ISO de distribución de SO | $\rho_{hide} \approx 0.05 - 0.15$ | Algunos archivos de sistema ocultos |
| ISO malicioso (vector de ataque) | $\rho_{hide} \approx 0.6 - 1.0$ | La mayoría de archivos ocultos |
| ISO con señuelo único | $\rho_{hide} \rightarrow 1$ | Solo el señuelo visible |

### 7.4 Invariante Detectable

**Teorema 7.4.1 — Detección por Ratio de Ocultamiento**

*Un ISO donde $\rho_{hide} > \theta$ (para un umbral $\theta \approx 0.5$) presenta una distribución anómala de visibilidad que es estadísticamente distinguible de la distribución de ISOs legítimos.*

**Demostración (esquema):**

Se asume que la distribución de $\rho_{hide}$ para ISOs legítimos se modela como:

$$\rho_{legítimo} \sim \text{Beta}(\alpha_1, \beta_1) \quad \text{con } \alpha_1 \ll \beta_1 \quad \text{(concentración cerca de 0)}$$

y la distribución para ISOs maliciosos:

$$\rho_{malicioso} \sim \text{Beta}(\alpha_2, \beta_2) \quad \text{con } \alpha_2 \gg \beta_2 \quad \text{(concentración cerca de 1)}$$

La separación de estas distribuciones permite clasificación con tasa de error acotada. Un detector basado en $\rho_{hide} > \theta$ tiene:

$$P(\text{FP}) = P(\rho_{legítimo} > \theta) \approx 0$$

$$P(\text{FN}) = P(\rho_{malicioso} < \theta) \approx \text{pequeño}$$

$\blacksquare$

### 7.5 Análisis de la Estructura Interna de un ISO Malicioso Típico

Un ISO diseñado para explotar esta vulnerabilidad presenta una estructura interna característica:

```
ISO Root (ISO 9660 / UDF)
│
├── factura.pdf.lnk              ← [Visible] Señuelo para el usuario
│   ├── IconLocation: Acrobat.exe
│   ├── Target: cmd.exe
│   └── Arguments: /c powershell ...
│
├── .autorun.inf                 ← [Hidden] Opcional: AutoRun metadata
│
├── stage1.dat                   ← [Hidden] Cargador C++ cifrado
│
├── metadata.db                  ← [Hidden] Datos del payload ASM cifrado
│
└── readme.txt                   ← [Hidden] (Relleno para justificar tamaño)
```

**Métricas de esta estructura:**

| Métrica | Valor | Interpretación |
|---|---|---|
| $\|\mathcal{F}_{visible}\|$ | 1 | Solo el señuelo |
| $\|\mathcal{F}_{hidden}\|$ | 4 | Todos los componentes maliciosos |
| $\rho_{hide}$ | 0.8 | 80% de archivos ocultos |
| $\|iso\|_{bytes}$ | ~2 MB | Desproporcionado para 1 archivo visible |
| $\sum_{f \in \mathcal{F}_{visible}} \|f\|$ | ~50 KB | Tamaño visible mínimo |
| Ratio de desperdicio | ~40x | 40 veces más espacio que contenido visible |

---

## 8. Análisis de la Cadena de Confianza Rota: Del Contenedor al Contenido

### 8.1 Modelo de Cadena de Confianza

**Definición 8.1.1 — Cadena de Confianza**

Sea $\mathcal{T}(f)$ la función que asigna un nivel de confianza a un archivo $f$. En un sistema de atribución correcto, la cadena de confianza satisface:

$$\mathcal{T}(f_{hijo}) \leq \mathcal{T}(f_{padre}) \quad \forall f_{hijo} \sqsubseteq f_{padre}$$

Es decir, un archivo contenido nunca tiene **más** confianza que su contenedor. Esta es una **propiedad de monotonicidad decreciente** de la confianza en la jerarquía de contención.

### 8.2 Violación de la Monotonía

En el bypass ISO, la cadena de confianza se viola:

$$\mathcal{T}(f_{dentro\;de\;ISO}) = \mathcal{T}_{default} > \mathcal{T}(ISO_{descargado})$$

El archivo dentro del ISO recibe la confianza **por defecto** del sistema (que equivale a "confiable"), mientras que el ISO como contenedor fue clasificado como "no confiable" (zona 3).

**Formalización:**

$$\mathcal{T}_{default} = \text{Confianza sin zona atribuida} = \text{Ejecución sin inspección}$$

$$\mathcal{T}_{zona3} = \text{Confianza con zona 3} = \text{SmartScreen + AMSI + advertencia}$$

$$\mathcal{T}_{default} > \mathcal{T}_{zona3}$$

El contenido del ISO obtiene **mayor confianza** que el contenedor, lo que es una inversión directa de la jerarquía de confianza esperada.

### 8.3 Diagrama de la Cadena de Confianza Rota

```
┌─────────────────────────────────────────────────────────────────┐
│           CADENA DE CONFIANZA: ESPERADA vs. REAL                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   CADENA ESPERADA (si PPT se cumpliera):                       │
│                                                                 │
│   Internet ──zona 3──→ ISO ──hereda──→ factura.lnk             │
│                              zona 3    └── SmartScreen ACTIVO  │
│                                        └── AMSI ACTIVO         │
│                                        └── Banner ACTIVO       │
│                                                                 │
│   CADENA REAL (PPT violada):                                   │
│                                                                 │
│   Internet ──zona 3──→ ISO ──no hereda──→ factura.lnk          │
│                              zona ⊥      └── SmartScreen OFF   │
│                                        └── AMSI NORMAL         │
│                                        └── Banner OFF          │
│                                        └── Ejecución LIBRE     │
│                                                                 │
│   INVERSIÓN DE CONFIANZA:                                      │
│   T(factura.lnk) = T_default > T_zona3 = T(ISO)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 8.4 Análisis del Impacto por Cada Consumidor de Zona

| Consumidor | Sin bypass (ZoneId=3) | Con bypass (ZoneId=⊥) | Diferencia |
|---|---|---|---|
| SmartScreen | Evaluación reputacional completa | Sin evaluación | **Completamente eludido** |
| AMSI (PowerShell) | Escaneo profundo de scripts | Escaneo estándar | Escaneo reducido |
| PowerShell ExecutionPolicy | Scripts sin firma → bloqueados | Scripts sin firma → permitidos | **Ejecución habilitada** |
| Explorer | Banner "archivo de otro equipo" | Sin banner | **Indicador visual eliminado** |
| Office Protected View | Apertura en sandbox | Apertura normal | **Sandbox eludido** |
| Attachment Manager | Advertencia antes de abrir | Apertura directa | **Advertencia eliminada** |
| Windows Defender | Escaneo agravado | Escaneo estándar | Detección reducida |

---

## 9. Superficie de Detección: Formalización y Predicados de Alerta

### 9.1 Predicados de Detección de Primer Nivel

**Predicado 9.1.1 — Montaje de ISO desde zona no confiable**

$$P_1(iso) \iff \text{ZoneAttrib}(iso) = 3 \wedge \text{IsMounted}(iso)$$

**Predicado 9.1.2 — Archivos sin zona en volumen montado desde zona no confiable**

$$P_2(iso) \iff \exists\, f \in V_{iso}: f \sqsubseteq iso \wedge \text{ZoneAttrib}(f) = \bot \wedge \text{ZoneAttrib}(iso) \neq \bot$$

**Predicado 9.1.3 — Ratio de ocultamiento anómalo**

$$P_3(iso) \iff \rho_{hide}(iso) > \theta \quad \text{donde } \theta \approx 0.5$$

**Predicado 9.1.4 — Tamaño desproporcionado**

$$P_4(iso) \iff \|iso\|_{bytes} \gg \sum_{f \in \mathcal{F}_{visible}} \|f\|_{bytes}$$

### 9.2 Señal Compuesta de Alta Confianza

$$\text{HighConfidence}(iso) \iff P_1(iso) \wedge P_2(iso) \wedge (P_3(iso) \vee P_4(iso))$$

Es decir: un ISO descargado de Internet, montado, cuyos archivos internos no tienen zona, **y** presenta estructura anómala (archivos ocultos o tamaño desproporcionado).

### 9.3 Señales de Segundo Nivel (Correlación Temporal)

**Predicado 9.3.1 — Ejecución de proceso hijo anómalo post-montaje**

$$P_5(iso, t) \iff \text{IsMounted}(iso, t_0) \wedge t > t_0 \wedge \exists\, p: \text{Created}(p, t) \wedge \text{Parent}(p) = \text{explorer.exe} \wedge \text{Name}(p) \in \mathcal{B}_{LOL}$$

**Predicado 9.3.2 — LNK dentro de ISO con Target ≠ IconApp**

$$P_6(lnk, iso) \iff lnk \sqsubseteq iso \wedge \text{Target}(lnk) \neq \text{IconApp}(lnk)$$

### 9.4 Tabla Consolidada de Superficies de Detección

| Nivel | Señal | Predicado | Subsistema | Tasa de FP estimada |
|---|---|---|---|---|
| 1 | Montaje desde zona 3 | $P_1$ | ETW `VHDMP` | Alta (muchos ISOs legítimos) |
| 1 | ADS ausente en contenido | $P_2$ | Auditoría MotW | Baja (requiere ISO montado) |
| 1 | Ratio ocultamiento alto | $P_3$ | Análisis estático | Muy baja |
| 1 | Tamaño desproporcionado | $P_4$ | Análisis estático | Baja |
| 2 | Proceso LOLBin post-montaje | $P_5$ | ETW `Kernel-Process` | Media |
| 2 | LNK con discrepancia Target/Icon | $P_6$ | Análisis Shell Link | Muy baja |
| 3 | **Señal compuesta** | $P_1 \wedge P_2 \wedge (P_3 \vee P_4)$ | Correlación | **Muy baja** |

### 9.5 Teorema de Efectividad de la Señal Compuesta

**Teorema 9.5.1 — Información Mutua de la Señal Compuesta**

$$I(P_1 \wedge P_2 \wedge P_3; \text{Ataque}) \geq \max(I(P_1; \text{Ataque}), I(P_2; \text{Ataque}), I(P_3; \text{Ataque}))$$

La información mutua de la señal compuesta es no decreciente respecto a las señales individuales. Esto formaliza la superioridad de la detección multi-predicado.

---

## 10. Historial de Explotación Documentado y Contexto APT

### 10.1 Cronología de Explotación

| Período | Evento | Actores documentados |
|---|---|---|
| Pre-2020 | Uso de documentos Office con macros como vector principal | Diversos |
| Feb 2021 | Investigación de Proofpoint: ISO como vector para eludir MotW | Proofpoint Threat Research |
| Jun 2021 | FIN7 adopta ISO como vector primario para distribución de Backdoor.JSLoader | FIN7 (Carbon Spider) |
| Ago 2021 | BazarLoader distribuido vía ISOs con LNK + DLL | TA551 |
| Oct 2021 | Emotet renace usando ISO como vector de distribución | Mummy Spider (TA542) |
| Nov 2021 | CVE-2021-41379 y variantes de bypass MotW reportadas | Abdelhamid Naceri |
| Dic 2021 | Prometei botnet distribuida vía ISO | Actores no atribuidos |
| Ene 2022 | Magniber ransomware usa ISOs para eludir SmartScreen | Actores coreanos |
| Mar 2022 | IcedID (BokBot) distribuido vía ISO en campañas masivas | TA580 |
| Jun 2022 | Quantum Locker ransomware distribuido vía ISO | Twisted Spider |
| Oct 2022 | Microsoft parcha parcialmente: Win11 22H2 propaga MotW en ISO | Microsoft |
| Nov 2022 | Actores APT adaptan vector: migración a VHDX y otros contenedores | Diversos |
| 2023 | Investigación: bypasses alternativos (LNK stomping, container abuse) | Diversos investigadores |

### 10.2 Adopción por Grupos APT Documentados

| Grupo | Aliases | Uso del vector ISO | Objetivos |
|---|---|---|---|
| FIN7 | Carbon Spider, Navigator | Backdoor.JSLoader vía ISO con LNK | Retail, Hospitality |
| TA551 | Shathak | BazarLoader/IcedID vía ISO | Enterprise, Healthcare |
| Mummy Spider | TA542 | Emotet vía ISO con LNK | Masivo, multi-sector |
| APT29 | Cozy Bear, The Dukes | Documentado en reportes de Mandiant | Government, Think Tanks |
| Turla | Snake, Uroburos | Variantes con ISO y LNK | Government, Military |

### 10.3 Técnicas de Evasión Complementarias Observadas en APTs

Los actores avanzados no usan el bypass ISO de forma aislada. Las observaciones de campo documentan las siguientes combinaciones:

**Capa 1 — Contenedor:**
- ISO estándar (más común)
- ISO con UDF en lugar de ISO 9660 (para evitar parsers simplistas)
- VHD/VHDX (contenedores virtuales Windows nativos, misma vulnerabilidad)
- IMG (imágenes de disco, misma familia de bypass)
- ZIP con contraseña (otro vector de no-propagación de zona)

**Capa 2 — Señuelo:**
- LNK con icono de PDF
- LNK con icono de Office (Word, Excel)
- LNK con icono de navegador (acceso a "portal web")
- Documento real + LNK oculto (para inspección visual superficial)

**Capa 3 — Disparador:**
- cmd.exe → powershell.exe (cadena estándar)
- mshta.exe → JavaScript/HTA (alternativa a PowerShell)
- rundll32.exe → DLL cargada directamente
- certutil.exe → descarga y decodificación de payload

### 10.4 Contexto de la Ventana de Explotación

La ventana de tiempo durante la cual esta vulnerabilidad fue ampliamente explotable:

```
2021 ──────────────────────────────────────────── 2024
  │                                                 │
  │  [Ventana principal de explotación]             │
  │  Feb 2021 ─────────────────────── Oct 2022      │
  │                                                 │
  │  [Parche parcial Win11 22H2]                    │
  │  Oct 2022                                       │
  │                                                 │
  │  [Persistencia en Win10, Win11 < 22H2]          │
  │  Oct 2022 ───────────────────────────────────── │
  │                                                 │
  │  [Migración a vectores alternativos]            │
  │  Nov 2022 ───────────────────────────────────── │
  │                                                 │
  │  [Parches adicionales y mitigaciones graduales] │
  │  2023 ───────────────────────────────────────── │
```

---

## 11. Contramedidas: Niveles de Defensa según Modelo de Capas

### 11.1 Modelo de Defensa en Profundidad

Las contramedidas se organizan en capas, desde la más genérica hasta la más específica:

```
┌──────────────────────────────────────────────────────────────┐
│                    MODELO DE DEFENSA EN CAPAS                 │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  CAPA 5: CORRECCIÓN DEL SISTEMA OPERATIVO                   │
│  ├── Parche Win11 22H2+ (propagación de MotW al montar)    │
│  └── Actualización de vhdmp.sys                             │
│                                                              │
│  CAPA 4: ENDPOINT DETECTION & RESPONSE (EDR)                │
│  ├── Monitoreo de montaje de ISO desde zona no confiable   │
│  ├── Análisis estático de ratio de ocultamiento             │
│  ├── Detección de LNK con Target ≠ IconApp                 │
│  └── Correlación temporal: montaje + creación LOLBin        │
│                                                              │
│  CAPA 3: POLÍTICAS DE SEGURIDAD                             │
│  ├── GPO: Ocultar extensiones DESACTIVADO                  │
│  ├── AppLocker/WDAC: Bloquear ejecución desde volúmenes    │
│  │   removibles/montados                                    │
│  ├── Bloquear montaje de ISO por usuarios no administradores│
│  └── PowerShell Constrained Language Mode                   │
│                                                              │
│  CAPA 2: GATEWAY / CORREO / WEB                             │
│  ├── Sandbox de archivos adjuntos (detonación)              │
│  ├── Bloqueo de .iso en adjuntos de correo                  │
│  ├── Inspección de contenido de ISO en proxy               │
│  └── Bloqueo de descargas de .iso desde categorías          │
│       no confiables                                          │
│                                                              │
│  CAPA 1: CONCIENCIA DEL USUARIO                             │
│  ├── Entrenamiento en reconocimiento de extensiones         │
│  ├── Alertas sobre archivos .iso inesperados                │
│  └── Procedimientos de reporte                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 11.2 Efectividad de Cada Capa

| Capa | Efectividad contra el vector ISO | Limitaciones |
|---|---|---|
| Parche OS (22H2+) | **Máxima** — elimina la vulnerabilidad de diseño | Solo Win11 22H2+; Win10 no parcheado permanece vulnerable |
| EDR avanzado | **Alta** — detecta patrones anómalos | Depende de cobertura de reglas; FP posibles |
| GPO (extensiones) | **Media** — revela la verdadera extensión del LNK | No evita que el usuario ejecute el archivo |
| AppLocker/WDAC | **Alta** — bloquea ejecución desde volúmenes montados | Requiere configuración cuidadosa; puede impactar flujos legítimos |
| Bloqueo de ISO | **Máxima** para ISO | Puede impactar distribución legítima de software |
| Gateway/Sandbox | **Alta** — detonación antes de entrega | Latencia; puede no detectar payloads cifrados |
| Conciencia usuario | **Baja-Media** | No confiable como control primario |

### 11.3 Análisis Probabilístico de Defensa

Si cada condición de fallo del vector tiene probabilidad independiente $p_i$ de estar activa:

$$P(\text{Éxito del vector}) = \prod_{i=1}^{n} (1 - p_i)$$

| Defensa | $p_i$ estimado (empresa promedio) | $p_i$ estimado (entorno endurecido) |
|---|---|---|
| Parche Win11 22H2+ | 0.60 | 0.95 |
| Extensiones visibles (GPO) | 0.15 | 0.90 |
| AppLocker/WDAC | 0.25 | 0.85 |
| EDR con reglas ISO/LNK | 0.50 | 0.90 |
| Bloqueo gateway de .iso | 0.20 | 0.80 |

**Empresa promedio:**

$$P(\text{Éxito}) \approx 0.40 \times 0.85 \times 0.75 \times 0.50 \times 0.80 \approx 0.102 \quad (\approx 10.2\%)$$

**Entorno endurecido:**

$$P(\text{Éxito}) \approx 0.05 \times 0.10 \times 0.15 \times 0.10 \times 0.20 \approx 0.000015 \quad (\approx 0.0015\%)$$

---

## 12. Análisis de Variaciones y Mutaciones del Vector

### 12.1 Familia de Contenedores Vulnerables

La vulnerabilidad no es exclusiva de ISO. Cualquier sistema de archivos que no soporte ADS NTFS es potencialmente vulnerable:

| Contenedor | Sistema de archivos interno | Soporta ADS | Vulnerable |
|---|---|---|---|
| `.iso` | ISO 9660 / UDF | No | **Sí** |
| `.img` | FAT / NTFS / ISO 9660 | Depende | **Parcialmente** |
| `.vhd` | NTFS (generalmente) | Sí (si NTFS interno) | **No** (generalmente) |
| `.vhdx` | NTFS (generalmente) | Sí (si NTFS interno) | **No** (generalmente) |
| `.zip` (Windows 11) | N/A (proyección) | No | **Sí** (similar mecanismo) |
| `.rar` | N/A (extracción) | Depende de herramienta | **Variable** |
| `.7z` | N/A (extracción) | Depende de herramienta | **Variable** |

### 12.2 Mutaciones Observadas Post-Parche

Tras el parche de Win11 22H2, los actores han documentado las siguientes mutaciones:

**Mutación 1 — Contenedor alternativo:**
- Migración de `.iso` a `.img` (misma familia de bypass)
- Uso de `.vhd` con sistemas de archivos FAT internos

**Mutación 2 — Bypass del parche:**
- Investigadores demostraron que ciertas variantes de montaje (por ejemplo, montaje vía PowerShell `Mount-DiskImage` vs. doble clic) pueden tener diferentes comportamientos de propagación

**Mutación 3 — Vector independiente:**
- Abandono del vector de contenedor en favor de técnicas alternativas como OneNote (.one) con objetos embebidos, archivos HTML (.html/.mhtml), o archivos ISO con contraseñas que evitan la inspección del contenido

**Mutación 4 — Explotación combinada:**
- Uso de ISO + LNK + archivo DLL real (en lugar de solo LNK): el LNK ejecuta `rundll32.exe` con una DLL maliciosa oculta en el ISO

### 12.3 Árbol de Decisiones del Atacante

```
¿El objetivo usa Windows 11 22H2+?
├── NO → ISO clásico con LNK (vector probado)
└── SÍ → ¿El parche de propagación MotW está activo?
    ├── NO (deshabilitado por GPO/error) → ISO clásico
    └── SÍ → Mutación necesaria:
        ├── Opción A: Usar .img en lugar de .iso
        ├── Opción B: Usar .zip con estructura ofuscada
        ├── Opción C: ISO + archivo .hta/.one/.html embebido
        ├── Opción D: ISO con contraseña + scripts de extracción
        └── Opción E: Abandonar contenedor, usar macro/phishing directo
```

---

## 13. Referencias y Marco Normativo

### Investigación de Vulnerabilidades y MotW

- Sandvik, O. (2021). *"Mark-of-the-Web Bypass via ISO Mounting."* Microsoft Security Response Center (MSRC).
- Naceri, A. (2021). *"Windows Installer Elevation of Privilege — MotW Bypass Variant."* CVE-2021-41379.
- Microsoft (2022). *"Changes to Mark of the Web in Windows 11 22H2."* Microsoft Security Blog.

### Análisis de Campañas APT

- Proofpoint Threat Research (2021). *"Cybercrime and the Mark-of-the-Web: How Threat Actors Abuse ISO Files."*
- SentinelOne (2022). *"The ISO Dilemma: A Deep Dive into MotW Bypass."*
- Mandiant (2022). *"Not Your Average Malware: APT29 and Novel Delivery Mechanisms."*
- Trend Micro (2022). *"Magniber Ransomware Shifts to ISO Distribution."*
- Elastic Security Labs (2023). *"Container-Based Evasion: Taxonomy and Detection."*

### Sistemas Operativos y Kernel NT

- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.
- Microsoft (2024). *[MS-SHLLINK]: Shell Link Binary File Format.* Microsoft Open Specifications.
- Microsoft (2024). *Attachment Execution Service Reference.* Microsoft Learn.

### Formatos de Sistema de Archivos

- ISO/IEC 9660:1999. *Information processing — Volume and file structure of CD-ROM for information interchange.*
- ISO/IEC 13346:1995. *Information technology — Volume and file structure of write-once and rewritable media using non-sequential recording for information interchange (UDF).*
- Microsoft (2024). *NTFS Alternate Data Streams Reference.* Microsoft Learn.

### Teoría de la Información

- Shannon, C.E. (1948). *"A Mathematical Theory of Communication."* Bell System Technical Journal, 27, 379-423.
- Cover, T.M. & Thomas, J.A. (2006). *Elements of Information Theory*, 2nd Edition. Wiley.

### Detección y Respuesta

- MITRE ATT&CK (2024). *Technique T1553.005: Subvert Trust Controls — Mark-of-the-Web Bypass.*
- MITRE ATT&CK (2024). *Technique T1566.001: Phishing Attachment.*
- NIST SP 800-83 (2013). *Guide to Malware Incident Prevention and Handling.*

---

*Documento de investigación técnica sobre el vector de bypass del Mark-of-the-Web mediante contenedores ISO. El análisis se limita a la descripción objetiva del fenómeno desde la perspectiva de la ciencia computacional, la teoría de la información y los modelos formales de seguridad, con el propósito de fundamentar mecanismos de detección y defensa.*
