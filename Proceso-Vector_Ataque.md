# Análisis Formal del Vector de Ataque de 5 Etapas en Windows 11

## Integración de Modelos Formales de Subsistemas con Lógica de Predicados, Álgebra Abstracta y Teoría de la Información

---

> **Alcance:** Este documento presenta un análisis riguroso de un vector de ataque compuesto de cinco etapas contra la arquitectura Windows 11. Cada etapa es descompuesta mediante especificaciones formales en lógica de predicados de primer orden, álgebra abstracta, teoría de la información, y modelos de autómatas híbridos. Las superficies de ataque y detección son caracterizadas como invariantes y contradependencias en el espacio de estados del sistema operativo. El análisis se limita a la descripción objetiva del fenómeno delincuencial sin instrucciones de implementación.

---

## Tabla de Contenidos

1. [Marco Formal Preliminar](#1-marco-formal-preliminar)
2. [Etapa 1 — El Contenedor ISO: Bypass del Mark-of-the-Web](#2-etapa-1--el-contenedor-iso-bypass-del-mark-of-the-web)
3. [Etapa 2 — El Señuelo: Ingeniería Social Visual y Semiótica Formal](#3-etapa-2--el-señuelo-ingeniería-social-visual-y-semiótica-formal)
4. [Etapa 3 — El Disparador: LOLBins, LNK Stomping y el Motor WQL](#4-etapa-3--el-disparador-lolbins-lnk-stomping-y-el-motor-wql)
5. [Etapa 4 — El Cargador C++: Evasión de Telemetría y el Mecanismo APC](#5-etapa-4--el-cargador-c-evasión-de-telemetría-y-el-mecanismo-apc)
6. [Etapa 5 — El Payload ASM: PIC, Evasión y Superficie de Estado Global](#6-etapa-5--el-payload-asm-pic-evasión-y-superficie-de-estado-global)
7. [Análisis de Superficie Compuesta y Correlación de Invariantes](#7-análisis-de-superficie-compuesta-y-correlación-de-invariantes)
8. [Diagrama Integrado del Vector y Subsistemas](#8-diagrama-integrado-del-vector-y-subsistemas)
9. [Análisis de Dependencias y Condiciones de Fallo](#9-análisis-de-dependencias-y-condiciones-de-falo)
10. [Referencias Teóricas](#10-referencias-teóricas)

---

## 1. Marco Formal Preliminar

### 1.1 Espacio de Estados del Sistema

El sistema Windows 11 se modela como un **espacio de estados** $\Sigma$ definido como producto cartesiano de los estados de sus subsistemas fundamentales:

$$\Sigma = \Sigma_{FS} \times \Sigma_{Shell} \times \Sigma_{Proc} \times \Sigma_{CIM} \times \Sigma_{WQL} \times \Sigma_{APC} \times \Sigma_{COM} \times \Sigma_{ETW}$$

donde cada componente $\Sigma_i$ representa el conjunto de estados posibles del subsistema $i$. Una **configuración del sistema** en un instante $t$ es una tupla:

$$\sigma(t) = (\sigma_{FS}(t),\; \sigma_{Shell}(t),\; \sigma_{Proc}(t),\; \sigma_{CIM}(t),\; \sigma_{WQL}(t),\; \sigma_{APC}(t),\; \sigma_{COM}(t),\; \sigma_{ETW}(t))$$

### 1.2 Modelo de Transiciones

Una **transición del sistema** es una función parcial $\tau: \Sigma \rightharpoonup \Sigma$ que modifica uno o más componentes del estado. Definimos el **operador de proyección** $\pi_i: \Sigma \rightarrow \Sigma_i$ que extrae el componente $i$-ésimo del estado global. Un **invariante del sistema** es un predicado $\mathcal{I}: \Sigma \rightarrow \{\top, \bot\}$ tal que:

$$\forall \sigma \in \Sigma:\; \mathcal{I}(\sigma) \Rightarrow \mathcal{I}(\tau(\sigma))$$

Es decir, el invariante se preserva bajo toda transición válida del sistema.

### 1.3 Definición Formal de Superficie de Ataque

**Definición 1.3.1 — Superficie de Ataque**

Sea $\mathcal{P}$ el conjunto de primitivas de seguridad del sistema. Una **superficie de ataque** es un subconjunto $S_A \subseteq \Sigma \times \mathcal{P}$ tal que:

$$S_A = \{(\sigma, p) \mid \exists\, \tau': \Sigma \rightharpoonup \Sigma : \tau' \text{ viola } p \text{ en estado } \sigma\}$$

Es decir, $S_A$ contiene todos los pares (estado, primitiva) para los cuales existe al menos una transición que viola la primitiva de seguridad.

### 1.4 Notación de Lógica de Predicados

A lo largo del documento se utiliza la siguiente convención:

| Símbolo | Significado |
|---|---|
| $\forall$ | Cuantificador universal |
| $\exists$ | Cuantificador existencial |
| $\exists!$ | Existencial único |
| $\Rightarrow$ | Implicación material |
| $\Leftrightarrow$ | Equivalencia lógica |
| $\wedge$ | Conjunción (AND) |
| $\vee$ | Disyunción (OR) |
| $\neg$ | Negación |
| $\models$ | Satisfacibilidad semántica |
| $\vdash$ | Derivabilidad sintáctica |
| $\top, \bot$ | Verdadero, Falso |
| $\circ$ | Composición de funciones |
| $\hookrightarrow$ | Inyección (embedding) |
| $\twoheadrightarrow$ | Sobreyección |
| $\xrightarrow{\sim}$ | Isomorfismo |

---

## 2. Etapa 1 — El Contenedor ISO: Bypass del Mark-of-the-Web

### 2.1 Fundamento del Mecanismo MotW como Función de Atribución

El Mark-of-the-Web (MotW) es un mecanismo de **atribución de zona de seguridad** implementado sobre el subsistema NTFS mediante Alternate Data Streams (ADS). Formalmente, definimos:

**Definición 2.1.1 — Función de Atribución de Zona**

Sea $\mathcal{F}$ el conjunto de archivos en un volumen y $\mathcal{Z} = \{0, 1, 2, 3, 4\}$ el conjunto de zonas de seguridad (0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Restringido). La función de atribución de zona es:

$$\text{ZoneAttrib}: \mathcal{F} \rightarrow \mathcal{Z} \cup \{\bot\}$$

donde $\text{ZoneAttrib}(f) = \bot$ indica que el archivo $f$ no posee atributo de zona (no tiene ADS `Zone.Identifier`).

La implementación de esta función depende del **Attachment Execution Service (AES)**, un componente de `shlwapi.dll` que escribe el ADS `Zone.Identifier` como un flujo NTFS alternativo con la estructura:

```
Zone.Identifier ADS = {
    [ZoneTransfer]
    ZoneId      ∈ Z            ; Valor de zona
    ReferrerUrl ∈ {0,1}^*      ; URL de referencia (opcional)
    HostUrl     ∈ {0,1}^*      ; URL de origen (opcional)
}
```

### 2.2 Modelo Formal de la Propagación de Atributos

**Definición 2.2.1 — Relación de Contención Archivística**

Sea $\sqsubseteq \;\subseteq \mathcal{F} \times \mathcal{F}$ la relación "está archivado dentro de". Para un contenedor ISO $c$ y un archivo contenido $f$, escribimos $f \sqsubseteq c$. Esta relación es:

- **Reflexiva:** $\forall f: f \sqsubseteq f$ (un archivo se contiene a sí mismo)
- **Transitiva:** $f_1 \sqsubseteq f_2 \wedge f_2 \sqsubseteq f_3 \Rightarrow f_1 \sqsubseteq f_3$
- **Antisimétrica:** $f_1 \sqsubseteq f_2 \wedge f_2 \sqsubseteq f_1 \Rightarrow f_1 = f_2$

Por lo tanto, $(\mathcal{F}, \sqsubseteq)$ es un **preorden parcial** (partial order) sobre los archivos.

**Definición 2.2.2 — Propiedad de Propagación Transitiva (Esperada)**

En un volumen NTFS nativo, se espera que la función de atribución de zona satisfaga:

$$\forall f_1, f_2 \in \mathcal{F}: f_1 \sqsubseteq f_2 \wedge \text{ZoneAttrib}(f_2) \neq \bot \Rightarrow \text{ZoneAttrib}(f_1) = \text{ZoneAttrib}(f_2)$$

Es decir, si un archivo está contenido en otro que tiene zona atribuida, el archivo contenido debe heredar la misma zona. Esta es la **propiedad de propagación transitiva** (PPT).

**Teorema 2.2.1 — Violación de la PPT en Volúmenes Montados desde ISO**

*Sea $c$ un contenedor ISO con $\text{ZoneAttrib}(c) = 3$ (descargado de Internet). Sea $V_c$ el volumen virtual montado desde $c$ por el driver `vhdmp.sys` / `vdrvroot.sys`. Entonces:*

$$\exists\, f \in V_c : f \sqsubseteq c \wedge \text{ZoneAttrib}(f) = \bot$$

*Es decir, la PPT se viola: los archivos dentro del volumen montado no heredan la zona del contenedor.*

**Demostración (esquema):**

1. El AES escribe `Zone.Identifier` exclusivamente como ADS NTFS sobre el archivo `.iso`.
2. El driver de montaje (`vhdmp.sys`) proyecta el sistema de archivos ISO 9660/UDF como un volumen virtual.
3. ISO 9660/UDF no soporta ADS NTFS (no es NTFS); el sistema de archivos proyectado no tiene la capacidad de almacenar flujjos alternativos.
4. El subsistema NTFS no intercepta el montaje para propagar el ADS del contenedor a los archivos proyectados.
5. Por lo tanto: $\text{ZoneAttrib}(f) = \bot$ para todo $f$ en el volumen montado.

$\blacksquare$

### 2.3 Diagrama de Estados de la Atribución de Zona

```
═══════════════════════════════════════════════════════════════════
                    FLUJO DE ATRIBUCIÓN MotW
═══════════════════════════════════════════════════════════════════

   Descarga desde Internet
          │
          ▼
   ┌──────────────────────────────────┐
   │  AES (shlwapi.dll)              │
   │  ZoneAttrib(iso) = 3            │
   │  Escribe ADS: Zone.Identifier   │
   │  sobre archivo.iso              │
   └──────────────┬───────────────────┘
                  │
          ┌───────┴────────┐
          │                │
          ▼                ▼
   NTFS Nativo        Montaje ISO
   (Copia manual)     (vhdmp.sys)
          │                │
          ▼                ▼
   ┌─────────────┐   ┌──────────────────────────────────┐
   │ Propagación │   │ NO Propagación                   │
   │ Transitiva  │   │ ZoneAttrib(f_hijo) = ⊥           │
   │ Correcta    │   │ ISO 9660 ≠ NTFS                  │
   │             │   │ No hay ADS en FS proyectado       │
   │ Zona(f) = 3 │   │                                  │
   └─────────────┘   │ SmartScreen no alerta            │
                     │ PowerShell no bloquea            │
                     │ Explorer no muestra advertencia  │
                     └──────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
     VULNERABILIDAD: ¬PPT  ≡  ∃f: f ⊑ c ∧ ZoneAttrib(f) = ⊥
═══════════════════════════════════════════════════════════════════
```

### 2.4 Análisis Información-Teórico

**Definición 2.4.1 — Pérdida de Información por No-Propagación**

La función de atribución de zona en un volumen NTFS es un **morfismo de preórdenes**:

$$\text{ZoneAttrib}: (\mathcal{F}_{NTFS}, \sqsubseteq) \rightarrow (\mathcal{Z}, =)$$

que preserva la relación de orden (si $f_1 \sqsubseteq f_2$, entonces $\text{ZoneAttrib}(f_1) = \text{ZoneAttrib}(f_2)$). En un volumen ISO montado, esta función **deja de ser un morfismo**; la estructura algebraica se rompe.

Podemos cuantificar la pérdida de información usando la **entropía condicional**. Sea $H(Z|F)$ la entropía condicional de la zona dado el archivo. En NTFS nativo:

$$H(Z \mid F_{NTFS}) = 0$$

(dado el archivo, la zona está determinada por herencia). En un volumen ISO montado:

$$H(Z \mid F_{ISO}) = H(Z) > 0$$

(la zona del archivo es independiente del contenedor; la información se pierde). La **ganancia de entropía** es:

$$\Delta H = H(Z \mid F_{ISO}) - H(Z \mid F_{NTFS}) = H(Z) = \log_2 |\mathcal{Z}| = \log_2 5 \approx 2.32 \;\text{bits}$$

Esto significa que la no-propagación introduce aproximadamente 2.32 bits de incertidumbre por archivo respecto a su zona de seguridad.

### 2.5 El Atributo FILE_ATTRIBUTE_HIDDEN como Función de Selección

**Definición 2.5.1 — Función de Visibilidad**

En ISO 9660, cada registro de directorio contiene un byte de flags donde el bit 0 (0x01) indica "archivo oculto". Windows traduce esto al atributo `FILE_ATTRIBUTE_HIDDEN` (0x02). Definimos la **función de visibilidad**:

$$\text{Vis}: \mathcal{F} \rightarrow \{\text{Visible}, \text{Hidden}\}$$

$$\text{Vis}(f) = \begin{cases} \text{Hidden} & \text{si } f.\text{Attributes} \wedge \text{FILE\_ATTRIBUTE\_HIDDEN} \neq 0 \\ \text{Visible} & \text{en otro caso} \end{cases}$$

La configuración predeterminada del Explorador de Windows implementa un **filtro de visibilidad**:

$$\text{ExplorerView} = \{f \in \mathcal{F} \mid \text{Vis}(f) = \text{Visible}\}$$

Por lo tanto, si un ISO contiene un conjunto de archivos $\mathcal{F}_{ISO}$ donde $\text{Vis}$ particiona $\mathcal{F}_{ISO}$ en $\mathcal{F}_{visible}$ y $\mathcal{F}_{hidden}$, el usuario solo interactúa con $\mathcal{F}_{visible}$. Definimos el **ratio de ocultamiento**:

$$\rho_{hide} = \frac{|\mathcal{F}_{hidden}|}{|\mathcal{F}_{ISO}|}$$

Un ISO malicioso típicamente presenta $\rho_{hide} \rightarrow 1$ (la mayoría de archivos están ocultos), dejando solo el señuelo visible. Este ratio es un **invariante detectable**: un ISO legítimo raramente tiene $\rho_{hide} > 0.5$.

### 2.6 Superficie de Detección (Etapa 1) — Formalización

| Señal | Predicado de Detección | Subsistema |
|---|---|---|
| Montaje de ISO desde descargas | $\exists\, iso: \text{ZoneAttrib}(iso) = 3 \wedge \text{IsMounted}(iso)$ | ETW: `Microsoft-Windows-VHDMP` |
| ADS ausente en volumen montado | $\exists\, f: f \sqsubseteq iso \wedge \text{ZoneAttrib}(f) = \bot \wedge \text{ZoneAttrib}(iso) \neq \bot$ | Auditoría de integridad MotW |
| Ratio de ocultamiento anómalo | $\rho_{hide}(iso) > \theta$ donde $\theta \approx 0.5$ | Análisis estático heurístico |
| Tamaño inconsistente | $\|iso\|_{bytes} \gg \sum_{f \in \mathcal{F}_{visible}} \|f\|_{bytes}$ | Correlación tamaño/contenido |

---

## 3. Etapa 2 — El Señuelo: Ingeniería Social Visual y Semiótica Formal

### 3.1 Modelo Semiótico del Engaño

**Definición 3.1.1 — Signo Visual como Terna**

Siguiendo la semiótica de Peirce, un signo visual en el Explorador de Windows se modela como una terna:

$$S = (R, O, I)$$

donde:
- $R$ es el **representamen** (lo que el usuario percibe: icono de Acrobat + nombre "Factura.pdf")
- $O$ es el **objeto** (la entidad real: un acceso directo `.lnk` que ejecuta `cmd.exe`)
- $I$ es el **interpretante** (el significado construido por el usuario: "documento PDF legítimo")

El engaño ocurre cuando $R \neq O$ pero el usuario opera bajo la asunción $R = O$. Formalmente, el atacante explota la discrepancia:

$$\text{Deceit}(S) \iff R \neq O \wedge I(R) = I(O)$$

El representamen y el objeto son diferentes, pero el interpretante los trata como equivalentes.

### 3.2 Estructura Formal del Formato LNK (Shell Link Binary)

El formato Shell Link Binary está especificado en `[MS-SHLLINK]`. Un archivo `.lnk` se modela como una estructura compuesta:

$$\text{LNK} = (H, L, \Pi, E)$$

donde:
- $H$ = **ShellLinkHeader** (76 bytes obligatorios)
- $L$ = **LinkTargetIDList** (lista de identificadores al destino)
- $\Pi$ = conjunto de **estructuras de información** (LocationInfo, Description, RelativePath, WorkingDir, IconLocation, CommandLineArguments)
- $E$ = **ExtraData** (bloques opcionales: Tracker, SpecialFolder, Darwin, PropertyStore, etc.)

**Campos relevantes para el engaño:**

```
┌────────────────────────────────────────────────────────────────┐
│              ShellLinkHeader (76 bytes)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ HeaderSize      : 0x0000004C (76)                       │  │
│  │ LinkCLSID       : 00021401-0000-0000-C000-000000000046  │  │
│  │ LinkFlags       : LinkFlags bitmask                      │  │
│  │   ├── HasLinkTargetIDList     (0x00000001)               │  │
│  │   ├── HasLinkInfo             (0x00000002)               │  │
│  │   ├── HasName                 (0x00000004)               │  │
│  │   ├── HasArguments            (0x00000020)  ← CRÍTICO   │  │
│  │   ├── HasIconLocation         (0x00000040)  ← CRÍTICO   │  │
│  │   └── ...                                                │  │
│  │ ShowCommand     : SW_SHOWNORMAL (0x00000001)             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ LinkTargetIDList → Target: C:\Windows\System32\cmd.exe  │  │
│  │ CommandLineArguments → "/c powershell -ep bypass ..."    │  │
│  │ IconLocation → "C:\Program Files\Adobe\Reader\AcroRd32.exe,0" │
│  │ Name (StringData) → "Factura.pdf"                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 3.3 Diagrama de la Discrepancia Visual

```
═══════════════════════════════════════════════════════════════════
               MODELO DE DECEPCIÓN SEMIÓTICA
═══════════════════════════════════════════════════════════════════

   PERCEPCIÓN DEL USUARIO              REALIDAD DEL SISTEMA
   ┌─────────────────────┐            ┌─────────────────────────┐
   │  [Icono Acrobat]    │            │  Formato: .LNK          │
   │  Factura.pdf        │            │  Target:  cmd.exe       │
   │                     │            │  Args:    /c powershell  │
   │  I(R) = "Documento  │     ≠     │            -ep bypass    │
   │   PDF legítimo"     │            │            -w hidden     │
   │                     │            │            -c "..."      │
   │  Tipo percibido:    │            │  I(O) = "Ejecutable     │
   │  Application/PDF    │            │   con argumentos        │
   │                     │            │   maliciosos"           │
   └─────────────────────┘            └─────────────────────────┘
            │                                    │
            │  R ≠ O                             │
            │  I(R) = I(O)                       │
            └────────── Deceit(S) ───────────────┘

   CONDICIÓN HABILITANTE:
   ┌─────────────────────────────────────────────────────────────┐
   │ HideFileExt = TRUE (configuración por defecto de Windows)   │
   │ → "Factura.pdf.lnk" se muestra como "Factura.pdf"          │
   │ → El usuario no puede distinguir R de O sin inspección     │
   │   explícita de propiedades                                  │
   └─────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 3.4 Formalización de la Extensión Oculta

**Definición 3.4.1 — Función de Presentación del Shell**

El Explorador de Windows implementa una función de presentación que transforma el nombre real del archivo en el nombre mostrado:

$$\text{DisplayName}: \text{String} \times \{\text{ShowExt}, \text{HideExt}\} \rightarrow \text{String}$$

$$\text{DisplayName}(n, \text{HideExt}) = \begin{cases} n[0..\text{lastDot}(n)-1] & \text{si } n.\text{Ext} \in \text{KnownExtensions} \\ n & \text{en otro caso} \end{cases}$$

donde $\text{KnownExtensions}$ es el conjunto de extensiones registradas en `HKEY_CLASSES_ROOT`. El atacante explota:

$$\text{DisplayName}(\text{"Factura.pdf.lnk"}, \text{HideExt}) = \text{"Factura.pdf"}$$

porque `.lnk` es una extensión conocida. Formalmente, la condición de engaño es:

$$\text{Deceit}(S) \iff \text{Target}(lnk) \neq \text{IconApp}(lnk) \wedge \text{HideExt} = \text{TRUE}$$

### 3.5 Superficie de Detección (Etapa 2) — Formalización

| Señal | Predicado de Detección | Mecanismo |
|---|---|---|
| LNK con icono de PDF | $\text{Target}(lnk) \neq \text{IconApp}(lnk) \wedge \text{IconApp}(lnk) \in \text{PDFReaders}$ | Análisis de estructura Shell Link |
| Extensión oculta explotada | $\text{HideExt} = \text{TRUE} \wedge \exists\, lnk: lnk.\text{Name}.\text{Ext} = \text{".lnk"}$ | Política de grupo: forzar `HideFileExt = FALSE` |
| LNK desde volumen montado | $\exists\, lnk: lnk \sqsubseteq iso \wedge \text{ZoneAttrib}(iso) = 3$ | Correlación: LNK + zona no confiable |
| Magic bytes LNK | $\text{ReadBytes}(f, 0..3) = \text{0x4C000001}$ | Inspección de firma de archivo |

---

## 4. Etapa 3 — El Disparador: LOLBins, LNK Stomping y el Motor WQL

### 4.1 Living-off-the-Land Binaries: Modelo de Redirección de Confianza

**Definición 4.1.1 — Cadena de Confianza**

Sea $\mathcal{B}$ el conjunto de binarios del sistema y $\mathcal{T}: \mathcal{B} \rightarrow \{\text{Trusted}, \text{Untrusted}\}$ la función de confianza basada en firma digital. Un **LOLBin** es un binario $b \in \mathcal{B}$ tal que:

$$\mathcal{T}(b) = \text{Trusted} \wedge \text{HasScriptingCapability}(b) = \top$$

El conjunto de LOLBins en Windows 11 incluye:

$$\mathcal{B}_{LOL} = \{\text{cmd.exe}, \text{powershell.exe}, \text{rundll32.exe}, \text{mshta.exe}, \text{certutil.exe}, \text{bitsadmin.exe}, \text{wmic.exe}, \ldots\}$$

El atacante redirige la ejecución a través de un LOLBin, creando una **cadena de confianza**:

$$\text{Explorer} \xrightarrow{\text{lnk}} \text{cmd.exe} \xrightarrow{/c} \text{powershell.exe} \xrightarrow{-ep\;bypass} \text{payload}$$

Cada eslabón de la cadena involucra un binario $\mathcal{T}$-Trusted. El EDR basado en allow-listing de firmas permite cada transición individual, pero la **cadena compuesta** es anómala.

### 4.2 LNK Stomping: Manipulación del Árbol de Parseo

**Definición 4.2.1 — Modelo de Parsing del Shell Link**

El parser de `shell32.dll` procesa un archivo LNK según los flags en `LinkFlags`. Definimos la **función de parseo**:

$$P_{shell}: \text{LNK} \times \text{LinkFlags} \rightarrow \text{Interpretation}$$

El "stomping" explota una discrepancia entre dos funciones de parseo:

$$P_{shell}(lnk, F_{display}) \neq P_{shell}(lnk, F_{execution})$$

donde $F_{display}$ son los flags usados por el diálogo de propiedades y $F_{execution}$ son los flags usados por el ejecutor de accesos directos. Específicamente:

- El bit `HasArguments` (0x00000020) controla si el parser busca la estructura `COMMAND_LINE_ARGUMENTS`
- Si `HasArguments = 0` en el header pero los argumentos existen en `ExtraData`, el diálogo de propiedades no los muestra
- El ejecutor, sin embargo, puede procesar argumentos desde `ExtraData` independientemente del flag del header

Formalizamos esta discrepancia como un **invariante violado**:

$$\text{Inv}_{parse}: \forall\, lnk: \text{ArgsDisplayed}(lnk) = \text{ArgsExecuted}(lnk)$$

$$\text{LNK\_Stomping}(lnk) \iff \neg\text{Inv}_{parse}(lnk)$$

### 4.3 Modelo WQL como Superficie de Detección

**Definición 4.3.1 — Detección de Procesos Anómalos**

El motor WQL de WMI proporciona un marco formal para la detección basada en predicados. Una consulta de monitoreo se formula como:

$$\omega_{detect} = \text{SELECT } \pi \text{ FROM } \epsilon \text{ WHERE } \psi$$

Para detectar procesos hijos anómalos de `explorer.exe`:

$$\psi_{anomaly}(e) \iff \text{ParentPID}(e) = \text{PID}(\text{explorer.exe}) \wedge \text{ProcessName}(e) \in \mathcal{B}_{LOL}$$

En notación de lógica de predicados:

$$\psi_{anomaly}(e) \equiv \exists\, p \in \text{Win32\_Process}: \text{Name}(p) = \text{"explorer.exe"} \wedge \text{ParentProcessId}(e) = \text{ProcessId}(p) \wedge \text{Name}(e) \in \mathcal{B}_{LOL}$$

### 4.4 Pipeline de Eventos y Latencia como Ventana de Oportunidad

Recordemos el autómata híbrido del motor de eventos WQL:

$$\mathcal{A}_H = (S, E, \delta, G, \text{Init})$$

La **latencia de entrega** $L = t_c - t_g = L_q + L_f + L_d$ define una ventana temporal durante la cual el evento ha ocurrido pero aún no ha sido consumido. El atacante explota esta ventana:

$$\text{OpportunityWindow} = \{t \mid t_g \leq t < t_c\}$$

$$|\text{OpportunityWindow}| = L$$

Para consumidores fuera de proceso ($L \in [1, 50]\;\text{ms}$), esta ventana es suficiente para que el cargador complete operaciones críticas (resolución de APIs, unhooking, ETW patching) antes de que el EDR reciba la notificación.

```
═══════════════════════════════════════════════════════════════════
            PIPELINE DE EVENTOS WQL Y VENTANA DE OPORTUNIDAD
═══════════════════════════════════════════════════════════════════

  t_g                EVENTO GENERADO                    t_c
   │                                                      │
   │  ┌─────────────────────────────────────────────┐     │
   │  │           VENTANA DE OPORTUNIDAD            │     │
   │  │                                             │     │
   │  │  Fase 1: GENERACIÓN                        │     │
   │  │  ├── Win32_ProcessStartTrace               │     │
   │  │  └── __InstanceCreationEvent                │     │
   │  │                                             │     │
   │  │  Fase 2: FILTRADO (WQL ψ)                  │     │
   │  │  ├── Evaluación del predicado              │     │
   │  │  └── Latencia L_f                          │     │
   │  │                                             │     │
   │  │  Fase 3: ENRUTAMIENTO                      │     │
   │  │  ├── __FilterToConsumerBinding             │     │
   │  │  └── Latencia L_d                          │     │
   │  │                                             │     │
   │  │  Fase 4: CONSUMO                           │     │
   │  │  └── Activación del consumidor             │     │
   │  └─────────────────────────────────────────────┘     │
   │                                                      │
   ▼                                                      ▼
  Atacante ejecuta                              EDR recibe
  operaciones críticas                          notificación

═══════════════════════════════════════════════════════════════════
```

### 4.5 Superficie de Detección (Etapa 3) — Formalización

| Señal | Predicado de Detección | Mecanismo |
|---|---|---|
| LOLBin desde LNK | $\exists\, lnk, b: \text{Target}(lnk) = b \wedge b \in \mathcal{B}_{LOL}$ | Regla YARA/Sigma |
| Argumentos contradictorios | $\text{HasArguments}(lnk) = 0 \wedge \text{ArgsExecuted}(lnk) \neq \emptyset$ | Contradicción de invariante |
| Shell desde volumen montado | $\text{ProcessName}(e) \in \mathcal{B}_{LOL} \wedge \text{Source}(e) \sqsubseteq iso \wedge \text{ZoneAttrib}(iso) = 3$ | Correlación ETW+WMI |
| AMSI intercepta | $\text{ScriptContent}(p) \models \psi_{malicious}$ donde $p$ es el flujo de PowerShell | `System.Management.Automation.dll` |
| CmdSpawn anómalo | $\text{Name}(e) \in \{\text{"cmd.exe"}, \text{"powershell.exe"}\} \wedge \text{ParentPID}(e) = \text{PID}(\text{explorer.exe})$ | ETW Kernel-Process |

---

## 5. Etapa 4 — El Cargador C++: Evasión de Telemetría y el Mecanismo APC

### 5.1 Resolución PEB: Cadena de Punteros Arquitectónica

**Definición 5.1.1 — PEB como Nodo del Grafo de Resolución**

El Process Environment Block (PEB) es el nodo raíz de un **grafo dirigido acíclico** (DAG) de resolución de módulos. Formalmente, definimos el grafo:

$$G_{PEB} = (V, E_{resolve})$$

donde $V = \{\text{PEB}, \text{PEB\_LDR\_DATA}, \text{LDR\_DATA\_TABLE\_ENTRY}, \text{DllBase}, \text{ExportTable}\}$ y $E_{resolve}$ son las aristas de resolución de punteros.

La cadena de resolución en x64 se expresa como una composición de funciones de acceso:

$$\text{Resolve}: \text{ArchReg} \xrightarrow{\text{offset}} \text{PEB} \xrightarrow{+0x18} \text{Ldr} \xrightarrow{+0x20} \text{InMemoryOrderModuleList} \xrightarrow{\text{walk}} \text{DllBase}$$

```
═══════════════════════════════════════════════════════════════════
              GRAFO DE RESOLUCIÓN PEB (x64)
═══════════════════════════════════════════════════════════════════

  gs:[0x60]
      │
      ▼
  ┌─────────┐     +0x18     ┌──────────────┐     +0x20
  │   PEB   │──────────────►│ PEB_LDR_DATA │──────────────┐
  └─────────┘               └──────────────┘              │
                                                          ▼
                                              ┌───────────────────────┐
                                              │ InMemoryOrderModuleList│
                                              │ (LIST_ENTRY双向链表)    │
                                              └───────────┬───────────┘
                                                          │
                              ┌───────────────────────────┼───────────────────┐
                              ▼                           ▼                   ▼
                    ┌─────────────────┐      ┌─────────────────┐   ┌─────────────────┐
                    │ LDR_ENTRY:      │      │ LDR_ENTRY:      │   │ LDR_ENTRY:      │
                    │ ntdll.dll       │      │ kernel32.dll    │   │ ...             │
                    │ DllBase=0x7FF...│      │ DllBase=0x7FF...│   │                 │
                    └────────┬────────┘      └─────────────────┘   └─────────────────┘
                             │
                    ┌────────▼────────┐
                    │ PE Header Parse │
                    │ DOS → NT →      │
                    │ Export Directory│
                    │ ┌─────────────┐ │
                    │ │ Name→Hash   │ │
                    │ │ Ordinal→Func│ │
                    │ └─────────────┘ │
                    └─────────────────┘

═══════════════════════════════════════════════════════════════════
```

**Función de hash para resolución de APIs:**

Para evitar strings detectables, las funciones se resuelven por hash del nombre. La función de hash más común es FNV-1a:

$$h_{FNV1a}(s) = \text{fold}_{n=0}^{|s|-1} \left( h_i = (h_{i-1} \oplus s[i]) \times p \right), \quad h_{-1} = \text{offset}_{basis}, \; p = \text{FNV\_prime}$$

donde $\text{fold}$ es un pliegue iterativo, $\oplus$ es XOR bit a bit, y $p$ es el primo FNV ($16777619$ para 32 bits). La función $h_{FNV1a}$ es **determinística** pero no inyectiva (colisiones posibles), lo que introduce un riesgo teórico de resolución errónea.

### 5.2 API Unhooking: Restauración de la Sección .text

**Definición 5.2.1 — Hook como Transformación Local**

Un EDR hook es una **transformación local** de la sección `.text` de `ntdll.dll` en el espacio de usuario. Sea $\mu_{orig}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo original y $\mu_{hooked}: \text{Addr} \rightarrow \text{Bytes}$ el mapeo modificado. Para la dirección de entrada de una función $f$:

$$\mu_{hooked}(f_{entry}) = \underbrace{\text{jmp}\; \text{EDR\_handler}}_{5-14\;\text{bytes}} \; \| \; \mu_{orig}(f_{entry} + k)[k+1..]$$

donde $k$ es el número de bytes sobrescritos por el trampolín.

**Unhooking** es la operación inversa:

$$\mu_{restored} = \mu_{disk} \circ \pi_{.text}$$

donde $\mu_{disk}$ es el mapeo leído desde el archivo en disco (`C:\Windows\System32\ntdll.dll`) y $\pi_{.text}$ es la proyección sobre la sección `.text`.

```
═══════════════════════════════════════════════════════════════════
              ESTADOS DE NtAllocateVirtualMemory
═══════════════════════════════════════════════════════════════════

  ESTADO ORIGINAL (en disco):
  ┌──────────────────────────────────────┐
  │ 0x0000: mov r10, rcx                │  ← Prólogo estándar NT syscall
  │ 0x0003: mov eax, 0x18               │  ← Syscall number
  │ 0x0008: test byte ptr [...], 0x01   │  ← Syscall stub validation
  │ 0x000F: jne ...                     │
  │ 0x0015: syscall                     │  ← Transición Ring 3 → Ring 0
  │ 0x0017: ret                         │
  └──────────────────────────────────────┘

  ESTADO HOOKEADO (en memoria, por EDR):
  ┌──────────────────────────────────────┐
  │ 0x0000: jmp 0x7FFxxxxx              │  ← Trampolín al handler EDR
  │ 0x0005: [bytes sobrescritos]         │  ← Código original destruido
  │ 0x0008: ...                          │
  │ 0x0015: syscall                      │  ← Intacto (después del hook)
  │ 0x0017: ret                          │
  └──────────────────────────────────────┘

  OPERACIÓN DE UNHOOKING:
  ┌──────────────────────────────────────┐
  │ 1. NtCreateFile → abrir ntdll.dll   │  ← Desde disco
  │ 2. NtReadFile → leer .text section  │
  │ 3. NtProtectVirtualMemory → RW      │  ← Cambiar protección de página
  │ 4. memcpy → sobrescribir hooked     │  ← Restaurar bytes originales
  │ 5. NtProtectVirtualMemory → RX      │  ← Restaurar protección
  └──────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 5.3 Indirect Syscalls: Redirección del Punto de Transición

**Definición 5.3.1 — Syscall Directo vs. Indirecto**

Un **syscall directo** ejecuta la instrucción `syscall` desde una dirección fuera de `ntdll.dll`:

$$\text{DirectSyscall}: \text{Addr}_{syscall} \notin \text{Range}(\text{ntdll.dll})$$

Un **syscall indirecto** lee la dirección de la instrucción `syscall; ret` desde dentro de `ntdll.dll` y salta a ella, evitando el trampolín del hook:

$$\text{IndirectSyscall}: \text{Addr}_{syscall} \in \text{Range}(\text{ntdll.dll}) \wedge \text{Addr}_{entry} \notin \text{Range}(\text{ntdll.dll})$$

Formalmente, la diferencia está en la **cadena de llamadas** (call stack):

$$\text{Stack}_{direct} = [\text{payload}, \underbrace{\text{syscall}}_{\text{fuera de ntdll}}]$$

$$\text{Stack}_{indirect} = [\text{payload}, \underbrace{\text{ntdll!NtXxx+offset}}_{\text{dentro de ntdll}}]$$

El EDR que verifica que la dirección de retorno del syscall caiga dentro de `ntdll.dll` no detecta el syscall indirecto.

### 5.4 ETW Patching: Supresión de la Función de Generación de Eventos

**Definición 5.4.1 — Función de Generación ETW**

El subsistema ETW implementa una función de generación de eventos:

$$G_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \text{EventRecord}$$

El ETW patching reemplaza las primeras instrucciones de `EtwEventWrite` en `ntdll.dll` con un stub que retorna `STATUS_SUCCESS` inmediatamente:

$$G'_{ETW}: \text{Provider} \times \text{EventDescriptor} \times \text{Payload} \rightarrow \emptyset$$

**Impacto en el autómata híbrido WQL:**

Recordemos que el motor de eventos WMI se modela como $\mathcal{A}_H = (S, E, \delta, G, \text{Init})$. El conjunto de eventos $E$ se particiona en:

$$E = E_{intrinsic} \uplus E_{extrinsic}$$

donde $E_{extrinsic}$ depende de ETW y $E_{intrinsic}$ es generado directamente por el repositorio CIM. El ETW patching elimina $E_{extrinsic}$:

$$E' = E_{intrinsic}$$

El autómata pierde transiciones:

$$|\{\delta(s, e) \mid e \in E_{extrinsic}\}| > 0$$

pero $\delta(s, e)$ queda indefinida para todo $e \in E_{extrinsic}$. El autómata se **congela parcialmente**: solo responde a eventos intrínsecos (CRUD sobre el repositorio).

```
═══════════════════════════════════════════════════════════════════
            IMPACTO DEL ETW PATCHING EN EL AUTÓMATA WQL
═══════════════════════════════════════════════════════════════════

  ANTES DEL PATCH:
  ┌───────────────────────────────────────────────────────────┐
  │                                                           │
  │  E = E_intrinsic ⊎ E_extrinsic                           │
  │                                                           │
  │  s₀ ──δ(s₀,e₁)──► s₁ ──δ(s₁,e₂)──► s₂ ──...──► sₙ   │
  │       e₁∈E_int        e₂∈E_ext                          │
  │                                                           │
  │  El autómata transiciona con eventos de ambos tipos      │
  └───────────────────────────────────────────────────────────┘

  DESPUÉS DEL PATCH:
  ┌───────────────────────────────────────────────────────────┐
  │                                                           │
  │  E' = E_intrinsic  (E_extrinsic eliminado)               │
  │                                                           │
  │  s₀ ──δ(s₀,e₁)──► s₁ ──✗── s₂ ──δ(s₂,e₃)──► s₃      │
  │       e₁∈E_int       e₂∉E'    e₃∈E_int                  │
  │                     (transición                           │
  │                      bloqueada)                           │
  │                                                           │
  │  El autómata solo transiciona con eventos intrínsecos     │
  │  Win32_ProcessStartTrace → NO GENERADO                   │
  │  __InstanceCreationEvent → SOLO si es CRUD sobre CIM     │
  └───────────────────────────────────────────────────────────┘

  FORMALMENTE:
  G'_ETW = ∅  ⟹  ∀e ∈ E_extrinsic: G(e) = false
             ⟹  ∀s ∈ S, e ∈ E_extrinsic: δ(s,e) indefinida
             ⟹  Σ_WQL opera con información incompleta

═══════════════════════════════════════════════════════════════════
```

### 5.5 El Mecanismo APC como Vector de Inyección

#### 5.5.1 Modelo CSP del Hilo con Inyección

El modelo CSP de un hilo $T$ (Definición 3.1.1) es:

$$T = \text{Running} \rightarrow T' \;\Box\; \text{AlertableWait} \rightarrow \text{ProcessAPCQueue} \rightarrow T''$$

La inyección APC inserta un elemento en el canal bufferizado:

$$\text{APCQueue}_T \xrightarrow{+\text{APC}(f_{mal}, ctx_{mal})} \text{APCQueue}'_T$$

donde $f_{mal}$ es la dirección de la función maliciosa y $ctx_{mal}$ es su contexto. El hilo, al entrar en `AlertableWait`, procesa esta APC como si fuera una operación legítima.

#### 5.5.2 Especificación Formal de la Inyección

La inyección APC se especifica como una **transformación del estado** del subsistema APC:

$$\tau_{APC}: \Sigma_{APC} \rightarrow \Sigma_{APC}$$

donde la transformación agrega una KAPC a la cola de un hilo existente:

$$\tau_{APC}(\sigma_{APC}) = \sigma_{APC}[\text{APCQueue}_T \mapsto \text{APCQueue}_T \cup \{\text{KAPC}(m=\text{UserMode}, n_r=f_{mal}, ctx=ctx_{mal})\}]$$

**Precondiciones** (de la Definición 3.5.1):

$$\text{Pre}(\tau_{APC}) \iff \text{HasAccess}(\text{caller}, T_{target}, \text{THREAD\_SET\_CONTEXT}) \wedge \text{IsValidAddr}(f_{mal}, \text{ProcessSpace}(T_{target})) \wedge \neg\text{IsTerminated}(T_{target})$$

**Postcondiciones:**

$$\text{Post}(\tau_{APC}) \iff \text{Inserted}(kapc) = \text{TRUE} \wedge \text{ApcMode}(kapc) = \text{UserMode} \wedge \text{NormalRoutine}(kapc) = f_{mal}$$

**Propiedad de herencia de contexto de seguridad:**

$$\text{SecurityContext}(\text{APC}) = \text{SecurityContext}(T_{host})$$

Esta es una **contradependencia** del sistema: el mecanismo APC confía en que el emisor de la APC es legítimo (posee `THREAD_SET_CONTEXT`), y por lo tanto hereda implícitamente el contexto de seguridad del hilo anfitrión. El atacante explota esta contradependencia.

```
═══════════════════════════════════════════════════════════════════
          CICLO DE VIDA DEL APC INYECTADO
═══════════════════════════════════════════════════════════════════

  PROCESO ATACANTE                   HILO LEGÍTIMO (T_host)
  ┌──────────────────┐              ┌──────────────────────────┐
  │                  │              │ Estado: Running           │
  │ NtQueueApcThread │              │                          │
  │ (T_handle,       │              │                          │
  │  f_mal,          │──────────────│ APCQueue_T: [...]        │
  │  ctx_mal)        │   Enqueue    │                 │        │
  │                  │──────────────│ APCQueue'_T: [...,      │
  │                  │              │   KAPC(m=User,           │
  │                  │              │   n_r=f_mal,             │
  └──────────────────┘              │   ctx=ctx_mal)]          │
                                    │                          │
                                    │ ... ejecución normal ... │
                                    │                          │
                                    │ WaitForSingleObjectEx    │
                                    │ (alertable=TRUE)         │
                                    │                          │
                                    │ ▼ ProcessAPCQueue        │
                                    │                          │
                                    │ Kernel entrega APC:      │
                                    │ f_mal(ctx_mal)           │
                                    │                          │
                                    │ ★ Ejecución con          │
                                    │   SecurityContext(T_host)│
                                    │   = privilegios heredados│
                                    └──────────────────────────┘

═══════════════════════════════════════════════════════════════════
```

### 5.6 Comparación Formal de Métodos de Inyección

| Dimensión | `NtCreateThreadEx` | `NtQueueApcThread` |
|---|---|---|
| Modelo CSP | Creación de nuevo proceso $T_{new}$ | Inserción en canal existente $\text{APCQueue}_T$ |
| Visibilidad | Alta: creación de hilo genera `__InstanceCreationEvent` en ETW | Baja: APC delivery no genera evento ETW visible |
| Contexto de seguridad | `SecurityContext(T_{new})` = proceso actual | `SecurityContext(APC) = SecurityContext(T_{host})` |
| Requisito | Ninguno adicional | $T_{host}$ debe entrar en estado alertable |
| Detección | ETW: `ThreadCreate` event del kernel | Kernel: auditoría de `NtQueueApcThread` cross-process |

### 5.7 COM/DCOM como Superficie de Interacción con WMI

La cadena de invocación WMI (Sección 5.2 del documento de referencia):

$$\text{Consumer} \xrightarrow{\text{COM}} \text{WMI Service} \xrightarrow{\text{WQL}} \text{CIM Repository} \xrightarrow{\text{Esent}} \text{Disk}$$

Toda interacción con el repositorio CIM pasa por el **functor de activación COM**:

$$\mathcal{F}_{act}: \mathbf{CLSID} \rightarrow \mathbf{Instance}$$

El **marshaling** $\mu: \text{Data}_{client} \rightarrow \text{WireFormat} \rightarrow \text{Data}_{server}$ es una transformación natural que preserva composición, identidad e inversibilidad. Esto implica que los datos que transitan por la interfaz COM de WMI son **inspeccionables** en el formato wire (NDR).

El **descriptor de seguridad COM**:

$$\text{SD}_{COM} = (\text{Owner}, \text{Group}, \text{DACL}, \text{SACL})$$

controla el acceso a la activación de objetos WMI. Un intento de manipular el repositorio CIM (ej. crear un `__EventFilter` malicioso) debe satisfacer las verificaciones de la DACL del servicio WMI.

### 5.8 Superficie de Detección (Etapa 4) — Formalización

| Señal | Predicado de Detección | Mecanismo |
|---|---|---|
| Lectura de ntdll.dll desde disco | $\exists\, p: \text{Reads}(p, \text{ntdll.dll}) \wedge \text{HasLoaded}(p, \text{ntdll.dll})$ | Minifilter: IRP_MJ_READ |
| Escritura en .text de ntdll | $\exists\, p, a: \text{Writes}(p, a) \wedge a \in \text{Range}(\text{ntdll}.text)$ | Protección de página RWX |
| Syscall fuera de ntdll | $\text{RetAddr}_{syscall} \notin \text{Range}(\text{ntdll.dll})$ | Kernel-mode: inspección de caller |
| Páginas RW→RX sin respaldo | $\exists\, p: \text{PageState}(p) = RW \wedge \text{PageState}'(p) = RX \wedge \text{MemType}(p) = \text{MEM\_PRIVATE}$ | ETW `Microsoft-Windows-Kernel-Memory` |
| ETW patching | $\mu_{mem}(\text{EtwEventWrite}_{entry}) \neq \mu_{disk}(\text{EtwEventWrite}_{entry})$ | Verificación periódica de integridad |
| APC cross-process | $\text{Source}(\text{NtQueueApcThread}) \neq \text{Process}(T_{target})$ | Auditoría de syscall cross-process |
| Interacción COM sospechosa | $\text{Method}(call) = \text{ExecNotificationQuery} \vee \text{CreateInstance}(\text{__EventFilter})$ | Monitoreo de proxy/stub COM |

---

## 6. Etapa 5 — El Payload ASM: PIC, Evasión y Superficie de Estado Global

### 6.1 Position Independent Code: Formalización

**Definición 6.1.1 — Código Posicional-Independiente**

Un bloque de código $C$ es **Position Independent** si y solo si:

$$\forall\, a_1, a_2 \in \text{AddrSpace}: \text{Semantics}(C \text{ @ } a_1) = \text{Semantics}(C \text{ @ } a_2)$$

donde $C \text{ @ } a$ denota el código $C$ cargado en la dirección base $a$. Esto equivale a la condición de que **toda referencia a datos usa direccionamiento relativo al RIP**:

$$\forall\, \text{instr } i \in C: \text{if } i.\text{type} = \text{data\_ref} \Rightarrow i.\text{addr} = \text{RIP} + \text{offset}$$

Ensamblador característico:

```asm
lea rax, [rip + offset_to_data]    ; Referencia relativa al RIP
mov rbx, [rax]                      ; Acceso a datos sin dirección absoluta
```

**Propiedad algebraica:** El código PIC es **invariante bajo translación** en el espacio de direcciones. Si definimos la operación de translación $T_\Delta(a) = a + \Delta$, entonces:

$$\text{Semantics}(T_\Delta(C)) = \text{Semantics}(C) \quad \forall\, \Delta$$

### 6.2 Hardware Breakpoints: Modelo de Registros de Depuración

**Definición 6.2.1 — Registros de Depuración x64**

El procesador x64 provee un conjunto de registros de depuración que forman un **subsistema de monitoreo hardware**:

$$\mathcal{D} = (\text{DR0}, \text{DR1}, \text{DR2}, \text{DR3}, \text{DR6}, \text{DR7})$$

donde:
- $\text{DR0..DR3} \in \text{AddrSpace}$: Direcciones de los 4 breakpoints
- $\text{DR6}$: Registro de estado (cuál breakpoint se activó)
- $\text{DR7}$: Registro de control (habilitación, tipo, tamaño de cada breakpoint)

El tipo de breakpoint se codifica en los bits de DR7:

$$\text{BPType}(n) \in \{\text{Exec}, \text{Write}, \text{IO}, \text{RW}\}$$

$$\text{BPLen}(n) \in \{1, 2, 4, 8\} \;\text{bytes}$$

**Función de detección de breakpoints:**

$$\text{DetectBP}: \mathcal{D} \rightarrow \{\text{Clean}, \text{Compromised}\}$$

$$\text{DetectBP}(\mathcal{D}) = \begin{cases} \text{Compromised} & \text{si } \exists\, n \in [0,3]: \text{DR7.LocalEnable}(n) = 1 \wedge \text{DR}n \in \text{CodeRange} \\ \text{Clean} & \text{en otro caso} \end{cases}$$

### 6.3 Stack Spoofing: Falsificación del Grafo de Pila

**Definición 6.3.1 — Pila como Grafo de Marcos**

La pila de llamadas de un hilo se modela como una **lista enlazada** de marcos de activación:

$$\text{Stack} = [f_0 \rightarrow f_1 \rightarrow f_2 \rightarrow \ldots \rightarrow f_n]$$

donde cada marco $f_i$ contiene una **dirección de retorno** $\text{ret}_i \in \text{AddrSpace}$. Un **stack walk** es el recorrido de esta lista:

$$\text{StackWalk}: \text{RSP} \rightarrow [\text{ret}_0, \text{ret}_1, \ldots, \text{ret}_n]$$

El **stack spoofing** reemplaza la secuencia real con una secuencia sintética que imita una cadena de llamadas legítima:

$$\text{StackWalk}(RSP_{spoofed}) = [\text{ntdll!RtlUserThreadStart}, \text{kernel32!BaseThreadInitThunk}, \text{legitimate\_frame}, \ldots]$$

```
═══════════════════════════════════════════════════════════════════
              STACK SPOOFING: PILA REAL vs. FALSIFICADA
═══════════════════════════════════════════════════════════════════

  PILA REAL (detectable por EDR):       PILA FALSIFICADA (spoofed):
  ┌──────────────────────────┐         ┌──────────────────────────────┐
  │ ret_addr: payload+0x1A3  │         │ ret_addr: ntdll!RtlUser...   │
  │ ret_addr: payload+0x0F2  │         │ ret_addr: kernel32!BaseT...  │
  │ ret_addr: payload+0x008  │         │ ret_addr: legitimate.dll!... │
  │ datos del payload        │         │ stack frame "legítimo"       │
  │ ...                      │         │ ...                          │
  └──────────────────────────┘         └──────────────────────────────┘
       │                                      │
       ▼                                      ▼
  EDR detecta:                       EDR observa:
  "Ejecución desde                  "Cadena de llamadas
   memoria no respaldada,           legítima del sistema,
   sin frames válidos"              sin anomalías aparentes"

═══════════════════════════════════════════════════════════════════
```

**Invariante detectable:** Un EDR avanzado puede verificar la coherencia entre la pila y las tablas de unwind del PE (`.pdata`). Si la secuencia de direcciones de retorno no corresponde a una cadena válida según las `RUNTIME_FUNCTION` entries, el spoofing es detectado:

$$\text{ValidateStack}(\text{stack}) = \forall\, f_i \in \text{stack}: \exists\, \text{RUNTIME\_FUNCTION}_j : f_i.\text{ret} \in \text{Range}(\text{RF}_j)$$

### 6.4 Syscalls Directos: Omisión de ntdll.dll

**Definición 6.4.1 — Número de Syscall como Función Dependiente de Versión**

El número de syscall no es estático entre versiones de Windows. Definimos:

$$\text{SyscallNum}: \text{FuncName} \times \text{WinVersion} \rightarrow \mathbb{N}$$

Por ejemplo, para `NtAllocateVirtualMemory`:

$$\text{SyscallNum}(\text{NtAllocateVirtualMemory}, \text{Win11\_23H2}) = 0x18$$

pero este valor cambia entre builds. El payload debe resolver el número de syscall dinámicamente (leyendo desde la EAT de `ntdll.dll` en memoria) o embeberlo estáticamente con riesgo de incompatibilidad.

**Modelo de ejecución directa:**

```asm
; Syscall directo — sin pasar por ntdll.dll
mov r10, rcx               ; Convención de llamada NT
mov eax, [syscall_number]  ; Número resuelto dinámicamente
syscall                    ; Transición Ring 3 → Ring 0
ret                        ; Retorno
```

**Detección por HVCI:** Con Virtualization-Based Security (VBS) e HVCI habilitados, el hypervisor verifica que toda página ejecutable esté firmada por un binario de confianza. El payload PIC ejecutándose desde una página `MEM_PRIVATE` sin respaldo en disco es bloqueado:

$$\text{HVCI}(\text{page}) = \begin{cases} \text{Allow} & \text{si } \text{PageSignature}(\text{page}) \in \text{TrustedSignatures} \\ \text{Block} & \text{en otro caso} \end{cases}$$

### 6.5 Integración con el Espacio de Estados Global

Recordemos que:

$$\Sigma_{total} = \Sigma_{FS} \times \Sigma_{Shell} \times \Sigma_{Proc} \times \Sigma_{CIM} \times \Sigma_{WQL} \times \Sigma_{APC} \times \Sigma_{COM} \times \Sigma_{ETW}$$

El payload ASM, al operar, produce **transiciones compuestas** que afectan múltiples componentes simultáneamente:

| Componente | Predicado de Efecto | Formalización |
|---|---|---|
| $\Sigma_{ETW}$ | ETW parcheado | $G'_{ETW} = \emptyset \Rightarrow E' = E_{intrinsic}$ |
| $\Sigma_{APC}$ | APCs inyectadas | $\text{APCQueue}_T \supsetneq \text{APCQueue}_T^{orig}$ |
| $\Sigma_{Proc}$ | Memoria RX sin respaldo | $\exists\, p: \text{Prot}(p) = RX \wedge \text{Type}(p) = \text{MEM\_PRIVATE}$ |
| $\Sigma_{COM}$ | Posible comunicación C2 | $\exists\, \text{RPC\_binding}: \text{State} = \text{Active}$ |
| $\Sigma_{CIM}$ | Posible manipulación | $\sigma_{CIM} \neq \sigma_{CIM}^{orig}$ si se crean event subscriptions |

La **señal compuesta** de alta confianza se define como la conjunción de múltiples predicados:

$$\text{HighConfidenceSignal}(\sigma) \iff \neg\text{ETWIntact}(\sigma) \wedge \exists\, \text{injected\_APC}(\sigma) \wedge \exists\, \text{COM\_anomaly}(\sigma)$$

Esta señal compuesta es más difícil de evadir que cualquier señal individual, porque requiere evadir múltiples subsistemas simultáneamente.

### 6.6 Superficie de Detección (Etapa 5) — Formalización

| Señal | Predicado de Detección | Mecanismo |
|---|---|---|
| Ejecución sin respaldo en disco | $\exists\, p: \text{Exec}(p) \wedge \text{MemType}(p) = \text{MEM\_PRIVATE} \wedge \text{Prot}(p) = RX$ | HVCI/VBS |
| Syscall desde fuera de ntdll | $\text{RetAddr}_{syscall} \notin \text{Range}(\text{ntdll.dll}) \wedge \text{HVCI} = \text{Enabled}$ | Hypervisor enforcement |
| Stack walk incoherente | $\exists\, f_i \in \text{stack}: \nexists\, \text{RF}_j : f_i.\text{ret} \in \text{Range}(\text{RF}_j)$ | EDR avanzado con unwind validation |
| Registros DR manipulados | $\text{DR7}.\text{LocalEnable} \neq 0 \wedge \text{Source}(DR\_access) \neq \text{kernel}$ | Kernel: trap on DR access |
| Señal compuesta | $\neg\text{ETWIntact} \wedge \text{injected\_APC} \wedge \text{COM\_anomaly}$ | Correlación multi-subsistema |

---

## 7. Análisis de Superficie Compuesta y Correlación de Invariantes

### 7.1 Invariantes del Sistema que Son Violados por el Vector

Cada etapa del vector viola un **invariante de seguridad** del sistema:

| Etapa | Invariante Violado | Formalización |
|---|---|---|
| 1 (ISO) | Propagación transitiva de zona | $\neg\text{PPT}: \exists\, f: f \sqsubseteq c \wedge \text{ZoneAttrib}(f) = \bot \wedge \text{ZoneAttrib}(c) = 3$ |
| 2 (LNK) | Consistencia representamen-objeto | $\text{Deceit}(S): R \neq O \wedge I(R) = I(O)$ |
| 3 (LOLBins) | Consistencia de parseo | $\neg\text{Inv}_{parse}: \text{ArgsDisplayed}(lnk) \neq \text{ArgsExecuted}(lnk)$ |
| 4 (Cargador) | Integridad de código de ntdll | $\mu_{mem}(\text{ntdll}.text) \neq \mu_{disk}(\text{ntdll}.text)$ |
| 4 (Cargador) | Integridad de generación ETW | $G'_{ETW} = \emptyset$ |
| 5 (ASM) | Integridad de pila de llamadas | $\neg\text{ValidateStack}(\text{stack})$ |

### 7.2 Función de Detección Compuesta

**Definición 7.2.1 — Función de Confianza del Sistema**

Definimos una función de confianza que mapea cada estado del sistema a un nivel de confianza:

$$\mathcal{T}: \Sigma \rightarrow [0, 1]$$

$$\mathcal{T}(\sigma) = \prod_{i=1}^{k} \mathcal{T}_i(\sigma)$$

donde cada $\mathcal{T}_i$ es la confianza del invariante $i$:

$$\mathcal{T}_i(\sigma) = \begin{cases} 1 & \text{si invariante } i \text{ se preserva en } \sigma \\ 0 & \text{si invariante } i \text{ se viola en } \sigma \end{cases}$$

Un vector de ataque exitoso requiere $\mathcal{T}(\sigma) = 0$ (todos los invariantes violados). Un EDR efectivo busca $\mathcal{T}_i(\sigma) = 0$ para algún $i$ (cualquier invariante violado es señal de anomalía).

La ventaja del atacante es que cada invariante se verifica en un **subsistema diferente**, y la evasión de un subsistema no implica evasión de los demás. La ventaja del defensor es que la **conjunción** de señales parciales produce una señal compuesta de alta confianza.

### 7.3 Análisis Información-Teórico de la Detección

**Definición 7.3.1 — Información Mutua entre Señal y Ataque**

La efectividad de una señal de detección $D$ se mide por la **información mutua** entre la señal y la presencia del ataque $A$:

$$I(D; A) = H(A) - H(A \mid D) = \sum_{a, d} P(a, d) \log_2 \frac{P(a, d)}{P(a) \cdot P(d)}$$

Una señal compuesta $D = D_1 \wedge D_2 \wedge \ldots \wedge D_k$ tiene información mutua no decreciente:

$$I(D_1 \wedge D_2; A) \geq \max(I(D_1; A), I(D_2; A))$$

Esto formaliza la intuición de que la correlación multi-subsistema es más informativa que cualquier señal individual.

---

## 8. Diagrama Integrado del Vector y Subsistemas

```
═══════════════════════════════════════════════════════════════════════════════
                    VECTOR DE ATAQUE DE 5 ETAPAS
              MAPEO A SUBSISTEMAS DE WINDOWS 11
═══════════════════════════════════════════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ETAPA 1: CONTENEDOR ISO                                               │
  │                                                                         │
  │  Subsistema: Σ_FS (File System) + VHDMP.sys                            │
  │  Invariante violado: PPT (Propagación Transitiva de Zona)              │
  │                                                                         │
  │  Descarga ──► AES escribe Zone.Identifier ──► Montaje ISO              │
  │                  ZoneAttrib(iso)=3            ZoneAttrib(f∈iso)=⊥       │
  │                                                                         │
  │  ΔH = log₂|Z| ≈ 2.32 bits/archivo de pérdida de información           │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ETAPA 2: SEÑUELO LNK                                                  │
  │                                                                         │
  │  Subsistema: Σ_Shell (shell32.dll, Explorer)                           │
  │  Invariante violado: Consistencia R=O (Semiótica)                     │
  │                                                                         │
  │  ┌──────────────────┐     ┌──────────────────────────┐                 │
  │  │ Percepción:      │  ≠  │ Realidad:                │                 │
  │  │ [Acrobat]        │     │ Target = cmd.exe         │                 │
  │  │ "Factura.pdf"    │     │ Args = /c powershell ... │                 │
  │  └──────────────────┘     └──────────────────────────┘                 │
  │                                                                         │
  │  Deceit(S) ⟺ R ≠ O ∧ I(R) = I(O) ∧ HideFileExt = TRUE               │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ETAPA 3: DISPARADOR LOLBins                                           │
  │                                                                         │
  │  Subsistema: Σ_Proc + Σ_WQL                                            │
  │  Invariante violado: Inv_parse (consistencia de parseo LNK)           │
  │                                                                         │
  │  Explorer ──► cmd.exe ──► powershell.exe ──► payload                  │
  │      │            │            │                                       │
  │      │     T(cmd)=Trusted  T(ps)=Trusted                               │
  │      │            │            │                                       │
  │      │     ┌──────▼────────────▼──────┐                                │
  │      │     │  WQL Event Engine         │                                │
  │      │     │  __InstanceCreationEvent  │                                │
  │      │     │  Latencia: L = Lq+Lf+Ld  │                                │
  │      │     │  Ventana: [tg, tc)       │                                │
  │      │     └───────────────────────────┘                                │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ETAPA 4: CARGADOR C++                                                 │
  │                                                                         │
  │  Subsistemas: Σ_Proc + Σ_ETW + Σ_APC + Σ_COM                          │
  │  Invariantes violados: Integridad ntdll, Integridad ETW               │
  │                                                                         │
  │  ┌─────────────────────────────────────────────────────────┐           │
  │  │ 1. PEB Resolution → gs:[0x60] → ntdll.dll base        │           │
  │  │ 2. API Unhooking: μ_disk → μ_restored (ntdll.text)     │           │
  │  │ 3. ETW Patching: G_ETW → G'_ETW = ∅                   │           │
  │  │ 4. Indirect Syscalls: Addr_syscall ∈ Range(ntdll)      │           │
  │  │ 5. NtAllocateVirtualMemory(RW)                         │           │
  │  │ 6. Decrypt(ASM_payload)                                 │           │
  │  │ 7. NtWriteVirtualMemory                                 │           │
  │  │ 8. NtProtectVirtualMemory(RW→RX)                       │           │
  │  │ 9a. NtCreateThreadEx → hilo dedicado                   │           │
  │  │ 9b. NtQueueApcThread → APC en hilo existente           │           │
  │  │     └── SecurityContext(APC) = SecurityContext(Thost)   │           │
  │  └─────────────────────────────────────────────────────────┘           │
  │                                                                         │
  │  COM/DCOM: F_act(CLSID) → Instance → μ(Data) → WMI Service           │
  └───────────────────────────────┬─────────────────────────────────────────┘
                                  │
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ETAPA 5: PAYLOAD ASM                                                  │
  │                                                                         │
  │  Subsistemas: Σ_total (todos)                                          │
  │                                                                         │
  │  ┌────────────────────────────────────────────────────────┐            │
  │  │ Position Independent Code: ∀a₁,a₂: Sem(C@a₁)=Sem(C@a₂)│            │
  │  │ Hardware BP Check: DetectBP(D) = Clean|Compromised     │            │
  │  │ Stack Spoofing: StackWalk(RSP') ∈ LegitimateFrames     │            │
  │  │ Direct Syscalls: SyscallNum(f,v) → N                   │            │
  │  └────────────────────────────────────────────────────────┘            │
  │                                                                         │
  │  Σ_total = Σ_FS × Σ_Shell × Σ_Proc × Σ_CIM × Σ_WQL × Σ_APC          │
  │            × Σ_COM × Σ_ETW                                              │
  │                                                                         │
  │  Transiciones compuestas:                                               │
  │  ├── Σ_ETW: G'_ETW = ∅ → autómata WQL parcialmente congelado          │
  │  ├── Σ_APC: APCQueue_T ⊋ APCQueue_T^orig                              │
  │  ├── Σ_COM: posible canal C2 vía DCOM                                  │
  │  └── Σ_CIM: posible manipulación de event subscriptions                │
  └─────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
```

---

## 9. Análisis de Dependencias y Condiciones de Fallo

### 9.1 Cadena de Dependencias como Fórmula de Satisfacibilidad

Cada etapa depende de supuestos que deben cumplirse **simultáneamente** para que la cadena no se rompa. El vector completo es exitoso si y solo si:

$$\text{Success} \iff \bigwedge_{i=1}^{5} \text{Assumption}_i$$

donde cada $\text{Assumption}_i$ es la conjunción de las precondiciones de la etapa $i$:

| Etapa | Asunción Crítica | Negación (Condición de Fallo) | Subsistema |
|---|---|---|---|
| 1 | $\neg\text{PPT}$ (MotW no se propaga en ISO) | Parche Windows 11 22H2+: `vhdmp.sys` propaga MotW | $\Sigma_{FS}$ |
| 2 | $\text{HideExt} = \text{TRUE}$ | Política: forzar mostrar extensiones | $\Sigma_{Shell}$ |
| 3 | $\text{ConstrainedLanguageMode} = \text{FALSE}$ | WDAC/AppLocker: modo restringido de PowerShell | $\Sigma_{Proc}$ |
| 4 | $\text{HVCI} = \text{FALSE}$ (ntdll modificable) | VBS/HVCI: integridad de código forzada | $\Sigma_{ETW}, \Sigma_{APC}$ |
| 5 | $\text{HVCI} = \text{FALSE}$ (páginas no firmadas ejecutables) | VBS/HVCI: rechazo de ejecución desde páginas no firmadas | $\Sigma_{total}$ |

### 9.2 Diagrama de Condiciones de Fallo

```
═══════════════════════════════════════════════════════════════════
           CONDICIONES DE FALLO DEL VECTOR (DEFENSA)
═══════════════════════════════════════════════════════════════════

  Etapa 1 ─── MotW Propagation Fix (Win11 22H2+)
      │         ZoneAttrib(f∈iso) = ZoneAttrib(iso)
      │         PPT restaurada → atacante necesita otro vector
      │
  Etapa 2 ─── Show File Extensions (GPO)
      │         HideFileExt = FALSE
      │         DisplayName("x.pdf.lnk") = "x.pdf.lnk"
      │         Deceit(S) = FALSE
      │
  Etapa 3 ─── Constrained Language Mode / WDAC
      │         PowerShell = ConstrainedLanguage
      │         T(cmd.exe) = Blocked (si AppLocker)
      │         ψ_anomaly detectada por WQL
      │
  Etapa 4 ─── HVCI / VBS
      │         ntdll.text no modificable (hypervisor enforcement)
      │         EtwEventWrite no parcheable
      │         Páginas MEM_PRIVATE + RX = bloqueadas
      │         NtQueueApcThread auditada cross-process
      │
  Etapa 5 ─── HVCI + EDR Avanzado
      │         Ejecución desde páginas no firmadas = bloqueada
      │         Stack walk incoherente = detectada
      │         Correlación multi-subsistema = señal compuesta

  ═══════════════════════════════════════════════════════════
  5 infracciones de invariantes → 5 superficies de detección
  La defensa más efectiva: HVCI + correlación multi-subsistema
  ═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════════
```

### 9.3 Análisis Probabilístico de la Cadena

Si cada condición de fallo tiene una probabilidad independiente $p_i$ de estar activa (defensa implementada), la probabilidad de que el vector sea exitoso es:

$$P(\text{Success}) = \prod_{i=1}^{5} (1 - p_i)$$

Asumiendo estimaciones conservadoras para un entorno empresarial Windows 11 con políticas de seguridad estándar:

| Condición | $p_i$ estimado | Rationale |
|---|---|---|
| MotW propagation (22H2+) | 0.60 | Adopción creciente de 22H2+ |
| Show extensions | 0.15 | Raramente forzado en empresas |
| CLM/WDAC | 0.25 | Implementación moderada |
| HVCI/VBS | 0.40 | Hardware compatible pero a menudo deshabilitado |
| EDR avanzado | 0.50 | Despliegue común en empresas |

$$P(\text{Success}) \approx (1-0.60)(1-0.15)(1-0.25)(1-0.40)(1-0.50) \approx 0.40 \times 0.85 \times 0.75 \times 0.60 \times 0.50 \approx 0.077$$

Es decir, aproximadamente **7.7% de probabilidad de éxito** contra un entorno empresarial Windows 11 con defensas estándar. Contra un entorno sin defensas ($p_i = 0$ para todo $i$), $P(\text{Success}) = 1$.

---

## 10. Referencias Teóricas

### Sistemas Operativos y Kernel NT
- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.
- Nebbett, G. (2000). *Windows NT/2000 Native API Reference*. Sams Publishing.
- Yason, M. (2019). *Windows 10 x64 Ring 0 to Ring 3 Internals*. OFFSEC.

### Formato Shell Link y MotW
- Microsoft (2024). *[MS-SHLLINK]: Shell Link Binary File Format*. Microsoft Open Specifications.
- Microsoft (2024). *Attachment Execution Service Reference*. MSDN.
- Sandvik, O. (2021). *Mark-of-the-Web Bypass via ISO Mounting*. Microsoft Security Response Center.

### Modelo CIM, WMI y WQL
- DMTF (2023). *Common Information Model (CIM) Infrastructure Specification*, DSP0004.
- Golomshtok, A. (2007). *WMI Essentials for Automating Windows Management*. Sams Publishing.
- Microsoft (2024). *Windows Management Instrumentation Documentation*. Microsoft Learn.

### Teoría de Concurrencia, CSP y Autómatas
- Hoare, C.A.R. (1985). *Communicating Sequential Processes*. Prentice Hall.
- Henzinger, T.A. (1996). *The Theory of Hybrid Automata*. Proceedings of LICS'96.
- Alur, R., et al. (1995). *The Algorithmic Analysis of Hybrid Systems*. Theoretical Computer Science.
- Schneider, S. (1999). *Concurrent and Real-Time Systems: The CSP Approach*. Wiley.

### Modelo COM/DCOM y Distribución
- Box, D. (1998). *Essential COM*. Addison-Wesley.
- Brown, N. & Kindel, C. (1998). *Distributed Component Object Model Protocol*. Microsoft.
- Microsoft (2024). *COM and DCOM Reference*. Microsoft Learn.

### Evasión de Telemetría y Detección
- Ligh, M.H., Case, A., Levy, J., & Walters, A. (2014). *The Art of Memory Forensics*. Wiley.
- Image-File-Execution-Options (2019). *Indirect Syscalls in Malware*. PoC Exploit.
- MalwareTech (2023). *EDR Evasion Techniques: A Taxonomy*. Black Hat USA.

### Teoría de la Información y Detección
- Shannon, C.E. (1948). *A Mathematical Theory of Communication*. Bell System Technical Journal.
- Cover, T.M. & Thomas, J.A. (2006). *Elements of Information Theory*, 2nd Edition. Wiley.

### Álgebra y Teoría de Categorías
- Pierce, B.C. (1991). *Basic Category Theory for Computer Scientists*. MIT Press.
- Asperti, A., Longo, G. (1991). *Categories, Types, and Structures*. MIT Press.
- Mac Lane, S. (1998). *Categories for the Working Mathematician*, 2nd Edition. Springer.

### Semiótica y Cognición
- Peirce, C.S. (1931-1958). *Collected Papers*. Harvard University Press.
- Eco, U. (1976). *A Theory of Semiotics*. Indiana University Press.
- Kahneman, D. (2011). *Thinking, Fast and Slow*. Farrar, Straus and Giroux.

---

*Documento de investigación sobre el fenómeno delincuencial del ataque compuesto de 5 etapas contra Windows 11. El análisis se realiza desde la objetividad científica, formalizando cada mecanismo mediante modelos matemáticos, lógica de predicados y teoría de la información, sin instrucciones de implementación.*
