# Formalización Matemática y Computacional de Subsistemas de Windows 11

## Arquitectura Interna: Modelo Algebraico, Lógico y de Concurrencia

---

> **Alcance:** Este documento presenta una formalización rigurosa de cuatro subsistemas críticos de la arquitectura Windows 11: el Repositorio CIM/WMI, el motor de eventos WQL, el mecanismo de Procedimientos Asíncronos (APC), y el Modelo de Objetos Componentes (COM/DCOM). Cada subsistema es modelado mediante estructuras algebraicas, lógica formal y teoría de concurrencia, con el objetivo de proporcionar una comprensión profunda de los primitivas computacionales que sustentan el sistema operativo.

---

## Tabla de Contenidos

1. [Repositorio CIM — Modelo Algebraico de Objetos](#1-repositorio-cim--modelo-algebraico-de-objetos)
2. [WQL y Motor de Eventos — Modelo Lógico de Predicados](#2-wql-y-motor-de-eventos--modelo-lógico-de-predicados)
3. [Colas APC — Modelo de Concurrencia Asíncrona](#3-colas-apc--modelo-de-concurrencia-asíncrona)
4. [COM/DCOM — Modelo Categorial de Componentes](#4-comdcom--modelo-categorial-de-componentes)
5. [Relaciones Formales entre Subsistemas](#5-relaciones-formales-entre-subsistemas)
6. [Referencias Teóricas](#6-referencias-teóricas)

---

## 1. Repositorio CIM — Modelo Algebraico de Objetos

### 1.1 Definición Formal del Common Information Model

El Common Information Model (CIM) es el esquema de metadatos que gobierna el repositorio WMI en Windows 11. Desde una perspectiva algebraica, el CIM define un **retículo (lattice) de clases** con herencia múltiple controlada.

**Definición 1.1.1 — Espacio de Clases CIM**

Sea $\mathcal{C}$ el conjunto de todas las clases CIM definidas en el repositorio. Definimos la relación de herencia como un preorden:

$$\preceq \; \subseteq \; \mathcal{C} \times \mathcal{C}$$

donde $c_1 \preceq c_2$ significa que $c_1$ es subclase de $c_2$. El par $(\mathcal{C}, \preceq)$ forma un **preorden acíclico** (no un retículo completo, debido a restricciones de MOF sobre herencia múltiple), pero cada par de clases con ancestro común posee un **ínfimo** (meet) bien definido.

**Propiedades del preorden CIM:**

- **Reflexividad:** $\forall c \in \mathcal{C}: c \preceq c$
- **Transitividad:** $c_1 \preceq c_2 \wedge c_2 \preceq c_3 \Rightarrow c_1 \preceq c_3$
- **Antisimetría heredada:** Si $c_1 \preceq c_2 \wedge c_2 \preceq c_1$, entonces $c_1$ y $c_2$ representan la misma definición de clase en el esquema MOF compilado
- **Aciclicidad:** No existe secuencia $c_1 \preceq c_2 \preceq \ldots \preceq c_1$ con $c_i$ distintos

**Corolario:** El espacio $\mathcal{C}$ forma un **bosque de árboles enraizados** (rooted forest), donde cada árbol tiene como raíz una clase base del esquema estándar (ej. `CIM_ManagedSystemElement`, `CIM_Setting`, `CIM_LogicalElement`).

### 1.2 Estructura de Tipos y Propiedades

**Definición 1.2.1 — Esquema de Clase**

Cada clase $c \in \mathcal{C}$ se define como una terna:

$$c = (N_c, P_c, Q_c)$$

donde:
- $N_c$ es el nombre calificado (namespace-qualified) de la clase
- $P_c = \{p_1, p_2, \ldots, p_k\}$ es el conjunto de propiedades, cada una con tipo $\tau_i \in \mathcal{T}$ (el universo de tipos CIM: `uint8`, `string`, `boolean`, `object:ref`, arrays, etc.)
- $Q_c = \{q_1, q_2, \ldots, q_m\}$ es el conjunto de calificadores (metadatos sobre la clase y sus propiedades: `Key`, `Description`, `Dynamic`, `Provider`, etc.)

**Definición 1.2.2 — Herencia de Propiedades**

La función de herencia $\phi: \mathcal{C} \rightarrow \mathcal{P}(\mathcal{T} \times \text{String})$ que mapea cada clase a su conjunto de propiedades efectivas satisface:

$$\phi(c) = P_c \cup \bigcup_{c' \preceq c} \phi(c')$$

Esta es una **clausura transitiva** sobre la relación de herencia, garantizando que cada subclase hereda todas las propiedades de sus ancestros. Las propiedades pueden ser sobrescritas (override) mediante calificadores, lo que introduce una **relación de sombreado** (shadowing) que se resuelve por cercanía en la cadena de herencia.

### 1.3 Modelo de Serialización Binaria

**Definición 1.3.1 — Función de Serialización**

El repositorio WMI almacena instancias como objetos binarios serializados. Sea $\mathcal{I}_c$ el conjunto de todas las instancias de una clase $c$. La serialización es una función inyectiva:

$$\sigma: \mathcal{I}_c \rightarrow \{0,1\}^*$$

que cumple las propiedades de un **codificador de prefijo** (prefix-free encoding):

1. **Inyectividad:** $\sigma(i_1) = \sigma(i_2) \Rightarrow i_1 = i_2$ (decodificación unívoca)
2. **Prefix-free:** $\nexists\, i_1, i_2 \in \mathcal{I}_c : \sigma(i_1)$ es prefijo propio de $\sigma(i_2)$ (permite decodificación en flujo)

**Estructura de la representación binaria en Windows 11:**

La codificación interna del repositorio CIM (implementada en `cimwin32.dll` y `wbemcomn.dll`) sigue una estructura por capas:

$$\sigma(i) = \underbrace{\text{Header}}_{\text{Object Marshal}} \; \| \; \underbrace{\text{ClassDef}}_{\text{Esquema MOF compilado}} \; \| \; \underbrace{\text{DynData}}_{\text{Valores de propiedades}} \; \| \; \underbrace{\text{Qualifiers}}_{\text{Metadatos}}$$

donde $\|$ denota concatenación binaria. El formato interno utiliza una variante de **NDR (Network Data Representation)** adaptada por Microsoft para el transporte DCOM subyacente de WMI.

**Definición 1.3.2 — Entropía de la Serialización**

La entropía de Shannon del espacio de instancias serializadas se define como:

$$H(\mathcal{I}_c) = -\sum_{i \in \mathcal{I}_c} P(i) \log_2 P(i)$$

donde $P(i)$ es la probabilidad de ocurrencia de la instancia $i$ bajo una distribución uniforme sobre el espacio de estados válidos. Para instancias con propiedades de tipo `string` de longitud variable, $H(\mathcal{I}_c)$ es potencialmente no acotada, lo que tiene implicaciones directas en la gestión de memoria del proceso `WmiPrvSE.exe`.

### 1.4 Arquitectura del Repositorio en Windows 11

En Windows 11, el repositorio CIM reside físicamente en:

```
C:\Windows\System32\wbem\Repository\
```

La estructura de almacenamiento utiliza una **base de datos transaccional** basada en un motor JET/Esent (Extended Storage Engine), el mismo que sustenta Active Directory y Exchange. Esto garantiza:

- **Atomicidad:** Las operaciones de escritura sobre el repositorio son transaccionales (commit/rollback)
- **Consistencia:** El esquema MOF se valida contra restricciones de tipo antes de la persistencia
- **Aislamiento:** Las lecturas concurrentes no ven escrituras parciales (snapshot isolation)
- **Durabilidad:** El log de transacciones (`objects.data`) garantiza recuperación ante fallos

El proceso anfitrión del repositorio es `WmiPrvSE.exe` (proveedor desacoplado) o el servicio `Winmgmt` (en proceso compartido con `svchost.exe -k netsvcs`), dependiendo del modelo de alojamiento del proveedor.

**Modelo de acceso:**

```
Aplicación Cliente (WMI Consumer)
        │
        ▼
   COM Proxy/Stub (wbemprox.dll)
        │
        ▼
   Winmgmt Service (svchost)
        │
        ▼
   CIM Repository (Esent Engine)
        │
        ▼
   objects.data / index.btr / writing.log
```

### 1.5 Álgebra de Operaciones del Repositorio

Las operaciones fundamentales sobre el repositorio forman un **magma** con las siguientes operaciones:

| Operación | Notación | Semántica |
|-----------|----------|-----------|
| Crear instancia | $\text{Create}(c, v)$ | Genera $i \in \mathcal{I}_c$ con valores $v$ |
| Leer instancia | $\text{Read}(c, k)$ | Recupera $i$ identificada por clave $k$ |
| Actualizar | $\text{Update}(i, p, v')$ | Modifica propiedad $p$ de $i$ a valor $v'$ |
| Eliminar | $\text{Delete}(i)$ | Remueve $i$ del repositorio |
| Consultar | $\text{Query}(\omega)$ | Evalúa predicado WQL $\omega$ sobre $\mathcal{I}$ |

Estas operaciones satisfacen un **invariante de consistencia del esquema**: toda instancia $i$ creada o actualizada debe satisfacer las restricciones de tipo impuestas por $\phi(c)$ y los calificadores $Q_c$.

---

## 2. WQL y Motor de Eventos — Modelo Lógico de Predicados

### 2.1 WQL como Cálculo de Predicados de Primer Orden

**Definición 2.1.1 — Sintaxis de WQL**

WQL (WMI Query Language) es un sublenguaje de SQL adaptado al modelo de objetos CIM. Formalmente, una consulta WQL de eventos se expresa como:

$$\omega = \text{SELECT } \pi \text{ FROM } \epsilon \text{ WHERE } \psi$$

donde:
- $\pi \subseteq P_c$ es la proyección (subconjunto de propiedades)
- $\epsilon$ es la clase de evento (subclase de `__ExtrinsicEvent` o `__InstanceOperationEvent`)
- $\psi$ es un predicado sobre las propiedades de $\epsilon$

**Definición 2.1.2 — Semántica Formal**

La evaluación de una consulta WQL sobre el universo de instancias $\mathcal{U}$ en un instante $t$ se define como:

$$\llbracket \omega \rrbracket_t = \{ \pi(e) \mid e \in \mathcal{I}_{\epsilon}(t) \wedge \psi(e) \}$$

donde $\mathcal{I}_{\epsilon}(t)$ es el conjunto de instancias de evento $\epsilon$ generadas en el instante $t$, y $\pi(e)$ es la proyección de las propiedades seleccionadas sobre la instancia de evento $e$.

**Teorema 2.1.1 — WQL es un fragmento decidible**

WQL carece de cuantificadores universales ($\forall$), subconsultas anidadas y `JOIN`. Por lo tanto, toda consulta WQL se reduce a un **fragmento existencial-conjuntivo** del cálculo de predicados de primer orden, que es decidible (membership en PSPACE para el problema de evaluación, pero típicamente en P para consultas bien formadas sin expresiones regulares complejas).

### 2.2 Modelo de Eventos como Autómata Híbrido

El subsistema de eventos WMI se modela como un **autómata híbrido** $\mathcal{A}_H = (S, E, \delta, G, \text{Init})$ donde:

- $S$ es el conjunto de estados del sistema observable (modelo CIM en instante $t$)
- $E$ es el conjunto de eventos que provocan transiciones
- $\delta: S \times E \rightarrow S$ es la función de transición
- $G: E \rightarrow \{\text{true}, \text{false}\}$ es la función de guarda (el predicado WQL $\psi$)
- $\text{Init} \in S$ es el estado inicial

**Ejecución del autómata:**

Una traza de ejecución es una secuencia:

$$\rho = (s_0, e_1, s_1, e_2, s_2, \ldots)$$

donde $s_0 = \text{Init}$ y para cada paso $i$: $\delta(s_{i-1}, e_i) = s_i$ si y solo si $G(e_i) = \text{true}$.

### 2.3 Clasificación Taxonómica de Eventos en Windows 11

Windows 11 clasifica los eventos WMI en dos categorías formales:

**Eventos Intrínsecos** — Generados por el repositorio ante operaciones CRUD:

| Clase de Evento | Predicado Disparador |
|---|---|
| `__InstanceCreationEvent` | $\exists\, i \in \mathcal{I}_c : i \notin \mathcal{I}_c(t-1) \wedge i \in \mathcal{I}_c(t)$ |
| `__InstanceDeletionEvent` | $\exists\, i \in \mathcal{I}_c : i \in \mathcal{I}_c(t-1) \wedge i \notin \mathcal{I}_c(t)$ |
| `__InstanceModificationEvent` | $\exists\, i, i' : i \in \mathcal{I}_c(t-1) \wedge i' \in \mathcal{I}_c(t) \wedge i.\text{Key} = i'.\text{Key} \wedge i \neq i'$ |

**Eventos Extrínsecos** — Generados por proveedores WMI como señales asíncronas:

| Clase de Evento | Origen |
|---|---|
| `Win32_ProcessStartTrace` | Proveedor de trazas ETW |
| `Win32_DeviceChangeEvent` | Proveedor de Plug and Play |
| `RegistryValueChangeEvent` | Proveedor del registro |
| `Win32_NetworkAdapterChangeEvent` | Proveedor de red |

### 2.4 Arquitectura del Pipeline de Eventos en Windows 11

El flujo de un evento desde su generación hasta la activación del consumidor sigue un pipeline de cuatro fases:

```
Fase 1: GENERACIÓN
  Proveedor WMI / ETW → __ExtrinsicEvent / __InstanceOperationEvent
        │
Fase 2: FILTRADO
  __EventFilter (WQL ψ) → Evaluación del predicado sobre el evento
        │
Fase 3: ENRUTAMIENTO
  __FilterToConsumerBinding → Vinculación lógica filtro↔consumidor
        │
Fase 4: CONSUMO
  __EventConsumer (ActiveScript / CommandLine / SMTP / LogFile)
```

**Definición 2.4.1 — Álgebra de Vinculación**

La vinculación Filter-Consumer es una **relación binaria** en el repositorio:

$$\mathcal{B} \subseteq \mathcal{F} \times \mathcal{C}_s$$

donde $\mathcal{F}$ es el conjunto de filtros activos y $\mathcal{C}_s$ es el conjunto de consumidores registrados. Esta relación es **many-to-many**: un filtro puede activar múltiples consumidores y un consumidor puede ser activado por múltiples filtros.

La semántica de la vinculación es un **funtor** entre categorías:

$$\mathcal{F} \xrightarrow{\mathcal{B}} \mathcal{C}_s$$

que mapea cada evento $e$ que satisface el predicado de un filtro $f$ al conjunto de consumidores $\{c_s \mid (f, c_s) \in \mathcal{B}\}$.

### 2.5 Modelado de la Latencia de Eventos

**Definición 2.5.1 — Latencia de Entrega**

Sea $t_g$ el instante de generación del evento y $t_c$ el instante de consumo. La latencia se modela como:

$$L = t_c - t_g = L_q + L_f + L_d$$

donde:
- $L_q$ = latencia de encolamiento en el subsistema de eventos (dependiente de la carga del sistema)
- $L_f$ = latencia de evaluación del filtro WQL (complejidad proporcional a $|\psi|$, la longitud del predicado)
- $L_d$ = latencia de despacho al consumidor (incluye activación del proceso si es `CommandLineEventConsumer`)

**Cota superior en Windows 11:** Para consumidores en proceso, $L$ es típicamente del orden de $10\text{-}100\;\mu\text{s}$. Para consumidores fuera de proceso, $L$ puede alcanzar $1\text{-}50\;\text{ms}$ dependiendo de la necesidad de crear un nuevo proceso vía `CreateProcess`.

---

## 3. Colas APC — Modelo de Concurrencia Asíncrona

### 3.1 Formalización en CSP (Communicating Sequential Processes)

El mecanismo APC (Asynchronous Procedure Call) de Windows NT se modela naturalmente en el **Cálculo de Procesos Comunicantes** de C.A.R. Hoare.

**Definición 3.1.1 — Hilo como Proceso CSP**

Un hilo $T$ en Windows se modela como un proceso CSP:

$$T = \text{Running} \rightarrow T' \; \Box \; \text{AlertableWait} \rightarrow \text{ProcessAPCQueue} \rightarrow T''$$

donde:
- $\text{Running}$ representa la ejecución normal del hilo
- $\text{AlertableWait}$ es el estado en el que el hilo invoca una primitiva de espera alertable (e.g., `SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx` con `alertable=TRUE`)
- $\text{ProcessAPCQueue}$ es la acción de drenar la cola APC antes de retornar de la espera
- $\Box$ denota elección externa (external choice)

**Definición 3.1.2 — Cola APC como Canal**

La cola APC de un hilo se modela como un **canal bufferizado** en CSP:

$$\text{APCQueue}_T = \text{Enqueue}.\text{APC}(f, ctx) \rightarrow \text{APCQueue}_T \; \Box \; \text{Dequeue} \rightarrow \text{APCQueue}_T$$

donde cada elemento $\text{APC}(f, ctx)$ contiene:
- $f$: dirección de la función callback (punto de entrada)
- $ctx$: puntero al contexto/parámetro pasado a la función

### 3.2 Modelo de Estados del APC

**Definición 3.2.1 — Autómata de Estados del APC**

El ciclo de vida de un APC se modela como un autómata finito determinista:

```
                    EnqueueAPC
    [No Existe] ──────────────► [En Cola (Queued)]
                                     │
                              Thread enters
                              alertable wait
                                     │
                                     ▼
                               [Entregado (Delivered)]
                                     │
                                Kernel calls
                                callback f(ctx)
                                     │
                                     ▼
                               [Ejecutado (Executed)]
                                     │
                                   Return
                                     │
                                     ▼
                               [Completado (Completed)]
```

**Formalización algebraica:**

$$\text{APC} = (\Sigma, S, s_0, \delta, F)$$

donde:
- $\Sigma = \{\text{Enqueue}, \text{AlertableWait}, \text{Dispatch}, \text{Return}\}$
- $S = \{\text{None}, \text{Queued}, \text{Delivered}, \text{Executed}, \text{Completed}\}$
- $s_0 = \text{None}$
- $\delta$ se define por la tabla de transiciones del diagrama anterior
- $F = \{\text{Completed}\}$

### 3.3 Clasificación de APCs en Windows 11

El kernel NT distingue tres modos de APC con semántica diferente:

**APC de Modo Kernel (Kernel-mode APC):**

| Tipo | Prioridad | Uso |
|---|---|---|
| APC Regular (Normal) | Baja | Operaciones de I/O asíncrono (IRP completion) |
| APC Especial | Alta | Sincronización de I/O, temporizadores del kernel |

**APC de Modo Usuario (User-mode APC):**

| Atributo | Descripción |
|---|---|
| Entrega | Solo cuando el hilo entra en estado alertable (`WaitForSingleObjectEx(..., TRUE)`) |
| Contexto | Se ejecuta en el contexto del hilo destino (misma pila, mismos privilegios) |
| Cola | FIFO dentro del mismo modo (kernel APCs tienen prioridad sobre user APCs) |

**Definición 3.3.1 — Orden de Despacho**

El dispatcher del kernel sigue un orden estricto al procesar las colas APC de un hilo al salir de una espera alertable:

$$\text{DispatchOrder} = \underbrace{\text{SpecialKernelAPC}}_{\text{Prioridad máxima}} \rightarrow \underbrace{\text{NormalKernelAPC}}_{\text{Media}} \rightarrow \underbrace{\text{UserModeAPC}}_{\text{Baja}}$$

Dentro de cada categoría, el orden es FIFO estricto. Esta jerarquía garantiza que las operaciones críticas del kernel (como la finalización de I/O) no sean postergadas por APCs de modo usuario.

### 3.4 Estructura Interna del KAPC

En el kernel NT, cada APC se representa mediante la estructura `KAPC` (definida en `ntddk.h`):

```
KAPC {
    Type            : UCHAR          // ApcObject
    SpareByte1      : UCHAR
    SpareByte2      : UCHAR
    ApcStateIndex   : UCHAR          // Adjunto o desadjunto
    KernelRoutine   : PKKERNEL_ROUTINE  // Siempre modo kernel
    RundownRoutine  : PKRUNDOWN_ROUTINE // Limpieza si el hilo termina
    NormalRoutine   : PKNORMAL_ROUTINE   // Función objetivo
    NormalContext   : PVOID              // Contexto/parámetro
    SystemArgument1 : PVOID
    SystemArgument2 : PVOID
    ApcMode         : KPROCESSOR_MODE    // KernelMode o UserMode
    Inserted        : BOOLEAN            // ¿Está en la cola?
}
```

**Modelado algebraico de KAPC:**

$$\text{KAPC} = (k_r, r_r, n_r, ctx, a_1, a_2, m, i)$$

donde:
- $k_r: \text{KAPC} \rightarrow \text{void}$ es la rutina kernel (siempre se ejecuta en Ring 0)
- $r_r: \text{KAPC} \rightarrow \text{void}$ es la rutina de limpieza
- $n_r$ es la rutina normal (puede ser Ring 0 o Ring 3 según $m$)
- $ctx$ es el contexto pasado a $n_r$
- $a_1, a_2$ son argumentos del sistema
- $m \in \{\text{KernelMode}, \text{UserMode}\}$
- $i \in \{0, 1\}$ indica si está insertada en la cola

### 3.5 Semántica de `NtQueueApcThread`

**Definición 3.5.1 — Especificación Formal**

La syscall `NtQueueApcThread(ThreadHandle, ApcRoutine, ApcContext, Argument1, Argument2)` se modela como:

$$\text{NtQueueApcThread}: \mathcal{H} \times \mathcal{F} \times \mathcal{V} \times \mathcal{V} \times \mathcal{V} \rightarrow \{\text{STATUS\_SUCCESS}, \text{STATUS\_ACCESS\_DENIED}, \ldots\}$$

donde:
- $\mathcal{H}$ es el dominio de handles de hilos
- $\mathcal{F}$ es el dominio de direcciones de función (puntos de entrada)
- $\mathcal{V}$ es el dominio de valores genéricos (punteros)

**Precondiciones:**

1. El llamante debe tener acceso `THREAD_SET_CONTEXT` al hilo destino
2. La dirección `ApcRoutine` debe ser válida en el espacio de direcciones del proceso destino
3. El hilo destino debe existir y no estar en estado terminado

**Postcondiciones:**

1. Se crea una estructura `KAPC` con $m = \text{UserMode}$ y $n_r = \text{ApcRoutine}$
2. La KAPC se inserta en la cola APC del hilo destino (`Inserted = TRUE`)
3. Si el hilo destino está actualmente en espera alertable, se señala para despertar

### 3.6 Modelo de Concurrencia: Interleaving vs. Atomicidad

**Definición 3.6.1 — Semántica de Ejecución APC**

La ejecución de un APC de modo usuario en el contexto de un hilo $T$ se modela como una **interrupción controlada** en la traza de ejecución de $T$:

$$\rho_T = \ldots, s_k, \underbrace{a_1^{APC}, a_2^{APC}, \ldots, a_n^{APC}}_{\text{Secuencia APC}}, s_{k+1}, \ldots$$

donde $s_k$ es el estado del hilo antes de procesar la cola APC y $s_{k+1}$ es el estado después. Los pasos $a_i^{APC}$ se ejecutan **atómicamente** respecto a otros APCs en la misma cola (no hay interleaving entre APCs de la misma cola), pero **no atómicamente** respecto a la ejecución normal del hilo.

**Implicación de seguridad:** Un APC de modo usuario se ejecuta con el token de seguridad y los privilegios del hilo anfitrión. Esto significa que el contexto de seguridad de la ejecución APC es:

$$\text{SecurityContext}(APC) = \text{SecurityContext}(T_{host})$$

---

## 4. COM/DCOM — Modelo Categorial de Componentes

### 4.1 COM como Categoría

**Definición 4.1.1 — Categoría COM**

El modelo COM se formaliza como una categoría $\mathbf{COM}$ donde:

- **Objetos:** Interfaces COM (contratos binarios identificados por IID)
- **Morfismos:** Relaciones de implementación y composición entre interfaces

Una interfaz COM $I$ se define como:

$$I = (\text{IID}, M_I)$$

donde $\text{IID}$ es un GUID de 128 bits que identifica unívocamente la interfaz, y $M_I = \{m_1, m_2, \ldots, m_k\}$ es el conjunto de métodos del vtable.

**Definición 4.1.2 — VTable como Morfismo**

La vtable de una interfaz COM es una función que mapea cada método a su implementación:

$$\text{vtable}: M_I \rightarrow \text{CodePtr}$$

donde $\text{CodePtr}$ es el dominio de punteros a código ejecutable. Esta función es el **testigo** de que una coclase implementa una interfaz.

**Definición 4.1.3 — Coclase como Objeto Terminal**

Una coclase (component class) $C$ se define como:

$$C = (\text{CLSID}, \{I_1, I_2, \ldots, I_n\})$$

donde $\text{CLSID}$ es un GUID que identifica la clase, y $\{I_1, \ldots, I_n\}$ es el conjunto de interfaces que implementa. La coclase es el **objeto terminal** en el sentido de que toda solicitud de creación ($\text{CoCreateInstance}$) se resuelve a una única coclase vía su CLSID.

### 4.2 Functor de Activación

**Definición 4.2.1 — Activación COM**

La activación de un componente COM es un **funtor** del espacio de CLSIDs al espacio de instancias:

$$\mathcal{F}_{act}: \mathbf{CLSID} \rightarrow \mathbf{Instance}$$

que mapea cada CLSID a una instancia concreta del objeto, con las siguientes propiedades:

1. **Preservación de identidad:** $\mathcal{F}_{act}(\text{CLSID})$ siempre produce un objeto que implementa las interfaces declaradas
2. **Preservación de composición:** Si el CLSID está registrado para un servidor local (surrogate), $\mathcal{F}_{act}$ incluye la activación del proceso servidor

**Tabla de registro que sustenta $\mathcal{F}_{act}$ en Windows 11:**

```
HKEY_CLASSES_ROOT\CLSID\{CLSID}
  ├── InprocServer32  →  DLL en proceso (carga en espacio del llamante)
  ├── LocalServer32   →  EXE fuera de proceso (activación vía LPC/RPC)
  ├── InprocHandler32 →  Proxy/stub marshaling
  └── TreatAs         →  Redirección a otro CLSID (transformación natural)
```

### 4.3 Marshaling como Transformación Natural

**Definición 4.3.1 — Marshaling**

El marshaling COM es la transformación de los datos de una llamada a método desde el espacio de direcciones del llamante al espacio del servidor. Formalmente:

$$\mu: \text{Data}_{client} \rightarrow \text{WireFormat} \rightarrow \text{Data}_{server}$$

donde $\mu$ es una **transformación natural** entre los functores de representación de datos en cada espacio de direcciones.

**Propiedades formales del marshaling:**

1. **Composición:** $\mu(g \circ f) = \mu(g) \circ \mu(f)$ (preservación de composición de llamadas)
2. **Identidad:** $\mu(id) = id$ (el marshaling de un no-op es un no-op)
3. **Inversibilidad:** Para tipos soportados, $\mu^{-1}$ existe (unmarshaling exitoso)

**Protocolo de marshaling estándar (NDR):**

El Network Data Representation (NDR) define la codificación wire:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Stub Client │────►│  NDR Wire    │────►│  Stub Server │
│  (Unmarshal) │     │  Format      │     │  (Unmarshal) │
└──────────────┘     └──────────────┘     └──────────────┘
      ▲                                          │
      │              ORPC Response               │
      └──────────────────────────────────────────┘
```

### 4.4 Arquitectura de Activación en Windows 11

**Pipeline de `CoCreateInstance`:**

```
CoCreateInstance(CLSID, IID)
        │
        ▼
   [1] Lookup Registry
        │
        ├── InprocServer32 → LoadLibrary → DllGetClassObject → QueryInterface
        │
        └── LocalServer32 → COM SCM (combase.dll)
                                  │
                                  ├── [2] Check Running Object Table
                                  │       └── If found: return existing proxy
                                  │
                                  └── [3] Launch New Process
                                          │
                                          ├── [3a] COM Service (dllhost.exe surrogate)
                                          └── [3b] Dedicated EXE server
                                                  │
                                                  ▼
                                          Create RPC Binding
                                                  │
                                                  ▼
                                          Return Proxy to Client
```

**Definición 4.4.1 — Service Control Manager (SCM) de COM**

El SCM de COM (implementado en `combase.dll` / `rpcss.dll`) es el **orfesto** (orchestrator) de la activación:

$$\text{SCM}: \text{CLSID} \times \text{IID} \times \text{Context} \rightarrow \text{IUnknown}^*$$

donde $\text{Context} \in \{\text{CLSCTX\_INPROC}, \text{CLSCTX\_LOCAL}, \text{CLSCTX\_REMOTE}\}$ determina el modelo de alojamiento.

### 4.5 Modelo de Seguridad COM

**Definición 4.5.1 — Descriptor de Seguridad COM**

Cada objeto COM está protegido por un descriptor de seguridad que especifica:

$$\text{SD}_{COM} = (\text{Owner}, \text{Group}, \text{DACL}, \text{SACL})$$

donde:
- **DACL** (Discretionary ACL): Controla qué principals pueden activar el objeto
- **SACL** (System ACL): Especifica qué accesos generarán auditorías en el Security Event Log

**Niveles de seguridad en Windows 11:**

| Nivel | Descripción | Configuración |
|---|---|---|
| Autenticación | Verificación de identidad del llamante | `RPC_C_AUTHN_LEVEL_{NONE, CONNECT, CALL, PKT, PKT_INTEGRITY, PKT_PRIVACY}` |
| Impersonación | Nivel de delegación de credenciales | `RPC_C_IMP_LEVEL_{ANONYMOUS, IDENTIFY, IMPERSONATE, DELEGATE}` |
| Activación | Permisos de creación de instancias | Configurado via DCOMCNFG o registro |

### 4.6 DCOM: Extensión Distribuida

**Definición 4.6.1 — DCOM como Functor Distribuido**

DCOM extiende COM a un entorno distribuido mediante un functor:

$$\mathcal{D}: \mathbf{COM}_{local} \rightarrow \mathbf{COM}_{distributed}$$

que preserva la estructura de componentes pero transforma las llamadas locales en llamadas RPC sobre protocolos de transporte:

$$\text{Transport} \in \{\text{ncacn\_ip\_tcp}, \text{ncacn\_np}, \text{ncacn\_http}, \text{ncalrpc}\}$$

En Windows 11, DCOM utiliza por defecto `ncacn_ip_tcp` para comunicaciones entre máquinas y `ncalrpc` (Local RPC) para comunicaciones locales entre procesos.

**Protocolo de comunicación DCOM:**

```
Cliente (Proxy)                          Servidor (Stub)
     │                                        │
     │──── ORPC Request (NDR) ──────────────►│
     │     [Method Call Marshaled]            │
     │                                        │
     │◄─── ORPC Response (NDR) ──────────────│
     │     [Return Values Marshaled]          │
```

---

## 5. Relaciones Formales entre Subsistemas

### 5.1 Mapa de Dependencias

Los cuatro subsistemas no son entidades aisladas; mantienen relaciones funcionales precisas en la arquitectura de Windows 11:

```
┌─────────────────────────────────────────────────┐
│                 COM / DCOM                       │
│         (Capa de Componentes Distribuidos)       │
│                                                   │
│   ┌───────────────────────────────────────┐      │
│   │         WMI / CIM Repository          │      │
│   │    (Capa de Modelado y Almacenamiento)│      │
│   │                                       │      │
│   │   ┌─────────────────────────────┐     │      │
│   │   │   WQL Event Engine          │     │      │
│   │   │   (Capa de Predicados y     │     │      │
│   │   │    Disparadores Lógicos)    │     │      │
│   │   └─────────────────────────────┘     │      │
│   └───────────────────────────────────────┘      │
└─────────────────────────────────────────────────┘
         │
         │  RPC / LPC
         ▼
┌─────────────────────────────────────────────────┐
│              NT Kernel                           │
│   ┌─────────────┐  ┌──────────┐  ┌───────────┐ │
│   │  APC Queue  │  │  ETW     │  │  Object   │ │
│   │  Dispatcher │  │  Tracing │  │  Manager  │ │
│   └─────────────┘  └──────────┘  └───────────┘ │
└─────────────────────────────────────────────────┘
```

### 5.2 Relaciones Algebraicas

**WMI depende de COM:** Toda comunicación con el servicio WMI se realiza vía interfaces COM (`IWbemServices`, `IWbemLocator`). Formalmente:

$$\text{WMI} \xrightarrow{\text{COM}} \text{Winmgmt}$$

**WQL depende de CIM:** Los predicados WQL se evalúan sobre instancias CIM. Formalmente:

$$\llbracket \psi_{WQL} \rrbracket : \mathcal{I}_{CIM} \rightarrow \{\text{true}, \text{false}\}$$

**APC es primitiva del Kernel:** El mecanismo APC es una primitiva del scheduler del kernel NT, no una abstracción Ring 3. Los demás subsistemas son implementaciones en Ring 3 que eventualmente invocan primitivas del kernel:

$$\text{COM} \xrightarrow{\text{syscall}} \text{Kernel APC} \quad \text{(para completación asíncrona de RPC)}$$

**COM es el sustrato de WMI:** El servicio WMI expone su funcionalidad exclusivamente a través de interfaces COM. La cadena de invocación es:

$$\text{Consumer} \xrightarrow{\text{COM}} \text{WMI Service} \xrightarrow{\text{WQL}} \text{CIM Repository} \xrightarrow{\text{Esent}} \text{Disk}$$

### 5.3 Espacio de Estados Compartido

El estado global del sistema Windows 11 puede modelarse como el producto cartesiano de los estados de cada subsistema:

$$\Sigma_{total} = \Sigma_{CIM} \times \Sigma_{WQL} \times \Sigma_{APC} \times \Sigma_{COM}$$

Una transición del sistema es una tupla:

$$\tau: \Sigma_{total} \rightarrow \Sigma_{total}$$

donde típicamente solo uno o dos componentes cambian en cada transición (los demás permanecen invariantes). Las **transiciones compuestas** (donde múltiples subsistemas cambian de forma coordinada) corresponden a operaciones como la activación de un consumidor de evento WMI, que implica:

1. $\Sigma_{WQL}$: Evaluación del predicado → generación de evento
2. $\Sigma_{CIM}$: Actualización del estado del consumidor
3. $\Sigma_{COM}$: Activación del componente consumidor vía `CoCreateInstance`
4. $\Sigma_{APC}$: Si el consumidor está en proceso, la notificación se entrega vía APC de modo kernel

---

## 6. Referencias Teóricas

### Sistemas Operativos y Kernel NT
- Russinovich, M., Solomon, D., & Ionescu, A. (2021). *Windows Internals*, 7th Edition. Microsoft Press.
- Nebbett, G. (2000). *Windows NT/2000 Native API Reference*. Sams Publishing.

### Modelo CIM y WMI
- DMTF (2023). *Common Information Model (CIM) Infrastructure Specification*, DSP0004.
- Golomshtok, A. (2007). *WMI Essentials for Automating Windows Management*. Sams Publishing.
- Microsoft (2024). *Windows Management Instrumentation Documentation*. Microsoft Learn.

### Teoría de Concurrencia y CSP
- Hoare, C.A.R. (1985). *Communicating Sequential Processes*. Prentice Hall.
- Schneider, S. (1999). *Concurrent and Real-Time Systems: The CSP Approach*. Wiley.
- Milner, R. (1989). *Communication and Concurrency*. Prentice Hall.

### Modelo COM y Distribución
- Box, D. (1998). *Essential COM*. Addison-Wesley.
- Brown, N. & Kindel, C. (1998). *Distributed Component Object Model Protocol*. Microsoft.
- Schmidt, D., Huston, S. (2002). *C++ Network Programming: Systematic Reuse with ACE and Frameworks*. Addison-Wesley.

### Álgebra y Teoría de Categorías Aplicada
- Pierce, B.C. (1991). *Basic Category Theory for Computer Scientists*. MIT Press.
- Asperti, A., Longo, G. (1991). *Categories, Types, and Structures*. MIT Press.
- Barr, M., Wells, C. (1990). *Category Theory for Computing Science*. Prentice Hall.

### Modelado de Autómatas Híbridos
- Henzinger, T.A. (1996). *The Theory of Hybrid Automata*. Proceedings of LICS'96.
- Alur, R., et al. (1995). *The Algorithmic Analysis of Hybrid Systems*. Theoretical Computer Science.

---

*Documento generado para fines de investigación y estudio de la arquitectura interna de Windows 11. Cada subsistema es analizado como una primitiva del sistema operativo con modelo formal independiente.*
