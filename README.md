# 🛡️ PROYECTO: NEVERTRSTMEPDF — [OP: OMEGA]

### 📁 CLASIFICACIÓN: TOP SECRET // RED TEAM // AUTORIZACIÓN NIVEL 1
**Cuerpo:** Centro Nacional de Inteligencia (CNI) — División de Operaciones de Ciberinteligencia.  
**Estado:** Operativo (Fase de Despliegue Estratégico).  
**Objetivo:** Desarrollo y validación de vectores de intrusión persistente para entornos Windows 11 mediante técnicas de engaño multinivel y evasión de telemetría de próxima generación.

---

## 📑 RESUMEN OPERATIVO

El **Proyecto NeverTrstMePdf** es una suite modular de armamento digital diseñada para la infiltración silenciosa en infraestructuras críticas. A diferencia de los vectores convencionales, este sistema explota vulnerabilidades lógicas en la gestión de confianza del sistema operativo Windows 11, combinando ingeniería social semiótica con explotación de bajo nivel en Assembly x64.

### 🧬 ARQUITECTURA DEL VECTOR (5 ETAPAS)

| Etapa | Designación | Mecanismo Crítico | Objetivo |
| :--- | :--- | :--- | :--- |
| **01** | [Contenedor ISO](file:///home/jesuslangarica/Infected/NeverTrstMePdf/01-iso) | Bypass Mark-of-the-Web (MotW) | Evasión de SmartScreen y políticas de seguridad NTFS. |
| **02** | [Señuelo Social](file:///home/jesuslangarica/Infected/NeverTrstMePdf/02-social) | Decepción Semiótica Visual | Manipulación del interpretante humano (PDF Bait). |
| **03** | [Disparador LNK](file:///home/jesuslangarica/Infected/NeverTrstMePdf/03-lnk) | LNK Stomping & LOLBins | Ejecución de cadena de confianza a través de binarios firmados. |
| **04** | [Cargador C++](file:///home/jesuslangarica/Infected/NeverTrstMePdf/04-loader) | APC Injection & ETW Patching | Infiltración en memoria y cegado de telemetría local (EDR). |
| **05** | [Payload ASM](file:///home/jesuslangarica/Infected/NeverTrstMePdf/05-payload) | Halo's Gate / Direct Syscalls | Persistencia en el repositorio CIM (WMI) y control total. |

---

## 🛠️ REGISTRO DE MÓDULOS TÉCNICOS

### 🧪 1. El Contenedor ISO (Evasión de Atribución)
Explotación de la falta de propagación de ADS (Alternate Data Streams) en volúmenes montados virtualmente. El sistema no hereda la zona de seguridad del archivo origen, permitiendo la ejecución de contenido descargado sin alertas del sistema.

### 🎭 2. Ingeniería Social Semiótica
Diseño de artefactos visuales que aprovechan la configuración por defecto de Windows (`HideFileExt = TRUE`). El vector utiliza la discrepancia entre el icono proyectado y la extensión real para inducir la ejecución por parte del objetivo.

### ⚡ 3. Inyección APC y Evasión de Ganchos (Hooks)
Implementación de **Halo's Gate** y **Tartarus' Gate** en Assembly x64 para resolver números de servicio del sistema (SSN) dinámicamente. Esto permite realizar llamadas al sistema (syscalls) directas, evitando los puntos de intercepción (hooks) que los agentes EDR colocan en las DLLs de usuario.

### 🌑 4. Supresión de Telemetría (ETW Blinding)
El cargador parchea en caliente la función `EtwEventWrite` en el espacio de memoria de los procesos críticos, neutralizando la capacidad del sistema para reportar telemetría a los SIEM/EDR centrales.

---

## 📜 PROTOCOLO DE DESPLIEGUE (RED TEAM)

1. **Generación:** Utilizar [orden_auditor.cpp](file:///home/jesuslangarica/Infected/NeverTrstMePdf/00-generador/orden_auditor.cpp) para compilar el vector base.
2. **Obfuscación:** Aplicar polimorfismo al payload ASM mediante [auditoria_poliglota.asm](file:///home/jesuslangarica/Infected/NeverTrstMePdf/05-payload/auditoria_poliglota.asm).
3. **Encapsulamiento:** Generar la imagen ISO con el ratio de ocultamiento anómalo ($\rho_{hide} \rightarrow 1$).
4. **Exfiltración:** Configurar el canal C2 a través de suscripciones de eventos WMI para persistencia a largo plazo.

---

## ⚖️ AVISO DE AUTORIZACIÓN

> [!IMPORTANT]
> Este repositorio y su contenido son propiedad del **CNI (Centro Nacional de Inteligencia)**. Su uso está estrictamente limitado a personal con **Clearance Nivel 1** en el marco de operaciones de Red Teaming autorizadas, auditoría extrema y pruebas de concepto para el fortalecimiento de infraestructuras nacionales. La reproducción o distribución no autorizada de estas técnicas constituye un delito de alta traición.

---
**[SISTEMA OMEGA]** - *Nihil Prius Fide*
