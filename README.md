# Sentinel Anti-Ransomware Daemon

Sentinel es un sistema de prevención y detección conductual de ransomware de alto rendimiento para GNU/Linux. Utiliza **eBPF (Extended Berkeley Packet Filter)** para interceptar eventos del sistema de archivos a nivel de kernel en tiempo real, neutralizando instantáneamente procesos maliciosos antes de que puedan cifrar el disco.

A diferencia de los antivirus tradicionales basados en firmas, Sentinel depende de **heurística conductual** y cálculo de **Entropía de Shannon** para detectar ransomware zero-day basándose estrictamente en sus acciones.

## Características Principales

- **Intercepción a Nivel de Kernel (eBPF):** Intercepta las llamadas al sistema `vfs_write`, `sys_enter_renameat2` y `sys_enter_unlinkat` directamente dentro del kernel con latencia cero.
- **Análisis de Entropía en Tiempo Real:** Analiza la distribución de bytes de las escrituras de archivos utilizando un algoritmo de histograma sin bifurcaciones (branchless) altamente optimizado que evade los límites estrictos del verificador de eBPF.
- **Sistema de Canarios (Honeypot):** Despliega automáticamente archivos trampa ocultos (`.canary_sentinel`) en el sistema. Si un proceso en segundo plano los manipula, es terminado instantáneamente.
- **Prevención Avanzada de Falsos Positivos:** Escanea el árbol de procesos en `procfs` para poner en lista blanca comandos humanos interactivos (como `bash` dentro de `gnome-terminal`) y binarios confiables, asegurando que los usuarios administradores nunca sean bloqueados por usar sus propias herramientas.
- **Neutralización Instantánea:** Detiene amenazas en menos de un milisegundo utilizando `SIGSTOP` (congelar) seguido de `SIGKILL` (terminar), acompañado de una alerta nativa de escritorio GNOME.

## Requisitos Previos

- Kernel de Linux 5.8 o superior.
- Cadena de herramientas `rustup` con `nightly-2026-05-15` (o un nightly reciente).
- Componentes `bpf-linker` y `rust-src`.
- `clang` y `llvm` instalados.

## Instalación y Uso

Sentinel se divide en dos componentes: el objeto del kernel eBPF y el demonio de espacio de usuario.

### 1. Instalación
Compila ambos componentes e instala el objeto eBPF en el directorio del sistema:
```bash
./install-sentinel.sh
```

### 2. Ejecución
Inicia el demonio en segundo plano con privilegios de administrador para comenzar el monitoreo:
```bash
./run-sentinel.sh
```

## Arquitectura
Sentinel está construido puramente en Rust (utilizando el framework Aya). Para un análisis profundo de la ingeniería, los desafíos del verificador eBPF y las decisiones arquitectónicas, por favor lee el documento [Arquitectura y Diseño](ARCHITECTURE.md) incluido en este repositorio.

## Dependencias
Para ver a detalle dependencias necesarias y posibles problemas al compilar, visite: [Dependencias](DEPENDENCIES.md)

## Licencia
Licencia MIT

## ETC
Uso de memoria:
<img width="1064" height="191" alt="Captura desde 2026-09-02 01-17-50" src="https://github.com/user-attachments/assets/32400c72-b0a6-46f4-8d09-0baf1b5755ac" />
5824 kB en Physical RAM

Ejecución de Sentinel
<img width="1494" height="532" alt="Captura desde 2026-09-02 01-18-55" src="https://github.com/user-attachments/assets/186d09c5-702a-4ef2-bdda-c50e12dad8c4" />

Ejecución de Sentinel + Ransomware TEST inicializado (y luego neutralizado)
<img width="1920" height="1080" alt="Captura desde 2026-09-02 01-19-45" src="https://github.com/user-attachments/assets/d506d0f4-1568-4e6c-943f-f69090a0c244" />
