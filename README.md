# Sentinel Anti-Ransomware Daemon 🛡️

Sentinel es un sistema de prevención y detección conductual de ransomware de alto rendimiento para GNU/Linux. En lugar de utilizar bases de firmas de virus conocidos, Sentinel analiza el **comportamiento** de los procesos en tiempo real, neutralizando instantáneamente cualquier amenaza antes de que pueda secuestrar el disco.

---

## ¿Qué es eBPF y por qué es la clave del sistema?

**eBPF (Extended Berkeley Packet Filter)** es una tecnología integrada en el núcleo (Kernel) de Linux. Permite ejecutar pequeños programas de forma segura y ultrarrápida directamente dentro de la memoria del Kernel.

Sentinel utiliza eBPF porque ofrece tres ventajas insuperables:
1. **Visibilidad Subterránea Absoluta:** Se sitúa en la capa más profunda del sistema operativo. Un ransomware ejecutándose en el espacio de usuario *no tiene forma de evadir o engañar a eBPF*, ya que este audita la petición antes de que el propio disco duro la procese.
2. **Latencia Cero (Rendimiento):** Al operar directamente dentro del Kernel, analiza la matemática de los archivos en microsegundos sin ralentizar el ordenador.
3. **Intercepción Precisa:** Nos permite interceptar las llamadas al sistema `vfs_write`, `sys_enter_renameat2` y `sys_enter_unlinkat` en tiempo real.

---

## ¿Cómo funciona la detección?

Sentinel clasifica un proceso como Ransomware utilizando un sistema de **doble escudo**:

### Escudo A: El Motor Heurístico (Sistema de Puntos)
Cada vez que un proceso escribe o renombra un archivo, el demonio evalúa tres factores. Si un proceso acumula **100 puntos**, es catalogado como ransomware y destruido:

1. **Entropía de Shannon (+40 puntos):** Un archivo normal (un documento, una foto) tiene patrones estructurados. Cuando un ransomware cifra un archivo, los datos se vuelven ruido criptográfico puro. Sentinel calcula la entropía matemática; si supera el umbral de `7.8` (aleatoriedad casi perfecta), asume un cifrado malicioso.
2. **Frecuencia de E/S (+30 puntos):** Un ransomware necesita secuestrar millones de archivos a velocidad robótica. Si Sentinel detecta más de 50 modificaciones en una ventana de 100 milisegundos, penaliza al proceso.
3. **Cambios Masivos de Extensión (+30 puntos):** El malware suele cambiar la extensión de los archivos secuestrados (ej. de `.pdf` a `.pdf.enc`). Renombrar más de 5 archivos de forma simultánea dispara este medidor.

### Escudo B: El Sistema de Canarios (Honeypot)
Sentinel crea silenciosamente una carpeta oculta (`~/.canary_sentinel`) con archivos cebo de nombres atractivos (`passwords.txt`, `bitcoin_wallet.dat`). Un ransomware recorrerá ciegamente el disco atacando carpeta por carpeta. Si la sonda eBPF reporta que un proceso de fondo tocó uno de estos canarios, **se ignora el sistema de puntos y se aniquila al proceso instantáneamente**.

---

## Prevención de Falsos Positivos y sus Limitaciones

Si un usuario decide comprimir miles de archivos o cifrar legítimamente una base de datos, los escudos de Sentinel podrían identificar la acción como "Ransomware". Para evitar que el sistema te bloquee a ti mismo, Sentinel implementa el `proc_inspector`.

**¿Cómo te perdona la vida?**
Antes de disparar a un proceso, Sentinel rastrea su árbol genealógico (`procfs`). Si descubre que el comando fue lanzado por un humano interactuando a través de una terminal (ej. `bash` ejecutado dentro de `gnome-terminal`), clasifica el evento como un *"Falso Positivo"* y silencia la alerta.

**Limitación (El Modelo de Amenaza)**
Esta lista blanca tiene una vulnerabilidad conocida: Si caes víctima de una estafa de Phishing y eres convencido para abrir tu propia consola y pegar un comando malicioso manualmente, Sentinel **dejará pasar el ataque** al heredar la "confianza" de tu terminal. 

El sistema está diseñado bajo la premisa de que el 99% del ransomware real opera en **segundo plano**, mediante vulnerabilidades de navegador, tareas programadas (cron) o servicios invisibles. En estos escenarios del mundo real, al no haber una terminal interactiva en el árbol de procesos, Sentinel aniquila la amenaza sin piedad.

---

## Requisitos Previos

- Kernel de Linux 5.8 o superior.
- Cadena de herramientas `rustup` configurada en `nightly-2026-05-15`.
- `bpf-linker`, `rust-src`, `clang` y `llvm` instalados.

## Instalación y Uso

El proyecto consta de la sonda eBPF y el Demonio asíncrono en Rust.

### 1. Instalación
Compila ambos componentes e instala el objeto eBPF en tu sistema:
```bash
./install-sentinel.sh
```

### 2. Ejecución
Inicia el demonio en segundo plano (requiere permisos de root):
```bash
./run-sentinel.sh
```

*(Cuando una amenaza es neutralizada mediante las señales `SIGSTOP` y `SIGKILL`, el demonio suplantará tu identidad de usuario para enviarte una alerta visual nativa al escritorio GNOME).*

## Arquitectura y Dependencias

Para leer sobre cómo evadimos los estrictos límites del Verificador del Kernel mediante matemáticas *branchless*, consulta los documentos:
- [Arquitectura y Diseño (Tesis)](ARCHITECTURE.md)
- [Dependencias y Solución de Problemas](DEPENDENCIES.md)

## Imágenes

Uso de memoria:
<img width="1064" height="191" alt="Captura desde 2026-09-02 01-17-50" src="https://github.com/user-attachments/assets/32400c72-b0a6-46f4-8d09-0baf1b5755ac" />
5824 kB en Physical RAM

Ejecución de Sentinel
<img width="1494" height="532" alt="Captura desde 2026-09-02 01-18-55" src="https://github.com/user-attachments/assets/186d09c5-702a-4ef2-bdda-c50e12dad8c4" />

Ejecución de Sentinel + Ransomware TEST inicializado (y luego neutralizado)
<img width="1920" height="1080" alt="Captura desde 2026-09-02 01-19-45" src="https://github.com/user-attachments/assets/d506d0f4-1568-4e6c-943f-f69090a0c244" />
