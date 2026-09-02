# Dependencias y Configuración del Entorno

Este documento detalla todas las dependencias (a nivel de sistema operativo y de Rust) necesarias para compilar y ejecutar **Sentinel**, así como una guía de solución de problemas (troubleshooting) documentando los obstáculos arquitectónicos que superamos durante el desarrollo.

---

## 1. Dependencias del Sistema Operativo

Para compilar código eBPF, tu sistema necesita herramientas capaces de generar *bytecode* BPF y enlazar binarios ELF.

### Instalación en Arch Linux (Pacman)
```bash
sudo pacman -S clang llvm libelf zlib linux-headers base-devel
```

### Instalación en Debian / Ubuntu (APT)
```bash
sudo apt update
sudo apt install clang llvm libelf-dev zlib1g-dev linux-headers-$(uname -r) build-essential
```

---

## 2. Dependencias del Entorno Rust

El código eBPF se compila en un entorno `no_std` (sin librería estándar) utilizando características experimentales de Rust, por lo que es estrictamente necesario usar la versión **Nightly**.

### 2.1. Instalación de Rustup y Nightly
El proyecto requiere una versión específica de Nightly para garantizar la compatibilidad entre el compilador de Rust, LLVM y el framework Aya.

```bash
# Instalar toolchain nightly
rustup toolchain install nightly-2026-05-15

# Establecer como predeterminado para este proyecto (ejecutar dentro de la carpeta)
rustup override set nightly-2026-05-15
```

### 2.2. Componentes Adicionales de Rust
El código eBPF requiere compilar el núcleo (`core`) desde cero y necesita un enlazador especializado.

```bash
# Código fuente de Rust (necesario para -Z build-std=core)
rustup component add rust-src --toolchain nightly-2026-05-15

# Enlazador BPF para Aya
cargo install bpf-linker
```

---

## 3. Librerías (Crates) Principales del Proyecto

- **Aya (`aya`, `aya-ebpf`)**: El framework principal que permite escribir, compilar y cargar código eBPF puramente en Rust.
- **Tokio (`tokio`)**: El motor asíncrono para el demonio de espacio de usuario. Utiliza `AsyncFd` para leer el Ring Buffer de eBPF sin consumir CPU (epoll).
- **Libc (`libc`)**: Utilizado para enviar señales Unix puras (como `SIGSTOP` y `SIGKILL`) y para manipular permisos de archivos (`chown`) en los canarios.
- **Notify Rust (`notify-rust`)**: Permite enviar notificaciones D-Bus de emergencia al entorno de escritorio gráfico del usuario (GNOME/KDE).

---

## 4. Problemas Comunes y Soluciones Históricas

Durante el desarrollo de Sentinel, nos encontramos con varios problemas técnicos de muy bajo nivel. Aquí documentamos las soluciones por si necesitas modificar el código en el futuro:

### Error de Relocalización y Símbolos Faltantes
**Error:** `Failed to load eBPF object: error relocating function... function not found while relocating`
**Causa:** El compilador de Rust (LLVM) eliminaba o no podía enlazar funciones externas auxiliares (como `bpf_get_current_comm` para obtener el nombre del proceso) al compilar hacia el target `bpfel`.
**Solución:** Se abandonó la llamada a la función C y se llamó directamente al Helper BPF del kernel por su identificador numérico interno (`16`) utilizando magia negra de memoria (`core::mem::transmute(16usize)`). Además, se forzó la habilitación de `lto = true` (Link Time Optimization) en el `Cargo.toml` para garantizar el *inlining* de todas las funciones.

### Explosión de Estados del Verificador eBPF (State Explosion)
**Error:** El kernel se negaba a cargar la sonda `vfs_write` indicando que el programa sobrepasaba el límite de 1.000.000 de instrucciones analizadas.
**Causa:** Intentábamos leer bloques dinámicos de 4096 bytes y usar condicionales lógicos (`saturating_add`) dentro del bucle para generar el histograma de entropía. El verificador del kernel simula *todas las ramas posibles* de un `if`, por lo que un bucle condicional grande colapsa el verificador.
**Solución:** Se redujo la lectura a ventanas fijas de **512 bytes** estáticos y se reescribió la lógica matemática del histograma de forma completamente **Branchless** (código sin bifurcaciones condicionales lógicas), satisfaciendo los requisitos de seguridad extrema del kernel.

### Error: "Missing program" al cargar el eBPF
**Error:** `Program not found in ELF file`
**Causa:** Se intentaba cargar el programa buscando el nombre `"kprobe_vfs_write"`. En versiones recientes de las macros de Aya, el símbolo ELF generado toma exactamente el mismo nombre que la función en Rust.
**Solución:** Renombrar la búsqueda en el demonio a `"vfs_write"`.

### Las Notificaciones Visuales no llegaban al Escritorio
**Error:** `Failed to send GNOME notification: Connection reset by peer`
**Causa:** El demonio corre como `root`, pero el escritorio pertenece al usuario estándar (ej. UID 1000). D-Bus bloquea por seguridad cualquier inyección de gráficos proveniente de otros usuarios, incluso de root.
**Solución:** En lugar de invocar `notify-send` tradicionalmente, el demonio utiliza `std::os::unix::process::CommandExt` para abandonar los privilegios de root momentáneamente (`.uid(1000)`), suplantando la identidad del usuario e inyectando explícitamente la variable de entorno `DISPLAY=:0`.

### El Canario no Detectaba Infecciones (Punto Ciego de eBPF)
**Error:** Comandos como `mv` dentro de la carpeta del canario no activaban el escudo.
**Causa:** Al estar dentro de la carpeta, el atacante usa rutas relativas (ej. `renameat2("archivo", "archivo.enc")`). La sonda eBPF interceptaba exactamente ese texto, el cual *no* contenía la palabra clave `.canary_sentinel`. (Este es un punto ciego conocido al no usar el LSM `d_path`).
**Solución:** Se compensó esto integrando el robusto sistema heurístico de Entropía, que reacciona a operaciones masivas sin importar la ruta absoluta del archivo.
