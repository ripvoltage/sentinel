# Sentinel: Arquitectura y Diseño de un Detector Conductual de Ransomware basado en eBPF

Este documento detalla la investigación, diseño e implementación técnica de **Sentinel**, un sistema de detección y prevención de ransomware a nivel de kernel para entornos GNU/Linux.

---

## 1. Introducción y Motivación

Los sistemas antivirus tradicionales operan bajo un paradigma basado en firmas (hashes, secuencias de bytes conocidas), lo cual es ineficaz contra *ransomwares zero-day* o binarios polimórficos. Para combatir estas amenazas modernas, el enfoque debe cambiar hacia el **Análisis Conductual**: no importa cómo luzca el binario, importa lo que hace. Un ransomware, por definición, debe leer archivos, cifrarlos (aumentando su entropía) y sobrescribirlos o renombrarlos.

**eBPF (Extended Berkeley Packet Filter)** surge como la tecnología perfecta para este propósito. Permite ejecutar código aislado (sandboxed) dentro del espacio de memoria del Kernel de Linux de forma segura y ultrarrápida, interceptando llamadas al sistema antes de que se completen, sin la latencia de enviar datos ida y vuelta entre el kernel y el espacio de usuario (como ocurre con inotify o fanotify).

---

## 2. Arquitectura Global

El sistema se divide en dos dominios estrictamente separados que se comunican de forma asíncrona mediante un *Ring Buffer* de memoria compartida:
1. **Espacio de Kernel (Sonda eBPF):** Rastrea, filtra y preprocesa los datos.
2. **Espacio de Usuario (Demonio Sentinel):** Analiza, juzga y ejecuta represalias.

---

## 3. Espacio de Kernel: Desafíos e Implementación (eBPF)

### 3.1. Interceptación de Llamadas
La sonda eBPF (escrita en Rust usando `aya-ebpf`) se adhiere a tres puntos críticos:
- **Kprobe en `vfs_write`:** Intercepta cada escritura a disco. Lee un fragmento de los bytes que el proceso está intentando escribir en el archivo.
- **Tracepoints en `sys_enter_renameat2` y `sys_enter_unlinkat`:** Capturan los intentos de renombrar archivos (ej. de `.pdf` a `.pdf.enc`) y eliminar archivos, obteniendo directamente el texto de la ruta solicitada por el atacante.

### 3.2. El Desafío del Verificador eBPF y la Entropía
El núcleo de la detección es la **Entropía de Shannon**, una métrica matemática de aleatoriedad. Los datos cifrados exhiben una entropía casi perfecta. El eBPF debe construir un histograma de los bytes escritos para calcular esta entropía.

Sin embargo, el Verificador del Kernel de Linux prohíbe bucles dinámicos complejos y limita la ejecución a un millón de instrucciones para evitar cuelgues del sistema (kernel panics). Intentar leer 4096 bytes y actualizar un histograma usando condicionales (`if`, `saturating_add`) generaba una **explosión de estados** que el verificador rechazaba.

**La Solución (Algoritmo Branchless):**
Se rediseñó el procesamiento de memoria a bloques estáticos más pequeños (512 bytes) y se eliminaron todas las bifurcaciones lógicas. En lugar de comprobar si el contador se desbordaba, se confió en el tamaño de las variables matemáticas, asegurando matemáticamente al verificador que el código se ejecuta en un tiempo constante (O(1)) y predecible.

---

## 4. Espacio de Usuario: Motor de Análisis y Respuesta

El demonio (`sentinel-daemon`), construido sobre `tokio`, escucha los eventos del Ring Buffer utilizando `AsyncFd` (notificación de descriptores de archivos de epoll) para consumir 0% de CPU en estado de inactividad.

### 4.1. Heurística y Puntuación Continua
A medida que llegan eventos de E/S, el motor heurístico aplica una puntuación a cada proceso (PID):
- **Cálculo final de Entropía:** Traduce el histograma provisto por eBPF a un logaritmo base 2 para obtener la puntuación de Shannon. Una entropía > 7.8 (muy alta) otorga +40 puntos de amenaza.
- **Cambios masivos de extensiones:** Si un proceso renombra más de 5 archivos con diferentes extensiones en una fracción de segundo, otorga +30 puntos.
- **Frecuencia de E/S:** Si un proceso realiza más de 50 operaciones en 100ms, otorga +30 puntos.

Si un proceso alcanza los 100 puntos, es declarado como amenaza confirmada.

### 4.2. Trampas "Honeypot" (Canarios)
Para neutralización garantizada (independientemente del puntaje), el demonio siembra silenciosamente archivos cebo en una carpeta oculta (`~/.canary_sentinel`).
El eBPF reporta cualquier manipulación sobre este directorio. Si un atacante entra al directorio y altera un canario, la trampa se activa y la amenaza es sentenciada instantáneamente.

### 4.3. Prevención de Falsos Positivos (Árbol de Procesos)
La principal desventaja del análisis conductual es que un usuario legítimo encriptando un archivo (ej. usando GPG o moviendo archivos) puede exhibir un comportamiento idéntico al del malware. 

Para evitar neutralizar al usuario, Sentinel incluye un módulo `proc_inspector`. Al detectarse una anomalía, el demonio pausa un instante e inspecciona `/proc/<PID>`. 
Rastrea el árbol de ascendencia del proceso hasta 5 niveles buscando la presencia de un emulador de terminal interactivo (ej. `gnome-terminal`) ejecutando una shell (ej. `bash`). Si se comprueba que el comando fue disparado manualmente por un ser humano interactuando con su computadora, la alerta es silenciada de inmediato.

### 4.4. Secuencia de Neutralización
Una vez que el motor confirma un ransomware en segundo plano, la secuencia de ejecución es implacable:
1. **Envío de `SIGSTOP`:** Congela instantáneamente el proceso. El sistema operativo le quita todo el tiempo de CPU, impidiendo que encripte un solo archivo más mientras se procede.
2. **Envío de `SIGKILL`:** Destruye el proceso permanentemente de la memoria.
3. **Notificación D-Bus:** El demonio asume temporalmente la identidad (UID) del usuario gráfico para conectarse a su bus de sesión y arrojar una alerta crítica nativa en el escritorio, advirtiendo de los archivos afectados.

---

## 5. Conclusión

Sentinel demuestra la viabilidad de utilizar eBPF para defensa de host activa en Linux. Superando las severas limitaciones del verificador a través de algoritmos *branchless*, y gestionando la disonancia entre las alertas automáticas y la intención humana a través de inspección de árboles de procesos, el software consigue erradicar ataques de ransomware en menos de un milisegundo desde el inicio de su ejecución, estableciendo un estándar moderno para sistemas de prevención de intrusiones de nueva generación.
