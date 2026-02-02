# SentinelX Agent

El **SentinelX Agent** es un script en Bash que recolecta y envía logs a SentinelX de forma incremental usando **inode + offset**.

Está diseñado para:

- Enviar logs por partes sin perder bytes
- Evitar duplicados tras rotación de logs
- Evitar cortar líneas (chunks alineados a `\n`)
- Soportar interrupciones: si falla el envío, encola en spool y reintenta
- Modo “protección”: si el backend no responde (sin HTTP), **no encola** y resetea estados para que el siguiente run mande “contexto” como primer run

---

## Cómo funciona

1) Mantiene un estado por archivo (inode y offset) en `STATE_DIR`.
2) En cada corrida:
   - Primero intenta enviar lo pendiente del `SPOOL_DIR`.
   - Luego revisa cada fuente de logs y genera chunks alineados a newline.
   - Comprime cada chunk (`.gz`) y lo envía al endpoint de ingestión usando `curl`.
3) Si el backend no responde (curl devuelve http_code `000`):
   - Con `SENTINELX_RESET_ON_BACKEND_DOWN=1`: purga spool + resetea states y termina.
   - Esto evita acumular payloads cuando el backend está caído.

---

## Requerimientos

Sistema: Linux (cPanel/DirectAdmin/otros).

Dependencias mínimas:
- `bash`
- `curl`
- `python3` (requerido para alinear chunks a newline)
- `gzip`, `coreutils`, `util-linux`, `procps` (comandos como `dd`, `stat`, `flock`, `ionice`, `renice`)

Opcional:
- `sysstat` (comando `sar`) si deseas enviar métricas SAR

---

## Archivos

En el repo:
- `agent/sentinelx-agent.sh` script principal
- `agent/sentinelx-agent.env.example` ejemplo de variables (copia a `/etc/sentinelx-agent.env`)
- `agent/sentinelx-agent.sources.example` ejemplo de sources (copia a `/etc/sentinelx-agent.sources`)

En el servidor:
- `/usr/local/bin/sentinelx-agent.sh` script instalado
- `/etc/sentinelx-agent.env` variables y secretos
- `/etc/sentinelx-agent.sources` (opcional) lista de logs a enviar
- `/var/lib/sentinelx-agent/` estados (inode/offset)
- `/var/spool/sentinelx-agent/` cola local (payloads pendientes)
- `/tmp/sentinelx-agent/` temporales

---

## Instalación (manual)

1) Copia el script:
```bash
cp agent/sentinelx-agent.sh /usr/local/bin/sentinelx-agent.sh
chmod +x /usr/local/bin/sentinelx-agent.sh
```
2) Copia el env de ejemplo:
```bash
cp agent/sentinelx-agent.env.example /etc/sentinelx-agent.env
chmod 600 /etc/sentinelx-agent.env
```
3) Edita /etc/sentinelx-agent.env y configura:

SENTINELX_INGEST_URL
SENTINELX_API_KEY

4) (Opcional) Configura sources sin tocar el script:
```bash
cp agent/sentinelx-agent.sources.example /etc/sentinelx-agent.sources
chmod 644 /etc/sentinelx-agent.sources
```
5) Ejecuta una prueba:
```bash
/usr/local/bin/sentinelx-agent.sh
```
---

## Configurar fuentes de logs (SOURCES_FILE)

El archivo /etc/sentinelx-agent.sources permite definir rutas sin modificar el agente.

Formato por línea:
```bash
TAG:PATH:NAME
```
Ejemplo:
```bash
lfd:/var/log/lfd.log:lfd
maillog:/var/log/maillog:maillog
apache_access:/usr/local/apache/logs/access_log:apache_access
```
- Comentarios con # y líneas vacías se ignoran.
- Si no existe SOURCES_FILE, el agente usa una lista default basada en el modo detectado (cpanel/directadmin/auto).

---

## Variables importantes (env)

- SENTINELX_INGEST_URL (obligatorio)
-SENTINELX_API_KEY (obligatorio)

Calidad/volumen:
- SENTINELX_FIRST_RUN_CONTEXT_LINES (default 200)
- SENTINELX_CHUNK_MB (default 50)
- SENTINELX_LIMIT_RATE (vacío = sin límite)
- SENTINELX_MAX_SECONDS_PER_RUN (default 3300)

SAR:
- SENTINELX_SAR_BACKFILL_DAYS (default 3; 0 deshabilita SAR)

Resiliencia:
- SENTINELX_RESET_ON_BACKEND_DOWN (default 1)

Rutas:
- STATE_DIR, SPOOL_DIR, TMP_DIR, SENTINELX_LOCK_FILE
- SOURCES_FILE (default /etc/sentinelx-agent.sources)
- SENTINELX_PYTHON_BIN (default python3)

---

## Consideraciones y buenas prácticas

- API Key: trátala como secreto (chmod 600 al env).
- Backend caído: con reset habilitado no se acumularán payloads.
- Volumen alto: ajusta SENTINELX_CHUNK_MB y SENTINELX_LIMIT_RATE.
- Rotación de logs: el estado por inode ayuda a detectar resets/rotaciones.
- Permisos: el agente debe poder leer los logs (a veces requiere root).

