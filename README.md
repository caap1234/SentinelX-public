## ¿Qué hace SentinelX?

SentinelX realiza:

- Ingesta y parsing de logs:
  - Apache / Nginx
  - Exim / Dovecot
  - SSH / Secure
  - ModSecurity
  - LFD / CSF
  - Logs de sistema
- Normalización y almacenamiento de eventos
- Enriquecimiento con:
  - GeoIP (país / ASN)
  - Contexto de entidad (IP, usuario, dominio)
- Correlación mediante reglas
- Generación de alertas e incidentes
- Scoring de entidades y decaimiento temporal
- Arquitectura escalable con workers

---

## Arquitectura

             ┌───────────────┐
             │     Logs      │
             └───────┬───────┘
                     │
                     ▼
      ┌────────────────────────────────┐
      │  parsing_worker (escalable)     │
      │  - Apache / Nginx               │
      │  - Mail / SSH / System          │
      └───────────────┬────────────────┘
                      │
                      ▼
             ┌─────────────────┐
             │   Events DB     │
             │  PostgreSQL     │
             └────────┬────────┘
                      │
                      ▼
      ┌────────────────────────────────┐
      │ engine_worker (correlación)    │
      │ - Reglas                       │
      │ - Scoring                      │
      │ - Decaimiento temporal         │
      └───────────────┬────────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │ Alerts / Incidents       │
          └─────────────────────────┘


---

## Componentes

### 1) Backend (API)
Servicio principal HTTP. Recibe logs, expone endpoints de administración (usuarios, reglas, alertas, etc.) y sirve recursos para el frontend.

### 2) parsing_worker
Consume uploads/colas de logs, parsea y normaliza eventos, guarda en PostgreSQL.

### 3) engine_worker (rule engine)
Procesa eventos nuevos, evalúa reglas y genera alertas/incidentes.

### 4) Frontend
Interfaz web (Astro). Fuente en `./front`.

### 5) Agent
Script Bash que corre en servidores a monitorear. Envia logs por partes usando inode+offset y evita cortar líneas.

---

## Requerimientos

### Para levantar SentinelX (server)
- Docker Engine + Docker Compose v2
- CPU/RAM según volumen de logs (referencia: 2 vCPU / 4GB para entornos pequeños)
- Disco: depende de retención y volumen (PostgreSQL crece con el tiempo)

### Para desarrollo
- Node.js + npm (para `./front`)
- Docker + Compose v2

---

## Estructura del repositorio

- `app/` Código del backend y workers
- `alembic/` Migraciones de BD
- `postgres/init/` Scripts iniciales de PostgreSQL (extensiones, tuning)
- `front/` Frontend (Astro)
- `agent/` SentinelX Agent (instalación en servidores a monitorear)
- `docker-compose.example.yml` Compose de ejemplo
- `.env.example` Variables de ejemplo (NO usar en producción sin cambiar secretos)

---

## Quick start (local)

1) Copia variables:
```bash
cp .env.example .env
```
2) Ajusta variables mínimas (DB, admin, URLs).
3) Levanta stack:
```bash
docker compose -f docker-compose.example.yml up -d --build
```
4) Verifica
```bash
docker compose ps
docker compose logs backend --tail 100
```
---

## Escalado de workers

SentinelX permite escalar fácilmente:
- parsing_worker → parsing de logs
- engine_worker → correlación y reglas

Ejemplo:
```bash
docker compose up -d --scale parsing_worker=2 --scale engine_worker=1
```
---

## Variables de entorno (resumen)
Estas variables viven en .env:
- DATABASE_URL: conexión a PostgreSQL
- SECRET_KEY: firma JWT (secreto)
- INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD: crea admin inicial
- GEOIP_COUNTRY_DB_PATH, GEOIP_ASN_DB_PATH: rutas internas a GeoIP
- FRONTEND_BASE_URL: URL base del frontend
- SMTP (opcional): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, FROM_EMAIL

> Nota: Nunca subas secretos reales al repositorio. Mantén .env dentro de .gitignore.
---

## GeoIP

Para enriquecimiento GeoIP se requieren:
- GeoLite2-Country.mmdb
- GeoLite2-ASN.mmdb

Colócalos en ./geoip/ y monta ese directorio como volumen de solo lectura en los contenedores.

---

## Seguridad / recomendaciones

- Ejecuta SentinelX detrás de un reverse proxy (Nginx) con TLS.
- Restringe el endpoint de ingestión (API keys, rate limit).
- No expongas PostgreSQL a Internet.
- Mantén backups de PostgreSQL (y pruebas de restore).
- Mantén actualizado Docker y el sistema base.

---

## Agent

El agente vive en ./agent.
Consulta: agent/README.md.

---

## Licencia

---

## Contribuciones

- Issues: reporta bugs y mejoras
- Pull Requests: bienvenidos, especialmente en parsing de logs, performance y reglas



