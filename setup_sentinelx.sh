#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# SentinelX Setup - Community Installer
# - NO hardcodea credenciales ni datos del autor.
# - Genera .env (chmod 600) y docker-compose.yml
# - Opcional: Nginx reverse proxy para FRONT + /api -> backend
# - Detecta/mitiga CSF + Docker iptables issues (pide permiso)
# - Modo LOCALHOST o SERVER (dominio)
#
# Requisitos:
# - Linux recomendado (Alma/Rocky/Debian/Ubuntu).
# - Docker + docker compose v2.
# - Git (opcional pero recomendado).
#
# Nota:
# - Para SMTP en el mismo VPS: puede necesitar host-gateway mapping.
# ============================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
COMPOSE_EXAMPLE_FILE="${ROOT_DIR}/docker-compose.example.yml"

GEOIP_DIR="${ROOT_DIR}/geoip"
COUNTRY_MMDB="${GEOIP_DIR}/GeoLite2-Country.mmdb"
ASN_MMDB="${GEOIP_DIR}/GeoLite2-ASN.mmdb"

FRONT_SRC_DEFAULT="${ROOT_DIR}/front"
FRONT_DIST_DEFAULT="${ROOT_DIR}/front/dist"

# ---------- helpers ----------
die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { echo "-> $*"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }
require_cmd() { has_cmd "$1" || die "Falta comando requerido: $1"; }
is_root() { [[ "${EUID}" -eq 0 ]]; }

confirm() {
  local label="$1" default="${2:-y}"
  local ans=""
  read -r -p "${label} [${default}]: " ans
  [[ -z "$ans" ]] && ans="$default"
  [[ "$ans" =~ ^[Yy]$ ]]
}

prompt() {
  # prompt VAR "Label" "default" secret(0/1) allow_empty(0/1)
  local var_name="$1" label="$2" default="${3:-}" secret="${4:-0}" allow_empty="${5:-0}"
  local value=""
  while true; do
    if [[ "$secret" == "1" ]]; then
      if [[ -n "$default" ]]; then
        read -r -s -p "${label} [default oculto]: " value; echo
        [[ -z "$value" ]] && value="$default"
      else
        read -r -s -p "${label}: " value; echo
      fi
    else
      if [[ -n "$default" ]]; then
        read -r -p "${label} [${default}]: " value
        [[ -z "$value" ]] && value="$default"
      else
        read -r -p "${label}: " value
      fi
    fi
    if [[ "$allow_empty" == "1" ]]; then break; fi
    [[ -n "$value" ]] && break
    echo "-> Este valor no puede ir vacío."
  done
  printf -v "$var_name" "%s" "$value"
}

detect_os_id() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

is_linux() { [[ "$(uname -s 2>/dev/null || echo unknown)" == "Linux" ]]; }

install_pkgs() {
  local os_id; os_id="$(detect_os_id)"
  if [[ "$os_id" =~ (almalinux|rocky|rhel|centos|fedora) ]]; then
    require_cmd dnf
    dnf -y install "$@"
  elif [[ "$os_id" =~ (debian|ubuntu) ]]; then
    require_cmd apt-get
    apt-get update -y
    apt-get install -y "$@"
  else
    die "OS no soportado para instalación automática (ID=${os_id}). Instala manual: $*"
  fi
}

ensure_python3() {
  if has_cmd python3; then return 0; fi
  if is_linux && is_root; then
    info "python3 no está instalado. Intentando instalar..."
    install_pkgs python3
  else
    die "Falta python3. Instálalo o ejecuta como root en Linux para instalarlo."
  fi
  require_cmd python3
}

urlencode_str() {
  python3 - <<'PY'
import os, urllib.parse
s = os.environ.get("SX_URLENCODE_IN", "")
print(urllib.parse.quote(s, safe=""))
PY
}

gen_secret_key() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
}

gen_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits + "!@#$%_=+-."
print("".join(secrets.choice(alphabet) for _ in range(24)))
PY
}

ensure_docker_compose() {
  require_cmd docker
  if ! docker compose version >/dev/null 2>&1; then
    die "docker compose no está disponible. Instala Docker Compose v2."
  fi
}

compose_time_mounts_block() {
  if is_linux; then
    cat <<'EOF'
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
EOF
  fi
}

ensure_empty_dir() {
  local dir="$1"
  mkdir -p "$dir"
  rm -rf "${dir:?}/"*
}

# ---------- GeoIP ----------
check_geoip_files() {
  mkdir -p "${GEOIP_DIR}"
  local missing=0
  [[ -f "${COUNTRY_MMDB}" ]] || missing=1
  [[ -f "${ASN_MMDB}" ]] || missing=1

  if [[ "$missing" -eq 0 ]]; then
    info "GeoIP OK: existen Country y ASN en ${GEOIP_DIR}"
    return 0
  fi

  echo
  echo "Faltan archivos GeoIP en ${GEOIP_DIR}"
  echo "Requeridos:"
  echo "  - GeoLite2-Country.mmdb"
  echo "  - GeoLite2-ASN.mmdb"
  echo
  echo "Opciones:"
  echo "  1) Descarga automática (requiere MaxMind License Key)"
  echo "  2) Los copiaré manualmente"
  echo "  3) Omitir (enrich GeoIP puede fallar si se habilita)"
  echo

  local opt; prompt opt "Elige (1/2/3)" "2" 0 0

  if [[ "$opt" == "1" ]]; then
    if ! has_cmd curl; then
      if is_root && is_linux; then install_pkgs curl; else die "Falta curl."; fi
    fi
    if ! has_cmd tar; then
      if is_root && is_linux; then install_pkgs tar; else die "Falta tar."; fi
    fi
    local MM_LICENSE; prompt MM_LICENSE "MaxMind License Key" "" 1 0

    local tmpdir; tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT

    info "Descargando GeoLite2-Country..."
    curl -fL \
      "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MM_LICENSE}&suffix=tar.gz" \
      -o "${tmpdir}/country.tar.gz"

    info "Descargando GeoLite2-ASN..."
    curl -fL \
      "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MM_LICENSE}&suffix=tar.gz" \
      -o "${tmpdir}/asn.tar.gz"

    info "Extrayendo..."
    tar -xzf "${tmpdir}/country.tar.gz" -C "${tmpdir}"
    tar -xzf "${tmpdir}/asn.tar.gz" -C "${tmpdir}"

    local country_path asn_path
    country_path="$(find "${tmpdir}" -type f -name "GeoLite2-Country.mmdb" | head -n 1 || true)"
    asn_path="$(find "${tmpdir}" -type f -name "GeoLite2-ASN.mmdb" | head -n 1 || true)"
    [[ -n "$country_path" ]] || die "No encontré GeoLite2-Country.mmdb en el tar."
    [[ -n "$asn_path" ]] || die "No encontré GeoLite2-ASN.mmdb en el tar."

    cp -f "$country_path" "${COUNTRY_MMDB}"
    cp -f "$asn_path" "${ASN_MMDB}"
    chmod 644 "${COUNTRY_MMDB}" "${ASN_MMDB}"
    info "GeoIP descargado y copiado a ${GEOIP_DIR}"
  elif [[ "$opt" == "2" ]]; then
    echo "Copia manualmente a:"
    echo "  ${COUNTRY_MMDB}"
    echo "  ${ASN_MMDB}"
  else
    warn "Omitiendo GeoIP."
  fi
}

# ---------- Trust config ----------
ensure_trust_config_file() {
  local repo_path="${ROOT_DIR}/app/config/trust_list.json"
  mkdir -p "$(dirname "$repo_path")"
  if [[ -f "$repo_path" ]]; then
    info "Trust config OK: ${repo_path}"
    return 0
  fi
  cat > "$repo_path" <<'JSON'
{
  "trusted_ip_ranges": [],
  "trusted_asns": [],
  "trusted_countries": [],
  "trusted_domains": [],
  "notes": "Archivo generado por setup. Ajusta tus listas de confianza aquí."
}
JSON
  info "Trust config creado: ${repo_path}"
}

# ---------- CSF / iptables / Docker checks ----------
csf_installed() { [[ -x /usr/sbin/csf || -x /usr/local/sbin/csf || -x /usr/local/csf/bin/csf ]]; }

csf_enable_docker_integration() {
  local conf="/etc/csf/csf.conf"
  [[ -f "$conf" ]] || return 0

  local current
  current="$(grep -E '^DOCKER\s*=' "$conf" 2>/dev/null | head -n1 || true)"
  if [[ "$current" =~ \"1\" ]]; then
    info "CSF: DOCKER=\"1\" ya está habilitado."
    return 0
  fi

  echo
  echo "CSF detectado. Para que Docker cree redes sin errores, se recomienda:"
  echo "  - DOCKER=\"1\" en /etc/csf/csf.conf"
  echo
  if ! confirm "¿Quieres que el script habilite DOCKER=\"1\" y reinicie CSF? (recomendado)" "y"; then
    warn "CSF no modificado. Si vuelve el error de DOCKER-ISOLATION, habilita DOCKER=\"1\" y csf -r."
    return 0
  fi

  if ! is_root; then
    die "Necesitas ejecutar como root para modificar CSF."
  fi

  info "Habilitando DOCKER=\"1\" en ${conf}"
  if grep -qE '^DOCKER\s*=' "$conf"; then
    sed -i 's/^DOCKER\s*=.*/DOCKER = "1"/' "$conf"
  else
    echo 'DOCKER = "1"' >> "$conf"
  fi

  info "Reiniciando CSF (csf -r)"
  csf -r >/dev/null 2>&1 || true
  info "CSF actualizado."
}

docker_fix_isolation_chain() {
  # Si Docker no puede insertar DOCKER-ISOLATION, normalmente es por iptables/csf.
  # La mitigación más confiable es: habilitar DOCKER en CSF + reiniciar docker.
  if ! is_linux; then return 0; fi

  if ! has_cmd iptables; then
    warn "No encontré iptables. Omitiendo check DOCKER-ISOLATION."
    return 0
  fi

  if iptables -S FORWARD 2>/dev/null | grep -q 'DOCKER-ISOLATION-STAGE-1'; then
    info "iptables: DOCKER-ISOLATION-STAGE-1 presente."
    return 0
  fi

  echo
  echo "No se encontró la cadena DOCKER-ISOLATION-STAGE-1 en iptables."
  echo "Esto puede causar errores al hacer docker compose up (crear redes)."
  echo
  if ! confirm "¿Quieres intentar reparar reiniciando Docker (systemctl restart docker)?" "y"; then
    warn "No se intentó reparar Docker iptables."
    return 0
  fi

  if ! is_root; then
    die "Necesitas ejecutar como root para reiniciar docker."
  fi

  info "Reiniciando docker..."
  systemctl restart docker || die "No pude reiniciar docker."
  info "Docker reiniciado. Revisa nuevamente si el error desapareció."
}

# ---------- Nginx reverse proxy ----------
nginx_install_if_needed() {
  if has_cmd nginx; then return 0; fi
  echo
  echo "Nginx no está instalado."
  if ! confirm "¿Quieres que el script instale Nginx? (recomendado para SERVER)" "y"; then
    die "Nginx requerido para reverse proxy. Reintenta o usa modo LOCALHOST."
  fi
  if ! is_root; then
    die "Necesitas ejecutar como root para instalar Nginx."
  fi
  info "Instalando Nginx..."
  install_pkgs nginx
  systemctl enable nginx >/dev/null 2>&1 || true
}

nginx_write_conf() {
  local domain="$1"
  local front_root="$2"
  local backend_port="$3"
  local conf_path="/etc/nginx/conf.d/sentinelx.conf"

  echo
  echo "Se creará/actualizará:"
  echo "  ${conf_path}"
  echo "Con:"
  echo "  server_name ${domain}"
  echo "  root ${front_root}"
  echo "  /api -> http://127.0.0.1:${backend_port}"
  echo
  if ! confirm "¿Confirmas escribir configuración Nginx?" "y"; then
    warn "Nginx no configurado. Deberás hacerlo manual."
    return 0
  fi

  if ! is_root; then
    die "Necesitas ejecutar como root para escribir config de Nginx."
  fi

  cat > "$conf_path" <<EOF
server {
    listen 80;
    server_name ${domain};

    # Front estático (Astro dist)
    root ${front_root};
    index index.html;

    # Seguridad básica
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Single Page App fallback (Astro)
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # API proxy hacia backend (FastAPI)
    location /api/ {
        proxy_pass http://127.0.0.1:${backend_port}/;
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_read_timeout 120s;
        proxy_connect_timeout 15s;
        proxy_send_timeout 120s;
    }
}
EOF

  nginx -t || die "nginx -t falló. Revisa ${conf_path}"
  systemctl restart nginx || die "No pude reiniciar Nginx."
  info "Nginx configurado y reiniciado."
  echo "Nota: si quieres HTTPS, instala certbot y emite certificado para ${domain}."
}

# ---------- Front build/deploy ----------
ensure_npm() {
  if has_cmd npm; then return 0; fi
  echo
  echo "npm no está instalado."
  if ! confirm "¿Quieres que el script instale nodejs/npm? (requerido para build del front)" "y"; then
    die "npm requerido para build del front."
  fi
  if ! is_root; then
    die "Necesitas ejecutar como root para instalar nodejs/npm."
  fi
  info "Instalando nodejs/npm..."
  install_pkgs nodejs npm
  require_cmd npm
}

frontend_build() {
  local front_src="$1"
  [[ -d "$front_src" ]] || die "No existe carpeta front: ${front_src}"
  [[ -f "${front_src}/package.json" ]] || die "No existe package.json en ${front_src}"
  ensure_npm
  info "npm install (front)"
  (cd "${front_src}" && npm install)
  info "npm run build (front)"
  (cd "${front_src}" && npm run build)
  [[ -d "${front_src}/dist" ]] || die "No se generó dist/. Revisa npm run build."
}

frontend_deploy_dist() {
  local dist_dir="$1"
  local deploy_path="$2"
  [[ -d "${dist_dir}" ]] || die "No existe dist/: ${dist_dir}"
  info "Deploy: copiando dist/ a ${deploy_path}"
  mkdir -p "${deploy_path}"
  ensure_empty_dir "${deploy_path}"
  cp -a "${dist_dir}/." "${deploy_path}/"
  info "Front deploy OK: ${deploy_path}"
}

# ============================================================
# PREFLIGHT
# ============================================================
echo "== SentinelX Setup =="
echo "Repo: ${ROOT_DIR}"
echo

ensure_docker_compose
ensure_python3

if ! is_linux; then
  warn "Este script está orientado a Linux. En Mac puedes usarlo, pero Nginx/CSF no aplican."
fi

# ============================================================
# MODE SELECTION
# ============================================================
echo
echo "== Modo =="
echo "1) LOCALHOST  (solo local, sin Nginx, acceso por puertos: 8000 + (front opcional))"
echo "2) SERVER     (dominio + Nginx reverse proxy para front y /api)"
prompt MODE_OPT "Elige (1/2)" "1" 0 0
MODE="LOCALHOST"
[[ "$MODE_OPT" == "2" ]] && MODE="SERVER"
info "Modo: ${MODE}"

# ============================================================
# CHECKS (GeoIP + trust config)
# ============================================================
echo
echo "== GeoIP =="
check_geoip_files

echo
echo "== Trust config =="
ensure_trust_config_file

# ============================================================
# CSF + Docker mitigation (solo Linux)
# ============================================================
if is_linux && csf_installed; then
  echo
  echo "== CSF/Docker check =="
  csf_enable_docker_integration
fi

if is_linux; then
  echo
  echo "== Docker iptables check =="
  docker_fix_isolation_chain
fi

# ============================================================
# INPUTS (.env)
# ============================================================
echo
echo "== Configuración (.env) =="

# DB
prompt POSTGRES_DB "POSTGRES_DB" "sentinelx_db" 0 0
prompt POSTGRES_USER "POSTGRES_USER" "sentinelx" 0 0
prompt POSTGRES_PASSWORD "POSTGRES_PASSWORD (secreto)" "" 1 0

export SX_URLENCODE_IN="${POSTGRES_PASSWORD}"
DB_PASS_URLENC="$(urlencode_str)"
unset SX_URLENCODE_IN
[[ -n "${DB_PASS_URLENC}" ]] || die "No pude URL-encode de POSTGRES_PASSWORD."

DATABASE_URL="postgresql+psycopg2://${POSTGRES_USER}:${DB_PASS_URLENC}@db:5432/${POSTGRES_DB}"

# JWT/Secrets
prompt SECRET_KEY "SECRET_KEY (vacío = autogenerar)" "" 0 1
if [[ -z "${SECRET_KEY}" ]]; then
  SECRET_KEY="$(gen_secret_key)"
  info "SECRET_KEY generado."
fi
prompt ACCESS_TOKEN_EXPIRE_MINUTES "ACCESS_TOKEN_EXPIRE_MINUTES" "14400" 0 0

# Admin inicial
prompt INITIAL_ADMIN_EMAIL "INITIAL_ADMIN_EMAIL" "admin@example.com" 0 0
echo "INITIAL_ADMIN_PASSWORD:"
echo "  - Puedes escribirla"
echo "  - O dejar vacío para autogenerarla"
prompt INITIAL_ADMIN_PASSWORD "INITIAL_ADMIN_PASSWORD (vacío=autogenerar)" "" 1 1
if [[ -z "${INITIAL_ADMIN_PASSWORD}" ]]; then
  INITIAL_ADMIN_PASSWORD="$(gen_password)"
  echo
  echo "IMPORTANTE: Password admin generado (cópialo y guárdalo):"
  echo "  ${INITIAL_ADMIN_PASSWORD}"
  echo
fi
prompt INITIAL_ADMIN_FULL_NAME "INITIAL_ADMIN_FULL_NAME" "SentinelX Admin" 0 0

# Paths
prompt UPLOADED_LOGS_DIR "UPLOADED_LOGS_DIR" "/app/uploaded_logs" 0 0
GEOIP_COUNTRY_DB_PATH="/geoip/GeoLite2-Country.mmdb"
GEOIP_ASN_DB_PATH="/geoip/GeoLite2-ASN.mmdb"
SIEM_TRUST_CONFIG_PATH="/app/app/config/trust_list.json"

# Ports
prompt BACKEND_PORT "BACKEND_PORT (host -> contenedor 8000)" "8000" 0 0

# Front build/deploy
echo
echo "== Frontend =="
prompt FRONT_SRC "Ruta del frontend (proyecto Astro)" "${FRONT_SRC_DEFAULT}" 0 0
prompt FRONT_DEPLOY_PATH "Ruta destino para copiar front/dist (Nginx root si SERVER)" "${ROOT_DIR}/public_html" 0 0

# SMTP
echo
echo "== SMTP (opcional) =="
prompt SMTP_HOST "SMTP_HOST (vacío = deshabilitar)" "" 0 1
SMTP_PORT=""
SMTP_USER=""
SMTP_PASS=""
FROM_EMAIL=""
SMTP_TIMEOUT_SECONDS="20"
SMTP_LOOPBACK_DOMAIN=""
SMTP_LOOPBACK_ENABLED="0"

if [[ -n "${SMTP_HOST}" ]]; then
  prompt SMTP_PORT "SMTP_PORT" "587" 0 0
  prompt SMTP_USER "SMTP_USER" "" 0 0
  prompt SMTP_PASS "SMTP_PASS" "" 1 0
  prompt FROM_EMAIL "FROM_EMAIL" "${SMTP_USER}" 0 0
  prompt SMTP_TIMEOUT_SECONDS "SMTP_TIMEOUT_SECONDS" "20" 0 0

  echo
  echo "Si tu SMTP está en el MISMO VPS y desde Docker no conecta bien por DNS->IP pública,"
  echo "podemos mapear el dominio SMTP hacia el host (host-gateway)."
  if confirm "¿Habilitar loopback SMTP vía host-gateway? (recomendado en cPanel local)" "y"; then
    SMTP_LOOPBACK_ENABLED="1"
    prompt SMTP_LOOPBACK_DOMAIN "Dominio a mapear (ej: mail.tudominio.com o tu dominio SMTP)" "${SMTP_HOST}" 0 0
  fi
fi

# Workers scale
echo
echo "== Workers =="
prompt PARSING_WORKERS "parsing_worker replicas" "2" 0 0
prompt ENGINE_WORKERS "engine_worker replicas" "3" 0 0

# Front URL (para reset links, etc.)
echo
echo "== FRONTEND_BASE_URL =="
if [[ "${MODE}" == "SERVER" ]]; then
  prompt FRONTEND_BASE_URL "FRONTEND_BASE_URL" "https://example.com/" 0 0
else
  prompt FRONTEND_BASE_URL "FRONTEND_BASE_URL" "http://localhost:4321/" 0 0
fi

# ============================================================
# WRITE .env (SECRETS: chmod 600)
# ============================================================
echo
info "Generando ${ENV_FILE}"

{
  cat <<EOF
# ----------------------
# DB
# ----------------------
DATABASE_URL=${DATABASE_URL}

# ----------------------
# JWT / Seguridad
# ----------------------
SECRET_KEY=${SECRET_KEY}
ACCESS_TOKEN_EXPIRE_MINUTES=${ACCESS_TOKEN_EXPIRE_MINUTES}

# ----------------------
# Admin inicial
# ----------------------
INITIAL_ADMIN_EMAIL=${INITIAL_ADMIN_EMAIL}
INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}
INITIAL_ADMIN_FULL_NAME=${INITIAL_ADMIN_FULL_NAME}

# ----------------------
# Paths
# ----------------------
UPLOADED_LOGS_DIR=${UPLOADED_LOGS_DIR}

# ----------------------
# GeoIP
# ----------------------
GEOIP_COUNTRY_DB_PATH=${GEOIP_COUNTRY_DB_PATH}
GEOIP_ASN_DB_PATH=${GEOIP_ASN_DB_PATH}

# ----------------------
# Front
# ----------------------
FRONTEND_BASE_URL=${FRONTEND_BASE_URL}

# ----------------------
# Trust config
# ----------------------
SIEM_TRUST_CONFIG_PATH=${SIEM_TRUST_CONFIG_PATH}

PYTHONDONTWRITEBYTECODE=1
EOF

  if [[ -n "${SMTP_HOST}" ]]; then
    cat <<EOF

# ----------------------
# SMTP
# ----------------------
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}
FROM_EMAIL=${FROM_EMAIL}
SMTP_TIMEOUT_SECONDS=${SMTP_TIMEOUT_SECONDS}
EOF
  fi
} > "${ENV_FILE}"

chmod 600 "${ENV_FILE}"

# ============================================================
# WRITE docker-compose.yml (parecido a tu compose real)
# ============================================================
echo
info "Generando ${COMPOSE_FILE}"

TIME_MOUNTS="$(compose_time_mounts_block)"

EXTRA_HOSTS_BLOCK=""
if [[ "${SMTP_LOOPBACK_ENABLED}" == "1" ]]; then
  # Usamos host-gateway para mapear al host sin IP hardcodeada.
  EXTRA_HOSTS_BLOCK=$(cat <<EOF
    extra_hosts:
      - "${SMTP_LOOPBACK_DOMAIN}:host-gateway"
EOF
)
fi

cat > "${COMPOSE_FILE}" <<EOF
services:
  db:
    image: postgres:16
    container_name: sentinelx-db
    shm_size: "1g"
    restart: unless-stopped

    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: "${POSTGRES_PASSWORD}"
      POSTGRES_INITDB_ARGS: "--data-checksums"

    ports:
      - "5432:5432"

    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./postgres/init:/docker-entrypoint-initdb.d:ro

    stop_signal: SIGINT
    stop_grace_period: 2m

    command: >
      postgres
      -c shared_buffers=256MB
      -c wal_compression=on
      -c max_wal_size=2GB
      -c checkpoint_timeout=10min
      -c checkpoint_completion_target=0.9
      -c log_checkpoints=on
      -c log_min_duration_statement=2000
      -c log_line_prefix='%m[%p] user=%u db=%d app=%a client=%h '
      -c idle_in_transaction_session_timeout=300000
      -c statement_timeout=0
      -c shared_preload_libraries=pg_stat_statements
      -c pg_stat_statements.track=all
      -c pg_stat_statements.max=10000
      -c pg_stat_statements.save=on

    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB} -h 127.0.0.1 || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 20s

    tmpfs:
      - /tmp

    ulimits:
      nofile:
        soft: 65536
        hard: 65536

  backend:
    build:
      context: .
    container_name: sentinelx-backend
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy

    env_file:
      - .env

    environment:
      UPLOADED_LOGS_DIR: ${UPLOADED_LOGS_DIR}
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH}
      ENRICH_INLINE: "1"
      ENRICH_CACHE_TTL: "86400"
      ENRICH_CACHE_MAX: "100000"
      RULES_RELOAD_SECONDS: "600"

${EXTRA_HOSTS_BLOCK}
    ports:
      - "${BACKEND_PORT}:8000"

    volumes:
      - .:/app
      - ./geoip:/geoip:ro
${TIME_MOUNTS}
    stop_grace_period: 1m

    command: >
      bash -lc "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"

    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  parsing_worker:
    build:
      context: .
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy

    env_file:
      - .env

    environment:
      UPLOADED_LOGS_DIR: ${UPLOADED_LOGS_DIR}
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH}
      ENRICH_INLINE: "1"
      ENRICH_CACHE_TTL: "86400"
      ENRICH_CACHE_MAX: "100000"
      RULES_RELOAD_SECONDS: "600"
      WORKER_POLL_SECONDS: "2"
      WORKER_MAX_PER_CYCLE: "1"
      WORKER_STALE_SECONDS: "3600"

${EXTRA_HOSTS_BLOCK}
    volumes:
      - .:/app
      - ./geoip:/geoip:ro
${TIME_MOUNTS}
    stop_grace_period: 1m

    command: >
      bash -lc "python -m app.workers.parsing_worker_loop"

    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

  engine_worker:
    build:
      context: .
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy

    env_file:
      - .env

    environment:
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH}
      RULES_RELOAD_SECONDS: "600"
      ENGINE_WORKER_POLL_SECONDS: "1"
      ENGINE_WORKER_MAX_PER_CYCLE: "200"
      ENGINE_WORKER_STALE_SECONDS: "3600"

${EXTRA_HOSTS_BLOCK}
    volumes:
      - .:/app
      - ./geoip:/geoip:ro
${TIME_MOUNTS}
    stop_grace_period: 1m

    command: >
      bash -lc "python -m app.workers.engine_worker_loop"

    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"

volumes:
  pgdata:
EOF

# ============================================================
# WRITE docker-compose.example.yml (public-friendly)
# ============================================================
echo
info "Generando ${COMPOSE_EXAMPLE_FILE}"

cat > "${COMPOSE_EXAMPLE_FILE}" <<'EOF'
# docker-compose.example.yml
services:
  db:
    image: postgres:16
    container_name: sentinelx-db
    shm_size: "1g"
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-sentinelx_db}
      POSTGRES_USER: ${POSTGRES_USER:-sentinelx}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: "--data-checksums"
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./postgres/init:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-sentinelx} -d ${POSTGRES_DB:-sentinelx_db} -h 127.0.0.1 || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 20s

  backend:
    build:
      context: .
    container_name: sentinelx-backend
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    env_file:
      - .env
    environment:
      UPLOADED_LOGS_DIR: ${UPLOADED_LOGS_DIR:-/app/uploaded_logs}
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH:-/geoip/GeoLite2-Country.mmdb}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH:-/geoip/GeoLite2-ASN.mmdb}
      ENRICH_INLINE: "${ENRICH_INLINE:-1}"
      ENRICH_CACHE_TTL: "${ENRICH_CACHE_TTL:-86400}"
      ENRICH_CACHE_MAX: "${ENRICH_CACHE_MAX:-100000}"
      RULES_RELOAD_SECONDS: "${RULES_RELOAD_SECONDS:-600}"
    ports:
      - "${BACKEND_PORT:-8000}:8000"
    volumes:
      - .:/app
      - ./geoip:/geoip:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command: >
      bash -lc "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"

  parsing_worker:
    build:
      context: .
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    env_file:
      - .env
    environment:
      UPLOADED_LOGS_DIR: ${UPLOADED_LOGS_DIR:-/app/uploaded_logs}
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH:-/geoip/GeoLite2-Country.mmdb}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH:-/geoip/GeoLite2-ASN.mmdb}
      ENRICH_INLINE: "${ENRICH_INLINE:-1}"
      ENRICH_CACHE_TTL: "${ENRICH_CACHE_TTL:-86400}"
      ENRICH_CACHE_MAX: "${ENRICH_CACHE_MAX:-100000}"
      RULES_RELOAD_SECONDS: "${RULES_RELOAD_SECONDS:-600}"
      WORKER_POLL_SECONDS: "${WORKER_POLL_SECONDS:-2}"
      WORKER_MAX_PER_CYCLE: "${WORKER_MAX_PER_CYCLE:-1}"
      WORKER_STALE_SECONDS: "${WORKER_STALE_SECONDS:-3600}"
    volumes:
      - .:/app
      - ./geoip:/geoip:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command: >
      bash -lc "python -m app.workers.parsing_worker_loop"

  engine_worker:
    build:
      context: .
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    env_file:
      - .env
    environment:
      GEOIP_COUNTRY_DB_PATH: ${GEOIP_COUNTRY_DB_PATH:-/geoip/GeoLite2-Country.mmdb}
      GEOIP_ASN_DB_PATH: ${GEOIP_ASN_DB_PATH:-/geoip/GeoLite2-ASN.mmdb}
      RULES_RELOAD_SECONDS: "${RULES_RELOAD_SECONDS:-600}"
      ENGINE_WORKER_POLL_SECONDS: "${ENGINE_WORKER_POLL_SECONDS:-1}"
      ENGINE_WORKER_MAX_PER_CYCLE: "${ENGINE_WORKER_MAX_PER_CYCLE:-200}"
      ENGINE_WORKER_STALE_SECONDS: "${ENGINE_WORKER_STALE_SECONDS:-3600}"
    volumes:
      - .:/app
      - ./geoip:/geoip:ro
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    command: >
      bash -lc "python -m app.workers.engine_worker_loop"

volumes:
  pgdata:
EOF

# ============================================================
# START DOCKER STACK
# ============================================================
echo
info "Levantando stack Docker (con escala de workers)"

docker compose -f "${COMPOSE_FILE}" down >/dev/null 2>&1 || true

docker compose -f "${COMPOSE_FILE}" up -d --build \
  --scale "parsing_worker=${PARSING_WORKERS}" \
  --scale "engine_worker=${ENGINE_WORKERS}"

docker compose -f "${COMPOSE_FILE}" ps

# ============================================================
# FRONT BUILD + DEPLOY
# ============================================================
echo
echo "== Front build & deploy =="

if [[ ! -d "${FRONT_SRC}" ]]; then
  warn "No existe carpeta front: ${FRONT_SRC}"
  echo "Crea/coloca tu frontend (Astro) en esa ruta y vuelve a correr el script."
else
  frontend_build "${FRONT_SRC}"
  frontend_deploy_dist "${FRONT_SRC}/dist" "${FRONT_DEPLOY_PATH}"
fi

# ============================================================
# NGINX (SERVER mode)
# ============================================================
if [[ "${MODE}" == "SERVER" ]]; then
  echo
  echo "== Nginx reverse proxy =="
  prompt DOMAIN "Dominio para Nginx (server_name)" "example.com" 0 0

  nginx_install_if_needed

  # Aviso de puertos
  echo
  echo "Puertos recomendados:"
  echo "  - 80/443 para Nginx (front + /api)"
  echo "  - ${BACKEND_PORT} puede quedarse cerrado al público si usas Nginx"
  if confirm "¿Quieres que el script continúe con Nginx ahora?" "y"; then
    nginx_write_conf "${DOMAIN}" "${FRONT_DEPLOY_PATH}" "${BACKEND_PORT}"
  fi
fi

# ============================================================
# END
# ============================================================
echo
echo "Listo."
echo "Archivos generados:"
echo "  - ${ENV_FILE} (chmod 600)"
echo "  - ${COMPOSE_FILE}"
echo "  - ${COMPOSE_EXAMPLE_FILE}"
echo
echo "Backend:"
echo "  - http://localhost:${BACKEND_PORT}"
if [[ "${MODE}" == "SERVER" ]]; then
  echo "Front por Nginx:"
  echo "  - http://${DOMAIN}  (y /api -> backend)"
else
  echo "Front:"
  echo "  - dist copiado en ${FRONT_DEPLOY_PATH} (sirve estático si lo expones con algún servidor)"
fi
echo
echo "Nota:"
echo "  - Si usas CSF y vuelve a fallar docker networks, revisa DOCKER=\"1\" en /etc/csf/csf.conf y ejecuta csf -r."

