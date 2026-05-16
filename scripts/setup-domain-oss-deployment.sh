#!/usr/bin/env bash
# Copyright 2026 Daytona Platforms Inc.
# SPDX-License-Identifier: AGPL-3.0

# Daytona Domain Setup
# Automated deployment of Daytona OSS for use behind an existing nginx reverse proxy.
# This script does not install packages, change firewall rules, or configure host TLS.
# Supports: Linux and macOS with Docker already installed.
# Usage: ./setup.sh
set -euo pipefail

# Remove transient per-step log on any exit so partial runs don't leave
# captured stdout/stderr lying around in /tmp.
trap 'rm -f "/tmp/daytona-step-$$.log"' EXIT INT TERM

# ── Colors ──────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Globals (filled during input/detection) ─────────────────
OS="" ARCH=""
DOMAIN="" ADMIN_EMAIL="" ADMIN_PASSWORD="" ADMIN_PASSWORD_HASH=""
ENCRYPTION_KEY="" ENCRYPTION_SALT=""
PROXY_API_KEY="" RUNNER_API_KEY="" SSH_GATEWAY_API_KEY=""
PGADMIN_EMAIL="" PGADMIN_PASSWORD=""
MINIO_USER="" MINIO_PASSWORD=""
DB_USER="" DB_PASS=""
REGISTRY_USER="" REGISTRY_PASSWORD=""
HEALTH_CHECK_KEY="" OTEL_COLLECTOR_KEY=""
CLICKHOUSE_ENABLED="" CLICKHOUSE_HOST_VAL="" CLICKHOUSE_PORT_VAL=""
CLICKHOUSE_USER="" CLICKHOUSE_PASS="" CLICKHOUSE_DB_VAL="" CLICKHOUSE_PROTO=""
REPO_DIR="${REPO_DIR:-$HOME/daytona}"

# ── Helpers ─────────────────────────────────────────────────
info()    { printf "  ${CYAN}▸${NC} %s\n" "$*"; }
ok()      { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
warn()    { printf "  ${YELLOW}!${NC} %s\n" "$*"; }
fail()    { printf "  ${RED}✗${NC} %s\n" "$*"; }
die()     { fail "$*"; exit 1; }

# Portable sed in-place: BSD sed (macOS) requires -i '', GNU sed requires -i
sedi() {
    if [ "$OS" = "macos" ]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Replace a literal placeholder in a file with a value.
# Uses awk + ENVIRON so the value never appears in the process command line.
_file_replace() {
    local file="$1" placeholder="$2" val="$3"
    _DAYTONA_VAL="$val" awk -v ph="$placeholder" '
    {
        while ((i = index($0, ph)) > 0)
            $0 = substr($0, 1, i-1) ENVIRON["_DAYTONA_VAL"] substr($0, i + length(ph))
        print
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

run_step() {
    local name="$1"; shift
    printf "  ${CYAN}▸${NC} %s" "$name"
    local log="/tmp/daytona-step-$$.log"
    install -m 600 /dev/null "$log"
    if "$@" > "$log" 2>&1; then
        printf "\r  ${GREEN}✓${NC} %s\n" "$name"
    else
        printf "\r  ${RED}✗${NC} %s\n" "$name"
        sed 's/^/    /' "$log"
        rm -f "$log"
        exit 1
    fi
    rm -f "$log"
}

# ── Platform Detection ──────────────────────────────────────
detect_platform() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        arm64)   ARCH="arm64" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    case "$(uname -s)" in
        Darwin)
            OS="macos"
            info "Detected macOS ($ARCH)"
            return
            ;;
        Linux) ;;
        *) die "Unsupported operating system: $(uname -s)" ;;
    esac

    # Linux: detect distro from /etc/os-release
    [ -f /etc/os-release ] || die "Cannot detect OS — /etc/os-release not found"
    # shellcheck disable=SC1091
    . /etc/os-release

    case "${ID:-}" in
        ubuntu|debian)
            OS="$ID" ;;
        fedora)
            OS="fedora" ;;
        centos|rhel|rocky|almalinux)
            OS="$ID" ;;
        *)
            case "${ID_LIKE:-}" in
                *debian*|*ubuntu*) OS="debian" ;;
                *fedora*|*rhel*)   OS="fedora" ;;
                *) die "Unsupported OS: ${PRETTY_NAME:-$ID}" ;;
            esac ;;
    esac

    info "Detected ${PRETTY_NAME:-$ID} ($ARCH)"
}

# ── Input Collection ────────────────────────────────────────
collect_input() {
    printf "\n${BOLD}  Daytona Docker Setup${NC}\n"
    printf "  ═════════════════════\n\n"
    printf "  This configures Daytona containers for an existing nginx reverse proxy.\n"
    printf "  It will not install packages, open firewall ports, or configure Caddy/TLS.\n\n"

    # Domain
    # Restrict to RFC 1123 hostname syntax. The value is substituted into
    # docker-compose env vars and Dex config; accepting only
    # letters/digits/hyphens/dots prevents a typo from corrupting those files.
    while true; do
        printf "  Domain (e.g. daytona.example.com): "; read -r DOMAIN
        DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN#http://}"
        DOMAIN="$(echo "$DOMAIN" | tr -d '[:space:]')"
        [ -z "$DOMAIN" ] && { fail "Required"; continue; }
        if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
            fail "Must be a valid hostname (e.g. daytona.example.com)"
            continue
        fi
        break
    done

    # Email validation for admin/service logins.
    local _email_re='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'

    # Admin email
    while true; do
        printf "\n  Admin login email: "; read -r ADMIN_EMAIL
        ADMIN_EMAIL="$(echo "$ADMIN_EMAIL" | tr -d '[:space:]')"
        echo "$ADMIN_EMAIL" | grep -qE "$_email_re" && break
        fail "Must be a valid email"
    done

    # Admin password — fronts the Daytona dashboard on the public internet,
    # so require 12 chars minimum rather than the bare-minimum 8.
    while true; do
        printf "  Admin password (min 12 chars): "; read -rs ADMIN_PASSWORD; echo
        [ ${#ADMIN_PASSWORD} -lt 12 ] && { fail "Too short"; continue; }
        printf "  Confirm password: "; read -rs pw_confirm; echo
        [ "$ADMIN_PASSWORD" = "$pw_confirm" ] && break
        fail "Passwords do not match"
    done

    # Service credentials
    printf "\n${BOLD}  Service Credentials${NC}\n"
    printf "  These replace default placeholder credentials and secure services behind HTTPS.\n\n"

    # Usernames are substituted into docker-compose env vars. Restrict the
    # charset so a stray quote or brace can't corrupt the config.
    local _user_re='^[a-zA-Z0-9_-]{1,63}$'

    # PostgreSQL
    while true; do
        printf "  PostgreSQL username: "; read -r DB_USER
        DB_USER="$(echo "$DB_USER" | tr -d '[:space:]')"
        echo "$DB_USER" | grep -qE "$_user_re" && break
        fail "Must be alphanumeric (plus _ -), 1-63 chars"
    done
    while true; do
        printf "  PostgreSQL password (min 12 chars): "; read -rs DB_PASS; echo
        [ ${#DB_PASS} -lt 12 ] && { fail "Too short"; continue; }
        break
    done

    # PgAdmin
    while true; do
        printf "  PgAdmin email: "; read -r PGADMIN_EMAIL
        PGADMIN_EMAIL="$(echo "$PGADMIN_EMAIL" | tr -d '[:space:]')"
        echo "$PGADMIN_EMAIL" | grep -qE "$_email_re" && break
        fail "Must be a valid email"
    done
    while true; do
        printf "  PgAdmin password (min 12 chars): "; read -rs PGADMIN_PASSWORD; echo
        [ ${#PGADMIN_PASSWORD} -lt 12 ] && { fail "Too short"; continue; }
        break
    done

    # MinIO
    while true; do
        printf "  MinIO admin username: "; read -r MINIO_USER
        MINIO_USER="$(echo "$MINIO_USER" | tr -d '[:space:]')"
        echo "$MINIO_USER" | grep -qE "$_user_re" && break
        fail "Must be alphanumeric (plus _ -), 1-63 chars"
    done
    while true; do
        printf "  MinIO admin password (min 12 chars): "; read -rs MINIO_PASSWORD; echo
        [ ${#MINIO_PASSWORD} -lt 12 ] && { fail "Too short"; continue; }
        break
    done

    # Registry
    while true; do
        printf "  Registry admin username: "; read -r REGISTRY_USER
        REGISTRY_USER="$(echo "$REGISTRY_USER" | tr -d '[:space:]')"
        echo "$REGISTRY_USER" | grep -qE "$_user_re" && break
        fail "Must be alphanumeric (plus _ -), 1-63 chars"
    done
    while true; do
        printf "  Registry admin password (min 12 chars): "; read -rs REGISTRY_PASSWORD; echo
        [ ${#REGISTRY_PASSWORD} -lt 12 ] && { fail "Too short"; continue; }
        break
    done

    # ClickHouse (optional)
    printf "\n  Configure ClickHouse for sandbox telemetry? [y/N] "; read -r ch_yn
    case "${ch_yn:-n}" in
        [yY]*)
            CLICKHOUSE_ENABLED="true"
            printf "  ClickHouse host: "; read -r CLICKHOUSE_HOST_VAL
            CLICKHOUSE_HOST_VAL="$(echo "$CLICKHOUSE_HOST_VAL" | tr -d '[:space:]')"
            [ -z "$CLICKHOUSE_HOST_VAL" ] && die "Host is required"

            printf "  ClickHouse port [8123]: "; read -r CLICKHOUSE_PORT_VAL
            CLICKHOUSE_PORT_VAL="${CLICKHOUSE_PORT_VAL:-8123}"

            printf "  ClickHouse database [otel]: "; read -r CLICKHOUSE_DB_VAL
            CLICKHOUSE_DB_VAL="${CLICKHOUSE_DB_VAL:-otel}"

            printf "  ClickHouse protocol (http/https) [https]: "; read -r CLICKHOUSE_PROTO
            CLICKHOUSE_PROTO="${CLICKHOUSE_PROTO:-https}"

            printf "  ClickHouse username: "; read -r CLICKHOUSE_USER
            CLICKHOUSE_USER="$(echo "$CLICKHOUSE_USER" | tr -d '[:space:]')"

            printf "  ClickHouse password: "; read -rs CLICKHOUSE_PASS; echo
            ;;
    esac

    # Confirmation
    printf "\n${BOLD}  Configuration${NC}\n"
    printf "  ─────────────\n"
    printf "  Domain:       %s\n" "$DOMAIN"
    printf "  Admin:        %s\n" "$ADMIN_EMAIL"
    printf "  DB user:      %s\n" "$DB_USER"
    printf "  PgAdmin:      %s\n" "$PGADMIN_EMAIL"
    printf "  MinIO user:   %s\n" "$MINIO_USER"
    printf "  Registry:     %s\n" "$REGISTRY_USER"
    [ "$CLICKHOUSE_ENABLED" = "true" ] && printf "  ClickHouse:   %s:%s\n" "$CLICKHOUSE_HOST_VAL" "$CLICKHOUSE_PORT_VAL"
    printf "\n  Proceed? [Y/n] "; read -r yn
    case "${yn:-y}" in [nN]*) echo "  Aborted."; exit 0 ;; esac
}

# ── Steps ───────────────────────────────────────────────────

step_clean() {
    local cf="$REPO_DIR/docker/docker-compose.yaml"
    [ -f "$cf" ] && docker compose -f "$cf" down -v --remove-orphans 2>/dev/null || true
    # Kill any orphaned daytona containers from a previous failed run
    docker ps -aq --filter "name=daytona-" 2>/dev/null | xargs -r docker rm -f 2>/dev/null || true
    # Clean transient files only — preserve $REPO_DIR so re-runs are non-destructive
    # and avoid touching host-level Daytona paths.
    rm -rf /tmp/dashboard-extract
}

step_prerequisites() {
    command -v docker >/dev/null 2>&1 || die "Docker is not installed. See https://docs.docker.com/engine/install/"
    docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not found"
    command -v git >/dev/null 2>&1 || die "git is required to clone Daytona"
    command -v curl >/dev/null 2>&1 || die "curl is required for local verification"
    command -v openssl >/dev/null 2>&1 || die "openssl is required to generate secrets"
}

step_clone() {
    # Idempotent: clone only if the repo isn't already present.
    # This makes re-runs non-destructive and lets users pre-stage the repo
    # (e.g. for testing local changes) without needing to edit this function.
    [ -d "$REPO_DIR/.git" ] && return 0
    git clone https://github.com/daytonaio/daytona.git "$REPO_DIR"
}

step_secrets() {
    _bcrypt_hash() {
        if command -v htpasswd >/dev/null 2>&1; then
            printf '%s' "$1" | htpasswd -niBC 10 "" | cut -d: -f2
            return
        fi

        # Keep host setup untouched: if htpasswd is absent, use a short-lived Docker container.
        printf '%s' "$1" | docker run --rm -i httpd:2.4-alpine htpasswd -niBC 10 "" | cut -d: -f2
    }

    ENCRYPTION_KEY=$(openssl rand -hex 16)
    ENCRYPTION_SALT=$(openssl rand -hex 16)
    PROXY_API_KEY=$(openssl rand -hex 16)
    RUNNER_API_KEY=$(openssl rand -hex 16)
    SSH_GATEWAY_API_KEY=$(openssl rand -hex 16)
    ADMIN_PASSWORD_HASH=$(_bcrypt_hash "$ADMIN_PASSWORD")
    HEALTH_CHECK_KEY=$(openssl rand -hex 16)
    OTEL_COLLECTOR_KEY=$(openssl rand -hex 16)
}

step_dex() {
    local dir="$REPO_DIR/docker/dex"
    mkdir -p "$dir"

    # Use a quoted heredoc so $2b in the bcrypt hash isn't expanded
    cat > "$dir/config.yaml" <<'DEXEOF'
issuer: https://DOMAIN_PH/dex
storage:
  type: sqlite3
  config:
    file: /var/dex/dex.db
web:
  http: 0.0.0.0:5556
  allowedOrigins: ['*']
  allowedHeaders: ['x-requested-with']
staticClients:
  - id: daytona
    redirectURIs:
      - 'https://DOMAIN_PH'
      - 'https://DOMAIN_PH/api/oauth2-redirect.html'
      - 'https://DOMAIN_PH/callback'
      - 'https://proxy.DOMAIN_PH/callback'
    name: 'Daytona'
    public: true
enablePasswordDB: true
staticPasswords:
  - email: 'ADMIN_EMAIL_PH'
    hash: 'ADMIN_HASH_PH'
    username: 'admin'
    userID: '1234'
DEXEOF

    _file_replace "$dir/config.yaml" "DOMAIN_PH"     "$DOMAIN"
    _file_replace "$dir/config.yaml" "ADMIN_EMAIL_PH" "$ADMIN_EMAIL"
    _file_replace "$dir/config.yaml" "ADMIN_HASH_PH"  "$ADMIN_PASSWORD_HASH"
}

step_compose() {
    local cf="$REPO_DIR/docker/docker-compose.yaml"

    # Helper: replace KEY: value and - KEY=value lines in docker-compose.
    # Uses awk + ENVIRON so credential values never appear in process arguments.
    _set() {
        local key="$1" val="$2"
        _DAYTONA_VAL="$val" awk -v key="$key" '
        {
            if (match($0, "^[[:space:]]*" key ":")) {
                n = index($0, key ":")
                print substr($0, 1, n-1) key ": " ENVIRON["_DAYTONA_VAL"]
            } else if (match($0, "^[[:space:]]*-[[:space:]]*" key "=")) {
                n = index($0, key "=")
                print substr($0, 1, n-1) key "=" ENVIRON["_DAYTONA_VAL"]
            } else {
                print
            }
        }' "$cf" > "${cf}.tmp" && mv "${cf}.tmp" "$cf"
    }

    _set ENCRYPTION_KEY        "$ENCRYPTION_KEY"
    _set ENCRYPTION_SALT       "$ENCRYPTION_SALT"
    _set PROXY_DOMAIN          "proxy.$DOMAIN"
    _set PROXY_TEMPLATE_URL    "https://{{PORT}}-{{sandboxId}}.proxy.$DOMAIN"
    _set PROXY_API_KEY         "$PROXY_API_KEY"
    _set PROXY_PROTOCOL        "https"
    _set DASHBOARD_URL         "https://$DOMAIN/dashboard"
    _set DASHBOARD_BASE_API_URL "https://$DOMAIN"
    _set PUBLIC_OIDC_DOMAIN    "https://$DOMAIN/dex"
    _set SSH_GATEWAY_URL       "$DOMAIN:2222"
    _set SSH_GATEWAY_COMMAND   "ssh -p 2222 {{TOKEN}}@$DOMAIN"
    _set SSH_GATEWAY_API_KEY   "$SSH_GATEWAY_API_KEY"
    _set DEFAULT_RUNNER_API_KEY "$RUNNER_API_KEY"
    _set COOKIE_DOMAIN         "proxy.$DOMAIN"
    _set OIDC_PUBLIC_DOMAIN    "https://$DOMAIN/dex"
    _set DAYTONA_RUNNER_TOKEN  "$RUNNER_API_KEY"

    # API_KEY inside ssh-gateway section only
    # Uses ENVIRON so the key value never appears in process arguments
    _DAYTONA_VAL="$SSH_GATEWAY_API_KEY" awk '
        /^  ssh-gateway:/ { in_svc=1 }
        in_svc && /^  [a-z]/ && !/ssh-gateway:/ { in_svc=0 }
        in_svc && /API_KEY:/ {
            n = index($0, "API_KEY:")
            $0 = substr($0, 1, n-1) "API_KEY: " ENVIRON["_DAYTONA_VAL"]
        }
        in_svc && /- API_KEY=/ {
            n = index($0, "API_KEY=")
            $0 = substr($0, 1, n-1) "API_KEY=" ENVIRON["_DAYTONA_VAL"]
        }
        { print }
    ' "$cf" > "${cf}.tmp" && mv "${cf}.tmp" "$cf"

    # Dex ports
    if ! grep -q '5556:5556' "$cf"; then
        awk '
            /^  dex:/ { in_dex=1; print; next }
            in_dex && /^  [a-z]/ && !/dex:/ {
                print "    ports:"; print "      - \"5556:5556\""
                in_dex=0
            }
            { print }
        ' "$cf" > "${cf}.tmp" && mv "${cf}.tmp" "$cf"
    fi

    # Bind published ports to localhost only. Public access should go through
    # the operator's existing nginx reverse proxy, not directly to containers.
    _bind_localhost_port() {
        local host_port="$1"
        awk -v hp="$host_port" '{
            if ($0 ~ "127\\.0\\.0\\.1:" hp ":") {
                print
            } else if ($0 ~ "- \\\"?" hp ":[0-9]+") {
                sub(hp ":", "127.0.0.1:" hp ":")
                print
            } else {
                print
            }
        }' "$cf" > "${cf}.tmp" && mv "${cf}.tmp" "$cf"
    }
    for port in 3000 3003 4000 2222 5556 5050 5100 6000 1080 9001 16686; do
        _bind_localhost_port "$port"
    done

    # Update PostgreSQL credentials (db service + API service connection)
    _set POSTGRES_USER         "$DB_USER"
    _set POSTGRES_PASSWORD     "$DB_PASS"
    _set DB_USERNAME           "$DB_USER"
    _set DB_PASSWORD           "$DB_PASS"

    # Update PgAdmin credentials and enable server mode (default is desktop mode with no login)
    _set PGADMIN_DEFAULT_EMAIL    "$PGADMIN_EMAIL"
    _set PGADMIN_DEFAULT_PASSWORD "$PGADMIN_PASSWORD"
    _set PGADMIN_CONFIG_SERVER_MODE       "'True'"
    _set PGADMIN_CONFIG_MASTER_PASSWORD_REQUIRED "'True'"

    # Update MinIO credentials (also used by API and Runner for S3 access)
    _set MINIO_ROOT_USER       "$MINIO_USER"
    _set MINIO_ROOT_PASSWORD   "$MINIO_PASSWORD"
    _set S3_ACCESS_KEY         "$MINIO_USER"
    _set S3_SECRET_KEY         "$MINIO_PASSWORD"
    _set AWS_ACCESS_KEY_ID     "$MINIO_USER"
    _set AWS_SECRET_ACCESS_KEY "$MINIO_PASSWORD"

    # Update Registry credentials (transient + internal point to same registry)
    _set TRANSIENT_REGISTRY_ADMIN    "$REGISTRY_USER"
    _set TRANSIENT_REGISTRY_PASSWORD "$REGISTRY_PASSWORD"
    _set INTERNAL_REGISTRY_ADMIN     "$REGISTRY_USER"
    _set INTERNAL_REGISTRY_PASSWORD  "$REGISTRY_PASSWORD"

    # Auto-generated API keys
    _set HEALTH_CHECK_API_KEY    "$HEALTH_CHECK_KEY"
    _set OTEL_COLLECTOR_API_KEY  "$OTEL_COLLECTOR_KEY"

    # ClickHouse (optional)
    if [ "$CLICKHOUSE_ENABLED" = "true" ]; then
        _set CLICKHOUSE_HOST     "$CLICKHOUSE_HOST_VAL"
        _set CLICKHOUSE_PORT     "$CLICKHOUSE_PORT_VAL"
        _set CLICKHOUSE_DATABASE "$CLICKHOUSE_DB_VAL"
        _set CLICKHOUSE_USERNAME "$CLICKHOUSE_USER"
        _set CLICKHOUSE_PASSWORD "$CLICKHOUSE_PASS"
        _set CLICKHOUSE_PROTOCOL "$CLICKHOUSE_PROTO"
    fi

    # SELinux :z labels on bind-mount volumes — Linux only
    if [ "$OS" != "macos" ]; then
        sedi -E '/^\s*-\s*(\.\/|\/)[^:]+:[^:]+$/s/$/:z/' "$cf"
    fi

    # Restrict permissions — compose file now contains plaintext credentials
    chmod 600 "$cf"
}

step_docker_start() {
    local cf="$REPO_DIR/docker/docker-compose.yaml"

    docker compose -f "$cf" up -d

    # Wait for services (90s timeout)
    local deadline=$(( $(date +%s) + 90 ))
    for svc in api proxy dex ssh-gateway; do
        while true; do
            [ "$(date +%s)" -gt "$deadline" ] && {
                echo "Timeout waiting for $svc"
                docker compose -f "$cf" logs "$svc" --tail 10
                return 1
            }
            local state
            state=$(docker compose -f "$cf" ps --format '{{.State}}' "$svc" 2>/dev/null || true)
            case "$state" in
                running|healthy) break ;;
                exited|dead)
                    echo "Service $svc failed:"
                    docker compose -f "$cf" logs "$svc" --tail 10
                    return 1 ;;
            esac
            sleep 3
        done
    done

    # Let API finish initializing
    sleep 10
}

step_verify() {
    local cf="$REPO_DIR/docker/docker-compose.yaml"
    local passed=0 failed=0
    local code=""

    _wait_http_code() {
        local url="$1" ok_codes="$2" deadline=$(( $(date +%s) + 90 ))
        code="000"
        while true; do
            code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || true)
            case " $ok_codes " in
                *" $code "*) return 0 ;;
            esac
            [ "$(date +%s)" -gt "$deadline" ] && return 1
            sleep 3
        done
    }

    printf "\n${BOLD}  Verification Results${NC}\n\n"

    # Container health
    local all_ok=true
    for svc in api proxy dex ssh-gateway; do
        local st
        st=$(docker compose -f "$cf" ps --format '{{.State}}' "$svc" 2>/dev/null || true)
        [ "$st" = "running" ] || [ "$st" = "healthy" ] || all_ok=false
    done
    if $all_ok; then ok "Docker container health"; passed=$((passed+1))
    else fail "Docker container health"; failed=$((failed+1)); fi

    # Dex OIDC
    if curl -sf --max-time 5 "http://localhost:5556/dex/.well-known/openid-configuration" | grep -q "https://$DOMAIN/dex"; then
        ok "Dex OIDC issuer"; passed=$((passed+1))
    else fail "Dex OIDC issuer"; failed=$((failed+1)); fi

    # Local HTTP services that nginx should reverse-proxy.
    if _wait_http_code "http://127.0.0.1:3000" "200 301 302 404"; then
        ok "Local API/dashboard port 3000"; passed=$((passed+1))
    else
        fail "Local API/dashboard port 3000 (HTTP $code)"; failed=$((failed+1))
    fi

    if _wait_http_code "http://127.0.0.1:4000" "200 301 302 404"; then
        ok "Local proxy port 4000"; passed=$((passed+1))
    else
        fail "Local proxy port 4000 (HTTP $code)"; failed=$((failed+1))
    fi

    # SSH Gateway — nc for macOS, bash /dev/tcp for Linux.
    if [ "$OS" = "macos" ]; then
        if nc -z -w 5 127.0.0.1 2222 2>/dev/null; then
            ok "Local SSH Gateway port 2222"; passed=$((passed+1))
        else fail "Local SSH Gateway port 2222"; failed=$((failed+1)); fi
    else
        if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/2222" 2>/dev/null; then
            ok "Local SSH Gateway port 2222"; passed=$((passed+1))
        else fail "Local SSH Gateway port 2222"; failed=$((failed+1)); fi
    fi

    printf "\n  %d passed, %d failed\n" "$passed" "$failed"

    if [ "$failed" -eq 0 ]; then
        printf "\n${GREEN}${BOLD}  Setup complete!${NC}\n"
    else
        printf "\n${YELLOW}  Some local checks failed. Check Docker logs before configuring nginx.${NC}\n"
    fi
}

print_nginx_instructions() {
    printf "\n${BOLD}  Configure nginx${NC}\n"
    printf "  ───────────────\n"
    printf "  DNS records needed:\n"
    printf "    %s -> this server\n" "$DOMAIN"
    printf "    proxy.%s and *.proxy.%s -> this server\n" "$DOMAIN" "$DOMAIN"
    printf "    Optional: pgadmin.%s, minio.%s, registry.%s -> this server\n" "$DOMAIN" "$DOMAIN" "$DOMAIN"
    printf "\n  nginx should terminate TLS and proxy to localhost-only Docker ports:\n\n"

    cat <<NGINXEOF
# Put this map in nginx's http context if you do not already have it.
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # ssl_certificate ...;
    # ssl_certificate_key ...;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
    }

    location /dex/ {
        proxy_pass http://127.0.0.1:5556;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

server {
    listen 443 ssl http2;
    server_name proxy.$DOMAIN *.proxy.$DOMAIN;

    # ssl_certificate must cover proxy.$DOMAIN and *.proxy.$DOMAIN;
    # ssl_certificate_key ...;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}

# Optional admin tools. Restrict them with nginx auth/IP allowlists.
server { listen 443 ssl http2; server_name pgadmin.$DOMAIN;  location / { proxy_pass http://127.0.0.1:5050; proxy_set_header Host \$host; proxy_set_header X-Forwarded-Proto https; } }
server { listen 443 ssl http2; server_name minio.$DOMAIN;    location / { proxy_pass http://127.0.0.1:9001; proxy_set_header Host \$host; proxy_set_header X-Forwarded-Proto https; } }
server { listen 443 ssl http2; server_name registry.$DOMAIN; location / { proxy_pass http://127.0.0.1:5100; proxy_set_header Host \$host; proxy_set_header X-Forwarded-Proto https; } }

# Optional TCP stream proxy for Daytona SSH access:
# stream { server { listen 2222; proxy_pass 127.0.0.1:2222; } }
NGINXEOF

    printf "\n${BOLD}  Endpoints after nginx is configured${NC}\n"
    printf "  Dashboard:   https://%s\n" "$DOMAIN"
    printf "               Login: %s\n" "$ADMIN_EMAIL"
    printf "  Sandbox URLs: https://<port>-<sandbox-id>.proxy.%s\n" "$DOMAIN"
    printf "  SSH Gateway: %s:2222, if you enable the nginx stream proxy\n" "$DOMAIN"
    printf "  PgAdmin:     https://pgadmin.%s\n" "$DOMAIN"
    printf "  MinIO:       https://minio.%s\n" "$DOMAIN"
    printf "  Registry UI: https://registry.%s\n" "$DOMAIN"
    printf "\n"
}

# ── Main ────────────────────────────────────────────────────
main() {
    detect_platform
    collect_input

    printf "\n${BOLD}  Setting up Daytona...${NC}\n\n"

    run_step "Cleaning previous installation"    step_clean
    run_step "Checking prerequisites"            step_prerequisites
    run_step "Cloning Daytona repository"        step_clone
    run_step "Generating security credentials"   step_secrets
    run_step "Configuring Dex OIDC provider"     step_dex
    run_step "Configuring Docker Compose"        step_compose
    run_step "Starting Docker services"          step_docker_start

    # Pull sandbox image with visible progress (blocking — sandboxes won't work without it)
    printf "  ${CYAN}▸${NC} Pulling sandbox image (this may take a few minutes)\n"
    if docker pull daytonaio/sandbox:0.5.0-slim; then
        printf "  ${GREEN}✓${NC} Sandbox image ready\n"
    else
        printf "  ${RED}✗${NC} Failed to pull sandbox image — sandbox creation will download it on first use\n"
    fi

    step_verify
    print_nginx_instructions
}

main "$@"
