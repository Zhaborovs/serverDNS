#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Общие утилиты, логирование, определение IP и версий релизов
# ==============================================================================

# Цветовая палитра терминала
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "\n${BOLD}${BLUE}==> $*${NC}"; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_err "Требуются права суперпользователя (root)."
        exit 1
    fi
}

# Динамическое определение текущего внешнего IPv4 сервера
detect_server_ip() {
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
    if [[ -z "$ip" ]]; then
        ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    fi
    echo "$ip"
}

# Генерация случайной безопасной алфавитно-цифровой строки заданной длины
gen_random_str() {
    local length="${1:-16}"
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$length" || true
}

# Генерация случайного свободного TCP/UDP порта в заданном диапазоне
gen_random_free_port() {
    local min_port="${1:-10000}"
    local max_port="${2:-60000}"
    local candidate
    for _ in $(seq 1 50); do
        candidate="$(shuf -i "${min_port}-${max_port}" -n 1)"
        if ! ss -tuln | awk '{print $5}' | grep -qE ":${candidate}$"; then
            echo "$candidate"
            return 0
        fi
    done
    echo "$min_port"
}

# Динамическое получение последнего стабильного тега релиза с GitHub API (без хардкода)
fetch_latest_github_release() {
    local repo="$1" # формат: owner/repo
    local fallback="${2:-latest}"
    local tag
    tag="$(curl -fsSL --max-time 10 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true)"
    if [[ -n "$tag" ]]; then
        echo "$tag"
    else
        echo "$fallback"
    fi
}

# Проверка, что домен указывает на указанный IPv4
verify_domain_a_record() {
    local domain="$1"
    local expected_ip="$2"
    local resolved_ip
    resolved_ip="$(dig +short A "$domain" @1.1.1.1 2>/dev/null | tail -n1 || true)"
    [[ "$resolved_ip" == "$expected_ip" ]]
}

# Проверка успешности вывода QR-кода в консоль
print_qr_if_available() {
    local payload="$1"
    if command -v qrencode &>/dev/null && [[ -n "$payload" ]]; then
        echo "$payload" | qrencode -t ANSIUTF8
    fi
}
