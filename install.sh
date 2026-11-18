#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Первичный установщик зависимостей и инициализатор проекта
# Поддерживаемая ОС: Ubuntu 24.04 LTS (запуск от root)
# ==============================================================================
set -Eeuo pipefail

PROJECT_DIR="/opt/server-combain"
BIN_LINK="/usr/local/bin/combain"
DEFAULT_REPO_URL="https://github.com/Zhaborovs/serverDNS.git"
REPO_URL="${COMBAIN_REPO_URL:-$DEFAULT_REPO_URL}"

# Определяем директорию, откуда запущен install.sh (локальный клон или curl | bash)
SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
LOCAL_ROOT=""
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
    LOCAL_ROOT="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
fi

log_info() { echo -e "\033[1;36m[INFO]\033[0m $*"; }
log_ok()   { echo -e "\033[1;32m[OK]\033[0m $*"; }
log_warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_err()  { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

check_root_and_os() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_err "Установщик должен запускаться от имени root (sudo -i)."
        exit 1
    fi

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        if [[ "${ID:-}" != "ubuntu" ]]; then
            log_warn "Обнаружена ОС: ${PRETTY_NAME:-unknown}. Проект тестировался на Ubuntu 24.04 LTS."
        fi
    fi
}

install_base_dependencies() {
    log_info "Обновление списков пакетов и установка базовых зависимостей..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        curl wget git jq unzip tar gzip openssl gettext-base \
        python3 python3-pip python3-yaml python3-bcrypt apache2-utils \
        dnsutils net-tools iproute2 iptables iptables-persistent \
        qrencode certbot sniproxy software-properties-common ca-certificates gnupg

    # Установка Docker Engine и Compose Plugin из официального репозитория при отсутствии
    if ! command -v docker &>/dev/null; then
        log_info "Установка актуального Docker Engine и Docker Compose..."
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        # shellcheck disable=SC1091
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -y
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        systemctl enable --now docker
    else
        log_ok "Docker уже установлен: $(docker --version)"
    fi
}

deploy_project_files() {
    if [[ -n "$LOCAL_ROOT" && -f "${LOCAL_ROOT}/combain.sh" ]]; then
        if [[ "$LOCAL_ROOT" != "$PROJECT_DIR" ]]; then
            log_info "Синхронизация файлов проекта в ${PROJECT_DIR}..."
            mkdir -p "$PROJECT_DIR"
            cp -a "${LOCAL_ROOT}/." "$PROJECT_DIR/"
        fi
    elif [[ -n "$REPO_URL" ]]; then
        log_info "Клонирование репозитория ${REPO_URL} в ${PROJECT_DIR}..."
        if [[ -d "${PROJECT_DIR}/.git" ]]; then
            git -C "$PROJECT_DIR" pull --ff-only
        else
            git clone "$REPO_URL" "$PROJECT_DIR"
        fi
    else
        log_err "Запустите install.sh из директории репозитория или задайте COMBAIN_REPO_URL."
        exit 1
    fi

    # Приведение прав на исполняемые скрипты и очистка возможных CRLF
    if [[ -d "${PROJECT_DIR}/.git" ]]; then
        git -C "$PROJECT_DIR" config core.fileMode false || true
    fi
    find "$PROJECT_DIR" -type f \( -name "*.sh" -o -name "*.py" \) -exec sed -i 's/\r$//' {} +
    chmod +x "${PROJECT_DIR}/install.sh" "${PROJECT_DIR}/combain.sh"
    find "${PROJECT_DIR}/scripts" -type f -name "*.sh" -exec chmod +x {} +
    find "${PROJECT_DIR}/scripts/py_helpers" -type f -name "*.py" -exec chmod +x {} +

    ln -sf "${PROJECT_DIR}/combain.sh" "$BIN_LINK"
    log_ok "Команда 'combain' зарегистрирована в ${BIN_LINK}."
}

main() {
    check_root_and_os
    install_base_dependencies
    deploy_project_files
    log_ok "Базовая подготовка завершена! Запускайте мастер настройки командой: combain"
}

main "$@"
