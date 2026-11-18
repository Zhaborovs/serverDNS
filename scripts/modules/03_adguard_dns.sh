#!/usr/bin/env bash
# ==============================================================================
# Модуль 03: AdGuard Home (DoH / DoT / DoQ + нестандартный порт + Geo-правила)
# ------------------------------------------------------------------------------
# Назначение:
#   - Динамическая загрузка актуального стабильного релиза AdGuard Home с GitHub
#   - Регистрация systemd-сервиса, копирование сертификатов (cp -L, chmod 600)
#   - Настройка внутреннего DoH (127.0.0.1:8444), DoT/DoQ (853 + нестандартный порт)
#   - Применение пресета доменов геоблока через agh_config_manager.py
#     СТРОГО при остановленном сервисе AdGuardHome!
# Входные переменные (state.env):
#   SERVER_IP, BASE_DOMAIN, DNS_DOMAIN, AGH_VERSION, AGH_INTERNAL_HTTPS_PORT,
#   AGH_DOT_PORT, AGH_CUSTOM_DOT_PORT, AGH_USER, AGH_PASS
# Выходные артефакты:
#   /opt/AdGuardHome/AdGuardHome, /opt/AdGuardHome/AdGuardHome.yaml
# Зависимости: scripts/py_helpers/agh_config_manager.py, config/presets/geo_domains.list
# ==============================================================================

AGH_DIR="/opt/AdGuardHome"
AGH_BIN="${AGH_DIR}/AdGuardHome"
AGH_CFG="${AGH_DIR}/AdGuardHome.yaml"
CUSTOM_DOMAINS_FILE="${STATE_DIR}/custom_geo_domains.list"
EXCLUDED_DOMAINS_FILE="${STATE_DIR}/excluded_geo_domains.list"

_agh_detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "amd64" ;;
    esac
}

_agh_sync_certs() {
    local cert_live="/etc/letsencrypt/live/${BASE_DOMAIN}"
    if [[ -f "${cert_live}/fullchain.pem" && -f "${cert_live}/privkey.pem" ]]; then
        mkdir -p "$AGH_DIR"
        cp -L "${cert_live}/fullchain.pem" "${AGH_DIR}/fullchain.pem"
        cp -L "${cert_live}/privkey.pem" "${AGH_DIR}/privkey.pem"
        chmod 600 "${AGH_DIR}/privkey.pem"
        log_ok "SSL-сертификаты скопированы в ${AGH_DIR} (cp -L)."
    else
        log_warn "Сертификаты Let's Encrypt в ${cert_live} не найдены."
    fi
}

_agh_install_or_update_binary() {
    local target_ver="$1"
    local arch
    arch="$(_agh_detect_arch)"
    local download_url
    if [[ "$target_ver" == "latest" ]]; then
        download_url="https://github.com/AdguardTeam/AdGuardHome/releases/latest/download/AdGuardHome_linux_${arch}.tar.gz"
    else
        download_url="https://github.com/AdguardTeam/AdGuardHome/releases/download/${target_ver}/AdGuardHome_linux_${arch}.tar.gz"
    fi

    if [[ -x "$AGH_BIN" ]]; then
        log_ok "Бинарник AdGuard Home уже установлен в ${AGH_BIN}."
        return 0
    fi

    log_info "Загрузка AdGuard Home (${target_ver}, ${arch})..."
    local tmp_tgz="/tmp/AdGuardHome.tar.gz"
    curl -fsSL "$download_url" -o "$tmp_tgz"
    mkdir -p /opt
    tar -xzf "$tmp_tgz" -C /opt
    rm -f "$tmp_tgz"

    chmod +x "$AGH_BIN"
    "$AGH_BIN" -s install >/dev/null 2>&1 || true
    log_ok "AdGuard Home установлен и зарегистрирован как сервис."
}

_agh_stop_safe() {
    if [[ -x "$AGH_BIN" ]]; then
        "$AGH_BIN" -s stop >/dev/null 2>&1 || systemctl stop AdGuardHome >/dev/null 2>&1 || true
    fi
}

_agh_start_safe() {
    if [[ -x "$AGH_BIN" ]]; then
        "$AGH_BIN" -s start >/dev/null 2>&1 || systemctl start AdGuardHome
    fi
}

mod_adguard_dns_setup() {
    log_step "Модуль 03: Установка и настройка AdGuard Home (latest)"
    state_load_silent

    local resolved_ver
    if [[ "${AGH_VERSION:-latest}" == "latest" ]]; then
        resolved_ver="$(fetch_latest_github_release "AdguardTeam/AdGuardHome" "latest")"
    else
        resolved_ver="${AGH_VERSION}"
    fi
    log_info "Целевая версия AdGuard Home: ${resolved_ver}"

    _agh_install_or_update_binary "$resolved_ver"
    _agh_stop_safe
    _agh_sync_certs

    touch "$CUSTOM_DOMAINS_FILE" "$EXCLUDED_DOMAINS_FILE"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" init-config \
        --config "$AGH_CFG" \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$CUSTOM_DOMAINS_FILE" \
        --excluded "$EXCLUDED_DOMAINS_FILE" \
        --ip "${SERVER_IP}" \
        --dns-domain "${DNS_DOMAIN}" \
        --https-port "${AGH_INTERNAL_HTTPS_PORT:-8444}" \
        --dot-port "${AGH_DOT_PORT:-853}" \
        --user "${AGH_USER:-dnsadmin}" \
        --password "${AGH_PASS:-}"

    _agh_start_safe
    fw_setup_dot_redirect "${AGH_CUSTOM_DOT_PORT:-}"
    log_ok "Модуль 03 завершен: AdGuard Home работает (DoH 127.0.0.1:${AGH_INTERNAL_HTTPS_PORT}, DoT 853 и ${AGH_CUSTOM_DOT_PORT:-853})."
}

mod_adguard_apply_geo_preset() {
    state_load_silent
    log_info "Применение пресета доменов к AdGuardHome.yaml..."
    _agh_stop_safe
    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" apply-preset \
        --config "$AGH_CFG" \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$CUSTOM_DOMAINS_FILE" \
        --excluded "$EXCLUDED_DOMAINS_FILE" \
        --ip "${SERVER_IP}"
    _agh_start_safe
}

mod_adguard_add_domain_interactive() {
    state_load_silent
    local domain
    read -rp "Введите домен для добавления в обход геоблока (напр. example.com): " domain
    [[ -z "$domain" ]] && return 0

    _agh_stop_safe
    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" add-domain \
        --config "$AGH_CFG" \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$CUSTOM_DOMAINS_FILE" \
        --excluded "$EXCLUDED_DOMAINS_FILE" \
        --ip "${SERVER_IP}" \
        --domain "$domain"
    _agh_start_safe
    log_ok "Домен ${domain} добавлен в AdGuard Home."
}

mod_adguard_remove_domain_interactive() {
    state_load_silent
    local domain
    read -rp "Введите домен для удаления из обхода геоблока: " domain
    [[ -z "$domain" ]] && return 0

    _agh_stop_safe
    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" remove-domain \
        --config "$AGH_CFG" \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$CUSTOM_DOMAINS_FILE" \
        --excluded "$EXCLUDED_DOMAINS_FILE" \
        --ip "${SERVER_IP}" \
        --domain "$domain"
    _agh_start_safe
    log_ok "Домен ${domain} удален из AdGuard Home."
}

mod_adguard_list_domains() {
    log_info "Активный итоговый список доменов обхода геоблока:"
    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" list-effective \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$CUSTOM_DOMAINS_FILE" \
        --excluded "$EXCLUDED_DOMAINS_FILE"
}
