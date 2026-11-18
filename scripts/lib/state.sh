#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Управление состоянием (/etc/server-combain/state.env)
# ==============================================================================

STATE_DIR="/etc/server-combain"
STATE_FILE="${STATE_DIR}/state.env"
BACKUP_DIR="/var/backups/server-combain"

state_ensure_dirs() {
    mkdir -p "$STATE_DIR" "$BACKUP_DIR" "${STATE_DIR}/clients" "${STATE_DIR}/awg"
    chmod 700 "$STATE_DIR" "$BACKUP_DIR"
}

state_load_silent() {
    state_ensure_dirs
    set -a
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
    elif [[ -f "${PROJECT_ROOT}/config/default.env.example" ]]; then
        # shellcheck disable=SC1090
        source "${PROJECT_ROOT}/config/default.env.example"
    fi
    set +a
}

# Безопасная запись/обновление ключа в state.env
state_set() {
    local key="$1"
    local val="$2"
    state_ensure_dirs
    if [[ ! -f "$STATE_FILE" ]]; then
        cp "${PROJECT_ROOT}/config/default.env.example" "$STATE_FILE"
        chmod 600 "$STATE_FILE"
    fi
    if grep -qE "^${key}=" "$STATE_FILE"; then
        # Экранируем спецсимволы для sed
        local escaped_val
        escaped_val="$(printf '%s\n' "$val" | sed -e 's/[\/&]/\\&/g')"
        sed -i "s/^${key}=.*/${key}=\"${escaped_val}\"/" "$STATE_FILE"
    else
        echo "${key}=\"${val}\"" >> "$STATE_FILE"
    fi
    export "${key}=${val}"
}

# Интерактивный опрос параметров домена, DNS-режима и генерация случайных секретов
state_init_interactive() {
    state_load_silent
    local detected_ip
    detected_ip="$(detect_server_ip)"

    echo ""
    echo -e "${BOLD}=== Шаг 1. Настройка домена и IP ===${NC}"
    echo -e "Обнаружен внешний IPv4 сервера: ${GREEN}${detected_ip}${NC}"
    state_set "SERVER_IP" "$detected_ip"

    local input_domain
    read -rp "Введите основной домен сервера [${BASE_DOMAIN:-example.com}]: " input_domain
    input_domain="${input_domain:-${BASE_DOMAIN:-}}"
    if [[ -z "$input_domain" ]]; then
        log_err "Домен обязателен для работы TLS/DoH/CDN."
        return 1
    fi
    state_set "BASE_DOMAIN" "$input_domain"

    echo ""
    echo "Выберите доменную схему (для минимизации следов в публичных логах crt.sh):"
    echo "  1) Раздельная (рекомендуется): ${input_domain} (заглушка/3x-ui/CDN) + dns.${input_domain} (AdGuard DoH/DoT)"
    echo "  2) Единый домен: всё работает только на ${input_domain}"
    echo "  3) Wildcard-сертификат: *.${input_domain} + ${input_domain}"
    read -rp "Ваш выбор [1-3, по умолч. 1]: " d_mode
    case "${d_mode:-1}" in
        2)
            state_set "DOMAIN_MODE" "single"
            state_set "DNS_DOMAIN" "$input_domain"
            ;;
        3)
            state_set "DOMAIN_MODE" "wildcard"
            state_set "DNS_DOMAIN" "dns.${input_domain}"
            state_set "SSL_METHOD" "dns_manual_wildcard"
            ;;
        *)
            state_set "DOMAIN_MODE" "split"
            state_set "DNS_DOMAIN" "dns.${input_domain}"
            ;;
    esac

    local input_email
    read -rp "Введите Email для Let's Encrypt уведомлений [${CERT_EMAIL:-admin@${input_domain}}]: " input_email
    state_set "CERT_EMAIL" "${input_email:-admin@${input_domain}}"

    # Генерация случайных портов, путей и секретов при первом запуске
    [[ -z "${XUI_INTERNAL_PORT:-}" ]]   && state_set "XUI_INTERNAL_PORT" "$(gen_random_free_port 21000 28000)"
    [[ -z "${AGH_CUSTOM_DOT_PORT:-}" ]] && state_set "AGH_CUSTOM_DOT_PORT" "$(gen_random_free_port 8850 9850)"
    [[ -z "${AWG_PORT:-}" ]]            && state_set "AWG_PORT" "$(gen_random_free_port 32000 54000)"
    [[ -z "${MTPROTO_PORT:-}" ]]        && state_set "MTPROTO_PORT" "$(gen_random_free_port 18000 20000)"
    [[ -z "${SOCKS5_PORT:-}" ]]         && state_set "SOCKS5_PORT" "$(gen_random_free_port 10800 17999)"

    [[ -z "${SECRET_PANEL_PATH:-}" ]]   && state_set "SECRET_PANEL_PATH" "adm-$(gen_random_str 10)"
    [[ -z "${XHTTP_VK_PATH:-}" ]]       && state_set "XHTTP_VK_PATH" "api-vk-$(gen_random_str 8)"
    [[ -z "${WS_VK_PATH:-}" ]]          && state_set "WS_VK_PATH" "ws-vk-$(gen_random_str 8)"
    [[ -z "${XHTTP_YA_PATH:-}" ]]       && state_set "XHTTP_YA_PATH" "api-ya-$(gen_random_str 8)"
    [[ -z "${WS_YA_PATH:-}" ]]          && state_set "WS_YA_PATH" "ws-ya-$(gen_random_str 8)"
    [[ -z "${BACKUP_DROP_PATH:-}" ]]    && state_set "BACKUP_DROP_PATH" "drop-$(gen_random_str 14)"

    [[ -z "${PANEL_USER:-}" ]]          && state_set "PANEL_USER" "admin_$(gen_random_str 4)"
    [[ -z "${PANEL_PASS:-}" ]]          && state_set "PANEL_PASS" "$(gen_random_str 18)"
    [[ -z "${AGH_USER:-}" ]]            && state_set "AGH_USER" "dnsadmin"
    [[ -z "${AGH_PASS:-}" ]]            && state_set "AGH_PASS" "$(gen_random_str 18)"
    [[ -z "${SOCKS5_PASS:-}" ]]         && state_set "SOCKS5_PASS" "$(gen_random_str 16)"

    echo ""
    echo -e "${BOLD}=== Настройка логинов и паролей (Enter = оставить автогенерацию) ===${NC}"
    local in_val
    read -rp "Логин AdGuard Home [${AGH_USER}]: " in_val
    [[ -n "$in_val" ]] && state_set "AGH_USER" "$in_val"
    read -rp "Пароль AdGuard Home [${AGH_PASS}]: " in_val
    [[ -n "$in_val" ]] && state_set "AGH_PASS" "$in_val"

    read -rp "Логин панели 3x-ui [${PANEL_USER}]: " in_val
    [[ -n "$in_val" ]] && state_set "PANEL_USER" "$in_val"
    read -rp "Пароль панели 3x-ui [${PANEL_PASS}]: " in_val
    [[ -n "$in_val" ]] && state_set "PANEL_PASS" "$in_val"

    # Подсказка пользователю по DNS-записям
    echo ""
    log_info "Убедитесь, что у регистратора прописаны следующие A-записи:"
    echo -e "  * ${GREEN}${BASE_DOMAIN}${NC} -> ${BOLD}${SERVER_IP}${NC}"
    if [[ "${DNS_DOMAIN}" != "${BASE_DOMAIN}" ]]; then
        echo -e "  * ${GREEN}${DNS_DOMAIN}${NC} -> ${BOLD}${SERVER_IP}${NC}"
    fi
    if ! verify_domain_a_record "$BASE_DOMAIN" "$SERVER_IP"; then
        log_warn "Домен ${BASE_DOMAIN} пока не резолвится на ${SERVER_IP} (возможно, DNS еще обновляется)."
        read -rp "Продолжить после настройки DNS или нажать Enter для проверки еще раз? [y/N]: " ans
        if [[ "${ans,,}" != "y" ]]; then
            log_warn "Ожидаем обновления DNS-записей перед выпуском SSL."
        fi
    else
        log_ok "DNS-запись ${BASE_DOMAIN} -> ${SERVER_IP} подтверждена!"
    fi
}
