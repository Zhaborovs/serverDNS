#!/usr/bin/env bash
# ==============================================================================
# Модуль 06: AmneziaWG 3.1 (официальный Docker-образ amneziavpn/amneziawg-go:latest)
# ------------------------------------------------------------------------------
# Назначение:
#   - Отключение устаревших хостовых интерфейсов awg0 от PPA (AWG 1.0 Legacy)
#   - Инициализация серверного конфига /etc/amnezia/amneziawg/awg0.conf в формате AWG 3.1
#   - Автогенерация параметров обфускации 3.1 (HeaderProtectionKey, S1-S4, H1-H4, I1)
#   - Запуск официального контейнера combain-awg (amneziavpn/amneziawg-go:latest)
#   - Интеграция DNS клиентов с локальным AdGuard Home (${AWG_SERVER_IP})
#   - Генерация .conf и нативного vpn:// URI (с корректным JSON в last_config)
# ==============================================================================

AWG_DIR="/etc/amnezia/amneziawg"
AWG_REGISTRY="${STATE_DIR}/awg/registry.json"

_awg_stop_legacy_host_iface() {
    local iface="${AWG_INTERFACE:-awg0}"
    if systemctl is-active --quiet "awg-quick@${iface}" 2>/dev/null || ip link show "$iface" &>/dev/null; then
        log_info "Остановка старого интерфейса ${iface} перед запуском контейнера AmneziaWG 3.1..."
        systemctl disable --now "awg-quick@${iface}" >/dev/null 2>&1 || true
        awg-quick down "$iface" >/dev/null 2>&1 || true
        ip link delete "$iface" >/dev/null 2>&1 || true
    fi
}

_awg_start_container() {
    state_load_silent
    _awg_stop_legacy_host_iface

    if declare -f _render_docker_compose >/dev/null 2>&1; then
        _render_docker_compose
    fi

    log_info "Запуск официального контейнера AmneziaWG 3.1 (amneziavpn/amneziawg-go:latest)..."
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" pull amnezia-awg >/dev/null 2>&1 || true
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d --force-recreate amnezia-awg

    sleep 2
    if docker ps --format '{{.Names}}' | grep -q '^combain-awg$' && ip link show "${AWG_INTERFACE:-awg0}" &>/dev/null; then
        log_ok "Контейнер combain-awg (AmneziaWG 3.1) успешно запущен, интерфейс ${AWG_INTERFACE:-awg0} активен."
    else
        log_warn "Проверьте логи контейнера AmneziaWG: docker logs combain-awg"
    fi
}

mod_amneziawg_setup() {
    log_step "Модуль 06: Установка и настройка AmneziaWG 3.1 (amneziavpn/amneziawg-go:latest)"
    state_load_silent

    local iface="${AWG_INTERFACE:-awg0}"
    local conf_file="${AWG_DIR}/${iface}.conf"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" init-server \
        --registry "$AWG_REGISTRY" \
        --server-conf "$conf_file" \
        --clients-dir "${STATE_DIR}/clients" \
        --interface "$iface" \
        --subnet "${AWG_SUBNET:-10.8.1.0/24}" \
        --dns-ip "${AWG_SERVER_IP:-10.8.1.1}" \
        --endpoint-ip "${SERVER_IP}" \
        --port "${AWG_PORT}"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" add-client "default" \
        --registry "$AWG_REGISTRY" \
        --server-conf "$conf_file" \
        --clients-dir "${STATE_DIR}/clients"

    _awg_start_container
    log_ok "Модуль 06 завершен: AmneziaWG 3.1 работает на порту ${AWG_PORT}/udp, профиль default обновлен."
}

mod_amneziawg_add_client() {
    state_load_silent
    local iface="${AWG_INTERFACE:-awg0}"
    local conf_file="${AWG_DIR}/${iface}.conf"
    local client_name
    read -rp "Введите имя нового клиента AmneziaWG (напр. phone, laptop): " client_name
    client_name="${client_name:-client_$(gen_random_str 4)}"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" add-client "$client_name" \
        --registry "$AWG_REGISTRY" \
        --server-conf "$conf_file" \
        --clients-dir "${STATE_DIR}/clients"

    _awg_start_container

    local vpn_file="${STATE_DIR}/clients/awg_${client_name}.vpn"
    local c_conf="${STATE_DIR}/clients/awg_${client_name}.conf"
    echo ""
    echo -e "${GREEN}Готовый .conf файл (AWG 3.1):${NC} ${c_conf}"
    if [[ -f "$vpn_file" ]]; then
        local vpn_uri
        vpn_uri="$(cat "$vpn_file")"
        echo -e "${GREEN}Ссылка для импорта в AmneziaVPN (vpn://):${NC}"
        echo "$vpn_uri"
        echo ""
        echo -e "${CYAN}QR-код AmneziaWG 3.1 (${client_name}):${NC}"
        print_qr_if_available "$vpn_uri"
    fi
}
