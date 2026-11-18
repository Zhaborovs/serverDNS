#!/usr/bin/env bash
# ==============================================================================
# Модуль 06: AmneziaWG (AWG 2.0+ с обфускацией, CPS-сигнатурами и локальным DNS)
# ------------------------------------------------------------------------------
# Назначение:
#   - Установка wireguard-tools + актуальных amneziawg/amneziawg-go с GitHub/PPA
#   - Развертывание на случайном высоком UDP-порту (${AWG_PORT})
#   - Автогенерация параметров AWG 2.0+ и создание клиента 'default'
#   - Настройка маршрутизации DNS клиентов через локальный AdGuard Home (${AWG_SERVER_IP})
#   - Выдача .conf, нативного vpn:// URI и QR-кода для приложения AmneziaVPN
# Входные переменные (state.env):
#   SERVER_IP, AWG_VERSION, AWG_PORT, AWG_SUBNET, AWG_SERVER_IP, AWG_INTERFACE
# Выходные артефакты:
#   /etc/amnezia/amneziawg/${AWG_INTERFACE}.conf,
#   /etc/server-combain/awg/registry.json, /etc/server-combain/clients/awg_*.conf/.vpn
# ==============================================================================

AWG_DIR="/etc/amnezia/amneziawg"
AWG_REGISTRY="${STATE_DIR}/awg/registry.json"

_awg_install_binaries() {
    export DEBIAN_FRONTEND=noninteractive

    if command -v awg &>/dev/null && command -v amneziawg-go &>/dev/null; then
        log_ok "Бинарники AmneziaWG уже установлены."
        return 0
    fi

    apt-get install -y wireguard-tools resolvconf >/dev/null 2>&1 || apt-get install -y wireguard-tools >/dev/null 2>&1 || true

    # 1. Пробуем поставить нативный пакет amneziawg из официального PPA (быстрее ядерный модуль)
    if ! command -v awg &>/dev/null; then
        log_info "Подключение PPA amnezia/ppa для установки amneziawg-tools и модуля..."
        add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y amneziawg amneziawg-tools >/dev/null 2>&1 || apt-get install -y amneziawg-tools >/dev/null 2>&1 || true
    fi

    # 2. Всегда держим актуальный userspace amneziawg-go как надежный fallback для LXC/VPS без kernel headers
    if ! command -v amneziawg-go &>/dev/null; then
        local arch tag dl_url
        case "$(uname -m)" in
            x86_64|amd64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) arch="amd64" ;;
        esac
        tag="$(fetch_latest_github_release "amnezia-vpn/amneziawg-go" "latest")"
        log_info "Проверка/загрузка amneziawg-go (${tag}, ${arch})..."
        dl_url="$(curl -fsSL --max-time 10 "https://api.github.com/repos/amnezia-vpn/amneziawg-go/releases/latest" 2>/dev/null \
            | jq -r --arg arch "$arch" '.assets[]?.browser_download_url | select(contains("linux") and contains($arch))' | head -n1 || true)"
        if [[ -n "$dl_url" ]]; then
            local tmp_dir="/tmp/awg_go_dl"
            rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
            curl -fsSL "$dl_url" -o "${tmp_dir}/awg.archive"
            tar -xf "${tmp_dir}/awg.archive" -C "$tmp_dir" 2>/dev/null || unzip -q "${tmp_dir}/awg.archive" -d "$tmp_dir" 2>/dev/null || true
            local bin_found
            bin_found="$(find "$tmp_dir" -type f -name "amneziawg-go*" | head -n1 || true)"
            if [[ -n "$bin_found" ]]; then
                install -m 0755 "$bin_found" /usr/local/bin/amneziawg-go
                log_ok "Userspace amneziawg-go установлен в /usr/local/bin/amneziawg-go."
            fi
            rm -rf "$tmp_dir"
        fi
    fi
}

_awg_up_interface() {
    local iface="${AWG_INTERFACE:-awg0}"
    local conf_file="${AWG_DIR}/${iface}.conf"

    if command -v awg-quick &>/dev/null; then
        # Если ядерный модуль не загрузился — автоматически переключаем awg-quick в userspace amneziawg-go
        if ! modprobe amneziawg 2>/dev/null; then
            export WG_QUICK_USERSPACE_IMPLEMENTATION="amneziawg-go"
            mkdir -p /etc/systemd/system/awg-quick@${iface}.service.d
            cat > /etc/systemd/system/awg-quick@${iface}.service.d/userspace.conf <<'EOF'
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
EOF
            systemctl daemon-reload
        fi
        awg-quick down "$iface" >/dev/null 2>&1 || true
        awg-quick up "$iface"
        systemctl enable "awg-quick@${iface}" >/dev/null 2>&1 || true
        log_ok "Интерфейс AmneziaWG (${iface}) поднят через awg-quick."
    elif command -v wg-quick &>/dev/null; then
        export WG_QUICK_USERSPACE_IMPLEMENTATION="amneziawg-go"
        wg-quick down "$conf_file" >/dev/null 2>&1 || true
        wg-quick up "$conf_file" || log_warn "Проверьте поддержку userspace amneziawg-go на данном ядре."
    else
        log_warn "Не найден awg-quick/wg-quick — конфиг сгенерирован в ${conf_file}, установите awg-tools вручную."
    fi
}

mod_amneziawg_setup() {
    log_step "Модуль 06: Установка и настройка AmneziaWG (AWG 2.0+)"
    state_load_silent

    local iface="${AWG_INTERFACE:-awg0}"
    local conf_file="${AWG_DIR}/${iface}.conf"

    _awg_install_binaries

    python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" init-server \
        --registry "$AWG_REGISTRY" \
        --server-conf "$conf_file" \
        --interface "$iface" \
        --subnet "${AWG_SUBNET:-10.8.1.0/24}" \
        --dns-ip "${AWG_SERVER_IP:-10.8.1.1}" \
        --endpoint-ip "${SERVER_IP}" \
        --port "${AWG_PORT}"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" add-client "default" \
        --registry "$AWG_REGISTRY" \
        --server-conf "$conf_file" \
        --clients-dir "${STATE_DIR}/clients"

    _awg_up_interface
    log_ok "Модуль 06 завершен: AmneziaWG активен на порту ${AWG_PORT}/udp, профиль default создан."
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

    _awg_up_interface

    local vpn_file="${STATE_DIR}/clients/awg_${client_name}.vpn"
    local c_conf="${STATE_DIR}/clients/awg_${client_name}.conf"
    echo ""
    echo -e "${GREEN}Готовый .conf файл:${NC} ${c_conf}"
    if [[ -f "$vpn_file" ]]; then
        local vpn_uri
        vpn_uri="$(cat "$vpn_file")"
        echo -e "${GREEN}Ссылка для импорта в AmneziaVPN (vpn://):${NC}"
        echo "$vpn_uri"
        echo ""
        echo -e "${CYAN}QR-код AmneziaWG (${client_name}):${NC}"
        print_qr_if_available "$vpn_uri"
    fi
}
