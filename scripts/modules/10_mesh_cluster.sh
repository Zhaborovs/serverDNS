#!/usr/bin/env bash
# ==============================================================================
# Модуль 10: Кластер Combain-Mesh (P2P-сеть, WireGuard wg-mesh0, пользователи)
# ------------------------------------------------------------------------------
# Назначение:
#   - Инициализация ноды кластера Combain-Mesh (роль exit или ru_relay)
#   - Настройка приватной P2P-сети WireGuard (wg-mesh0, 10.99.0.0/24)
#   - Изолированные правила фаервола в цепочке COMBAIN-PROTECT
#   - Установка и запуск systemd-сервиса combain-mesh.service
#   - Подключение соседних нод (join-peer) и синхронизация состояния (sync-now)
#   - Управление пользователями и персональными подписками (/u/, /u-json/, bootstrap)
#   - Генерация шаблона каскада RU-Relay -> Exit поверх wg-mesh0
# ==============================================================================

MESH_IFACE="wg-mesh0"
MESH_WG_CONF="/etc/wireguard/${MESH_IFACE}.conf"
MESH_SERVICE_PATH="/etc/systemd/system/combain-mesh.service"

_mesh_py_bin() {
    echo "${PROJECT_ROOT}/scripts/mesh/combain_mesh.py"
}

_mesh_require_cli() {
    local py_bin
    py_bin="$(_mesh_py_bin)"
    if [[ ! -f "$py_bin" ]]; then
        log_err "Не найден скрипт Combain-Mesh: ${py_bin}"
        return 1
    fi
    return 0
}

_mesh_ensure_dirs() {
    mkdir -p "${STATE_DIR}/mesh" /etc/wireguard
    chmod 700 "${STATE_DIR}/mesh"
}

# Применение правил фаервола строго внутри изолированной цепочки COMBAIN-PROTECT
_mesh_apply_firewall() {
    state_load_silent
    local chain="COMBAIN-PROTECT"
    local wg_port="${MESH_WG_PORT:-51829}"
    local api_port="${MESH_API_PORT:-22777}"

    # Убеждаемся, что цепочка COMBAIN-PROTECT существует и подключена к INPUT
    iptables -N "$chain" 2>/dev/null || true
    if ! iptables -C INPUT -j "$chain" 2>/dev/null; then
        iptables -I INPUT 1 -j "$chain"
    fi
    if ! iptables -C "$chain" -j RETURN 2>/dev/null; then
        iptables -A "$chain" -j RETURN
    fi

    # Вставляем правила в начало цепочки COMBAIN-PROTECT (до -j RETURN) в обратном порядке,
    # чтобы ACCEPT для lo и wg-mesh0 всегда срабатывали раньше DROP для остальных интерфейсов.
    if ! iptables -C "$chain" -p tcp --dport "$api_port" -j DROP 2>/dev/null; then
        iptables -I "$chain" 1 -p tcp --dport "$api_port" -j DROP
    fi
    if ! iptables -C "$chain" -i "$MESH_IFACE" -p tcp --dport "$api_port" -j ACCEPT 2>/dev/null; then
        iptables -I "$chain" 1 -i "$MESH_IFACE" -p tcp --dport "$api_port" -j ACCEPT
    fi
    if ! iptables -C "$chain" -i lo -p tcp --dport "$api_port" -j ACCEPT 2>/dev/null; then
        iptables -I "$chain" 1 -i lo -p tcp --dport "$api_port" -j ACCEPT
    fi
    if ! iptables -C "$chain" -p udp --dport "$wg_port" -j ACCEPT 2>/dev/null; then
        iptables -I "$chain" 1 -p udp --dport "$wg_port" -j ACCEPT
    fi

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 || true
    fi
    log_ok "Правила фаервола Combain-Mesh применены в ${chain} (${wg_port}/udp открыт, ${api_port}/tcp только на lo и ${MESH_IFACE})."
}

# Установка wireguard-tools при необходимости и генерация ключей wg-mesh0
_mesh_setup_wireguard() {
    state_load_silent
    _mesh_ensure_dirs

    if ! command -v wg &>/dev/null || ! command -v wg-quick &>/dev/null; then
        log_info "Установка wireguard-tools для приватной сети ${MESH_IFACE}..."
        if command -v apt-get &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools
        else
            log_err "Установите пакет wireguard-tools вручную (команда wg не найдена)."
            return 1
        fi
    fi

    local priv_file="${STATE_DIR}/mesh/wg_private.key"
    local pub_file="${STATE_DIR}/mesh/wg_public.key"

    if [[ ! -f "$priv_file" ]]; then
        umask 077
        wg genkey > "$priv_file"
        chmod 600 "$priv_file"
    fi
    wg pubkey < "$priv_file" > "$pub_file"
    chmod 644 "$pub_file"

    local priv_key
    priv_key="$(tr -d '\r\n' < "$priv_file")"
    local wg_ip="${MESH_WG_IP:-10.99.0.1}"
    local wg_port="${MESH_WG_PORT:-51829}"

    # Сохраняем существующие секции [Peer], если конфиг уже был создан ранее
    local existing_peers=""
    if [[ -f "$MESH_WG_CONF" ]]; then
        existing_peers="$(awk '/^\[Peer\]/{flag=1} flag{print}' "$MESH_WG_CONF" || true)"
    fi

    umask 077
    cat > "$MESH_WG_CONF" <<EOF
[Interface]
Address = ${wg_ip}/24
ListenPort = ${wg_port}
PrivateKey = ${priv_key}
SaveConfig = false
EOF
    if [[ -n "$existing_peers" ]]; then
        printf '\n%s\n' "$existing_peers" >> "$MESH_WG_CONF"
    fi
    chmod 600 "$MESH_WG_CONF"

    if systemctl is-active --quiet "wg-quick@${MESH_IFACE}" 2>/dev/null; then
        wg-quick down "$MESH_IFACE" >/dev/null 2>&1 || true
    fi
    systemctl enable --now "wg-quick@${MESH_IFACE}" >/dev/null 2>&1 || wg-quick up "$MESH_IFACE"
    log_ok "Интерфейс ${MESH_IFACE} поднят (${wg_ip}/24, порт ${wg_port}/udp)."
}

# Установка и запуск systemd-сервиса combain-mesh.service + перезагрузка Nginx
_mesh_install_systemd() {
    state_load_silent
    local tpl="${PROJECT_ROOT}/templates/combain-mesh.service.tpl"
    if [[ ! -f "$tpl" ]]; then
        log_err "Шаблон systemd не найден: ${tpl}"
        return 1
    fi

    export PROJECT_ROOT STATE_DIR
    export MESH_API_PORT="${MESH_API_PORT:-22777}"
    envsubst '${PROJECT_ROOT} ${STATE_DIR} ${MESH_API_PORT}' < "$tpl" > "$MESH_SERVICE_PATH"
    chmod 644 "$MESH_SERVICE_PATH"

    systemctl daemon-reload
    systemctl enable --now combain-mesh.service
    log_ok "Сервис combain-mesh.service установлен и запущен (порт ${MESH_API_PORT})."

    # Обновляем конфигурацию Nginx для маршрутов /api/v1/client/bootstrap, /u/, /u-json/
    if declare -f _render_nginx_conf >/dev/null 2>&1; then
        _render_nginx_conf
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^combain-nginx$'; then
            docker exec combain-nginx nginx -s reload >/dev/null 2>&1 || docker restart combain-nginx >/dev/null 2>&1 || true
            log_ok "Nginx перезагружен с маршрутами Combain-Mesh."
        fi
    fi
}

# Вывод карточки текущей ноды для быстрого подключения на других серверах
mod_mesh_show_node_card() {
    state_load_silent
    local pub_file="${STATE_DIR}/mesh/wg_public.key"
    local wg_pub="не сгенерирован"
    [[ -f "$pub_file" ]] && wg_pub="$(tr -d '\r\n' < "$pub_file")"

    echo ""
    echo -e "${CYAN}====================================================================${NC}"
    echo -e "${BOLD}   Карточка этой ноды Combain-Mesh (для команды Join Peer)${NC}"
    echo -e "${CYAN}====================================================================${NC}"
    echo -e " Имя ноды       : ${GREEN}${MESH_NODE_NAME:-не задано}${NC}"
    echo -e " Роль ноды      : ${GREEN}${MESH_ROLE:-exit}${NC}"
    echo -e " Публичный IP   : ${GREEN}${SERVER_IP:-$(detect_server_ip 2>/dev/null || echo 'не определен')}${NC}"
    echo -e " Домен          : ${GREEN}${BASE_DOMAIN:-не задан}${NC}"
    echo -e " Mesh IP (WG)   : ${GREEN}${MESH_WG_IP:-10.99.0.1}${NC}"
    echo -e " WG Порт (UDP)  : ${GREEN}${MESH_WG_PORT:-51829}${NC}"
    echo -e " WG Public Key  : ${YELLOW}${wg_pub}${NC}"
    echo -e " API Порт (TCP) : ${GREEN}${MESH_API_PORT:-22777}${NC}"
    echo -e " MESH_SECRET    : ${YELLOW}${MESH_SECRET:-не задан}${NC}"
    echo -e "${CYAN}====================================================================${NC}"
}

# 1. Инициализация текущей ноды (интерактивно или через переменные окружения)
mod_mesh_init_node() {
    log_step "Инициализация ноды Combain-Mesh"
    state_load_silent
    _mesh_require_cli || return 1
    _mesh_ensure_dirs

    local default_name
    default_name="${MESH_NODE_NAME:-$(hostname -s 2>/dev/null || echo 'node-1')}"
    local in_role in_name in_ip in_wg_port in_api_port in_secret

    if [[ -t 0 && "${MESH_NONINTERACTIVE:-0}" != "1" ]]; then
        echo ""
        echo "Выберите роль этой ноды в кластере:"
        echo "  0) auto     — определить автоматически по стране IP (RU -> ru_relay, иначе -> exit)"
        echo "  1) exit     — зарубежный выходной сервер (DE / NL / FI и др.)"
        echo "  2) ru_relay — российский ретранслятор (входная точка в РФ -> каскад на exit)"
        read -rp "Роль ноды [0-2, по умолч. 0 (auto)]: " in_role
        case "${in_role:-0}" in
            1|exit)     in_role="exit" ;;
            2|ru_relay) in_role="ru_relay" ;;
            *)          in_role="auto" ;;
        esac

        read -rp "Имя ноды в кластере [${default_name}]: " in_name
        in_name="${in_name:-$default_name}"

        local suggested_ip="${MESH_WG_IP:-10.99.0.1}"
        [[ "$in_role" == "ru_relay" && "$suggested_ip" == "10.99.0.1" ]] && suggested_ip="10.99.0.10"
        read -rp "Внутренний IP в подсети ${MESH_WG_SUBNET:-10.99.0.0/24} [${suggested_ip}]: " in_ip
        in_ip="${in_ip:-$suggested_ip}"

        read -rp "UDP-порт WireGuard wg-mesh0 [${MESH_WG_PORT:-51829}]: " in_wg_port
        in_wg_port="${in_wg_port:-${MESH_WG_PORT:-51829}}"

        read -rp "Порт HTTP API Combain-Mesh [${MESH_API_PORT:-22777}]: " in_api_port
        in_api_port="${in_api_port:-${MESH_API_PORT:-22777}}"

        if [[ -n "${MESH_SECRET:-}" ]]; then
            read -rp "MESH_SECRET (Enter = оставить текущий, или вставьте общий ключ кластера): " in_secret
            in_secret="${in_secret:-$MESH_SECRET}"
        else
            read -rp "MESH_SECRET (Enter = сгенерировать новый для первой ноды, или вставьте с другой ноды): " in_secret
            in_secret="${in_secret:-$(gen_random_str 32)}"
        fi
    else
        in_role="${MESH_ROLE:-exit}"
        in_name="${MESH_NODE_NAME:-$default_name}"
        in_ip="${MESH_WG_IP:-10.99.0.1}"
        in_wg_port="${MESH_WG_PORT:-51829}"
        in_api_port="${MESH_API_PORT:-22777}"
        in_secret="${MESH_SECRET:-$(gen_random_str 32)}"
    fi

    state_set "MESH_ENABLED" "1"
    state_set "MESH_ROLE" "$in_role"
    state_set "MESH_NODE_NAME" "$in_name"
    state_set "MESH_WG_SUBNET" "${MESH_WG_SUBNET:-10.99.0.0/24}"
    state_set "MESH_WG_IP" "$in_ip"
    state_set "MESH_WG_PORT" "$in_wg_port"
    state_set "MESH_API_PORT" "$in_api_port"
    state_set "MESH_SECRET" "$in_secret"

    local pub_ip="${SERVER_IP:-$(detect_server_ip 2>/dev/null || true)}"
    [[ -n "$pub_ip" && -z "${SERVER_IP:-}" ]] && state_set "SERVER_IP" "$pub_ip"

    _mesh_setup_wireguard
    _mesh_apply_firewall

    local py_bin wg_pub=""
    py_bin="$(_mesh_py_bin)"
    [[ -f "${MESH_WG_DIR}/public.key" ]] && wg_pub="$(tr -d ' \n\r' < "${MESH_WG_DIR}/public.key")"
    local init_args=(
        init-node
        --state-dir "${STATE_DIR}"
        --name "${in_name}"
        --role "${in_role}"
        --public-ip "${pub_ip}"
        --mesh-ip "${in_ip}"
        --wg-port "${in_wg_port}"
    )
    [[ -n "$wg_pub" ]] && init_args+=(--wg-pubkey "$wg_pub")
    [[ -n "${BASE_DOMAIN:-}" ]] && init_args+=(--base-domain "${BASE_DOMAIN}")
    [[ -n "${DNS_DOMAIN:-}" ]]  && init_args+=(--dns-domain "${DNS_DOMAIN}")
    [[ -n "${XHTTP_YA_PATH:-}" ]] && init_args+=(--xhttp-path "${XHTTP_YA_PATH}")
    [[ -n "${WS_YA_PATH:-}" ]]    && init_args+=(--ws-path "${WS_YA_PATH}")
    [[ -n "${REALITY_PUBLIC_KEY:-}" ]] && init_args+=(--vless-pub-key "${REALITY_PUBLIC_KEY}")
    [[ -n "${AWG_PORT:-}" ]]      && init_args+=(--awg-port "${AWG_PORT}")

    local init_json
    init_json="$(python3 "$py_bin" "${init_args[@]}" --json)"
    local resolved_role
    resolved_role="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('role','exit'))" "$init_json" 2>/dev/null || echo "exit")"
    state_set "MESH_ROLE" "$resolved_role"

    _mesh_install_systemd
    mod_mesh_show_node_card
    log_ok "Нода '${in_name}' (роль: ${resolved_role}) успешно инициализирована в Combain-Mesh."
}

# 2. Подключение соседней ноды (WireGuard wg-mesh0 + combain_mesh.py join-peer)
mod_mesh_join_peer() {
    log_step "Подключение соседней ноды (Join Peer)"
    state_load_silent
    _mesh_require_cli || return 1

    if [[ "${MESH_ENABLED:-0}" != "1" ]]; then
        log_warn "Сначала инициализируйте эту ноду (пункт 1)."
        return 1
    fi

    local p_name p_role p_pub_ip p_wg_port p_wg_pub p_mesh_ip p_domain p_secret
    read -rp "Имя соседней ноды (напр. nl-1 или ru-msk-1): " p_name
    read -rp "Роль соседней ноды [exit/ru_relay, по умолч. exit]: " p_role
    p_role="${p_role:-exit}"
    read -rp "Публичный IPv4 соседней ноды: " p_pub_ip
    read -rp "WireGuard UDP-порт соседней ноды [${MESH_WG_PORT:-51829}]: " p_wg_port
    p_wg_port="${p_wg_port:-${MESH_WG_PORT:-51829}}"
    read -rp "WireGuard Public Key соседней ноды: " p_wg_pub
    read -rp "Mesh IP соседней ноды в ${MESH_WG_SUBNET:-10.99.0.0/24} (напр. 10.99.0.2): " p_mesh_ip
    read -rp "Домен соседней ноды (опционально, напр. nl.example.com): " p_domain
    read -rp "MESH_SECRET (Enter = использовать текущий): " p_secret

    if [[ -z "$p_pub_ip" || -z "$p_wg_pub" || -z "$p_mesh_ip" ]]; then
        log_err "Публичный IP, WG Public Key и Mesh IP обязательны."
        return 1
    fi

    if [[ -n "$p_secret" && "$p_secret" != "${MESH_SECRET:-}" ]]; then
        state_set "MESH_SECRET" "$p_secret"
        systemctl restart combain-mesh.service >/dev/null 2>&1 || true
    fi

    # Идемпотентно добавляем [Peer] в /etc/wireguard/wg-mesh0.conf
    if [[ -f "$MESH_WG_CONF" ]] && grep -qF "$p_wg_pub" "$MESH_WG_CONF"; then
        log_info "Пир с ключом ${p_wg_pub:0:12}... уже присутствует в ${MESH_WG_CONF}."
    else
        cat >> "$MESH_WG_CONF" <<EOF

# Peer: ${p_name:-$p_mesh_ip} (${p_role})
[Peer]
PublicKey = ${p_wg_pub}
Endpoint = ${p_pub_ip}:${p_wg_port}
AllowedIPs = ${p_mesh_ip}/32
PersistentKeepalive = 25
EOF
    fi

    # Применяем пир на лету без обрыва текущих соединений
    wg set "$MESH_IFACE" peer "$p_wg_pub" allowed-ips "${p_mesh_ip}/32" endpoint "${p_pub_ip}:${p_wg_port}" persistent-keepalive 25 2>/dev/null || {
        wg-quick down "$MESH_IFACE" >/dev/null 2>&1 || true
        wg-quick up "$MESH_IFACE"
    }

    local py_bin
    py_bin="$(_mesh_py_bin)"
    local join_args=(
        join-peer
        --state-dir "${STATE_DIR}"
        --mesh-ip "${p_mesh_ip}"
        --public-ip "${p_pub_ip}"
        --role "${p_role}"
    )
    [[ -n "$p_name" ]]   && join_args+=(--name "$p_name")
    [[ -n "$p_domain" ]] && join_args+=(--base-domain "$p_domain")

    python3 "$py_bin" "${join_args[@]}"
    python3 "$py_bin" sync-now --state-dir "${STATE_DIR}" || true
    log_ok "Нода '${p_name:-$p_mesh_ip}' (${p_mesh_ip}) подключена! Не забудьте выполнить Join Peer на второй ноде, указав карточку этой ноды."
}

# 3. Подменю управления пользователями и подписками
mod_mesh_users_menu() {
    state_load_silent
    _mesh_require_cli || return 1
    local py_bin
    py_bin="$(_mesh_py_bin)"

    while true; do
        echo ""
        echo -e "${BOLD}--- Управление пользователями Combain-Mesh ---${NC}"
        echo " 1) Создать пользователя (лимит устройств + срок действия -> персональные ссылки)"
        echo " 2) Список пользователей и статус подписок"
        echo " 3) Продлить срок действия пользователя"
        echo " 4) Сбросить привязанные устройства (HWID)"
        echo " 5) Отключить пользователя (disable)"
        echo " 6) Включить пользователя (enable)"
        echo " 0) Назад"
        read -rp "Выберите действие [0-6]: " u_choice

        case "$u_choice" in
            1)
                local uname max_dev days note out token
                read -rp "Имя пользователя (латиница, напр. mama, alex): " uname
                if [[ -z "$uname" ]]; then
                    log_warn "Имя пользователя не может быть пустым."
                    continue
                fi
                read -rp "Максимум устройств (HWID) [3]: " max_dev
                max_dev="${max_dev:-3}"
                read -rp "Срок действия в днях (0 = бессрочно) [30]: " days
                days="${days:-30}"
                read -rp "Заметка (опционально, напр. телефон + ноутбук): " note

                out="$(python3 "$py_bin" user-add --state-dir "${STATE_DIR}" \
                    --username "$uname" \
                    --max-devices "$max_dev" \
                    --days "$days" \
                    --note "$note")"
                echo "$out"

                # Пробуем извлечь sub_token из JSON/текстового вывода для удобной печати ссылок и QR
                token="$(printf '%s' "$out" | python3 -c '
import json, re, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    if isinstance(data, dict) and data.get("sub_token"):
        print(data["sub_token"])
        sys.exit(0)
except Exception:
    pass
m = re.search(r"sub_token[\"'\''\s:=]+([A-Za-z0-9_-]{8,})", raw)
if m:
    print(m.group(1))
' 2>/dev/null || true)"

                if [[ -n "$token" && -n "${BASE_DOMAIN:-}" ]]; then
                    local sub_b64="https://${BASE_DOMAIN}/u/${token}"
                    local sub_json="https://${BASE_DOMAIN}/u-json/${token}"
                    local boot_url="https://${BASE_DOMAIN}/api/v1/client/bootstrap"
                    echo ""
                    echo -e "${GREEN}=== Персональные ссылки для ${uname} ===${NC}"
                    echo -e " Подписка Base64 (универсальная)     : ${BOLD}${sub_b64}${NC}"
                    echo -e " Подписка JSON (v2RayTun + RU-обход) : ${BOLD}${sub_json}${NC}"
                    echo -e " Bootstrap API (будущее приложение)  : ${BOLD}${boot_url}${NC}"
                    echo -e " Ключ доступа (X-Sub-Token)          : ${YELLOW}${token}${NC}"
                    echo ""
                    print_qr_if_available "$sub_json"
                fi
                ;;
            2)
                python3 "$py_bin" user-list --state-dir "${STATE_DIR}"
                ;;
            3)
                local uname days
                read -rp "Имя пользователя для продления: " uname
                read -rp "На сколько дней продлить [30]: " days
                days="${days:-30}"
                [[ -n "$uname" ]] && python3 "$py_bin" user-extend --state-dir "${STATE_DIR}" --username "$uname" --days "$days"
                ;;
            4)
                local uname
                read -rp "Имя пользователя для сброса устройств (HWID): " uname
                [[ -n "$uname" ]] && python3 "$py_bin" user-reset-devices --state-dir "${STATE_DIR}" --username "$uname"
                ;;
            5)
                local uname
                read -rp "Имя пользователя для отключения: " uname
                [[ -n "$uname" ]] && python3 "$py_bin" user-disable --state-dir "${STATE_DIR}" --username "$uname"
                ;;
            6)
                local uname
                read -rp "Имя пользователя для включения: " uname
                [[ -n "$uname" ]] && python3 "$py_bin" user-enable --state-dir "${STATE_DIR}" --username "$uname"
                ;;
            0) return 0 ;;
            *) log_warn "Неверный выбор." ;;
        esac
    done
}

# 4. Статус кластера, нод и WireGuard wg-mesh0
mod_mesh_show_status() {
    state_load_silent
    _mesh_require_cli || return 1
    local py_bin
    py_bin="$(_mesh_py_bin)"

    echo ""
    echo -e "${BOLD}=== Статус сервиса combain-mesh.service ===${NC}"
    systemctl status combain-mesh.service --no-pager -l 2>/dev/null | head -n 15 || log_warn "Сервис combain-mesh.service не активен."

    echo ""
    echo -e "${BOLD}=== Приватная сеть WireGuard (${MESH_IFACE}) ===${NC}"
    wg show "$MESH_IFACE" 2>/dev/null || log_warn "Интерфейс ${MESH_IFACE} не запущен."

    echo ""
    echo -e "${BOLD}=== Ноды кластера Combain-Mesh ===${NC}"
    python3 "$py_bin" node-list --state-dir "${STATE_DIR}" || true
}

# 5. Генерация шаблона и памятки для каскада RU-Relay -> Exit поверх wg-mesh0
mod_mesh_ru_relay_guide() {
    state_load_silent
    _mesh_ensure_dirs
    local cascade_file="${STATE_DIR}/mesh/ru_relay_cascade.json"
    local exit_mesh_ip
    read -rp "Mesh IP основной зарубежной exit-ноды [10.99.0.1]: " exit_mesh_ip
    exit_mesh_ip="${exit_mesh_ip:-10.99.0.1}"

    cat > "$cascade_file" <<EOF
{
  "_comment": "Combain-Mesh RU-Relay -> Exit каскад: клиент подключается к RU-ноде по 443/TCP, далее трафик уходит на exit-ноду через приватный wg-mesh0",
  "outbounds": [
    {
      "tag": "mesh-exit-primary",
      "protocol": "freedom",
      "settings": {
        "redirect": "${exit_mesh_ip}:443"
      }
    },
    {
      "tag": "direct-ru",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "domain": [
          "domain:gosuslugi.ru",
          "domain:max.ru",
          "domain:oneme.ru",
          "domain:vk.com",
          "domain:sberbank.ru",
          "domain:tbank.ru"
        ],
        "outboundTag": "direct-ru"
      },
      {
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "mesh-exit-primary"
      }
    ]
  }
}
EOF

    echo ""
    log_ok "Шаблон каскада RU-Relay -> Exit сохранен в: ${cascade_file}"
    echo -e "${BOLD}Как работает каскад RU-Relay -> Exit:${NC}"
    echo "  1. Клиент в РФ подключается к ru_relay по 443 порту (низкий пинг, нет потерь на ТСПУ)."
    echo "  2. Входящий трафик на ru_relay маршрутизируется на зарубежную exit-ноду (${exit_mesh_ip}) поверх зашифрованного туннеля ${MESH_IFACE}."
    echo "  3. При отказе одной exit-ноды Combain-Mesh автоматически помечает её offline (>45 сек) и исключает из клиентских подписок."
    echo "  4. Для прямого проброса TCP 443 на exit-ноду можно использовать Xray Dokodemo-door или Freedom outbound в 3x-ui."
}

# Инвайт-токен в 1 строку для подключения нового сервера к кластеру
mod_mesh_create_invite() {
    state_load_silent
    _mesh_require_cli || return 1
    if [[ "${MESH_ENABLED:-0}" != "1" ]]; then
        log_warn "Сначала инициализируйте эту ноду (пункт 1)."
        return 1
    fi
    local token
    token="$(python3 "$(_mesh_py_bin)" invite-create --state-dir "${STATE_DIR}")" || return 1
    echo ""
    echo -e "${CYAN}====================================================================${NC}"
    echo -e "${BOLD}   Инвайт-токен для нового сервера (вставьте на новом VPS в пункт 3)${NC}"
    echo -e "${CYAN}====================================================================${NC}"
    echo "$token"
    echo -e "${CYAN}====================================================================${NC}"
}

# Подключение нового сервера к кластеру по 1-строчному инвайт-токену (авто-роль + авто-WG)
mod_mesh_join_by_invite() {
    log_step "Подключение этого сервера к кластеру по инвайт-токену"
    state_load_silent
    _mesh_require_cli || return 1
    _mesh_ensure_dirs

    local inv_token
    read -rp "Вставьте строку инвайт-токена (combain-join://...): " inv_token
    if [[ -z "$inv_token" ]]; then
        log_warn "Токен не введен."
        return 1
    fi

    local py_bin parsed_json
    py_bin="$(_mesh_py_bin)"
    parsed_json="$(python3 "$py_bin" invite-parse --token "$inv_token")" || return 1

    local secret assigned_ip api_port
    secret="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['secret'])" "$parsed_json")"
    assigned_ip="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('assigned_mesh_ip','10.99.0.2'))" "$parsed_json")"
    api_port="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('api_port',22777))" "$parsed_json")"

    local default_name
    default_name="${MESH_NODE_NAME:-$(hostname -s 2>/dev/null || echo 'node-new')}"
    read -rp "Имя этой ноды [${default_name}]: " in_name
    in_name="${in_name:-$default_name}"

    echo "Роль ноды: Enter = определить автоматически по стране IP (RU -> ru_relay, иначе -> exit)"
    read -rp "Роль [auto / exit / ru_relay, по умолч. auto]: " in_role
    in_role="${in_role:-auto}"

    state_set "MESH_ENABLED" "1"
    state_set "MESH_NODE_NAME" "$in_name"
    state_set "MESH_WG_SUBNET" "${MESH_WG_SUBNET:-10.99.0.0/24}"
    state_set "MESH_WG_IP" "$assigned_ip"
    state_set "MESH_WG_PORT" "${MESH_WG_PORT:-51829}"
    state_set "MESH_API_PORT" "$api_port"
    state_set "MESH_SECRET" "$secret"

    local pub_ip="${SERVER_IP:-$(detect_server_ip 2>/dev/null || true)}"
    [[ -n "$pub_ip" && -z "${SERVER_IP:-}" ]] && state_set "SERVER_IP" "$pub_ip"

    _mesh_setup_wireguard
    _mesh_apply_firewall

    local wg_pub=""
    [[ -f "${MESH_WG_DIR}/public.key" ]] && wg_pub="$(tr -d ' \n\r' < "${MESH_WG_DIR}/public.key")"
    local init_args=(
        init-node
        --state-dir "${STATE_DIR}"
        --name "${in_name}"
        --role "${in_role}"
        --public-ip "${pub_ip}"
        --mesh-ip "${assigned_ip}"
        --wg-port "${MESH_WG_PORT:-51829}"
    )
    [[ -n "$wg_pub" ]] && init_args+=(--wg-pubkey "$wg_pub")
    [[ -n "${BASE_DOMAIN:-}" ]] && init_args+=(--base-domain "${BASE_DOMAIN}")
    [[ -n "${DNS_DOMAIN:-}" ]]  && init_args+=(--dns-domain "${DNS_DOMAIN}")
    [[ -n "${XHTTP_YA_PATH:-}" ]] && init_args+=(--xhttp-path "${XHTTP_YA_PATH}")
    [[ -n "${WS_YA_PATH:-}" ]]    && init_args+=(--ws-path "${WS_YA_PATH}")
    [[ -n "${REALITY_PUBLIC_KEY:-}" ]] && init_args+=(--vless-pub-key "${REALITY_PUBLIC_KEY}")
    [[ -n "${AWG_PORT:-}" ]]      && init_args+=(--awg-port "${AWG_PORT}")

    local init_json resolved_role
    init_json="$(python3 "$py_bin" "${init_args[@]}" --json)"
    resolved_role="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('role','exit'))" "$init_json" 2>/dev/null || echo "exit")"
    state_set "MESH_ROLE" "$resolved_role"

    # Автоматически добавляем всех существующих пиров из инвайта в wg-mesh0 и mesh.db
    local peers_lines
    peers_lines="$(python3 -c "
import json, sys
for p in json.loads(sys.argv[1]).get('peers', []):
    print('|'.join(str(p.get(k,'')) for k in ('node_id','name','role','public_ip','mesh_ip','wg_port','wg_pubkey')))
" "$parsed_json")"
    while IFS='|' read -r p_id p_name p_role p_pubip p_mip p_wgp p_wgpub; do
        [[ -z "$p_mip" ]] && continue
        if [[ -n "$p_wgpub" && -n "$p_pubip" ]]; then
            _mesh_wg_add_peer "$p_wgpub" "$p_mip" "${p_pubip}:${p_wgp:-51829}"
        fi
        python3 "$py_bin" join-peer \
            --state-dir "${STATE_DIR}" \
            --peer-node-id "$p_id" \
            --name "$p_name" \
            --role "${p_role:-exit}" \
            --public-ip "$p_pubip" \
            --mesh-ip "$p_mip" \
            --wg-pubkey "$p_wgpub" \
            --wg-port "${p_wgp:-51829}" \
            --no-sync >/dev/null || true
    done <<< "$peers_lines"

    _mesh_install_systemd
    python3 "$py_bin" sync-now --state-dir "${STATE_DIR}" || true
    log_ok "Нода '${in_name}' (роль: ${resolved_role}, Mesh IP: ${assigned_ip}) подключена к кластеру!"
    log_info "На старом сервере добавьте WG PubKey этой ноды (если еще не добавлен): ${wg_pub}"
}

# Смена роли любого узла в кластере (exit <-> ru_relay) с любого живого сервера
mod_mesh_set_node_role() {
    state_load_silent
    _mesh_require_cli || return 1
    local py_bin
    py_bin="$(_mesh_py_bin)"
    echo ""
    python3 "$py_bin" node-list --state-dir "${STATE_DIR}"
    echo ""
    local target_node target_role
    read -rp "Введите имя или node_id узла: " target_node
    [[ -z "$target_node" ]] && return 0
    read -rp "Новая роль (exit / ru_relay): " target_role
    python3 "$py_bin" node-set-role --state-dir "${STATE_DIR}" --node "$target_node" --role "$target_role"
}

# Главное меню модуля 10 (вызывается из combain.sh пункт 9 и `combain mesh`)
mod_mesh_menu() {
    state_load_silent
    while true; do
        echo ""
        echo -e "${CYAN}====================================================================${NC}"
        echo -e "${BOLD}   Кластер Combain-Mesh (P2P-сеть и управление пользователями)${NC}"
        echo -e "${CYAN}====================================================================${NC}"
        echo -e " Статус: ${GREEN}$([[ "${MESH_ENABLED:-0}" == "1" ]] && echo "ВКЛ (${MESH_NODE_NAME:-?}, роль: ${MESH_ROLE:-exit}, ${MESH_WG_IP:-?})" || echo "НЕ ИНИЦИАЛИЗИРОВАН")${NC}"
        echo ""
        echo " 1) Инициализировать эту ноду (авто-роль по GeoIP: RU -> ru_relay, иначе -> exit)"
        echo " 2) Выдать инвайт-токен в 1 строку (для подключения нового сервера)"
        echo " 3) Подключиться к кластеру по инвайт-токену (combain-join://...)"
        echo " 4) Сменить роль любого узла в кластере (exit <-> ru_relay с любого сервера)"
        echo " 5) Пользователи и подписки (создать, лимит устройств/дат, сброс HWID)"
        echo " 6) Статус кластера, нод и wg-mesh0 (node-list + cascade-target)"
        echo " 7) Принудительная синхронизация кластера сейчас (sync-now)"
        echo " 8) Ручное подключение пира (Join Peer) / карточка ноды"
        echo " 9) Настройка каскада RU-Relay -> Exit поверх wg-mesh0"
        echo " 0) Назад"
        read -rp "Выберите действие [0-9]: " mesh_choice

        case "$mesh_choice" in
            1) mod_mesh_init_node ;;
            2) mod_mesh_create_invite ;;
            3) mod_mesh_join_by_invite ;;
            4) mod_mesh_set_node_role ;;
            5) mod_mesh_users_menu ;;
            6)
                mod_mesh_show_status
                if _mesh_require_cli; then
                    python3 "$(_mesh_py_bin)" cascade-target --state-dir "${STATE_DIR}" || true
                fi
                ;;
            7)
                if _mesh_require_cli; then
                    python3 "$(_mesh_py_bin)" sync-now --state-dir "${STATE_DIR}"
                fi
                ;;
            8)
                mod_mesh_show_node_card
                read -rp "Добавить пира вручную прямо сейчас? [y/N]: " ans_jp
                [[ "${ans_jp,,}" == "y" ]] && mod_mesh_join_peer
                ;;
            9) mod_mesh_ru_relay_guide ;;
            0) return 0 ;;
            *) log_warn "Неверный выбор." ;;
        esac
    done
}
