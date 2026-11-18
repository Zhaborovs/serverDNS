#!/usr/bin/env bash
# ==============================================================================
# Модуль 05: 3x-ui и Xray-core (Скрытая панель + VLESS-Reality + VK/Yandex CDN)
# ------------------------------------------------------------------------------
# Назначение:
#   - Автоматический подбор оптимального SNI из whitelist_sni.list (TLS 1.3 + H2)
#   - Генерация ключей X25519 Reality, shortId и MAIN_CLIENT_UUID
#   - Запуск контейнера 3x-ui (ghcr.io/mhsanaei/3x-ui:latest)
#   - Настройка скрытой панели на 127.0.0.1:${XUI_INTERNAL_PORT}/${SECRET_PANEL_PATH}/
#   - Инициализация 5 инбаундов (Reality, VK XHTTP/WS, Yandex XHTTP/WS) через xui_db_manager.py
#   - Синхронизация sniproxy с выбранным REALITY_SNI
# Входные переменные (state.env):
#   XUI_VERSION, XUI_INTERNAL_PORT, SECRET_PANEL_PATH, PANEL_USER, PANEL_PASS,
#   REALITY_SNI, XRAY_REALITY_INTERNAL_PORT, XHTTP_VK_PATH, WS_VK_PATH,
#   XHTTP_YA_PATH, WS_YA_PATH, VK_CDN_DOMAIN, YA_CDN_DOMAIN
# Выходные артефакты:
#   /etc/x-ui/x-ui.db, ключи Reality в /etc/server-combain/state.env
# ==============================================================================

_xray_find_best_sni() {
    local verbose="${1:-false}"
    local wl_file="${PROJECT_ROOT}/config/presets/whitelist_sni.list"
    _FOUND_BEST_SNI=""
    _FOUND_BEST_MS="99999"
    [[ ! -f "$wl_file" ]] && return 0

    while IFS= read -r dom; do
        dom="$(printf '%s' "$dom" | tr -d '\r' | xargs)"
        [[ -z "$dom" || "$dom" == \#* ]] && continue

        # Замеряем успешность TLS 1.3 + H2 и время установления TLS-соединения по IPv4
        local res code t_connect
        res="$(LC_ALL=C curl -4 -sS -I -o /dev/null --tlsv1.3 --http2 --connect-timeout 2 --max-time 3 -w "%{http_code} %{time_connect}" "https://${dom}/" 2>/dev/null || true)"
        [[ -z "$res" ]] && res="000 99"
        code="${res%% *}"
        t_connect="${res##* }"

        if [[ "$code" != "000" ]]; then
            local ms
            ms="$(LC_ALL=C awk -v t="$t_connect" 'BEGIN {printf "%d", t * 1000}')"
            [[ "$verbose" == "true" ]] && echo -e "  [${GREEN}OK${NC}] ${dom} (HTTP ${code}, TLS ${ms} ms)"
            if [[ "$ms" =~ ^[0-9]+$ ]] && [[ "$ms" -lt "$_FOUND_BEST_MS" ]]; then
                _FOUND_BEST_MS="$ms"
                _FOUND_BEST_SNI="$dom"
            fi
        else
            [[ "$verbose" == "true" ]] && echo -e "  [${YELLOW}SKIP${NC}] ${dom} (нет ответа TLS 1.3 / таймаут)"
        fi
    done < "$wl_file"
}

_xray_auto_select_reality_sni() {
    log_info "Авто-проверка доменов из белого списка для VLESS-Reality (TLS 1.3 + HTTP/2)..."
    _xray_find_best_sni "true"

    if [[ -n "$_FOUND_BEST_SNI" ]]; then
        log_ok "Рекомендованный быстрый SNI для Reality: ${_FOUND_BEST_SNI} (${_FOUND_BEST_MS} ms)"
        read -rp "Использовать '${_FOUND_BEST_SNI}' или ввести свой SNI? [Enter = ${_FOUND_BEST_SNI}]: " custom_sni
        state_set "REALITY_SNI" "${custom_sni:-$_FOUND_BEST_SNI}"
    else
        log_warn "Авто-чекер не нашел доступный домен, оставлен SNI по умолчанию: ${REALITY_SNI:-www.microsoft.com}"
    fi
}

_xray_heal_reality_sni_if_needed() {
    if declare -f _sys_fix_dns_and_ipv4_precedence >/dev/null 2>&1; then
        _sys_fix_dns_and_ipv4_precedence
    fi
    state_load_silent
    local cur_sni="${REALITY_SNI:-}"
    local code="000"
    if [[ -n "$cur_sni" ]]; then
        code="$(LC_ALL=C curl -4 -sS -I -o /dev/null --tlsv1.3 --http2 --connect-timeout 2 --max-time 3 -w "%{http_code}" "https://${cur_sni}/" 2>/dev/null || true)"
        [[ -z "$code" ]] && code="000"
    fi

    if [[ -n "$code" && "$code" != "000" ]]; then
        return 0
    fi

    log_warn "Текущий Reality SNI '${cur_sni:-не задан}' недоступен с этого сервера (код ${code}). Подбираю рабочий SNI..."
    _xray_find_best_sni "false"
    if [[ -n "$_FOUND_BEST_SNI" ]]; then
        state_set "REALITY_SNI" "$_FOUND_BEST_SNI"
        log_ok "Reality SNI автоматически обновлен на рабочий: ${_FOUND_BEST_SNI} (${_FOUND_BEST_MS} ms)"
    else
        log_warn "Рабочий SNI из whitelist_sni.list не найден, оставлен '${cur_sni}'."
    fi
}

mod_xray_update_subscription() {
    state_load_silent
    if [[ -z "${MAIN_CLIENT_UUID:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
        return 0
    fi
    [[ -z "${SUB_TOKEN:-}" ]] && state_set "SUB_TOKEN" "$(gen_random_str 20)"

    local cur_ip="${SERVER_IP:-$(detect_server_ip)}"
    local sub_file="${STATE_DIR}/nginx/conf.d/sub_payload.b64"
    local extra_file="${STATE_DIR}/extra_sub_links.list"
    mkdir -p "${STATE_DIR}/nginx/conf.d"

    python3 "${PROJECT_ROOT}/scripts/py_helpers/xui_db_manager.py" export-sub \
        --server-ip "$cur_ip" \
        --base-domain "${BASE_DOMAIN:-}" \
        --uuid "${MAIN_CLIENT_UUID}" \
        --reality-sni "${REALITY_SNI:-www.microsoft.com}" \
        --reality-public-key "${REALITY_PUBLIC_KEY}" \
        --reality-short-id "${REALITY_SHORT_ID:-00}" \
        --vk-cdn-domain "${VK_CDN_DOMAIN:-}" \
        --vk-xhttp-path "${XHTTP_VK_PATH:-}" \
        --vk-ws-path "${WS_VK_PATH:-}" \
        --ya-cdn-domain "${YA_CDN_DOMAIN:-}" \
        --ya-xhttp-path "${XHTTP_YA_PATH:-}" \
        --ya-ws-path "${WS_YA_PATH:-}" \
        --extra-links-file "$extra_file" \
        --out "$sub_file"
}

_xray_ensure_keys() {
    state_load_silent
    if [[ -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${MAIN_CLIENT_UUID:-}" ]]; then
        return 0
    fi

    log_info "Генерация ключей X25519 Reality и UUID клиента..."
    local keys_out
    keys_out="$(python3 "${PROJECT_ROOT}/scripts/py_helpers/xui_db_manager.py" gen-keys)"
    while IFS='=' read -r k v; do
        [[ -n "$k" && -n "$v" ]] && state_set "$k" "$v"
    done <<< "$keys_out"
    log_ok "Ключи X25519 и UUID сгенерированы и сохранены в state.env."
}

mod_xray_apply_inbounds() {
    _xray_heal_reality_sni_if_needed
    state_load_silent
    if [[ -z "${MAIN_CLIENT_UUID:-}" || -z "${REALITY_PRIVATE_KEY:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
        log_err "Не найдены ключи Reality/UUID в state.env. Сначала запустите mod_xray_3xui_setup."
        return 1
    fi

    # Останавливаем контейнер на время безопасного патчинга БД x-ui.db
    docker stop combain-3xui >/dev/null 2>&1 || true

    python3 "${PROJECT_ROOT}/scripts/py_helpers/xui_db_manager.py" init-all \
        --db /etc/x-ui/x-ui.db \
        --panel-port "${XUI_INTERNAL_PORT}" \
        --panel-path "${SECRET_PANEL_PATH}" \
        --uuid "${MAIN_CLIENT_UUID}" \
        --reality-sni "${REALITY_SNI}" \
        --reality-private-key "${REALITY_PRIVATE_KEY}" \
        --reality-public-key "${REALITY_PUBLIC_KEY}" \
        --reality-short-id "${REALITY_SHORT_ID}" \
        --reality-port "${XRAY_REALITY_INTERNAL_PORT:-20443}" \
        --vk-xhttp-port "${XRAY_VK_XHTTP_PORT:-20444}" \
        --vk-xhttp-path "${XHTTP_VK_PATH}" \
        --vk-ws-port "${XRAY_VK_WS_PORT:-20445}" \
        --vk-ws-path "${WS_VK_PATH}" \
        --ya-xhttp-port "${XRAY_YA_XHTTP_PORT:-20446}" \
        --ya-xhttp-path "${XHTTP_YA_PATH}" \
        --ya-ws-port "${XRAY_YA_WS_PORT:-20447}" \
        --ya-ws-path "${WS_YA_PATH}"

    if declare -f _render_docker_compose >/dev/null 2>&1; then
        _render_docker_compose
        docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d --force-recreate 3x-ui >/dev/null
    else
        docker start combain-3xui >/dev/null
    fi

    if declare -f mod_sniproxy_sync_domains >/dev/null 2>&1; then
        mod_sniproxy_sync_domains
    fi
    mod_xray_update_subscription
}

mod_xray_3xui_setup() {
    log_step "Модуль 05: Установка 3x-ui (latest), автоподбор Reality SNI и настройка CDN инбаундов"
    state_load_silent

    local resolved_ver
    if [[ "${XUI_VERSION:-latest}" == "latest" ]]; then
        resolved_ver="$(fetch_latest_github_release "MHSanaei/3x-ui" "latest")"
        log_info "Последний релиз MHSanaei/3x-ui на GitHub: ${resolved_ver} (используется docker-тег :latest)."
    fi

    _xray_auto_select_reality_sni
    _xray_ensure_keys
    state_load_silent

    mkdir -p /etc/x-ui
    # Обновляем docker-compose.yml с актуальными переменными и запускаем 3x-ui для создания базовой БД
    if declare -f _render_docker_compose >/dev/null 2>&1; then
        _render_docker_compose
    fi

    log_info "Первичный запуск контейнера combain-3xui..."
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d 3x-ui

    # Ждем инициализации SQLite базы данных внутри контейнера
    for _ in $(seq 1 15); do
        [[ -f /etc/x-ui/x-ui.db ]] && break
        sleep 1
    done

    # Применяем учетные данные панели через встроенный CLI 3x-ui
    docker exec combain-3xui /app/x-ui setting \
        -username "${PANEL_USER}" \
        -password "${PANEL_PASS}" \
        -port "${XUI_INTERNAL_PORT}" \
        -webBasePath "/${SECRET_PANEL_PATH}/" >/dev/null 2>&1 || true

    mod_xray_apply_inbounds

    # Обновляем nginx (скрытый путь панели + подписка + отдельный vhost AdGuard)
    if declare -f _render_nginx_conf >/dev/null 2>&1; then
        _render_nginx_conf
        docker restart combain-nginx >/dev/null 2>&1 || true
    fi

    log_ok "Модуль 05 завершен: 3x-ui скрыта за /${SECRET_PANEL_PATH}/, инбаунды Reality и VK/Yandex CDN активны."

    echo ""
    echo -e "${BOLD}--- Опционально: привязка доменов VK Cloud CDN / Yandex Cloud CDN ---${NC}"
    echo "Если вы уже создали CDN-ресурс с источником ${BASE_DOMAIN}:443 (см. docs/cdn_whitelist_guide.md),"
    echo "укажите выданный CDN-домен сейчас (иначе просто нажмите Enter, настроите позже в меню 5 -> 1)."
    echo "  * Пути VK CDN:     /${XHTTP_VK_PATH} (XHTTP GET-only, без POST и WS)"
    echo "  * Пути Yandex CDN: /${XHTTP_YA_PATH} (XHTTP) | /${WS_YA_PATH} (WS)"
    read -rp "Подключить домены CDN сейчас? [y/N]: " cdn_now
    if [[ "${cdn_now,,}" == "y" ]]; then
        mod_xray_configure_cdn_domains
    fi
}

mod_xray_configure_cdn_domains() {
    state_load_silent
    echo ""
    echo -e "${BOLD}--- Настройка доменов VK Cloud CDN и Yandex Cloud CDN ---${NC}"
    echo "Подробная инструкция: ${PROJECT_ROOT}/docs/cdn_whitelist_guide.md"
    read -rp "Домен VK Cloud CDN (Enter оставить '${VK_CDN_DOMAIN:-}', '-' очистить): " vk_dom
    read -rp "Домен Yandex Cloud CDN (Enter оставить '${YA_CDN_DOMAIN:-}', '-' очистить): " ya_dom

    if [[ "$vk_dom" == "-" ]]; then
        state_set "VK_CDN_DOMAIN" ""
    elif [[ -n "$vk_dom" ]]; then
        state_set "VK_CDN_DOMAIN" "$vk_dom"
    fi

    if [[ "$ya_dom" == "-" ]]; then
        state_set "YA_CDN_DOMAIN" ""
    elif [[ -n "$ya_dom" ]]; then
        state_set "YA_CDN_DOMAIN" "$ya_dom"
    fi

    if declare -f _render_nginx_conf >/dev/null 2>&1; then
        _render_nginx_conf
        docker restart combain-nginx >/dev/null 2>&1 || true
    fi
    mod_xray_update_subscription
    log_ok "CDN-домены и единая подписка обновлены. Ссылки доступны через 'combain info'."
}

mod_xray_manage_extra_sub_nodes() {
    state_load_silent
    [[ -z "${SUB_TOKEN:-}" ]] && state_set "SUB_TOKEN" "$(gen_random_str 20)"
    local extra_file="${STATE_DIR}/extra_sub_links.list"
    touch "$extra_file"

    while true; do
        echo ""
        echo -e "${BOLD}--- Единая подписка (Happ / v2rayNG / Hiddify) ---${NC}"
        echo -e "URL подписки: ${GREEN}https://${BASE_DOMAIN:-?}/sub/${SUB_TOKEN}${NC}"
        echo "Файл внешних нод: ${extra_file}"
        echo ""
        echo " 1) Добавить ссылку (vless:// / vmess:// / trojan:// / ss://) от другой ноды"
        echo " 2) Показать список добавленных внешних нод"
        echo " 3) Очистить все внешние ноды (оставить только текущий сервер)"
        echo " 0) Назад"
        read -rp "Выберите действие [0-3]: " sub_choice
        case "$sub_choice" in
            1)
                local ext_uri
                read -rp "Вставьте URI-ссылку внешнего сервера: " ext_uri
                ext_uri="$(printf '%s' "$ext_uri" | tr -d '\r' | xargs)"
                if [[ -n "$ext_uri" ]]; then
                    echo "$ext_uri" >> "$extra_file"
                    mod_xray_update_subscription
                    log_ok "Внешняя нода добавлена и подписка пересобрана."
                else
                    log_warn "Пустая ссылка пропущена."
                fi
                ;;
            2)
                echo ""
                if [[ -s "$extra_file" ]]; then
                    nl -ba "$extra_file"
                else
                    echo "Внешние ноды пока не добавлены (в подписке только адреса этого сервера)."
                fi
                ;;
            3)
                : > "$extra_file"
                mod_xray_update_subscription
                log_ok "Список внешних нод очищен, подписка пересобрана."
                ;;
            0)
                return 0
                ;;
            *)
                log_warn "Неверный выбор."
                ;;
        esac
    done
}
