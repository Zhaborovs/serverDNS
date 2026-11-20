#!/usr/bin/env bash
# ==============================================================================
# Модуль 11: Сервис и автообновление стека (локально + синхронно на весь кластер)
# ==============================================================================

mod_service_update_local() {
    log_step "Автообновление стека Server-Combain на этом сервере"
    state_load_silent

    # 1. Подтягиваем свежую версию репозитория (если это git-клон)
    if [[ -d "${PROJECT_ROOT}/.git" ]]; then
        log_info "Обновление кода из Git (${PROJECT_ROOT})..."
        git -C "${PROJECT_ROOT}" config core.fileMode false 2>/dev/null || true
        if git -C "${PROJECT_ROOT}" pull --ff-only; then
            find "${PROJECT_ROOT}" -type f \( -name "*.sh" -o -name "*.py" \) -exec sed -i 's/\r$//' {} + 2>/dev/null || true
            chmod +x "${PROJECT_ROOT}/combain.sh" "${PROJECT_ROOT}/install.sh" 2>/dev/null || true
            find "${PROJECT_ROOT}/scripts" -type f -name "*.sh" -exec chmod +x {} + 2>/dev/null || true
            find "${PROJECT_ROOT}/scripts" -type f -name "*.py" -exec chmod +x {} + 2>/dev/null || true
            ln -sf "${PROJECT_ROOT}/combain.sh" /usr/local/bin/combain 2>/dev/null || true
            ln -sf "${PROJECT_ROOT}/combain.sh" /usr/local/bin/comb 2>/dev/null || true
            log_ok "Репозиторий обновлен до $(git -C "${PROJECT_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'latest')."
        else
            log_warn "git pull --ff-only не выполнен (возможно есть локальные правки). Продолжаю переприменение текущего кода."
        fi
    fi

    # 2. Перезагружаем библиотеки и модули, чтобы применить свежие функции сразу
    source "${PROJECT_ROOT}/scripts/lib/common.sh"
    source "${PROJECT_ROOT}/scripts/lib/state.sh"
    source "${PROJECT_ROOT}/scripts/lib/firewall.sh"
    for _mod in "${PROJECT_ROOT}/scripts/modules/"*.sh; do
        [[ "$(basename "$_mod")" == "11_service_update.sh" ]] && continue
        # shellcheck disable=SC1090
        source "$_mod"
    done
    state_load_silent

    # 3. Автодоопределяем IPv6 и страну (для флагов и IPv6-маршрутов в подписке)
    if [[ -z "${SERVER_IPV6:-}" ]] && declare -f detect_server_ipv6 >/dev/null 2>&1; then
        local v6=""
        v6="$(detect_server_ipv6 || true)"
        [[ -n "$v6" ]] && state_set "SERVER_IPV6" "$v6"
    fi
    if [[ -z "${SERVER_COUNTRY:-}" ]] && declare -f detect_server_country >/dev/null 2>&1; then
        local cc=""
        cc="$(detect_server_country || true)"
        [[ -n "$cc" ]] && state_set "SERVER_COUNTRY" "$cc"
    fi

    # 4. Переприменяем Nginx конфиг
    if declare -f _render_nginx_conf >/dev/null 2>&1 && [[ -n "${BASE_DOMAIN:-}" ]]; then
        log_info "Обновление конфигурации Nginx..."
        _render_nginx_conf
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^combain-nginx$'; then
            if docker exec combain-nginx nginx -t >/dev/null 2>&1; then
                docker exec combain-nginx nginx -s reload >/dev/null 2>&1 || docker restart combain-nginx >/dev/null
                log_ok "Nginx перезагружен с новым конфигом."
            else
                log_warn "Проверка nginx -t не прошла! Проверьте ${STATE_DIR}/nginx/conf.d/default.conf."
            fi
        fi
    fi

    # 5. Синхронизируем AdGuard Home (гео-домены + RU-телеметрия) и sniproxy (IPv4 + IPv6 [::]:443)
    if [[ -x /opt/AdGuardHome/AdGuardHome ]] && declare -f mod_adguard_apply_geo_preset >/dev/null 2>&1; then
        mod_adguard_apply_geo_preset || true
    fi
    if command -v sniproxy >/dev/null 2>&1 && declare -f mod_sniproxy_sync_domains >/dev/null 2>&1; then
        mod_sniproxy_sync_domains || true
    fi

    # 6. Переприменяем Xray / 3x-ui инбаунды и пересобираем подписки (/sub/ и /sub-json/)
    if [[ -n "${MAIN_CLIENT_UUID:-}" && -n "${REALITY_PRIVATE_KEY:-}" ]]; then
        if declare -f mod_xray_apply_inbounds >/dev/null 2>&1; then
            mod_xray_apply_inbounds || true
        fi
        if declare -f mod_xray_update_subscription >/dev/null 2>&1; then
            mod_xray_update_subscription || true
        fi
    fi

    # 7. Если включен Combain-Mesh — перезапускаем демон и синхронизируемся с пирами
    if [[ "${MESH_ENABLED:-0}" == "1" ]]; then
        if systemctl list-unit-files 2>/dev/null | grep -q '^combain-mesh\.service'; then
            systemctl restart combain-mesh >/dev/null 2>&1 || true
            log_ok "Служба combain-mesh перезапущена."
        fi
        if [[ -f "${PROJECT_ROOT}/scripts/mesh/combain_mesh.py" ]]; then
            python3 "${PROJECT_ROOT}/scripts/mesh/combain_mesh.py" sync-now --state-dir "${STATE_DIR}" >/dev/null 2>&1 || true
        fi
    fi

    # 8. Тихо обновляем сводку в last_summary.txt
    if declare -f mod_dashboard_save_summary >/dev/null 2>&1; then
        mod_dashboard_save_summary
    fi

    log_ok "Автообновление стека на этом сервере полностью завершено!"
}

mod_service_update_cluster() {
    log_step "Синхронное автообновление всего кластера Combain-Mesh"
    mod_service_update_local

    state_load_silent
    if [[ "${MESH_ENABLED:-0}" != "1" ]]; then
        log_info "Combain-Mesh на этом сервере не включен (обновлен только текущий сервер)."
        return 0
    fi
    if [[ ! -f "${PROJECT_ROOT}/scripts/mesh/combain_mesh.py" ]]; then
        log_warn "Скрипт combain_mesh.py не найден."
        return 1
    fi

    log_info "Отправка HMAC-подписанной команды обновления на все онлайн-ноды кластера..."
    python3 "${PROJECT_ROOT}/scripts/mesh/combain_mesh.py" cluster-update --state-dir "${STATE_DIR}"
}

mod_service_update_docker() {
    log_step "Обновление Docker-образов (Nginx, 3x-ui, MTProto, SOCKS5)"
    state_load_silent
    if [[ ! -f "${STATE_DIR}/docker-compose.yml" ]]; then
        log_warn "Файл ${STATE_DIR}/docker-compose.yml не найден."
        return 1
    fi
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" pull
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d
    log_ok "Docker-образы обновлены и контейнеры перезапущены."
}

mod_service_health_status() {
    state_load_silent
    echo ""
    echo -e "${CYAN}====================================================================${NC}"
    echo -e "${BOLD}   Статус всех служб Server-Combain${NC}"
    echo -e "${CYAN}====================================================================${NC}"
    local ver="unknown"
    [[ -d "${PROJECT_ROOT}/.git" ]] && ver="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    echo -e " Версия кода: ${GREEN}${ver}${NC}  |  IPv4: ${GREEN}${SERVER_IP:-?}${NC}  |  IPv6: ${GREEN}${SERVER_IPV6:-нет}${NC}  |  Страна: ${GREEN}${SERVER_COUNTRY:-?}${NC}"
    echo ""
    echo " Системные службы:"
    for svc in sniproxy AdGuardHome combain-mesh wg-quick@wg-mesh0 awg-quick@awg0; do
        local st
        st="$(systemctl is-active "$svc" 2>/dev/null || echo 'inactive')"
        printf "   %-22s : %s\n" "$svc" "$st"
    done
    echo ""
    echo " Docker-контейнеры:"
    if command -v docker >/dev/null 2>&1; then
        docker ps --format "   {{.Names}}\t{{.Status}}" 2>/dev/null | grep -E 'combain-' || echo "   (нет запущенных контейнеров combain-*)"
    fi
    echo ""
    echo " Открытые внешние TCP-порты (443 / 853):"
    ss -tln 2>/dev/null | grep -E ':(443|853)[[:space:]]' | sed 's/^/   /' || true
    echo -e "${CYAN}====================================================================${NC}"
}

mod_service_set_country() {
    state_load_silent
    echo ""
    echo -e "Текущий код страны (флаг в подписке): ${GREEN}${SERVER_COUNTRY:-не задан}${NC}"
    echo "Примеры: US (🇺🇸 США), DE (🇩🇪 Германия), NL (🇳🇱 Нидерланды), FI (🇫🇮 Финляндия), RU (🇷🇺 Россия), SE (🇸🇪), GB (🇬🇧)"
    local new_cc
    read -rp "Введите 2-буквенный ISO-код страны [US]: " new_cc
    new_cc="$(echo "${new_cc:-US}" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
    if [[ ! "$new_cc" =~ ^[A-Z]{2}$ ]]; then
        log_warn "Некорректный код страны (нужны ровно 2 латинские буквы, например US или DE)."
        return 1
    fi
    state_set "SERVER_COUNTRY" "$new_cc"
    if declare -f mod_xray_update_subscription >/dev/null 2>&1; then
        mod_xray_update_subscription || true
    fi
    if declare -f mod_dashboard_save_summary >/dev/null 2>&1; then
        mod_dashboard_save_summary
    fi
    log_ok "Страна сервера обновлена на '${new_cc}'. Подписки /sub/ и /sub-json/ пересобраны!"
}

mod_service_menu() {
    while true; do
        state_load_silent
        echo ""
        echo -e "${CYAN}====================================================================${NC}"
        echo -e "${BOLD}   Сервис и автообновление стека${NC}"
        echo -e "${CYAN}====================================================================${NC}"
        echo " 1) Обновить ЭТОТ сервер (git pull + переприменить Nginx, AdGuard, sniproxy, 3x-ui, подписки)"
        echo " 2) Синхронно обновить ВЕСЬ кластер Combain-Mesh (этот сервер + все онлайн-ноды)"
        echo " 3) Обновить Docker-образы (Nginx, 3x-ui, MTProto, SOCKS5)"
        echo " 4) Статус всех служб, контейнеров и портов"
        echo " 5) Сменить страну / флаг сервера в подписке (текущая: ${SERVER_COUNTRY:-авто})"
        echo " 0) Назад в главное меню"
        read -rp "Выберите действие [0-5]: " svc_choice

        case "$svc_choice" in
            1) mod_service_update_local ;;
            2) mod_service_update_cluster ;;
            3) mod_service_update_docker ;;
            4) mod_service_health_status ;;
            5) mod_service_set_country ;;
            0) return 0 ;;
            *) log_warn "Неверный выбор." ;;
        esac
    done
}
