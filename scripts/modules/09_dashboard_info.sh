#!/usr/bin/env bash
# ==============================================================================
# Модуль 09: Сводка всей конфигурации, ссылок и паролей (combain info / qr)
# ------------------------------------------------------------------------------
# Назначение:
#   - Форматированный вывод всей инфраструктуры в SSH-терминал и в файл last_summary.txt
#   - Секретная панель 3x-ui, ссылки VLESS-Reality, Direct XHTTP, VK CDN и Yandex CDN
#   - Профили AmneziaWG (AWG 3.1): пути к .conf и нативные vpn:// ссылки
#   - Ссылки Telegram Proxy (MTProto Fake-TLS + SOCKS5)
#   - Памятка DoH/DoT/DoQ + команда PowerShell для Windows 11
#   - Отдельное интерактивное меню QR-кодов (combain qr / пункт меню 8)
# ==============================================================================

_dashboard_export_xray_links() {
    local cur_ip="$1"
    if [[ -z "${MAIN_CLIENT_UUID:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
        return 0
    fi
    python3 "${PROJECT_ROOT}/scripts/py_helpers/xui_db_manager.py" export-links \
        --server-ip "$cur_ip" \
        --base-domain "${BASE_DOMAIN:-}" \
        --uuid "${MAIN_CLIENT_UUID}" \
        --reality-sni "${REALITY_SNI:-sun9-73.userapi.com}" \
        --reality-public-key "${REALITY_PUBLIC_KEY}" \
        --reality-short-id "${REALITY_SHORT_ID:-00}" \
        --direct-tls-port "${XRAY_DIRECT_TLS_PORT:-2053}" \
        --direct-reality-port "${XRAY_DIRECT_REALITY_PORT:-2083}" \
        --vk-cdn-domain "${VK_CDN_DOMAIN:-}" \
        --vk-xhttp-path "${XHTTP_VK_PATH:-}" \
        --vk-ws-path "${WS_VK_PATH:-}" \
        --ya-cdn-domain "${YA_CDN_DOMAIN:-}" \
        --ya-xhttp-path "${XHTTP_YA_PATH:-}" \
        --ya-ws-path "${WS_YA_PATH:-}" 2>/dev/null || true
}

_qr_show_payload() {
    local title="$1"
    local payload="$2"
    echo ""
    echo -e "${CYAN}=== ${title} ===${NC}"
    echo "$payload"
    echo ""
    print_qr_if_available "$payload"
}

mod_dashboard_show_info() {
    state_load_silent
    if [[ -n "${BASE_DOMAIN:-}" && -n "${MAIN_CLIENT_UUID:-}" ]] && declare -f mod_xray_update_subscription >/dev/null 2>&1; then
        mod_xray_update_subscription >/dev/null 2>&1 || true
        state_load_silent
    fi
    local summary_file="${STATE_DIR}/last_summary.txt"

    local cur_ip="${SERVER_IP:-$(detect_server_ip)}"
    local base_dom="${BASE_DOMAIN:-НЕ_ЗАДАН}"
    local dns_dom="${DNS_DOMAIN:-$base_dom}"
    local sub_url="не задана"
    local sub_json_url="не задана"
    if [[ "$base_dom" != "НЕ_ЗАДАН" && -n "${SUB_TOKEN:-}" ]]; then
        sub_url="https://${base_dom}/sub/${SUB_TOKEN}"
        sub_json_url="https://${base_dom}/sub-json/${SUB_TOKEN}"
    fi

    local xray_links=""
    xray_links="$(_dashboard_export_xray_links "$cur_ip")"

    local mtg_tg="tg://proxy?server=${cur_ip}&port=${MTPROTO_PORT:-18445}&secret=${MTPROTO_SECRET:-PENDING}"
    local mtg_web="https://t.me/proxy?server=${cur_ip}&port=${MTPROTO_PORT:-18445}&secret=${MTPROTO_SECRET:-PENDING}"
    local socks_tg="tg://socks?server=${cur_ip}&port=${SOCKS5_PORT:-10808}&user=${SOCKS5_USER:-tguser}&pass=${SOCKS5_PASS:-PENDING}"
    local socks_web="https://t.me/socks?server=${cur_ip}&port=${SOCKS5_PORT:-10808}&user=${SOCKS5_USER:-tguser}&pass=${SOCKS5_PASS:-PENDING}"

    local default_awg_vpn=""
    if [[ -f "${STATE_DIR}/clients/awg_default.vpn" ]]; then
        default_awg_vpn="$(cat "${STATE_DIR}/clients/awg_default.vpn")"
    fi

    {
        echo "========================================================================"
        echo "              SERVER-COMBAIN — СВОДКА НАСТРОЕК СЕРВЕРА"
        echo "========================================================================"
        echo "Внешний IPv4:       ${cur_ip} (ICMP Ping отключен)"
        echo "Сайт-заглушка:      https://${base_dom}/  (NetPulse SpeedTest + Рогалик «Лапки и Руны»)"
        echo "DNS домен:          ${dns_dom}"
        echo ""
        echo "--- [1] УМНЫЙ DNS (AdGuard Home + SNI Proxy на 443 порту) ---"
        echo "DoH URL:            https://${dns_dom}/dns-query"
        echo "DoT / DoQ (853):    tls://${dns_dom}:853  |  quic://${dns_dom}:853"
        echo "DoT / DoQ (Кастом): tls://${dns_dom}:${AGH_CUSTOM_DOT_PORT:-8853}"
        if [[ "$dns_dom" != "$base_dom" ]]; then
            echo "Веб-панель AdGuard: https://${dns_dom}/"
        else
            echo "Веб-панель AdGuard: доступна локально (туннель на 127.0.0.1:3000)"
        fi
        echo "Логин / Пароль:     ${AGH_USER:-dnsadmin} / ${AGH_PASS:-не задан}"
        echo ""
        echo "Команда настройки DoH в Windows 11 (PowerShell от Администратора):"
        echo "Add-DnsClientDohServerAddress -ServerAddress '${cur_ip}' -DohTemplate 'https://${dns_dom}/dns-query' -AllowFallbackToUdp \$False -AutoUpgrade \$True; Clear-DnsClientCache"
        echo ""
        echo "--- [2] СКРЫТАЯ ПАНЕЛЬ 3x-ui И XRAY (Reality + VK/Yandex CDN) ---"
        echo "URL панели 3x-ui:   https://${base_dom}/${SECRET_PANEL_PATH:-adm}/"
        echo "Логин / Пароль:     ${PANEL_USER:-admin} / ${PANEL_PASS:-не задан}"
        echo "Единая подписка:    ${sub_url}  (Base64: Happ / Hiddify / v2RayTun)"
        echo "JSON-подписка ТСПУ: ${sub_json_url}  (Xray JSON с TCP 1-1 фрагментацией для v2RayTun / v2rayNG)"
        if [[ -n "$xray_links" ]]; then
            echo "$xray_links"
        else
            echo "Ссылки Xray еще не сгенерированы (запустите установку модуля 05)."
        fi
        echo "Пути CDN (для настройки в панели VK/Yandex Cloud):"
        echo "  * VK Cloud CDN:     /${XHTTP_VK_PATH:-?} (XHTTP GET-only, POST и WS не нужны)"
        echo "  * Yandex Cloud CDN: /${XHTTP_YA_PATH:-?} (XHTTP) | /${WS_YA_PATH:-?} (WS)"
        echo ""
        echo "--- [3] AmneziaWG (AWG 3.1 с обфускацией и локальным DNS) ---"
        echo "UDP порт:           ${AWG_PORT:-не задан}"
        echo "Подсеть / DNS:      ${AWG_SUBNET:-10.8.1.0/24} (DNS внутри туннеля: ${AWG_SERVER_IP:-10.8.1.1})"
        echo "Профили (.conf):    ${STATE_DIR}/clients/"
        if [[ -n "$default_awg_vpn" ]]; then
            echo "AmneziaVPN (default): ${default_awg_vpn}"
        fi
        echo ""
        echo "--- [4] TELEGRAM PROXY (MTProto Fake-TLS + SOCKS5) ---"
        echo "MTProto (Fake-TLS): ${mtg_web}"
        echo "MTProto (App):      ${mtg_tg}"
        echo "SOCKS5 (Звонки):    ${socks_web}"
        echo "SOCKS5 (App):       ${socks_tg}"
        echo "========================================================================"
        echo "Памятка сохранена в ${summary_file}. Сводка: combain info | QR-коды: combain qr"
    } | tee "$summary_file"
}

mod_dashboard_qr_menu() {
    while true; do
        state_load_silent
        local cur_ip="${SERVER_IP:-$(detect_server_ip)}"
        local xray_links=""
        xray_links="$(_dashboard_export_xray_links "$cur_ip")"

        local reality_uri="" direct_xhttp_uri="" direct_ws_uri="" vk_cdn_uri="" ya_cdn_uri="" ya_ws_uri=""
        while IFS= read -r line; do
            case "$line" in
                *"#Combain-Reality")      reality_uri="${line#*: }" ;;
                *"#Combain-Direct-XHTTP") direct_xhttp_uri="${line#*: }" ;;
                *"#Combain-Direct-WS")    direct_ws_uri="${line#*: }" ;;
                *"#VK-CDN-XHTTP")         vk_cdn_uri="${line#*: }" ;;
                *"#Yandex-CDN-XHTTP")     ya_cdn_uri="${line#*: }" ;;
                *"#Yandex-CDN-WS")        ya_ws_uri="${line#*: }" ;;
            esac
        done <<< "$xray_links"

        local sub_uri="" sub_json_uri=""
        if [[ -n "${BASE_DOMAIN:-}" && -n "${SUB_TOKEN:-}" ]]; then
            sub_uri="https://${BASE_DOMAIN}/sub/${SUB_TOKEN}"
            sub_json_uri="https://${BASE_DOMAIN}/sub-json/${SUB_TOKEN}"
        fi
        local mtg_web=""
        [[ -n "${MTPROTO_SECRET:-}" ]] && mtg_web="https://t.me/proxy?server=${cur_ip}&port=${MTPROTO_PORT:-18445}&secret=${MTPROTO_SECRET}"
        local socks_web=""
        [[ -n "${SOCKS5_PASS:-}" ]] && socks_web="https://t.me/socks?server=${cur_ip}&port=${SOCKS5_PORT:-10808}&user=${SOCKS5_USER:-tguser}&pass=${SOCKS5_PASS}"

        echo ""
        echo -e "${BOLD}--- QR-коды подключений (выберите нужный) ---${NC}"
        echo " 1) Единая подписка (Base64 + JSON с анти-ТСПУ фрагментацией)"
        echo " 2) VLESS-Reality (Self-Steal / прямой с маскировкой)"
        echo " 3) VLESS-XHTTP (скоростной stream-one через домен)"
        echo " 4) VLESS-WS (резервный WebSocket через домен)"
        echo " 5) VK Cloud CDN (XHTTP GET-режим)"
        echo " 6) Yandex Cloud CDN (XHTTP / WS)"
        echo " 7) AmneziaWG 3.1 (выбор клиентского профиля)"
        echo " 8) Telegram MTProto Proxy"
        echo " 9) Telegram SOCKS5 Proxy"
        echo " 0) Назад"
        read -rp "Выберите QR-код [0-9]: " qr_choice

        local shown="true"
        case "$qr_choice" in
            1)
                if [[ -n "$sub_uri" ]]; then
                    _qr_show_payload "QR-код Единой подписки (Base64 URI)" "$sub_uri"
                    _qr_show_payload "QR-код JSON-подписки с анти-ТСПУ фрагментацией (v2RayTun / v2rayNG)" "$sub_json_uri"
                else
                    log_warn "Единая подписка еще не сформирована (проверьте BASE_DOMAIN и модуль 05)."
                    shown="false"
                fi
                ;;
            2)
                if [[ -n "$reality_uri" ]]; then
                    _qr_show_payload "QR-код VLESS-Reality" "$reality_uri"
                else
                    log_warn "Ссылка VLESS-Reality еще не сгенерирована (запустите модуль 05)."
                    shown="false"
                fi
                ;;
            3)
                if [[ -n "$direct_xhttp_uri" ]]; then
                    _qr_show_payload "QR-код VLESS-XHTTP (Direct stream-one)" "$direct_xhttp_uri"
                else
                    log_warn "Прямая ссылка XHTTP еще не сгенерирована (проверьте BASE_DOMAIN и модуль 05)."
                    shown="false"
                fi
                ;;
            4)
                if [[ -n "$direct_ws_uri" ]]; then
                    _qr_show_payload "QR-код VLESS-WS (Direct WebSocket)" "$direct_ws_uri"
                else
                    log_warn "Прямая ссылка WS еще не сгенерирована (проверьте BASE_DOMAIN и модуль 05)."
                    shown="false"
                fi
                ;;
            5)
                if [[ -n "$vk_cdn_uri" ]]; then
                    _qr_show_payload "QR-код VK Cloud CDN (XHTTP GET)" "$vk_cdn_uri"
                else
                    log_warn "Домен VK Cloud CDN не настроен. Задайте его в меню: 5 -> 1."
                    shown="false"
                fi
                ;;
            6)
                if [[ -n "$ya_cdn_uri" ]]; then
                    _qr_show_payload "QR-код Yandex Cloud CDN (XHTTP)" "$ya_cdn_uri"
                    [[ -n "$ya_ws_uri" ]] && _qr_show_payload "QR-код Yandex Cloud CDN (WS)" "$ya_ws_uri"
                else
                    log_warn "Домен Yandex Cloud CDN не настроен. Задайте его в меню: 5 -> 1."
                    shown="false"
                fi
                ;;
            7)
                local -a awg_files=()
                mapfile -t awg_files < <(find "${STATE_DIR}/clients" -maxdepth 1 -type f -name 'awg_*.vpn' 2>/dev/null | sort || true)
                if [[ "${#awg_files[@]}" -eq 0 ]]; then
                    log_warn "Профили AmneziaWG не найдены в ${STATE_DIR}/clients/ (запустите модуль 06)."
                    shown="false"
                elif [[ "${#awg_files[@]}" -eq 1 ]]; then
                    local cname
                    cname="$(basename "${awg_files[0]}" .vpn)"
                    cname="${cname#awg_}"
                    _qr_show_payload "QR-код AmneziaWG 3.1 (${cname})" "$(cat "${awg_files[0]}")"
                else
                    echo ""
                    echo "Доступные профили AmneziaWG 3.1:"
                    local i=1 f cname
                    for f in "${awg_files[@]}"; do
                        cname="$(basename "$f" .vpn)"
                        cname="${cname#awg_}"
                        echo "  ${i}) ${cname}"
                        ((i++))
                    done
                    read -rp "Выберите профиль [1-${#awg_files[@]}, Enter = 1]: " awg_idx
                    awg_idx="${awg_idx:-1}"
                    if [[ "$awg_idx" =~ ^[0-9]+$ ]] && (( awg_idx >= 1 && awg_idx <= ${#awg_files[@]} )); then
                        f="${awg_files[$((awg_idx - 1))]}"
                        cname="$(basename "$f" .vpn)"
                        cname="${cname#awg_}"
                        _qr_show_payload "QR-код AmneziaWG 3.1 (${cname})" "$(cat "$f")"
                    else
                        log_warn "Неверный номер профиля."
                        shown="false"
                    fi
                fi
                ;;
            8)
                if [[ -n "$mtg_web" ]]; then
                    _qr_show_payload "QR-код Telegram MTProto Proxy" "$mtg_web"
                else
                    log_warn "MTProto Proxy еще не настроен (запустите модуль 07)."
                    shown="false"
                fi
                ;;
            9)
                if [[ -n "$socks_web" ]]; then
                    _qr_show_payload "QR-код Telegram SOCKS5 Proxy" "$socks_web"
                else
                    log_warn "SOCKS5 Proxy еще не настроен (запустите модуль 07)."
                    shown="false"
                fi
                ;;
            0)
                return 0
                ;;
            *)
                log_warn "Неверный выбор."
                shown="false"
                ;;
        esac

        if [[ "$shown" == "true" ]]; then
            echo ""
            read -rp "Нажмите Enter, чтобы вернуться к списку QR-кодов..." _
        fi
    done
}
