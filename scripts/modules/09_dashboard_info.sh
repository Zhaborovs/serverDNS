#!/usr/bin/env bash
# ==============================================================================
# Модуль 09: Сводка всей конфигурации, ссылок, паролей и QR-кодов (combain info)
# ------------------------------------------------------------------------------
# Назначение:
#   - Форматированный вывод всей инфраструктуры в SSH-терминал и в файл last_summary.txt
#   - Секретная панель 3x-ui, ссылки VLESS-Reality, Direct XHTTP, VK CDN и Yandex CDN
#   - Профили AmneziaWG (AWG 3.1): пути к .conf и нативные vpn:// ссылки
#   - Ссылки Telegram Proxy (MTProto Fake-TLS + SOCKS5)
#   - Памятка DoH/DoT/DoQ + команда PowerShell для Windows 11
#   - QR-коды для мгновенного сканирования с телефона
# ==============================================================================

mod_dashboard_show_info() {
    state_load_silent
    local summary_file="${STATE_DIR}/last_summary.txt"

    local cur_ip="${SERVER_IP:-$(detect_server_ip)}"
    local base_dom="${BASE_DOMAIN:-НЕ_ЗАДАН}"
    local dns_dom="${DNS_DOMAIN:-$base_dom}"

    local xray_links=""
    if [[ -n "${MAIN_CLIENT_UUID:-}" && -n "${REALITY_PUBLIC_KEY:-}" ]]; then
        xray_links="$(python3 "${PROJECT_ROOT}/scripts/py_helpers/xui_db_manager.py" export-links \
            --server-ip "$cur_ip" \
            --base-domain "${BASE_DOMAIN:-}" \
            --uuid "${MAIN_CLIENT_UUID}" \
            --reality-sni "${REALITY_SNI:-sun9-73.userapi.com}" \
            --reality-public-key "${REALITY_PUBLIC_KEY}" \
            --reality-short-id "${REALITY_SHORT_ID:-00}" \
            --vk-cdn-domain "${VK_CDN_DOMAIN:-}" \
            --vk-xhttp-path "${XHTTP_VK_PATH:-}" \
            --vk-ws-path "${WS_VK_PATH:-}" \
            --ya-cdn-domain "${YA_CDN_DOMAIN:-}" \
            --ya-xhttp-path "${XHTTP_YA_PATH:-}" \
            --ya-ws-path "${WS_YA_PATH:-}" 2>/dev/null || true)"
    fi

    local reality_uri=""
    reality_uri="$(printf '%s\n' "$xray_links" | awk -F': ' '/VLESS-Reality/{print $2; exit}')"

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
        echo "Памятка сохранена в ${summary_file}. Повторный вывод: combain info"
    } | tee "$summary_file"

    if [[ -n "$reality_uri" ]]; then
        echo ""
        echo -e "${CYAN}QR-код VLESS-Reality:${NC}"
        print_qr_if_available "$reality_uri"
    fi

    if [[ -n "$default_awg_vpn" ]]; then
        echo ""
        echo -e "${CYAN}QR-код AmneziaWG 3.1 (default):${NC}"
        print_qr_if_available "$default_awg_vpn"
    fi

    if [[ -n "${MTPROTO_SECRET:-}" ]]; then
        echo ""
        echo -e "${CYAN}QR-код Telegram MTProto Proxy:${NC}"
        print_qr_if_available "$mtg_web"
    fi
}
