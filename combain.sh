#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Главный интерактивный CLI-комбайн (точка входа)
# Использование:
#   combain             — открыть интерактивное меню
#   combain info        — вывести актуальную сводку настроек и ссылок
#   combain qr          — открыть меню показа QR-кодов подключений
#   combain mesh        — открыть меню кластера Combain-Mesh и пользователей
#   combain change-ip   — запустить мастер быстрой смены IP
#   combain migrate     — запустить мастер переезда / бэкапа (Drag&Drop)
# ==============================================================================
set -Eeuo pipefail

# Разрешаем реальный путь к корню проекта (учитывая симлинк /usr/local/bin/combain)
SOURCE_PATH="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE_PATH" ]]; do
    DIR="$(cd -P "$(dirname "$SOURCE_PATH")" && pwd)"
    SOURCE_PATH="$(readlink "$SOURCE_PATH")"
    [[ "$SOURCE_PATH" != /* ]] && SOURCE_PATH="${DIR}/${SOURCE_PATH}"
done
PROJECT_ROOT="$(cd -P "$(dirname "$SOURCE_PATH")" && pwd)"
export PROJECT_ROOT

# Подключаем базовые библиотеки
# shellcheck source=scripts/lib/common.sh
source "${PROJECT_ROOT}/scripts/lib/common.sh"
# shellcheck source=scripts/lib/state.sh
source "${PROJECT_ROOT}/scripts/lib/state.sh"
# shellcheck source=scripts/lib/firewall.sh
source "${PROJECT_ROOT}/scripts/lib/firewall.sh"

# Подключаем модули
for module_file in "${PROJECT_ROOT}/scripts/modules/"*.sh; do
    # shellcheck disable=SC1090
    source "$module_file"
done

require_root

print_banner() {
    clear || true
    local cur_ip
    cur_ip="$(detect_server_ip 2>/dev/null || echo 'не определен')"
    echo -e "${CYAN}====================================================================${NC}"
    echo -e "${BOLD}   SERVER-COMBAIN  |  DNS + SNIProxy + Xray/CDN + AWG 3.1 + Decoy${NC}"
    echo -e "${CYAN}====================================================================${NC}"
    echo -e " IP сервера: ${GREEN}${cur_ip}${NC}   |   Домен: ${GREEN}${BASE_DOMAIN:-не задан}${NC}"
    echo -e " Корень: ${PROJECT_ROOT}   |   Конфиг: ${STATE_FILE}"
    echo -e "${CYAN}--------------------------------------------------------------------${NC}"
}

menu_full_install() {
    log_step "Запуск полной установки Server-Combain с нуля..."
    state_init_interactive
    mod_sys_hardening_apply
    mod_ssl_nginx_setup
    mod_adguard_dns_setup
    mod_sniproxy_setup
    mod_xray_3xui_setup
    mod_amneziawg_setup
    mod_telegram_proxy_setup
    mod_dashboard_save_summary
}

menu_quick_change_ip() {
    log_step "Запуск мастера быстрой смены IP..."
    mod_backup_quick_change_ip
    mod_dashboard_save_summary
}

menu_migration_and_backup() {
    echo ""
    echo -e "${BOLD}--- Переезд со старого сервера и резервное копирование ---${NC}"
    echo " 1) Создать архив бэкапа (локально + временная ссылка на скачивание на 1 час)"
    echo " 2) Восстановить из бэкапа через Drag&Drop веб-страницу (активна 1 час)"
    echo " 3) Восстановить из бэкапа по URL или локальному пути (.tar.gz)"
    echo " 4) Стянуть бэкап напрямую со старого сервера по SSH/SCP"
    echo " 0) Назад"
    read -rp "Выберите действие [0-4]: " sub_choice
    case "$sub_choice" in
        1) mod_backup_create ;;
        2) mod_backup_start_drop_portal "upload" ;;
        3) mod_backup_restore_from_path_or_url ;;
        4) mod_backup_pull_ssh ;;
        0) return 0 ;;
        *) log_warn "Неверный выбор." ;;
    esac
}

menu_geo_domains() {
    echo ""
    echo -e "${BOLD}--- Управление доменами обхода геоблокировок (AdGuard + SNIProxy) ---${NC}"
    echo " 1) Применить/обновить полный пресет из config/presets/geo_domains.list"
    echo " 2) Добавить новый домен (синхронно в AdGuard Home и sniproxy.conf)"
    echo " 3) Удалить домен из списков обхода"
    echo " 4) Показать текущий список активных доменов"
    echo " 0) Назад"
    read -rp "Выберите действие [0-4]: " dom_choice
    case "$dom_choice" in
        1) mod_adguard_apply_geo_preset && mod_sniproxy_sync_domains ;;
        2) mod_adguard_add_domain_interactive && mod_sniproxy_sync_domains ;;
        3) mod_adguard_remove_domain_interactive && mod_sniproxy_sync_domains ;;
        4) mod_adguard_list_domains ;;
        0) return 0 ;;
        *) log_warn "Неверный выбор." ;;
    esac
}

menu_vpn_management() {
    echo ""
    echo -e "${BOLD}--- Управление VPN, CDN и Telegram Proxy ---${NC}"
    echo " 1) Настроить/обновить домены VK Cloud CDN и Yandex Cloud CDN"
    echo " 2) Добавить клиента AmneziaWG (AWG 3.1) и получить .conf / vpn://"
    echo " 3) Пересоздать ключи / порты Telegram Proxy (MTProto + SOCKS5)"
    echo " 4) Обновить файлы сайта-заглушки и загрузить пак видео-котиков"
    echo " 5) Показать инструкцию по настройке VK/Yandex CDN"
    echo " 6) Показать QR-коды подключений (Подписка / VLESS / AWG / TG)"
    echo " 7) Единая подписка: управление внешними нодами (2-3 сервера)"
    echo " 0) Назад"
    read -rp "Выберите действие [0-7]: " vpn_choice
    case "$vpn_choice" in
        1) mod_xray_configure_cdn_domains ;;
        2) mod_amneziawg_add_client ;;
        3) mod_telegram_proxy_setup "regen" ;;
        4) mod_ssl_nginx_update_decoy ;;
        5) less "${PROJECT_ROOT}/docs/cdn_whitelist_guide.md" || cat "${PROJECT_ROOT}/docs/cdn_whitelist_guide.md" ;;
        6) mod_dashboard_qr_menu ;;
        7) mod_xray_manage_extra_sub_nodes ;;
        0) return 0 ;;
        *) log_warn "Неверный выбор." ;;
    esac
}

menu_credentials() {
    state_load_silent
    while true; do
        echo ""
        echo -e "${BOLD}--- Логины и пароли сервисов ---${NC}"
        echo -e " AdGuard Home (https://${DNS_DOMAIN:-?}/):"
        echo -e "   Логин: ${GREEN}${AGH_USER:-dnsadmin}${NC}  |  Пароль: ${GREEN}${AGH_PASS:-не задан}${NC}"
        echo -e " Панель 3x-ui (https://${BASE_DOMAIN:-?}/${SECRET_PANEL_PATH:-?}/):"
        echo -e "   Логин: ${GREEN}${PANEL_USER:-admin}${NC}  |  Пароль: ${GREEN}${PANEL_PASS:-не задан}${NC}"
        echo ""
        echo " 1) Сменить логин / пароль AdGuard Home"
        echo " 2) Сменить логин / пароль панели 3x-ui"
        echo " 0) Назад"
        read -rp "Выберите действие [0-2]: " cred_choice
        case "$cred_choice" in
            1)
                local new_u new_p
                read -rp "Новый логин AdGuard Home [${AGH_USER:-dnsadmin}]: " new_u
                read -rp "Новый пароль AdGuard Home (Enter = сгенерировать случайный): " new_p
                new_u="${new_u:-${AGH_USER:-dnsadmin}}"
                new_p="${new_p:-$(gen_random_str 18)}"
                state_set "AGH_USER" "$new_u"
                state_set "AGH_PASS" "$new_p"
                if [[ -x /opt/AdGuardHome/AdGuardHome ]]; then
                    _agh_stop_safe
                    python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" init-config \
                        --config /opt/AdGuardHome/AdGuardHome.yaml \
                        --ip "${SERVER_IP}" \
                        --dns-domain "${DNS_DOMAIN}" \
                        --https-port "${AGH_INTERNAL_HTTPS_PORT:-8444}" \
                        --dot-port "${AGH_DOT_PORT:-853}" \
                        --user "$new_u" \
                        --password "$new_p"
                    _agh_start_safe
                fi
                log_ok "Логин и пароль AdGuard Home обновлены: ${new_u} / ${new_p}"
                ;;
            2)
                local new_xu new_xp
                read -rp "Новый логин 3x-ui [${PANEL_USER:-admin}]: " new_xu
                read -rp "Новый пароль 3x-ui (Enter = сгенерировать случайный): " new_xp
                new_xu="${new_xu:-${PANEL_USER:-admin}}"
                new_xp="${new_xp:-$(gen_random_str 18)}"
                state_set "PANEL_USER" "$new_xu"
                state_set "PANEL_PASS" "$new_xp"
                if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^combain-3xui$'; then
                    docker exec combain-3xui /app/x-ui setting -username "$new_xu" -password "$new_xp" >/dev/null
                    docker restart combain-3xui >/dev/null
                fi
                log_ok "Логин и пароль 3x-ui обновлены: ${new_xu} / ${new_xp}"
                ;;
            0) return 0 ;;
            *) log_warn "Неверный выбор." ;;
        esac
    done
}

interactive_loop() {
    while true; do
        state_load_silent
        print_banner
        echo " 1. Полная установка с нуля (DNS + Заглушка + Xray/3x-ui + CDN + AWG 3.1 + TG Proxy)"
        echo " 2. Быстрая смена IP (хостер заменил IP, домен остался тем же)"
        echo " 3. Переезд / Бэкап (Drag&Drop портал на 1 час, SSH-перенос, экспорт/импорт)"
        echo " 4. Управление доменами геоблока (AdGuard Home + SNIProxy синхронно)"
        echo " 5. Управление VPN и клиентами (Xray / VK-Yandex CDN / AmneziaWG / TG Proxy)"
        echo " 6. Сводка настроек, ссылок и доступов (подменю: DNS / Xray / AWG / TG)"
        echo " 7. Пароли и доступы (просмотр и смена логинов/паролей AdGuard и 3x-ui)"
        echo " 8. QR-коды подключений (показать QR для выбранного протокола / клиента)"
        echo " 9. Кластер Combain-Mesh и пользователи (P2P-сеть, подписки с лимитом устройств/дат)"
        echo " 10. Сервис и автообновление стека (обновление этого сервера / всего кластера)"
        echo " 0. Выход"
        echo ""
        read -rp "Выберите пункт [0-10]: " choice
        case "$choice" in
            1) menu_full_install ;;
            2) menu_quick_change_ip ;;
            3) menu_migration_and_backup ;;
            4) menu_geo_domains ;;
            5) menu_vpn_management ;;
            6) mod_dashboard_info_menu; continue ;;
            7) menu_credentials; continue ;;
            8) mod_dashboard_qr_menu; continue ;;
            9) mod_mesh_menu; continue ;;
            10) mod_service_menu; continue ;;
            0) exit 0 ;;
            *) log_warn "Некорректный пункт меню." ;;
        esac
        echo ""
        read -rp "Нажмите Enter для возврата в меню..." _
    done
}

main() {
    local cmd="${1:-}"
    local sub_arg="${2:-}"
    state_load_silent

    case "$cmd" in
        "")
            interactive_loop
            ;;
        info|show|status)
            mod_dashboard_show_info "$sub_arg"
            ;;
        qr|qrcode|qrcodes)
            mod_dashboard_qr_menu
            ;;
        mesh|cluster|users)
            mod_mesh_menu
            ;;
        service)
            mod_service_menu
            ;;
        update)
            if [[ "$sub_arg" == "--cluster" ]]; then
                mod_service_update_cluster
            else
                mod_service_update_local
            fi
            ;;
        change-ip)
            menu_quick_change_ip
            [[ -t 0 ]] && interactive_loop
            ;;
        migrate|backup)
            menu_migration_and_backup
            ;;
        install)
            menu_full_install
            [[ -t 0 ]] && interactive_loop
            ;;
        *)
            echo "Использование: combain [info [--all] | qr | mesh | service | update [--cluster] | install | change-ip | migrate]"
            exit 1
            ;;
    esac
}

main "$@"
