#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Главный интерактивный CLI-комбайн (точка входа)
# Использование:
#   combain             — открыть интерактивное меню
#   combain info        — вывести актуальную сводку настроек, ссылок и QR-кодов
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
    echo -e "${BOLD}   SERVER-COMBAIN  |  DNS + SNIProxy + Xray/CDN + AWG 2.0+ + Decoy${NC}"
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
    mod_dashboard_show_info
}

menu_quick_change_ip() {
    log_step "Запуск мастера быстрой смены IP..."
    mod_backup_quick_change_ip
    mod_dashboard_show_info
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
    echo " 2) Добавить клиента AmneziaWG (AWG 2.0+) и показать .conf / vpn:// / QR"
    echo " 3) Пересоздать ключи / порты Telegram Proxy (MTProto + SOCKS5)"
    echo " 4) Переключить фоновый серверный генератор сетевого шума"
    echo " 5) Показать инструкцию по настройке VK/Yandex CDN"
    echo " 0) Назад"
    read -rp "Выберите действие [0-5]: " vpn_choice
    case "$vpn_choice" in
        1) mod_xray_configure_cdn_domains ;;
        2) mod_amneziawg_add_client ;;
        3) mod_telegram_proxy_setup "regen" ;;
        4) mod_ssl_nginx_toggle_noise_daemon ;;
        5) less "${PROJECT_ROOT}/docs/cdn_whitelist_guide.md" || cat "${PROJECT_ROOT}/docs/cdn_whitelist_guide.md" ;;
        0) return 0 ;;
        *) log_warn "Неверный выбор." ;;
    esac
}

interactive_loop() {
    while true; do
        state_load_silent
        print_banner
        echo " 1. Полная установка с нуля (DNS + Заглушка + Xray/3x-ui + CDN + AWG 2.0+ + TG Proxy)"
        echo " 2. Быстрая смена IP (хостер заменил IP, домен остался тем же)"
        echo " 3. Переезд / Бэкап (Drag&Drop портал на 1 час, SSH-перенос, экспорт/импорт)"
        echo " 4. Управление доменами геоблока (AdGuard Home + SNIProxy синхронно)"
        echo " 5. Управление VPN и клиентами (Xray / VK-Yandex CDN / AmneziaWG / TG Proxy)"
        echo " 6. Показать полную сводку настроек, ссылок, паролей и QR-кодов (combain info)"
        echo " 0. Выход"
        echo ""
        read -rp "Выберите пункт [0-6]: " choice
        case "$choice" in
            1) menu_full_install ;;
            2) menu_quick_change_ip ;;
            3) menu_migration_and_backup ;;
            4) menu_geo_domains ;;
            5) menu_vpn_management ;;
            6) mod_dashboard_show_info ;;
            0) exit 0 ;;
            *) log_warn "Некорректный пункт меню." ;;
        esac
        echo ""
        read -rp "Нажмите Enter для возврата в меню..." _
    done
}

main() {
    local cmd="${1:-}"
    state_load_silent

    case "$cmd" in
        "")
            interactive_loop
            ;;
        info|show|status)
            mod_dashboard_show_info
            ;;
        change-ip)
            menu_quick_change_ip
            ;;
        migrate|backup)
            menu_migration_and_backup
            ;;
        install)
            menu_full_install
            ;;
        *)
            echo "Использование: combain [info | install | change-ip | migrate]"
            exit 1
            ;;
    esac
}

main "$@"
