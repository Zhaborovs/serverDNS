#!/usr/bin/env bash
# ==============================================================================
# Модуль 04: SNI Proxy — Главный TLS-мультиплексор на порту 443/tcp
# ------------------------------------------------------------------------------
# Назначение:
#   - Генерация /etc/sniproxy.conf на базе templates/sniproxy.conf.tpl
#   - Маршрутизация SNI:
#       * DNS_DOMAIN (если отличается от BASE_DOMAIN) -> 127.0.0.1:${AGH_INTERNAL_HTTPS_PORT}
#       * BASE_DOMAIN и *.BASE_DOMAIN -> 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT}
#       * whitelist_sni.list (для VLESS-Reality) -> 127.0.0.1:${XRAY_REALITY_INTERNAL_PORT}
#       * geo_domains.list + кастомные + агрегированные Google/Microsoft -> *:443
#   - Инвариант: запрет глобального шаблона `.* *:443`
# Входные переменные (state.env):
#   BASE_DOMAIN, DNS_DOMAIN, NGINX_INTERNAL_HTTPS_PORT,
#   AGH_INTERNAL_HTTPS_PORT, XRAY_REALITY_INTERNAL_PORT, REALITY_SNI
# Выходные артефакты:
#   /etc/sniproxy.conf, systemd сервис sniproxy на 0.0.0.0:443
# Зависимости: templates/sniproxy.conf.tpl, scripts/py_helpers/agh_config_manager.py
# ==============================================================================

_sniproxy_escape_regex() {
    printf '%s' "$1" | sed 's/\./\\./g'
}

_sniproxy_ensure_enabled() {
    if [[ -f /etc/default/sniproxy ]]; then
        sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/sniproxy || true
    fi
    if [[ -f /etc/init.d/sniproxy ]] && ! grep -q '^DAEMON_ARGS=.*-c' /etc/default/sniproxy 2>/dev/null; then
        echo 'DAEMON_ARGS="-c /etc/sniproxy.conf"' >> /etc/default/sniproxy 2>/dev/null || true
    fi
}

mod_sniproxy_setup() {
    log_step "Модуль 04: Конфигурирование и запуск SNI Proxy на 443/tcp"
    state_load_silent
    _sniproxy_ensure_enabled
    mod_sniproxy_sync_domains
}

mod_sniproxy_sync_domains() {
    state_load_silent
    log_info "Генерация /etc/sniproxy.conf из пресетов и шаблона..."

    local custom_file="${STATE_DIR}/custom_geo_domains.list"
    local excluded_file="${STATE_DIR}/excluded_geo_domains.list"
    touch "$custom_file" "$excluded_file"

    local base_regex dns_regex dns_rules=""
    base_regex="$(_sniproxy_escape_regex "${BASE_DOMAIN}")"
    dns_regex="$(_sniproxy_escape_regex "${DNS_DOMAIN}")"

    if [[ -n "${DNS_DOMAIN:-}" && "${DNS_DOMAIN}" != "${BASE_DOMAIN}" ]]; then
        dns_rules="    ^${dns_regex}$ 127.0.0.1:${AGH_INTERNAL_HTTPS_PORT:-8444}"
    else
        dns_rules="    # Single-domain режим: /dns-query проксируется через Nginx"
    fi

    # Правила для VLESS-Reality (SNI из белого списка -> 127.0.0.1:20443)
    local whitelist_rules=""
    local reality_port="${XRAY_REALITY_INTERNAL_PORT:-20443}"
    local seen_sni=""
    if [[ -n "${REALITY_SNI:-}" ]]; then
        local r_esc
        r_esc="$(_sniproxy_escape_regex "${REALITY_SNI}")"
        whitelist_rules+="    ^${r_esc}\$ 127.0.0.1:${reality_port}"$'\n'
        seen_sni="${REALITY_SNI}"
    fi
    if [[ -f "${PROJECT_ROOT}/config/presets/whitelist_sni.list" ]]; then
        while IFS= read -r w_dom; do
            w_dom="$(printf '%s' "$w_dom" | tr -d '\r' | xargs)"
            [[ -z "$w_dom" || "$w_dom" == \#* || "$w_dom" == "$seen_sni" ]] && continue
            local w_esc
            w_esc="$(_sniproxy_escape_regex "$w_dom")"
            whitelist_rules+="    ^(.*\\.)?${w_esc}\$ 127.0.0.1:${reality_port}"$'\n'
        done < "${PROJECT_ROOT}/config/presets/whitelist_sni.list"
    fi

    # Правила обхода геоблокировок (строго из активного списка + агрегированные паттерны Google/MS)
    local geo_rules=""
    local effective_domains
    effective_domains="$(python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" list-effective \
        --preset "${PROJECT_ROOT}/config/presets/geo_domains.list" \
        --custom "$custom_file" \
        --excluded "$excluded_file")"

    while IFS= read -r g_dom; do
        [[ -z "$g_dom" ]] && continue
        local g_esc
        g_esc="$(_sniproxy_escape_regex "$g_dom")"
        geo_rules+="    ^(.*\\.)?${g_esc}\$ *:443"$'\n'
    done <<< "$effective_domains"

    # Агрегированные регулярные выражения для поддоменов Google и Microsoft (из legacy-архитектуры)
    geo_rules+="    .*google\\.com\$ *:443"$'\n'
    geo_rules+="    .*googleapis\\.com\$ *:443"$'\n'
    geo_rules+="    .*google\$ *:443"$'\n'
    geo_rules+="    .*goog\$ *:443"$'\n'
    geo_rules+="    .*gstatic\\.com\$ *:443"$'\n'
    geo_rules+="    .*microsoft\\.com\$ *:443"$'\n'

    # Безопасная сборка /etc/sniproxy.conf через python для точной подстановки многострочных блоков
    python3 - "${PROJECT_ROOT}/templates/sniproxy.conf.tpl" "/etc/sniproxy.conf" \
        "$base_regex" "${NGINX_INTERNAL_HTTPS_PORT:-8443}" "$dns_rules" "$whitelist_rules" "$geo_rules" <<'PYEOF'
import sys
from pathlib import Path

tpl_path, out_path, base_rx, nginx_port, dns_rules, wl_rules, geo_rules = sys.argv[1:]
content = Path(tpl_path).read_text(encoding="utf-8")
content = (
    content.replace("${BASE_DOMAIN_REGEX}", base_rx)
    .replace("${NGINX_INTERNAL_HTTPS_PORT}", nginx_port)
    .replace("${DNS_DOMAIN_RULES}", dns_rules.rstrip())
    .replace("${WHITELIST_SNI_RULES}", wl_rules.rstrip())
    .replace("${GEO_DOMAIN_RULES}", geo_rules.rstrip())
)
Path(out_path).write_text(content, encoding="utf-8")
PYEOF

    log_info "Перезапуск службы sniproxy..."
    killall sniproxy 2>/dev/null || true
    systemctl enable sniproxy >/dev/null 2>&1 || true
    systemctl restart sniproxy

    if ss -tulnp | grep -qE '0\.0\.0\.0:443\s|:::443\s'; then
        log_ok "SNI Proxy успешно запущен и слушает порт 443/tcp."
    else
        log_warn "Не удалось подтвердить прослушивание порта 443/tcp — проверьте 'systemctl status sniproxy'."
    fi
}
