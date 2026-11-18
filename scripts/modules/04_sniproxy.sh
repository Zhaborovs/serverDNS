#!/usr/bin/env bash
# ==============================================================================
# Модуль 04: SNI Proxy — Главный TLS-мультиплексор на порту 443/tcp
# ------------------------------------------------------------------------------
# Назначение:
#   - Генерация /etc/sniproxy.conf на базе templates/sniproxy.conf.tpl
#   - Создание нативного systemd-юнита /etc/systemd/system/sniproxy.service (-f)
#   - Маршрутизация SNI:
#       * DNS_DOMAIN -> 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT} (Nginx vhost dns_agh.conf -> AdGuard 8444, защита от HTTP/2 Coalescing)
#       * BASE_DOMAIN и *.BASE_DOMAIN -> 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT}
#       * whitelist_sni.list (для VLESS-Reality) -> 127.0.0.1:${XRAY_REALITY_INTERNAL_PORT}
#       * geo_domains.list + кастомные + агрегированные Google/Microsoft -> *:443
#   - Инвариант: запрет глобального шаблона `.* *:443`
# ==============================================================================

_sniproxy_escape_regex() {
    printf '%s' "$1" | sed 's/\./\\./g'
}

_sniproxy_install_systemd_unit() {
    local bin_path
    bin_path="$(command -v sniproxy || echo '/usr/sbin/sniproxy')"

    cat > /etc/systemd/system/sniproxy.service <<EOF
[Unit]
Description=SNI Proxy TLS Multiplexer (Server-Combain)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${bin_path} -c /etc/sniproxy.conf -f
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl unmask sniproxy >/dev/null 2>&1 || true
    systemctl daemon-reload
}

mod_sniproxy_setup() {
    log_step "Модуль 04: Конфигурирование и запуск SNI Proxy на 443/tcp"
    state_load_silent
    _sniproxy_install_systemd_unit
    mod_sniproxy_sync_domains
}

mod_sniproxy_sync_domains() {
    state_load_silent
    log_info "Генерация /etc/sniproxy.conf из пресетов и шаблона..."

    if [[ ! -f /etc/systemd/system/sniproxy.service ]]; then
        _sniproxy_install_systemd_unit
    fi

    local custom_file="${STATE_DIR}/custom_geo_domains.list"
    local excluded_file="${STATE_DIR}/excluded_geo_domains.list"
    touch "$custom_file" "$excluded_file"

    local base_regex dns_regex dns_rules=""
    base_regex="$(_sniproxy_escape_regex "${BASE_DOMAIN}")"
    dns_regex="$(_sniproxy_escape_regex "${DNS_DOMAIN}")"

    if [[ -n "${DNS_DOMAIN:-}" && "${DNS_DOMAIN}" != "${BASE_DOMAIN}" ]]; then
        dns_rules="    ^${dns_regex}$ 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT:-8443}"
    else
        dns_rules="    # Single-domain режим: /dns-query проксируется через Nginx"
    fi

    # Правила для VLESS-Reality (проверенный синтаксис .*domain$ без круглых скобок)
    local whitelist_rules=""
    local reality_port="${XRAY_REALITY_INTERNAL_PORT:-20443}"
    local seen_sni=""
    if [[ -n "${REALITY_SNI:-}" ]]; then
        local r_esc
        r_esc="$(_sniproxy_escape_regex "${REALITY_SNI}")"
        whitelist_rules+="    .*${r_esc}\$ 127.0.0.1:${reality_port}"$'\n'
        seen_sni="${REALITY_SNI}"
    fi
    if [[ -f "${PROJECT_ROOT}/config/presets/whitelist_sni.list" ]]; then
        while IFS= read -r w_dom; do
            w_dom="$(printf '%s' "$w_dom" | tr -d '\r' | xargs)"
            [[ -z "$w_dom" || "$w_dom" == \#* || "$w_dom" == "$seen_sni" ]] && continue
            local w_esc
            w_esc="$(_sniproxy_escape_regex "$w_dom")"
            whitelist_rules+="    .*${w_esc}\$ 127.0.0.1:${reality_port}"$'\n'
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
        geo_rules+="    .*${g_esc}\$ *:443"$'\n'
    done <<< "$effective_domains"

    # Агрегированные регулярные выражения для поддоменов Google и Microsoft
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
    sleep 1

    if ss -tulnp | grep -qE ':443\s'; then
        log_ok "SNI Proxy успешно запущен и слушает порт 443/tcp."
    else
        log_warn "Не удалось подтвердить прослушивание порта 443/tcp! Последние логи sniproxy:"
        journalctl -u sniproxy -n 15 --no-pager || true
    fi
}
