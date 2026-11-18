# ==============================================================================
# Server-Combain — Шаблон /etc/sniproxy.conf
# ИНВАРИАНТ 1: Запрещено использовать глобальный шаблон `.* *:443`!
# ИНВАРИАНТ 2: resolver обязан использовать внешний DNS (1.1.1.1),
#              чтобы избежать петли маршрутизации через локальный AdGuard Home!
# ==============================================================================

user daemon
pidfile /var/run/sniproxy.pid

error_log {
    syslog daemon
    priority notice
}

resolver {
    nameserver 1.1.1.1
    nameserver 8.8.8.8
    mode ipv4_only
}

listener 0.0.0.0:443 {
    proto tls
    table combain_sni
}

table combain_sni {
    # 1. Домен AdGuard Home (DoH + панель) — идет ПЕРЕД wildcard BASE_DOMAIN!
${DNS_DOMAIN_RULES}

    # 2. Собственные домены сервера (заглушка, 3x-ui, CDN origin, Drag&Drop) -> Nginx
    ^${BASE_DOMAIN_REGEX}$ 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT}
    ^.*\.${BASE_DOMAIN_REGEX}$ 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT}

    # 3. Домены белых списков (маскировка VLESS-Reality) -> Xray Reality
${WHITELIST_SNI_RULES}

    # 4. Домены обхода геоблокировок -> прозрачный проброс наружу
${GEO_DOMAIN_RULES}
}
