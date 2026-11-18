#!/usr/bin/env bash
# ==============================================================================
# Модуль 01: Системная подготовка, топовый тюнинг ОС/сети и hardening
# ------------------------------------------------------------------------------
# Назначение:
#   - Повышение лимитов открытых файлов (nofile = 1048576) в limits.d и systemd
#   - Применение Google BBR, сетевых буферов 64 МБ, TCP FastOpen и запрет ICMP ping
#   - Отключение конфликтующего systemd-resolved stub-listener на порту 53
#   - Применение изолированной цепочки iptables (закрытие портов 53, 3000 и внутренних)
# Входные переменные (state.env):
#   DISABLE_ICMP_PING, AWG_SUBNET, NGINX_INTERNAL_HTTPS_PORT,
#   AGH_INTERNAL_HTTPS_PORT, XUI_INTERNAL_PORT, BACKUP_DROP_INTERNAL_PORT
# Выходные артефакты:
#   /etc/sysctl.d/99-server-combain.conf
#   /etc/security/limits.d/99-combain.conf
#   /etc/systemd/system.conf.d/99-combain.conf
#   /etc/systemd/resolved.conf.d/99-combain.conf
# Зависимости: scripts/lib/firewall.sh
# ==============================================================================

_sys_fix_dns_and_ipv4_precedence() {
    # 1. Отключаем stub-listener systemd-resolved на 53 порту и прописываем быстрый статический /etc/resolv.conf,
    #    чтобы мертвые IPv6/DHCP DNS-серверы хостера не вызывали задержку 10 секунд (2x5с) при резолве доменов.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-combain.conf <<'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
DNSStubListener=no
EOF
        systemctl restart systemd-resolved 2>/dev/null || true
    fi

    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<'EOF'
options timeout:1 attempts:2
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF

    # 2. Приоритет IPv4 над сломанным маршрутом IPv6 на уровне системного getaddrinfo (/etc/gai.conf)
    if [[ -f /etc/gai.conf ]]; then
        if ! grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100' /etc/gai.conf; then
            echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
        fi
    else
        echo "precedence ::ffff:0:0/96  100" > /etc/gai.conf
    fi
}

mod_sys_hardening_apply() {
    log_step "Модуль 01: Системный hardening, лимиты дескрипторов и Google BBR+"

    # 1. Повышение лимитов файловых дескрипторов (критично для Xray, sniproxy и AdGuard под нагрузкой)
    mkdir -p /etc/security/limits.d /etc/systemd/system.conf.d
    cat > /etc/security/limits.d/99-combain.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    cat > /etc/systemd/system.conf.d/99-combain.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF

    ulimit -n 1048576 2>/dev/null || true
    systemctl daemon-reexec 2>/dev/null || true
    log_ok "Лимиты файловых дескрипторов повышены до 1048576."

    # 2. Тюнинг ядра Linux и сетевого стека
    fw_apply_kernel_tuning

    # 3. Быстрый IPv4 DNS (1.1.1.1 / 8.8.8.8) без 10-секундных таймаутов хостера и освобождение порта 53
    _sys_fix_dns_and_ipv4_precedence
    log_ok "Быстрый системный DNS (1.1.1.1/8.8.8.8) и приоритет IPv4 настроены, порт 53 освобожден."

    # 4. Точечная защита внутренних портов через iptables
    fw_apply_base_rules
    log_ok "Модуль 01 успешно завершен."
}
