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

    # 3. Освобождаем 127.0.0.53:53 от systemd-resolved, чтобы AdGuard Home мог занять порт 53
    if systemctl is-active --quiet systemd-resolved; then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-combain.conf <<'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
DNSStubListener=no
EOF
        systemctl restart systemd-resolved || true
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf || true
        log_ok "systemd-resolved stub listener отключен, порт 53 освобожден для AdGuard Home."
    fi

    # 4. Точечная защита внутренних портов через iptables
    fw_apply_base_rules
    log_ok "Модуль 01 успешно завершен."
}
