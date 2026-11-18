#!/usr/bin/env bash
# ==============================================================================
# Server-Combain — Безопасное идемпотентное управление iptables и тюнинг ядра
# ИНВАРИАНТ: Никогда не использовать `iptables -F` и `ufw enable` поверх Docker
# и AmneziaVPN! Только изолированная цепочка COMBAIN-PROTECT.
# ==============================================================================

fw_ensure_rule() {
    local args=("$@")
    if ! iptables -C "${args[@]}" 2>/dev/null; then
        iptables -A "${args[@]}"
    fi
}

# Топовый тюнинг ядра Linux и сетевого стека (Google BBR, буферы 64MB, защита от SYN-flood, откл. ICMP ping)
fw_apply_kernel_tuning() {
    local sysctl_conf="/etc/sysctl.d/99-server-combain.conf"
    local disable_ping="${DISABLE_ICMP_PING:-true}"
    local icmp_val="0"
    [[ "$disable_ping" == "true" ]] && icmp_val="1"

    # Загружаем модуль nf_conntrack и tcp_bbr заранее, чтобы sysctl применил все ключи без ошибок
    modprobe nf_conntrack 2>/dev/null || true
    modprobe tcp_bbr 2>/dev/null || true

    cat > "$sysctl_conf" <<EOF
# Server-Combain: Google BBR + сетевая оптимизация + hardening
net.ipv4.icmp_echo_ignore_all = ${icmp_val}
net.ipv4.icmp_echo_ignore_broadcasts = ${icmp_val}
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.ip_forward = 1

# Google BBR + Fair Queue
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Оптимизация TCP / UDP для высоконагруженного прокси и VPN
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 10240 65535

# Увеличенные буферы (до 64 МБ) для скоростных каналов и XHTTP/AWG
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Очереди и conntrack
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.netfilter.nf_conntrack_max = 262144
EOF

    sysctl --system >/dev/null 2>&1 || sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
    log_ok "Тюнинг ядра (BBR, буферы 64МБ, TCP FastOpen, ICMP=${icmp_val}) применен."
}

# Алиас для обратной совместимости
fw_disable_icmp_ping() {
    fw_apply_kernel_tuning
}

# Защита внутренних портов (53, 3000, Nginx/AGH/Xray/Drop) в изолированной цепочке
fw_apply_base_rules() {
    local awg_subnet="${AWG_SUBNET:-10.8.1.0/24}"
    local amnezia_app_subnet="172.29.172.0/24"
    local chain="COMBAIN-PROTECT"

    # Создаем или очищаем только нашу изолированную цепочку (не затрагивая INPUT/DOCKER/AWG)
    iptables -N "$chain" 2>/dev/null || iptables -F "$chain"
    if ! iptables -C INPUT -j "$chain" 2>/dev/null; then
        iptables -I INPUT 1 -j "$chain"
    fi

    # 1. Порт 53 (DNS): разрешаем только loopback, нашу подсеть AWG и подсеть нативного приложения AmneziaVPN (amn0)
    for proto in udp tcp; do
        iptables -A "$chain" -i lo -p "$proto" --dport 53 -j ACCEPT
        iptables -A "$chain" -s "$awg_subnet" -p "$proto" --dport 53 -j ACCEPT
        iptables -A "$chain" -s "$amnezia_app_subnet" -p "$proto" --dport 53 -j ACCEPT
        iptables -A "$chain" -p "$proto" --dport 53 -j DROP
    done

    # 2. Порт 3000 (резервный HTTP AdGuard) и внутренние порты сервисов — только loopback
    local internal_ports=(
        "3000"
        "${NGINX_INTERNAL_HTTPS_PORT:-8443}"
        "${AGH_INTERNAL_HTTPS_PORT:-8444}"
        "${BACKUP_DROP_INTERNAL_PORT:-20999}"
    )
    [[ -n "${XUI_INTERNAL_PORT:-}" ]] && internal_ports+=("${XUI_INTERNAL_PORT}")

    for port in "${internal_ports[@]}"; do
        iptables -A "$chain" -p tcp --dport "$port" ! -i lo -j DROP
    done

    # Диапазон внутренних инбаундов Xray (20443-20447) — только loopback
    iptables -A "$chain" -p tcp --dport 20443:20447 ! -i lo -j DROP

    # Возврат в основную цепочку INPUT для всего остального трафика
    iptables -A "$chain" -j RETURN

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 || true
    fi
    log_ok "Изолированная цепочка ${chain} применена (включая доступ DNS для подсети AmneziaVPN ${amnezia_app_subnet})."
}

# Проброс нестандартного порта DoT/DoQ (${AGH_CUSTOM_DOT_PORT}) на стандартный 853 AdGuard Home
fw_setup_dot_redirect() {
    local custom_port="${1:-${AGH_CUSTOM_DOT_PORT:-}}"
    [[ -z "$custom_port" || "$custom_port" == "853" ]] && return 0

    local nat_chain="COMBAIN-NAT-DOT"
    iptables -t nat -N "$nat_chain" 2>/dev/null || iptables -t nat -F "$nat_chain"
    if ! iptables -t nat -C PREROUTING -j "$nat_chain" 2>/dev/null; then
        iptables -t nat -I PREROUTING 1 -j "$nat_chain"
    fi

    iptables -t nat -A "$nat_chain" -p tcp --dport "$custom_port" -j REDIRECT --to-ports 853
    iptables -t nat -A "$nat_chain" -p udp --dport "$custom_port" -j REDIRECT --to-ports 853
    iptables -t nat -A "$nat_chain" -j RETURN

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 || true
    fi
    log_ok "DoT/DoQ нестандартный порт ${custom_port} (TCP+UDP) перенаправлен на 853."
}
