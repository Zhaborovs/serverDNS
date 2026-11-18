#!/usr/bin/env bash
# ==============================================================================
# Модуль 07: Telegram Proxy (MTProto Fake-TLS + SOCKS5 с авторизацией)
# ------------------------------------------------------------------------------
# Назначение:
#   - Генерация Fake-TLS секрета (nineseconds/mtg:2) с маскировкой под белый список
#   - Развертывание контейнеров combain-mtproto (MTProto) и combain-socks5 (звонки/медиа)
#   - Автогенерация ссылок tg://proxy, https://t.me/proxy, tg://socks, https://t.me/socks
# Входные переменные (state.env):
#   SERVER_IP, MTPROTO_PORT, MTPROTO_FAKE_SNI, MTPROTO_SECRET,
#   SOCKS5_PORT, SOCKS5_USER, SOCKS5_PASS, MTG_IMAGE, SOCKS5_IMAGE
# Выходные артефакты:
#   Контейнеры Docker combain-mtproto и combain-socks5, MTPROTO_SECRET в state.env
# ==============================================================================

_tg_generate_faketls_secret() {
    local fake_sni="${1:-yandex.ru}"
    local mtg_img="${MTG_IMAGE:-nineseconds/mtg:2}"
    local secret=""

    secret="$(docker run --rm "$mtg_img" generate-secret --hex "$fake_sni" 2>/dev/null | tr -d '\r\n' || true)"
    if [[ -z "$secret" ]]; then
        # Надежный RFC/MTProto Fake-TLS fallback: 'ee' + 16 random bytes (hex) + domain (hex)
        secret="$(python3 -c "import os,sys; print('ee' + os.urandom(16).hex() + sys.argv[1].encode('ascii').hex())" "$fake_sni")"
    fi
    echo "$secret"
}

mod_telegram_proxy_setup() {
    local mode="${1:-}"
    log_step "Модуль 07: Настройка Telegram Proxy (MTProto Fake-TLS + SOCKS5)"
    state_load_silent

    local fake_sni="${MTPROTO_FAKE_SNI:-${REALITY_SNI:-yandex.ru}}"
    state_set "MTPROTO_FAKE_SNI" "$fake_sni"

    if [[ "$mode" == "regen" ]]; then
        state_set "MTPROTO_PORT" "$(gen_random_free_port 18000 20000)"
        state_set "SOCKS5_PORT" "$(gen_random_free_port 10800 17999)"
        state_set "SOCKS5_PASS" "$(gen_random_str 16)"
        state_set "MTPROTO_SECRET" ""
    fi

    if [[ -z "${MTPROTO_SECRET:-}" ]]; then
        local new_secret
        new_secret="$(_tg_generate_faketls_secret "$fake_sni")"
        state_set "MTPROTO_SECRET" "$new_secret"
        log_ok "Секрет MTProto Fake-TLS сгенерирован (маскировка: ${fake_sni})."
    fi

    state_load_silent
    if declare -f _render_docker_compose >/dev/null 2>&1; then
        _render_docker_compose
    fi

    log_info "Запуск контейнеров combain-mtproto и combain-socks5..."
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d mtproto-proxy tg-socks5

    log_ok "Модуль 07 завершен: MTProto (${MTPROTO_PORT}/tcp) и SOCKS5 (${SOCKS5_PORT}/tcp) работают."
}
