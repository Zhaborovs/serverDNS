#!/usr/bin/env bash
# ==============================================================================
# Модуль 02: SSL-сертификаты (Certbot) и авто-конфигурируемый Nginx + Заглушка
# ------------------------------------------------------------------------------
# Назначение:
#   - Подсказка и проверка DNS A-записей (REG.RU / любой регистратор) через dig
#   - Выпуск SSL-сертификата (SAN для BASE_DOMAIN + DNS_DOMAIN или Wildcard)
#   - Настройка Certbot pre/post hooks для автопродления и синхронизации с AdGuard
#   - Генерация бинарных чанков шума (/videoplayback, /cloud-sync) и веб-игры
#   - Рендеринг nginx_site.conf.tpl и docker-compose.yml.tpl + запуск combain-nginx
# Входные переменные (state.env):
#   SERVER_IP, BASE_DOMAIN, DNS_DOMAIN, DOMAIN_MODE, CERT_EMAIL,
#   NGINX_INTERNAL_HTTPS_PORT, XUI_INTERNAL_PORT, SECRET_PANEL_PATH,
#   XHTTP_VK_PATH, WS_VK_PATH, XHTTP_YA_PATH, WS_YA_PATH, BACKUP_DROP_PATH,
#   BACKUP_DROP_INTERNAL_PORT, VK_CDN_DOMAIN, YA_CDN_DOMAIN
# Выходные артефакты:
#   /etc/letsencrypt/live/${BASE_DOMAIN}/, /etc/server-combain/nginx/,
#   /etc/server-combain/docker-compose.yml, /etc/letsencrypt/renewal-hooks/
# ==============================================================================

_render_docker_compose() {
    state_load_silent
    local tpl="${PROJECT_ROOT}/templates/docker-compose.yml.tpl"
    local dst="${STATE_DIR}/docker-compose.yml"
    local vars='${NGINX_IMAGE} ${XUI_VERSION} ${MTG_IMAGE} ${MTPROTO_PORT} ${MTPROTO_SECRET} ${SOCKS5_IMAGE} ${SOCKS5_PORT} ${SOCKS5_USER} ${SOCKS5_PASS}'
    envsubst "$vars" < "$tpl" > "$dst"
    log_ok "Файл Docker Compose обновлен: ${dst}"
}

_render_nginx_conf() {
    state_load_silent
    local nginx_dir="${STATE_DIR}/nginx"
    local tpl="${PROJECT_ROOT}/templates/nginx_site.conf.tpl"
    local dst="${nginx_dir}/conf.d/default.conf"
    mkdir -p "${nginx_dir}/conf.d" "${nginx_dir}/decoy/chunks"

    local vars='${BASE_DOMAIN} ${DNS_DOMAIN} ${VK_CDN_DOMAIN} ${YA_CDN_DOMAIN} ${NGINX_INTERNAL_HTTPS_PORT} ${AGH_INTERNAL_HTTPS_PORT} ${SECRET_PANEL_PATH} ${XUI_INTERNAL_PORT} ${XHTTP_VK_PATH} ${XRAY_VK_XHTTP_PORT} ${WS_VK_PATH} ${XRAY_VK_WS_PORT} ${XHTTP_YA_PATH} ${XRAY_YA_XHTTP_PORT} ${WS_YA_PATH} ${XRAY_YA_WS_PORT} ${BACKUP_DROP_PATH} ${BACKUP_DROP_INTERNAL_PORT}'
    envsubst "$vars" < "$tpl" > "$dst"
    log_ok "Конфигурация Nginx отрендерена: ${dst}"
}

_generate_noise_chunks() {
    local chunks_dir="${STATE_DIR}/nginx/decoy/chunks"
    mkdir -p "$chunks_dir"

    if [[ ! -f "${chunks_dir}/abr_stream.bin" ]]; then
        log_info "Генерация бинарного сегмента медиа-потока (2 МБ) для /videoplayback..."
        # Псевдо-заголовок ISO MP4 (ftypisom) + криптографически случайный контент
        printf '\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2avc1mp41' > "${chunks_dir}/abr_stream.bin"
        dd if=/dev/urandom bs=1024 count=2048 status=none >> "${chunks_dir}/abr_stream.bin"
    fi

    if [[ ! -f "${chunks_dir}/cloud_blob.bin" ]]; then
        log_info "Генерация бинарного блока (1 МБ) для /cloud-sync..."
        dd if=/dev/urandom bs=1024 count=1024 status=none > "${chunks_dir}/cloud_blob.bin"
    fi

    if [[ ! -f "${chunks_dir}/speedtest_8m.bin" ]]; then
        log_info "Генерация тестового файла (8 МБ) для замера скорости Download..."
        dd if=/dev/urandom bs=1024 count=8192 status=none > "${chunks_dir}/speedtest_8m.bin"
    fi
}

_prepare_cat_videos() {
    local cats_dir="${STATE_DIR}/nginx/decoy/cats"
    mkdir -p "$cats_dir"

    # 1. Копируем пользовательские .mp4/.webm/.gif из репозитория (если добавлены вручную)
    if [[ -d "${PROJECT_ROOT}/web/decoy_game/cats" ]]; then
        find "${PROJECT_ROOT}/web/decoy_game/cats" -maxdepth 1 -type f \( -iname "*.mp4" -o -iname "*.webm" -o -iname "*.gif" \) \
            -exec cp -u {} "$cats_dir/" \; 2>/dev/null || true
    fi

    # 2. Считаем текущее количество валидных медиа-котиков
    local current_count
    current_count="$(find "$cats_dir" -maxdepth 1 -type f \( -iname "*.mp4" -o -iname "*.webm" -o -iname "*.gif" \) -size +15k 2>/dev/null | wc -l)"

    if [[ "$current_count" -lt 10 ]]; then
        log_info "Загрузка локального пака видео/анимаций котиков для рогалика (текущих: ${current_count}, цель: 10)..."
        local ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

        # Пробуем пару легких .webm роликов с Wikimedia Commons
        local -A wiki_clips=(
            ["cat_meow.webm"]="https://upload.wikimedia.org/wikipedia/commons/3/37/Cat_meowing_into_camera.webm"
            ["cat_play.webm"]="https://upload.wikimedia.org/wikipedia/commons/e/e0/Ma%C4%8Dka_164113.webm"
        )
        for fname in "${!wiki_clips[@]}"; do
            if [[ ! -s "${cats_dir}/${fname}" ]]; then
                curl -4 -fsSL --connect-timeout 5 --max-time 15 -A "$ua" "${wiki_clips[$fname]}" -o "${cats_dir}/${fname}.tmp" 2>/dev/null || true
                if [[ -s "${cats_dir}/${fname}.tmp" ]] && [[ "$(wc -c < "${cats_dir}/${fname}.tmp")" -gt 15000 ]]; then
                    mv "${cats_dir}/${fname}.tmp" "${cats_dir}/${fname}"
                else
                    rm -f "${cats_dir}/${fname}.tmp"
                fi
            fi
        done

        # Добираем уникальные GIF-анимации с CATAAS (проверяя заголовок GIF8 и дедупликацию по md5)
        local seen_hashes=""
        for existing in "$cats_dir"/*; do
            [[ -f "$existing" ]] && seen_hashes+="$(md5sum "$existing" 2>/dev/null | awk '{print $1}') "
        done

        local idx=1
        local tries=0
        while [[ "$(find "$cats_dir" -maxdepth 1 -type f \( -iname "*.mp4" -o -iname "*.webm" -o -iname "*.gif" \) -size +15k 2>/dev/null | wc -l)" -lt 10 ]] && [[ "$tries" -lt 18 ]]; do
            tries=$((tries + 1))
            local target="${cats_dir}/cat_${idx}.gif"
            while [[ -f "$target" ]]; do
                idx=$((idx + 1))
                target="${cats_dir}/cat_${idx}.gif"
            done
            local tmp_f="${target}.tmp"
            curl -4 -fsSL --connect-timeout 4 --max-time 10 -A "$ua" "https://cataas.com/cat/gif?t=${tries}_$$" -o "$tmp_f" 2>/dev/null || true
            if [[ -s "$tmp_f" ]] && [[ "$(wc -c < "$tmp_f")" -gt 15000 ]] && head -c 4 "$tmp_f" | grep -q "GIF8"; then
                local h
                h="$(md5sum "$tmp_f" | awk '{print $1}')"
                if [[ "$seen_hashes" != *"$h"* ]]; then
                    mv "$tmp_f" "$target"
                    seen_hashes+="${h} "
                    idx=$((idx + 1))
                else
                    rm -f "$tmp_f"
                fi
            else
                rm -f "$tmp_f"
            fi
        done
    fi

    # 3. Генерируем manifest.json для фронтенда
    python3 - "$cats_dir" <<'PYEOF'
import json, sys
from pathlib import Path

cats_dir = Path(sys.argv[1])
exts = {".mp4", ".webm", ".gif"}
files = sorted(
    f"/cats/{p.name}"
    for p in cats_dir.iterdir()
    if p.is_file() and p.suffix.lower() in exts and p.stat().st_size > 15000
)
(cats_dir / "manifest.json").write_text(json.dumps(files, indent=2), encoding="utf-8")
print(f"[OK] Пак видео-котиков готов: {len(files)} файлов в {cats_dir}")
PYEOF
}

_check_regru_dns_loop() {
    local expected_ip="$SERVER_IP"
    local domains=("$BASE_DOMAIN")
    [[ "$DNS_DOMAIN" != "$BASE_DOMAIN" ]] && domains+=("$DNS_DOMAIN")

    while true; do
        local all_ok="true"
        echo ""
        echo -e "${BOLD}--- Проверка DNS A-записей (например, в панели REG.RU) ---${NC}"
        for d in "${domains[@]}"; do
            local r1 r2
            r1="$(dig +short A "$d" @1.1.1.1 2>/dev/null | tail -n1 || true)"
            r2="$(dig +short A "$d" @8.8.8.8 2>/dev/null | tail -n1 || true)"
            if [[ "$r1" == "$expected_ip" || "$r2" == "$expected_ip" ]]; then
                echo -e "  [${GREEN}OK${NC}] ${d} -> ${expected_ip}"
            else
                echo -e "  [${YELLOW}WAIT${NC}] ${d} -> сейчас '${r1:-пусто}', ожидается '${expected_ip}'"
                all_ok="false"
            fi
        done

        [[ "$all_ok" == "true" ]] && break

        echo ""
        echo "Подсказка для REG.RU / панели управления DNS:"
        echo "  Добавьте A-записи, указывающие на ${expected_ip}:"
        for d in "${domains[@]}"; do
            echo "    * ${d}  [A]  ${expected_ip}"
        done
        read -rp "Нажмите Enter для повторной проверки DNS (или введите 'skip' чтобы пропустить): " dns_ans
        [[ "${dns_ans,,}" == "skip" ]] && break
    done
}

_setup_certbot_hooks() {
    mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post

    cat > /etc/letsencrypt/renewal-hooks/pre/combain-stop-nginx.sh <<'EOF'
#!/usr/bin/env bash
docker stop combain-nginx >/dev/null 2>&1 || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/pre/combain-stop-nginx.sh

    cat > /etc/letsencrypt/renewal-hooks/post/combain-sync-certs.sh <<EOF
#!/usr/bin/env bash
set -e
CERT_DIR="/etc/letsencrypt/live/${BASE_DOMAIN}"
if [[ -d "/opt/AdGuardHome" && -f "\${CERT_DIR}/fullchain.pem" ]]; then
    cp -L "\${CERT_DIR}/fullchain.pem" /opt/AdGuardHome/fullchain.pem
    cp -L "\${CERT_DIR}/privkey.pem" /opt/AdGuardHome/privkey.pem
    chmod 600 /opt/AdGuardHome/privkey.pem
    if [[ -x "/opt/AdGuardHome/AdGuardHome" ]]; then
        /opt/AdGuardHome/AdGuardHome -s restart >/dev/null 2>&1 || true
    fi
fi
docker start combain-nginx >/dev/null 2>&1 || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/post/combain-sync-certs.sh
    log_ok "Хуки автопродления Let's Encrypt настроены (без остановки sniproxy на 443)."
}

_issue_ssl_certificate() {
    local cert_live="/etc/letsencrypt/live/${BASE_DOMAIN}/fullchain.pem"
    if [[ -f "$cert_live" ]]; then
        log_ok "SSL-сертификат для ${BASE_DOMAIN} уже существует (${cert_live})."
        return 0
    fi

    # Временно освобождаем 80 порт, если Nginx уже запущен
    docker stop combain-nginx >/dev/null 2>&1 || true
    mkdir -p /var/www/certbot

    if [[ "${DOMAIN_MODE:-split}" == "wildcard" ]]; then
        log_info "Запуск выпуска Wildcard-сертификата (*.${BASE_DOMAIN} + ${BASE_DOMAIN}) через DNS-01..."
        certbot certonly --manual --preferred-challenges dns \
            --agree-tos --email "${CERT_EMAIL}" \
            -d "${BASE_DOMAIN}" -d "*.${BASE_DOMAIN}"
    else
        local cert_args=(-d "$BASE_DOMAIN")
        [[ "$DNS_DOMAIN" != "$BASE_DOMAIN" ]] && cert_args+=(-d "$DNS_DOMAIN")
        log_info "Выпуск SAN SSL-сертификата через certbot --standalone для: ${cert_args[*]}..."
        certbot certonly --standalone --non-interactive --agree-tos \
            --email "${CERT_EMAIL}" "${cert_args[@]}"
    fi

    log_ok "SSL-сертификат успешно получен!"
}

mod_ssl_nginx_update_decoy() {
    log_step "Обновление сайта-заглушки, эндпоинтов SpeedTest и пака видео-котиков"
    state_load_silent
    local nginx_dir="${STATE_DIR}/nginx"
    mkdir -p "${nginx_dir}/conf.d" "${nginx_dir}/decoy/chunks" "${nginx_dir}/decoy/cats"
    cp -a "${PROJECT_ROOT}/web/decoy_game/." "${nginx_dir}/decoy/"
    _generate_noise_chunks
    _prepare_cat_videos
    _render_nginx_conf
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^combain-nginx$'; then
        docker exec combain-nginx nginx -s reload >/dev/null 2>&1 || docker restart combain-nginx >/dev/null
    fi
    log_ok "Сайт-заглушка и медиапак обновлены!"
}

mod_ssl_nginx_setup() {
    log_step "Модуль 02: Проверка DNS, выпуск SSL-сертификата и запуск Nginx + Заглушки"
    state_load_silent

    local nginx_dir="${STATE_DIR}/nginx"
    mkdir -p "${nginx_dir}/conf.d" "${nginx_dir}/decoy" /var/www/certbot
    cp -a "${PROJECT_ROOT}/web/decoy_game/." "${nginx_dir}/decoy/"
    _generate_noise_chunks
    _prepare_cat_videos

    _check_regru_dns_loop
    _issue_ssl_certificate
    _setup_certbot_hooks
    _render_nginx_conf
    _render_docker_compose

    log_info "Запуск контейнера combain-nginx..."
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d nginx
    log_ok "Модуль 02 завершен: сайт-заглушка и прокси Nginx работают на 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT}."
}

mod_ssl_nginx_toggle_noise_daemon() {
    mod_ssl_nginx_update_decoy
}
