#!/usr/bin/env bash
# ==============================================================================
# Модуль 08: Резервное копирование, быстрая смена IP и переезд со старого VPS
# ------------------------------------------------------------------------------
# Назначение:
#   - Быстрая смена IP (если хостер сменил IP, а домен остался тем же):
#     автообновление AdGuardHome.yaml, state.env, AWG/Xray/TG ссылок
#   - Создание полного зашифрованного бэкапа (пароль = базовое имя файла без .tar.gz.enc)
#     с сохранением конфигов комбайна и нативных контейнеров AmneziaVPN (если есть)
#   - Временный защищенный Drag&Drop портал на 1 час (работает как за Nginx HTTPS,
#     так и напрямую на голом новом VPS по IP до настройки домена)
#   - Прямой перенос по SSH/SCP и восстановление по URL или локальному пути
# ==============================================================================

mod_backup_quick_change_ip() {
    log_step "Модуль 08: Быстрая смена IP сервера"
    state_load_silent

    local new_ip old_ip
    new_ip="$(detect_server_ip)"
    old_ip="${SERVER_IP:-}"

    log_info "Предыдущий IP в конфиге: ${old_ip:-не задан}"
    log_info "Текущий внешний IPv4:  ${new_ip}"

    if [[ -n "$old_ip" && "$old_ip" == "$new_ip" ]]; then
        log_ok "IP-адрес не изменился (${new_ip}). Переприменяю правила и ссылки..."
    else
        read -rp "Подтвердить обновление всех конфигов на новый IP ${new_ip}? [Y/n]: " ans
        if [[ "${ans,,}" == "n" ]]; then
            log_warn "Операция смены IP отменена."
            return 0
        fi
        [[ -n "$old_ip" ]] && state_set "OLD_SERVER_IP" "$old_ip"
        state_set "SERVER_IP" "$new_ip"
    fi

    # 1. Обновление правил AdGuard Home при остановленном сервисе
    if [[ -f /opt/AdGuardHome/AdGuardHome.yaml ]]; then
        log_info "Обновление IP в AdGuardHome.yaml..."
        if declare -f _agh_stop_safe >/dev/null 2>&1; then _agh_stop_safe; fi
        python3 "${PROJECT_ROOT}/scripts/py_helpers/agh_config_manager.py" replace-ip \
            --config /opt/AdGuardHome/AdGuardHome.yaml \
            --old-ip "any" \
            --new-ip "$new_ip"
        if declare -f _agh_start_safe >/dev/null 2>&1; then _agh_start_safe; fi
    fi

    # 2. Обновление Endpoint в клиентских профилях AmneziaWG 2.0+
    if [[ -f "${STATE_DIR}/awg/registry.json" ]]; then
        python3 "${PROJECT_ROOT}/scripts/py_helpers/awg_config_gen.py" update-endpoint \
            --registry "${STATE_DIR}/awg/registry.json" \
            --clients-dir "${STATE_DIR}/clients" \
            --new-ip "$new_ip"
    fi

    # 3. Перезапуск sniproxy, пересборка подписки и проверка DNS A-записей
    killall sniproxy 2>/dev/null || true
    systemctl restart sniproxy >/dev/null 2>&1 || true
    if declare -f mod_xray_update_subscription >/dev/null 2>&1; then
        mod_xray_update_subscription
    fi

    echo ""
    log_warn "Не забудьте обновить A-записи у регистратора (REG.RU) на новый IP: ${new_ip}"
    echo -e "  * ${BASE_DOMAIN:-ваш_домен} -> ${new_ip}"
    [[ -n "${DNS_DOMAIN:-}" && "${DNS_DOMAIN:-}" != "${BASE_DOMAIN:-}" ]] && echo -e "  * ${DNS_DOMAIN} -> ${new_ip}"
    log_ok "Быстрая смена IP завершена! Актуальные ссылки ниже:"
}

_backup_collect_and_encrypt() {
    local bkp_name="combain-backup-$(date +%Y%m%d-%H%M%S)-$(gen_random_str 6)"
    local tmp_stage="/tmp/${bkp_name}_stage"
    local tmp_tar="/tmp/${bkp_name}.tar.gz"
    local final_enc="${BACKUP_DIR}/${bkp_name}.tar.gz.enc"

    rm -rf "$tmp_stage"
    mkdir -p "$tmp_stage" "$BACKUP_DIR"

    # Собираем все критические каталоги конфигурации
    local paths_to_backup=(
        "/etc/server-combain"
        "/etc/letsencrypt"
        "/opt/AdGuardHome/AdGuardHome.yaml"
        "/etc/x-ui/x-ui.db"
        "/etc/amnezia/amneziawg"
        "/etc/sniproxy.conf"
    )
    for p in "${paths_to_backup[@]}"; do
        if [[ -e "$p" ]]; then
            local parent_dir
            parent_dir="$(dirname "$p")"
            mkdir -p "${tmp_stage}${parent_dir}"
            cp -a "$p" "${tmp_stage}${parent_dir}/"
        fi
    done

    # Если параллельно работают нативные контейнеры приложения AmneziaVPN — дампим их конфиги
    if command -v docker &>/dev/null; then
        for amn_c in $(docker ps -a --format '{{.Names}}' | grep -E '^amnezia-' || true); do
            mkdir -p "${tmp_stage}/amnezia_containers/${amn_c}"
            docker cp "${amn_c}:/opt/amnezia" "${tmp_stage}/amnezia_containers/${amn_c}/" >/dev/null 2>&1 || true
        done
    fi

    tar -czf "$tmp_tar" -C "$tmp_stage" .
    # Пароль шифрования = базовое имя файла без расширения (просто и удобно для автоматики)
    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt \
        -in "$tmp_tar" -out "$final_enc" -pass "pass:${bkp_name}"

    rm -rf "$tmp_stage" "$tmp_tar"
    chmod 600 "$final_enc"
    echo "$final_enc"
}

_restore_backup_archive() {
    local archive_path="$1"
    if [[ ! -f "$archive_path" ]]; then
        log_err "Файл архива не найден: ${archive_path}"
        return 1
    fi

    local fname tmp_tar tmp_extract
    fname="$(basename "$archive_path")"
    tmp_tar="/tmp/combain_restore_$(gen_random_str 6).tar.gz"
    tmp_extract="/tmp/combain_extract_$(gen_random_str 6)"
    mkdir -p "$tmp_extract"

    if [[ "$fname" == *.tar.gz.enc ]]; then
        local pass="${fname%.tar.gz.enc}"
        log_info "Расшифровка архива ${fname} (пароль из имени файла)..."
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
            -in "$archive_path" -out "$tmp_tar" -pass "pass:${pass}" 2>/dev/null; then
            read -rsp "Авто-ключ не подошел. Введите пароль архива вручную: " manual_pass
            echo ""
            openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
                -in "$archive_path" -out "$tmp_tar" -pass "pass:${manual_pass}"
        fi
    else
        cp "$archive_path" "$tmp_tar"
    fi

    tar -xzf "$tmp_tar" -C "$tmp_extract"
    rm -f "$tmp_tar"

    log_info "Остановка активных сервисов перед восстановлением конфигов..."
    docker stop combain-nginx combain-3xui combain-mtproto combain-socks5 >/dev/null 2>&1 || true
    if declare -f _agh_stop_safe >/dev/null 2>&1; then _agh_stop_safe; fi

    for dir_name in etc opt; do
        if [[ -d "${tmp_extract}/${dir_name}" ]]; then
            cp -a "${tmp_extract}/${dir_name}/." "/${dir_name}/"
        fi
    done
    rm -rf "$tmp_extract"
    state_load_silent

    log_info "Развертывание и запуск сервисов на новом сервере с восстановленными данными..."
    mod_sys_hardening_apply
    mod_ssl_nginx_setup
    mod_adguard_dns_setup
    mod_sniproxy_setup

    # Для 3x-ui, AWG и Telegram обновляем контейнеры/интерфейс с уже восстановленными БД и ключами
    if declare -f _render_docker_compose >/dev/null 2>&1; then _render_docker_compose; fi
    docker compose --env-file "$STATE_FILE" -f "${STATE_DIR}/docker-compose.yml" up -d
    mod_amneziawg_setup

    mod_backup_quick_change_ip
    mod_dashboard_save_summary
    log_ok "Миграция и восстановление полностью завершены!"
}

mod_backup_create() {
    log_step "Модуль 08: Создание зашифрованного архива бэкапа"
    state_load_silent

    local archive_path
    archive_path="$(_backup_collect_and_encrypt)"
    log_ok "Бэкап создан и зашифрован: ${archive_path}"
    echo -e "  *(Пароль для расшифровки совпадает с именем файла без .tar.gz.enc)*"

    read -rp "Поднять временную ссылку на скачивание через браузер (на 1 час)? [y/N]: " share_ans
    if [[ "${share_ans,,}" == "y" ]]; then
        mod_backup_start_drop_portal "download" "$archive_path"
    fi
}

mod_backup_start_drop_portal() {
    local mode="${1:-upload}"
    local target_file="${2:-}"
    state_load_silent
    log_step "Запуск временного Drag&Drop портала миграции (TTL: 1 час)"

    local token cur_ip bind_addr port portal_url done_marker
    token="$(gen_random_str 24)"
    cur_ip="$(detect_server_ip)"
    done_marker="/tmp/combain_drop_done_$(gen_random_str 6)"
    rm -f "$done_marker"

    # Если Nginx уже настроен и работает — работаем через HTTPS за Nginx,
    # иначе на голом новом VPS открываем прямой временный порт на 1 час.
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^combain-nginx$' && [[ -n "${BASE_DOMAIN:-}" ]]; then
        bind_addr="127.0.0.1"
        port="${BACKUP_DROP_INTERNAL_PORT:-20999}"
        portal_url="https://${BASE_DOMAIN}/${BACKUP_DROP_PATH}/?token=${token}"
    else
        bind_addr="0.0.0.0"
        port="$(gen_random_free_port 18500 19500)"
        portal_url="http://${cur_ip}:${port}/?token=${token}"
    fi

    echo ""
    echo -e "${GREEN}Откройте ссылку в браузере (действует ровно 60 минут):${NC}"
    echo -e "  ${BOLD}${portal_url}${NC}"
    echo ""
    echo "Ожидание действия пользователя (Ctrl+C для отмены)..."

    local py_args=(
        "--mode" "$mode"
        "--bind" "$bind_addr"
        "--port" "$port"
        "--token" "$token"
        "--ttl" "3600"
        "--template" "${PROJECT_ROOT}/web/backup_portal/index.html"
        "--dest-dir" "$BACKUP_DIR"
        "--done-file" "$done_marker"
    )
    [[ -n "$target_file" ]] && py_args+=("--file" "$target_file")

    python3 "${PROJECT_ROOT}/scripts/py_helpers/backup_drop_server.py" "${py_args[@]}"

    if [[ "$mode" == "upload" && -f "$done_marker" ]]; then
        local uploaded_path
        uploaded_path="$(cat "$done_marker")"
        rm -f "$done_marker"
        log_ok "Архив получен: ${uploaded_path}. Запуск автоматического восстановления..."
        _restore_backup_archive "$uploaded_path"
    fi
}

mod_backup_restore_from_path_or_url() {
    state_load_silent
    local src local_file
    read -rp "Введите HTTPS URL или локальный путь к архиву (.tar.gz.enc / .tar.gz): " src
    [[ -z "$src" ]] && return 0

    if [[ "$src" == http://* || "$src" == https://* ]]; then
        local url_name
        url_name="$(basename "${src%%\?*}")"
        [[ -z "$url_name" || "$url_name" == "/" ]] && url_name="combain-downloaded.tar.gz.enc"
        local_file="${BACKUP_DIR}/${url_name}"
        log_info "Скачивание архива в ${local_file}..."
        curl -fL "$src" -o "$local_file"
    else
        local_file="$src"
    fi

    _restore_backup_archive "$local_file"
}

mod_backup_pull_ssh() {
    state_load_silent
    local old_host old_port old_user
    read -rp "IP или домен старого сервера: " old_host
    [[ -z "$old_host" ]] && return 0
    read -rp "SSH порт старого сервера [22]: " old_port
    old_port="${old_port:-22}"
    read -rp "SSH пользователь [root]: " old_user
    old_user="${old_user:-root}"

    log_info "Подключение к ${old_user}@${old_host}:${old_port} для создания и выгрузки бэкапа..."
    local remote_file
    remote_file="$(ssh -p "$old_port" "${old_user}@${old_host}" \
        "bash -c 'source /opt/server-combain/scripts/lib/common.sh; source /opt/server-combain/scripts/lib/state.sh; source /opt/server-combain/scripts/modules/08_backup_migrate.sh; _backup_collect_and_encrypt' | tail -n1")"

    if [[ -z "$remote_file" ]]; then
        log_err "Не удалось получить путь к бэкапу со старого сервера."
        return 1
    fi

    local local_file="${BACKUP_DIR}/$(basename "$remote_file")"
    scp -P "$old_port" "${old_user}@${old_host}:${remote_file}" "$local_file"
    log_ok "Архив скачан по SSH в ${local_file}."
    _restore_backup_archive "$local_file"
}
