# ==============================================================================
# Server-Combain — Шаблон конфигурации Nginx (127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT})
# Трафик поступает от sniproxy по 443 порту, сертификат берется из Let's Encrypt.
# ==============================================================================

server {
    listen 80 default_server;
    server_name ${BASE_DOMAIN} ${DNS_DOMAIN};
    client_max_body_size 32m;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location = /speedtest/sink {
        access_log off;
        return 204;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT} ssl;
    http2 on;
    server_name ${BASE_DOMAIN} ${VK_CDN_DOMAIN} ${YA_CDN_DOMAIN};
    large_client_header_buffers 8 32k;

    ssl_certificate     /etc/letsencrypt/live/${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${BASE_DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # Скрытая панель управления 3x-ui
    location ^~ /${SECRET_PANEL_PATH}/ {
        proxy_pass http://127.0.0.1:${XUI_INTERNAL_PORT}/${SECRET_PANEL_PATH}/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # --- VK Cloud CDN (XHTTP и WebSocket) ---
    location ^~ /${XHTTP_VK_PATH} {
        proxy_pass http://127.0.0.1:${XRAY_VK_XHTTP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        gzip off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 0;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location ^~ /${WS_VK_PATH} {
        proxy_pass http://127.0.0.1:${XRAY_VK_WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    # --- Yandex Cloud CDN (XHTTP и WebSocket) ---
    location ^~ /${XHTTP_YA_PATH} {
        proxy_pass http://127.0.0.1:${XRAY_YA_XHTTP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        gzip off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 0;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location ^~ /${WS_YA_PATH} {
        proxy_pass http://127.0.0.1:${XRAY_YA_WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    # --- Временный Drag&Drop портал миграции (активен только во время окна в 1 час) ---
    location ^~ /${BACKUP_DROP_PATH}/ {
        proxy_pass http://127.0.0.1:${BACKUP_DROP_INTERNAL_PORT}/;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        client_max_body_size 2G;
        proxy_set_header Host $host;
    }

    # --- Единая подписка для VPN-приложений (Happ / v2rayNG / Hiddify / v2rayN) ---
    location = /sub/${SUB_TOKEN} {
        access_log off;
        default_type "text/plain; charset=utf-8";
        alias /etc/nginx/conf.d/sub_payload.b64;
        add_header Profile-Title "base64:${SUB_TITLE_B64}" always;
        add_header Profile-Update-Interval "6" always;
        add_header Subscription-Userinfo "upload=0; download=0; total=0; expire=0" always;
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
    }

    location ^~ /sub/ {
        access_log off;
        return 404;
    }

    # --- Сервис проверки скорости NetPulse (Download / Upload / Ping) ---
    location = /speedtest/ping {
        access_log off;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        return 204;
    }

    location = /speedtest/down {
        access_log off;
        default_type application/octet-stream;
        alias /usr/share/nginx/decoy/chunks/speedtest_8m.bin;
        add_header Accept-Ranges bytes;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header X-Content-Type-Options nosniff;
    }

    location = /speedtest/up {
        access_log off;
        client_max_body_size 16m;
        client_body_buffer_size 8m;
        proxy_request_buffering on;
        proxy_pass http://127.0.0.1:80/speedtest/sink;
    }

    # --- Эмуляция медиа-сегментов для длительного теста стабильности 4K-потока ---
    location = /videoplayback {
        access_log off;
        default_type video/mp4;
        alias /usr/share/nginx/decoy/chunks/abr_stream.bin;
        add_header Accept-Ranges bytes;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header X-Content-Type-Options nosniff;
    }

    # --- Эмуляция синхронизации блока данных ---
    location = /cloud-sync {
        access_log off;
        default_type application/octet-stream;
        alias /usr/share/nginx/decoy/chunks/cloud_blob.bin;
        add_header Accept-Ranges bytes;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header X-Content-Type-Options nosniff;
    }

    # --- Локальная коллекция видео/анимаций котиков для карт рогалика ---
    location ^~ /cats/ {
        access_log off;
        root /usr/share/nginx/decoy;
        add_header Cache-Control "public, max-age=3600";
    }

    # --- Fallback DoH на основном домене (для режима single domain) ---
    location = /dns-query {
        proxy_pass https://127.0.0.1:${AGH_INTERNAL_HTTPS_PORT}/dns-query;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # --- Сайт-заглушка (NetPulse SpeedTest + карточный рогалик «Лапки и Руны») ---
    location / {
        root /usr/share/nginx/decoy;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
}
