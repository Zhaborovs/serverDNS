# ==============================================================================
# Server-Combain — Шаблон конфигурации Nginx (127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT})
# Трафик поступает от sniproxy по 443 порту, сертификат берется из Let's Encrypt.
# ==============================================================================

server {
    listen 80;
    server_name ${BASE_DOMAIN} ${DNS_DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 127.0.0.1:${NGINX_INTERNAL_HTTPS_PORT} ssl;
    http2 on;
    server_name ${BASE_DOMAIN} *.${BASE_DOMAIN} ${VK_CDN_DOMAIN} ${YA_CDN_DOMAIN};

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
        proxy_buffering off;
        proxy_request_buffering off;
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
        proxy_buffering off;
        proxy_request_buffering off;
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

    # --- Эмуляция медиа-чанков (ABR-профиль YouTube/HLS) ---
    location = /videoplayback {
        access_log off;
        default_type video/mp4;
        alias /usr/share/nginx/decoy/chunks/abr_stream.bin;
        add_header Accept-Ranges bytes;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header X-Content-Type-Options nosniff;
    }

    # --- Эмуляция синхронизации облачного диска (Google/Яндекс.Диск профиль) ---
    location = /cloud-sync {
        access_log off;
        default_type application/octet-stream;
        alias /usr/share/nginx/decoy/chunks/cloud_blob.bin;
        add_header Accept-Ranges bytes;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header X-Content-Type-Options nosniff;
        add_header X-Cloud-Sync "chunk-ok";
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

    # --- Сайт-заглушка (Веб-игра «Киберпанк Космо-Ранер») ---
    location / {
        root /usr/share/nginx/decoy;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
}
