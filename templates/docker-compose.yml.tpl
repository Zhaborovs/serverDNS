# ==============================================================================
# Server-Combain — Шаблон docker-compose.yml (Nginx, 3x-ui, Telegram Proxy)
# Использует динамические образы (без устаревшего хардкода версий).
# ==============================================================================

services:
  nginx:
    image: ${NGINX_IMAGE:-nginx:alpine}
    container_name: combain-nginx
    restart: unless-stopped
    network_mode: host
    volumes:
      - /etc/server-combain/nginx/conf.d:/etc/nginx/conf.d:ro
      - /etc/server-combain/nginx/decoy:/usr/share/nginx/decoy:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/certbot:/var/www/certbot:ro

  3x-ui:
    image: ghcr.io/mhsanaei/3x-ui:${XUI_VERSION:-latest}
    container_name: combain-3xui
    restart: unless-stopped
    network_mode: host
    tty: true
    volumes:
      - /etc/x-ui:/etc/x-ui
      - /etc/letsencrypt:/root/cert:ro
    environment:
      - XRAY_VMESS_AEAD_FORCED=false

  mtproto-proxy:
    image: ${MTG_IMAGE:-nineseconds/mtg:2}
    container_name: combain-mtproto
    restart: unless-stopped
    ports:
      - "${MTPROTO_PORT:-18445}:3128"
    command: ["simple-run", "-n", "1.1.1.1", "0.0.0.0:3128", "${MTPROTO_SECRET:-00000000000000000000000000000000}"]

  tg-socks5:
    image: ${SOCKS5_IMAGE:-serjs/go-socks5-proxy:latest}
    container_name: combain-socks5
    restart: unless-stopped
    ports:
      - "${SOCKS5_PORT:-10808}:1080"
    environment:
      - PROXY_USER=${SOCKS5_USER:-tguser}
      - PROXY_PASSWORD=${SOCKS5_PASS:-changeme}

  amnezia-awg:
    image: amneziavpn/amneziawg-go:latest
    container_name: combain-awg
    restart: unless-stopped
    network_mode: host
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - /etc/amnezia/amneziawg:/opt/amnezia/awg
    entrypoint: ["/bin/sh", "-c", "awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true; awg-quick up /opt/amnezia/awg/awg0.conf && tail -f /dev/null"]
