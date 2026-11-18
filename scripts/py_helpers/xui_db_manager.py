#!/usr/bin/env python3
"""
Server-Combain — Менеджер SQLite базы данных 3x-ui (/etc/x-ui/x-ui.db) и генератор Reality-ключей.

Назначение:
  - Генерация криптографической пары X25519 (Reality), shortId и UUIDv4
    (с чистым Python RFC 7748 fallback, не требующим внешних бинарников)
  - Настройка параметров панели 3x-ui (webListen=127.0.0.1, webPort, webBasePath)
  - Идемпотентное создание 5 инбаундов:
      1) VLESS-Reality (127.0.0.1:20443)
      2) VK-CDN-XHTTP (127.0.0.1:20444)
      3) VK-CDN-WS (127.0.0.1:20445)
      4) Yandex-CDN-XHTTP (127.0.0.1:20446)
      5) Yandex-CDN-WS (127.0.0.1:20447)
  - Экспорт готовых vless:// ссылок для всех профилей
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import urllib.parse
import uuid

_P = (1 << 255) - 19
_A24 = 121665

# Режим чистого GET-транспорта для VK Cloud CDN (где POST и WebSocket отключены по умолчанию)
VK_GET_XHTTP_EXTRA = {
    "mode": "packet-up",
    "xPaddingBytes": "100-1000",
    "uplinkHTTPMethod": "GET",
    "uplinkDataPlacement": "cookie",
    "uplinkDataKey": "x_data",
    "scMaxEachPostBytes": "2500-3500",
    "scMinPostsIntervalMs": "10-25",
}


def _x25519_clamp(scalar_bytes: bytes) -> int:
    b = bytearray(scalar_bytes)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    dummy = swap * (x_2 ^ x_3)
    return x_2 ^ dummy, x_3 ^ dummy


def x25519_scalarmult(scalar_bytes: bytes, u_bytes: bytes | None = None) -> bytes:
    """RFC 7748 Montgomery ladder на Curve25519 в чистом Python."""
    k = _x25519_clamp(scalar_bytes)
    if u_bytes is None:
        u = 9
    else:
        u_arr = bytearray(u_bytes)
        u_arr[31] &= 127
        u = int.from_bytes(u_arr, "little") % _P

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x_3 = pow((DA + CB) % _P, 2, _P)
        z_3 = (x_1 * pow((DA - CB) % _P, 2, _P)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P

    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    res = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return res.to_bytes(32, "little")


def generate_reality_keypair() -> tuple[str, str]:
    """Генерирует пару ключей X25519 в URL-safe Base64 без '=' (формат Xray Reality)."""
    priv_raw = bytearray(os.urandom(32))
    priv_raw[0] &= 248
    priv_raw[31] &= 127
    priv_raw[31] |= 64
    priv_bytes = bytes(priv_raw)
    pub_bytes = x25519_scalarmult(priv_bytes)
    priv_b64 = base64.urlsafe_b64encode(priv_bytes).decode("ascii").rstrip("=")
    pub_b64 = base64.urlsafe_b64encode(pub_bytes).decode("ascii").rstrip("=")
    return priv_b64, pub_b64


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Создает минимально необходимые таблицы 3x-ui, если база пустая."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT,
            value TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 1,
            up INTEGER DEFAULT 0,
            down INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            remark TEXT,
            enable INTEGER DEFAULT 1,
            expiry_time INTEGER DEFAULT 0,
            listen TEXT,
            port INTEGER,
            protocol TEXT,
            settings TEXT,
            stream_settings TEXT,
            tag TEXT,
            sniffing TEXT,
            allocate TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS client_traffics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER,
            enable INTEGER DEFAULT 1,
            email TEXT,
            up INTEGER DEFAULT 0,
            down INTEGER DEFAULT 0,
            expiry_time INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            reset INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()


def upsert_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    cur = conn.execute("SELECT id FROM settings WHERE key = ?", (key,))
    row = cur.fetchone()
    if row:
        conn.execute("UPDATE settings SET value = ? WHERE id = ?", (value, row[0]))
    else:
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))


def get_table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    """Возвращает множество реально существующих колонок в SQLite-таблице."""
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def upsert_inbound(
    conn: sqlite3.Connection,
    tag: str,
    remark: str,
    listen: str,
    port: int,
    protocol: str,
    settings_obj: dict,
    stream_obj: dict,
    client_email: str = "",
) -> None:
    sniffing_obj = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic", "fakedns"],
        "metadataOnly": False,
        "routeOnly": False,
    }
    allocate_obj = {"strategy": "always", "refresh": 5, "concurrency": 3}

    inb_cols = get_table_columns(conn, "inbounds")
    all_fields = {
        "user_id": 1,
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": 1,
        "expiry_time": 0,
        "listen": listen,
        "port": port,
        "protocol": protocol,
        "settings": json.dumps(settings_obj, separators=(",", ":")),
        "stream_settings": json.dumps(stream_obj, separators=(",", ":")),
        "tag": tag,
        "sniffing": json.dumps(sniffing_obj, separators=(",", ":")),
        "allocate": json.dumps(allocate_obj, separators=(",", ":")),
        "traffic_reset": "never",
    }
    filtered_fields = {k: v for k, v in all_fields.items() if k in inb_cols}

    cur = conn.execute("SELECT id FROM inbounds WHERE tag = ? OR port = ?", (tag, port))
    row = cur.fetchone()
    if row:
        inbound_id = row[0]
        update_fields = {k: v for k, v in filtered_fields.items() if k not in {"up", "down", "total"}}
        set_clause = ", ".join(f"{k}=?" for k in update_fields)
        conn.execute(
            f"UPDATE inbounds SET {set_clause} WHERE id=?",
            (*update_fields.values(), inbound_id),
        )
    else:
        cols_sql = ", ".join(filtered_fields.keys())
        qs_sql = ", ".join("?" for _ in filtered_fields)
        insert_cur = conn.execute(
            f"INSERT INTO inbounds ({cols_sql}) VALUES ({qs_sql})",
            tuple(filtered_fields.values()),
        )
        inbound_id = insert_cur.lastrowid

    # Синхронно создаем запись клиента в client_traffics для корректного отображения в UI 3x-ui
    ct_cols = get_table_columns(conn, "client_traffics")
    if ct_cols and client_email and inbound_id:
        ct_row = conn.execute(
            "SELECT id FROM client_traffics WHERE inbound_id = ? AND email = ?",
            (inbound_id, client_email),
        ).fetchone()
        if not ct_row:
            ct_fields = {
                "inbound_id": inbound_id,
                "enable": 1,
                "email": client_email,
                "up": 0,
                "down": 0,
                "expiry_time": 0,
                "total": 0,
                "reset": 0,
                "all_time": 0,
                "last_online": 0,
            }
            ct_filtered = {k: v for k, v in ct_fields.items() if k in ct_cols}
            ct_cols_sql = ", ".join(ct_filtered.keys())
            ct_qs_sql = ", ".join("?" for _ in ct_filtered)
            conn.execute(
                f"INSERT INTO client_traffics ({ct_cols_sql}) VALUES ({ct_qs_sql})",
                tuple(ct_filtered.values()),
            )


def build_vless_settings(client_uuid: str, email: str, flow: str = "") -> dict:
    return {
        "clients": [
            {
                "id": client_uuid,
                "flow": flow,
                "email": email,
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
                "tgId": "",
                "subId": "combain",
                "reset": 0,
            }
        ],
        "decryption": "none",
        "fallbacks": [],
    }


def cmd_gen_keys(_: argparse.Namespace) -> int:
    priv, pub = generate_reality_keypair()
    sid = secrets.token_hex(6)
    client_uuid = str(uuid.uuid4())
    print(f"REALITY_PRIVATE_KEY={priv}")
    print(f"REALITY_PUBLIC_KEY={pub}")
    print(f"REALITY_SHORT_ID={sid}")
    print(f"MAIN_CLIENT_UUID={client_uuid}")
    return 0


def cmd_init_all(args: argparse.Namespace) -> int:
    args.db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(args.db))
    try:
        ensure_schema(conn)
        panel_path = "/" + args.panel_path.strip("/") + "/"
        upsert_setting(conn, "webListen", "127.0.0.1")
        upsert_setting(conn, "webPort", str(args.panel_port))
        upsert_setting(conn, "webBasePath", panel_path)

        # 1. VLESS-Reality (127.0.0.1:20443, трафик приходит от sniproxy)
        reality_stream = {
            "network": "tcp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": {
                "show": False,
                "xver": 0,
                "dest": f"{args.reality_sni}:443",
                "serverNames": [args.reality_sni],
                "privateKey": args.reality_private_key,
                "minClient": "",
                "maxClient": "",
                "maxTimediff": 0,
                "shortIds": [args.reality_short_id],
                "settings": {
                    "publicKey": args.reality_public_key,
                    "fingerprint": "chrome",
                    "serverName": "",
                    "spiderX": "/",
                },
            },
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
        }
        upsert_inbound(
            conn,
            tag="combain-reality",
            remark="Combain-VLESS-Reality",
            listen="127.0.0.1",
            port=args.reality_port,
            protocol="vless",
            settings_obj=build_vless_settings(args.uuid, "combain-reality", "xtls-rprx-vision"),
            stream_obj=reality_stream,
            client_email="combain-reality",
        )

        # 2-5. Инбаунды за Nginx для VK Cloud CDN и Yandex Cloud CDN (XHTTP + WS)
        cdn_defs = [
            ("combain-vk-xhttp", "VK-CDN-XHTTP", args.vk_xhttp_port, "xhttp", f"/{args.vk_xhttp_path.lstrip('/')}", "vk-xhttp"),
            ("combain-vk-ws", "VK-CDN-WS", args.vk_ws_port, "ws", f"/{args.vk_ws_path.lstrip('/')}", "vk-ws"),
            ("combain-ya-xhttp", "Yandex-CDN-XHTTP", args.ya_xhttp_port, "xhttp", f"/{args.ya_xhttp_path.lstrip('/')}", "ya-xhttp"),
            ("combain-ya-ws", "Yandex-CDN-WS", args.ya_ws_port, "ws", f"/{args.ya_ws_path.lstrip('/')}", "ya-ws"),
        ]
        for tag, remark, port, net, path, email in cdn_defs:
            if net == "xhttp":
                if tag == "combain-vk-xhttp":
                    stream = {
                        "network": "xhttp",
                        "security": "none",
                        "externalProxy": [],
                        "xhttpSettings": {
                            "path": path,
                            "host": "",
                            "mode": "packet-up",
                            "xPaddingBytes": "100-1000",
                            "uplinkHTTPMethod": "GET",
                            "uplinkDataPlacement": "cookie",
                            "uplinkDataKey": "x_data",
                            "scMaxEachPostBytes": "2500-3500",
                            "scMinPostsIntervalMs": "10-25",
                            "scMaxBufferedPosts": 200,
                            "serverMaxHeaderBytes": 32768,
                        },
                    }
                else:
                    stream = {
                        "network": "xhttp",
                        "security": "none",
                        "externalProxy": [],
                        "xhttpSettings": {"path": path, "host": "", "mode": "auto"},
                    }
            else:
                stream = {
                    "network": "ws",
                    "security": "none",
                    "externalProxy": [],
                    "wsSettings": {"acceptProxyProtocol": False, "path": path, "headers": {}},
                }
            upsert_inbound(
                conn,
                tag=tag,
                remark=remark,
                listen="127.0.0.1",
                port=port,
                protocol="vless",
                settings_obj=build_vless_settings(args.uuid, email, ""),
                stream_obj=stream,
                client_email=email,
            )

        conn.commit()
    finally:
        conn.close()

    print(f"[OK] База 3x-ui ({args.db}) настроена: панель 127.0.0.1:{args.panel_port}/{args.panel_path.strip('/')}/ + 5 инбаундов.")
    return 0


def build_vless_uri(
    client_uuid: str,
    address: str,
    port: int,
    params: dict[str, str],
    name: str,
) -> str:
    qs = urllib.parse.urlencode(params, safe="")
    frag = urllib.parse.quote(name, safe="")
    return f"vless://{client_uuid}@{address}:{port}?{qs}#{frag}"


def cmd_export_links(args: argparse.Namespace) -> int:
    links: list[tuple[str, str]] = []
    links.append(
        (
            "VLESS-Reality (прямой с маскировкой)",
            build_vless_uri(
                args.uuid,
                args.server_ip,
                443,
                {
                    "type": "tcp",
                    "security": "reality",
                    "pbk": args.reality_public_key,
                    "fp": "chrome",
                    "sni": args.reality_sni,
                    "sid": args.reality_short_id,
                    "spx": "/",
                    "flow": "xtls-rprx-vision",
                },
                "Combain-Reality",
            ),
        )
    )
    if args.base_domain:
        if args.ya_xhttp_path:
            direct_params = {
                "type": "xhttp",
                "security": "tls",
                "sni": args.base_domain,
                "fp": "chrome",
                "path": f"/{args.ya_xhttp_path.lstrip('/')}",
            }
        else:
            direct_params = {
                "type": "xhttp",
                "security": "tls",
                "sni": args.base_domain,
                "fp": "chrome",
                "path": f"/{args.vk_xhttp_path.lstrip('/')}",
                "mode": "packet-up",
                "extra": json.dumps(VK_GET_XHTTP_EXTRA, separators=(",", ":")),
            }
        links.append(
            (
                "VLESS-XHTTP (прямой через ваш домен)",
                build_vless_uri(
                    args.uuid,
                    args.base_domain,
                    443,
                    direct_params,
                    "Combain-Direct-XHTTP",
                ),
            )
        )
    if args.vk_cdn_domain:
        links.append(
            (
                "VK Cloud CDN (XHTTP GET-режим, белый список)",
                build_vless_uri(
                    args.uuid,
                    args.vk_cdn_domain,
                    443,
                    {
                        "type": "xhttp",
                        "security": "tls",
                        "sni": args.vk_cdn_domain,
                        "host": args.vk_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.vk_xhttp_path.lstrip('/')}",
                        "mode": "packet-up",
                        "extra": json.dumps(VK_GET_XHTTP_EXTRA, separators=(",", ":")),
                    },
                    "VK-CDN-XHTTP",
                ),
            )
        )
    if args.ya_cdn_domain:
        links.append(
            (
                "Yandex Cloud CDN (XHTTP, белый список)",
                build_vless_uri(
                    args.uuid,
                    args.ya_cdn_domain,
                    443,
                    {
                        "type": "xhttp",
                        "security": "tls",
                        "sni": args.ya_cdn_domain,
                        "host": args.ya_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.ya_xhttp_path.lstrip('/')}",
                    },
                    "Yandex-CDN-XHTTP",
                ),
            )
        )
        links.append(
            (
                "Yandex Cloud CDN (WebSocket fallback)",
                build_vless_uri(
                    args.uuid,
                    args.ya_cdn_domain,
                    443,
                    {
                        "type": "ws",
                        "security": "tls",
                        "sni": args.ya_cdn_domain,
                        "host": args.ya_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.ya_ws_path.lstrip('/')}",
                    },
                    "Yandex-CDN-WS",
                ),
            )
        )

    for label, uri in links:
        print(f"{label}: {uri}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="3x-ui SQLite DB Manager for Server-Combain")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-keys", help="Сгенерировать ключи X25519 Reality, shortId и UUID")

    p_init = subparsers.add_parser("init-all", help="Настроить панель и 5 инбаундов в x-ui.db")
    p_init.add_argument("--db", type=Path, default=Path("/etc/x-ui/x-ui.db"))
    p_init.add_argument("--panel-port", type=int, required=True)
    p_init.add_argument("--panel-path", required=True)
    p_init.add_argument("--uuid", required=True)
    p_init.add_argument("--reality-sni", required=True)
    p_init.add_argument("--reality-private-key", required=True)
    p_init.add_argument("--reality-public-key", required=True)
    p_init.add_argument("--reality-short-id", required=True)
    p_init.add_argument("--reality-port", type=int, default=20443)
    p_init.add_argument("--vk-xhttp-port", type=int, default=20444)
    p_init.add_argument("--vk-xhttp-path", required=True)
    p_init.add_argument("--vk-ws-port", type=int, default=20445)
    p_init.add_argument("--vk-ws-path", required=True)
    p_init.add_argument("--ya-xhttp-port", type=int, default=20446)
    p_init.add_argument("--ya-xhttp-path", required=True)
    p_init.add_argument("--ya-ws-port", type=int, default=20447)
    p_init.add_argument("--ya-ws-path", required=True)

    p_links = subparsers.add_parser("export-links", help="Сформировать vless:// ссылки")
    p_links.add_argument("--server-ip", required=True)
    p_links.add_argument("--base-domain", default="")
    p_links.add_argument("--uuid", required=True)
    p_links.add_argument("--reality-sni", required=True)
    p_links.add_argument("--reality-public-key", required=True)
    p_links.add_argument("--reality-short-id", required=True)
    p_links.add_argument("--vk-cdn-domain", default="")
    p_links.add_argument("--vk-xhttp-path", default="")
    p_links.add_argument("--vk-ws-path", default="")
    p_links.add_argument("--ya-cdn-domain", default="")
    p_links.add_argument("--ya-xhttp-path", default="")
    p_links.add_argument("--ya-ws-path", default="")

    args = parser.parse_args()
    handlers = {
        "gen-keys": cmd_gen_keys,
        "init-all": cmd_init_all,
        "export-links": cmd_export_links,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
