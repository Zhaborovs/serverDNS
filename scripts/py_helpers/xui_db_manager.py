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
import time
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

# Anti-ТСПУ профиль XMUX для прямого XHTTP (удерживает все потоки YouTube/DNS в 1-2 H2-сессиях без всплесков коннектов)
DIRECT_XHTTP_XMUX = {
    "maxConnections": "1-2",
    "hMaxRequestTimes": "800-1200",
    "hMaxReusableSecs": "1800-3000",
}

# Сырая TCP-сегментация первого пакета (аналог zapret multisplit), совместимая с sniproxy (не ломает TLS Record Header)
ANTI_TSPU_FINALMASK = {
    "tcp": [
        {
            "type": "fragment",
            "settings": {
                "packets": "1-1",
                "length": "50-150",
                "delay": "5-10",
                "lengths": ["50-150"],
                "delays": ["5-10"],
            },
        }
    ]
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
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            sub_id TEXT,
            uuid TEXT,
            password TEXT DEFAULT '',
            flow TEXT DEFAULT '',
            limit_ip INTEGER DEFAULT 0,
            limit_hwid INTEGER DEFAULT 0,
            total_gb INTEGER DEFAULT 0,
            expiry_time INTEGER DEFAULT 0,
            enable INTEGER DEFAULT 1,
            tg_id INTEGER DEFAULT 0,
            group_name TEXT DEFAULT '',
            comment TEXT DEFAULT '',
            reset INTEGER DEFAULT 0,
            traffic_reset TEXT DEFAULT 'never',
            traffic_reset_day INTEGER DEFAULT 1,
            created_at INTEGER DEFAULT 0,
            updated_at INTEGER DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS client_inbounds (
            client_id INTEGER,
            inbound_id INTEGER,
            flow_override TEXT DEFAULT '',
            created_at INTEGER DEFAULT 0,
            PRIMARY KEY (client_id, inbound_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history_of_seeders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seeder_name TEXT
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
    client_uuid: str = "",
    client_flow: str = "",
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

    # Синхронно создаем/включаем запись клиента в client_traffics для корректного отображения в UI 3x-ui
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
        else:
            if "enable" in ct_cols:
                conn.execute("UPDATE client_traffics SET enable = 1 WHERE id = ?", (ct_row[0],))

    # Синхронизация с реляционными таблицами 3x-ui v3.x (clients + client_inbounds), откуда GetXrayConfig читает UUID
    cl_cols = get_table_columns(conn, "clients")
    if cl_cols and client_email and client_uuid and inbound_id:
        now_ms = int(time.time() * 1000)
        cl_row = conn.execute("SELECT id FROM clients WHERE email = ?", (client_email,)).fetchone()
        if cl_row:
            client_id = cl_row[0]
            upd_map = {
                "sub_id": "combain",
                "uuid": client_uuid,
                "flow": client_flow,
                "enable": 1,
                "tg_id": 0,
                "updated_at": now_ms,
            }
            upd_filtered = {k: v for k, v in upd_map.items() if k in cl_cols}
            if upd_filtered:
                set_sql = ", ".join(f"{k}=?" for k in upd_filtered)
                conn.execute(
                    f"UPDATE clients SET {set_sql} WHERE id=?",
                    (*upd_filtered.values(), client_id),
                )
        else:
            ins_map = {
                "email": client_email,
                "sub_id": "combain",
                "uuid": client_uuid,
                "password": "",
                "flow": client_flow,
                "limit_ip": 0,
                "limit_hwid": 0,
                "total_gb": 0,
                "expiry_time": 0,
                "enable": 1,
                "tg_id": 0,
                "group_name": "",
                "comment": "",
                "reset": 0,
                "traffic_reset": "never",
                "traffic_reset_day": 1,
                "created_at": now_ms,
                "updated_at": now_ms,
            }
            ins_filtered = {k: v for k, v in ins_map.items() if k in cl_cols}
            ins_cols_sql = ", ".join(ins_filtered.keys())
            ins_qs_sql = ", ".join("?" for _ in ins_filtered)
            cur_cl = conn.execute(
                f"INSERT INTO clients ({ins_cols_sql}) VALUES ({ins_qs_sql})",
                tuple(ins_filtered.values()),
            )
            client_id = cur_cl.lastrowid

        ci_cols = get_table_columns(conn, "client_inbounds")
        if ci_cols and client_id:
            ci_row = conn.execute(
                "SELECT 1 FROM client_inbounds WHERE client_id = ? AND inbound_id = ?",
                (client_id, inbound_id),
            ).fetchone()
            if not ci_row:
                ci_map = {
                    "client_id": client_id,
                    "inbound_id": inbound_id,
                    "flow_override": client_flow,
                    "created_at": now_ms,
                }
                ci_filtered = {k: v for k, v in ci_map.items() if k in ci_cols}
                ci_cols_sql = ", ".join(ci_filtered.keys())
                ci_qs_sql = ", ".join("?" for _ in ci_filtered)
                conn.execute(
                    f"INSERT INTO client_inbounds ({ci_cols_sql}) VALUES ({ci_qs_sql})",
                    tuple(ci_filtered.values()),
                )
            elif "flow_override" in ci_cols:
                conn.execute(
                    "UPDATE client_inbounds SET flow_override = ? WHERE client_id = ? AND inbound_id = ?",
                    (client_flow, client_id, inbound_id),
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
                "tgId": 0,
                "subId": "combain",
                "reset": 0,
            }
        ],
        "decryption": "none",
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


DEFAULT_XRAY_TEMPLATE = {
    "api": {
        "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"],
        "tag": "api",
    },
    "dns": {
        "servers": ["1.1.1.1", "8.8.8.8"],
        "queryStrategy": "UseIPv4",
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 62789,
            "protocol": "tunnel",
            "settings": {"rewriteAddress": "127.0.0.1"},
            "tag": "api",
        }
    ],
    "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
    "metrics": {"listen": "127.0.0.1:11111", "tag": "metrics_out"},
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "finalRules": [
                    {"action": "block", "ip": ["geoip:private"]},
                    {"action": "allow"},
                ]
            },
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "UseIPv4",
                    "tcpFastOpen": True,
                }
            },
            "tag": "direct",
        },
        {"protocol": "blackhole", "settings": {}, "tag": "blocked"},
    ],
    "policy": {
        "levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}},
        "system": {
            "statsInboundDownlink": True,
            "statsInboundUplink": True,
            "statsOutboundDownlink": False,
            "statsOutboundUplink": False,
        },
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {"inboundTag": ["api"], "outboundTag": "api", "type": "field"},
            {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
            {"network": "udp", "outboundTag": "blocked", "port": "443", "type": "field"},
            {"outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field"},
        ],
    },
    "stats": {},
}


def ensure_fast_ipv4_xray_template(conn: sqlite3.Connection) -> None:
    """Включает быстрый IPv4 DNS (1.1.1.1/8.8.8.8), UseIPv4 на freedom outbound и блокировку QUIC (udp:443)."""
    row = conn.execute("SELECT value FROM settings WHERE key = 'xrayTemplateConfig'").fetchone()
    tpl = None
    if row and row[0]:
        try:
            parsed = json.loads(row[0])
            if isinstance(parsed, dict):
                tpl = parsed
        except Exception:
            tpl = None
    if not tpl:
        tpl = json.loads(json.dumps(DEFAULT_XRAY_TEMPLATE))

    tpl["dns"] = {
        "servers": ["1.1.1.1", "8.8.8.8"],
        "queryStrategy": "UseIPv4",
    }
    outbounds = tpl.get("outbounds")
    if isinstance(outbounds, list):
        for ob in outbounds:
            if isinstance(ob, dict) and ob.get("protocol") == "freedom":
                ob.pop("targetStrategy", None)
                settings = ob.get("settings")
                if isinstance(settings, dict):
                    settings.pop("domainStrategy", None)
                    settings.pop("targetStrategy", None)
                stream = ob.setdefault("streamSettings", {})
                if not isinstance(stream, dict):
                    stream = {}
                    ob["streamSettings"] = stream
                sockopt = stream.setdefault("sockopt", {})
                if not isinstance(sockopt, dict):
                    sockopt = {}
                    stream["sockopt"] = sockopt
                sockopt["domainStrategy"] = "UseIPv4"
                sockopt["tcpFastOpen"] = True

    routing = tpl.setdefault("routing", {})
    if not isinstance(routing, dict):
        routing = {"domainStrategy": "AsIs", "rules": []}
        tpl["routing"] = routing
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        rules = []
        routing["rules"] = rules
    has_quic_block = any(
        isinstance(r, dict)
        and r.get("network") == "udp"
        and str(r.get("port", "")) == "443"
        and r.get("outboundTag") == "blocked"
        for r in rules
    )
    if not has_quic_block:
        rules.append({"type": "field", "network": "udp", "port": "443", "outboundTag": "blocked"})

    upsert_setting(conn, "xrayTemplateConfig", json.dumps(tpl, indent=2))


def cmd_init_all(args: argparse.Namespace) -> int:
    args.db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(args.db))
    try:
        ensure_schema(conn)
        panel_path = "/" + args.panel_path.strip("/") + "/"
        upsert_setting(conn, "webListen", "127.0.0.1")
        upsert_setting(conn, "webPort", str(args.panel_port))
        upsert_setting(conn, "webBasePath", panel_path)
        ensure_fast_ipv4_xray_template(conn)

        # 1. VLESS-Reality (127.0.0.1:20443, трафик приходит от sniproxy; Self-Steal проксирует веб на локальный Nginx)
        reality_dest = args.reality_dest.strip() if getattr(args, "reality_dest", "") else f"{args.reality_sni}:443"
        reality_stream = {
            "network": "tcp",
            "security": "reality",
            "externalProxy": [],
            "realitySettings": {
                "show": False,
                "xver": 0,
                "dest": reality_dest,
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
            client_uuid=args.uuid,
            client_flow="xtls-rprx-vision",
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
                client_uuid=args.uuid,
                client_flow="",
            )

        if get_table_columns(conn, "history_of_seeders"):
            conn.execute(
                "DELETE FROM history_of_seeders WHERE seeder_name IN ('ClientsTable', 'InboundClientTgIdFix2')"
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


def _collect_vless_links(
    args: argparse.Namespace,
    append_domain_label: bool = False,
) -> list[tuple[str, str]]:
    """Формирует список (описание, vless:// URI) для локальной и CDN-подписок."""
    def _tag(base_name: str) -> str:
        if append_domain_label and args.base_domain:
            return f"{base_name} [{args.base_domain}]"
        return base_name

    fm_json = json.dumps(ANTI_TSPU_FINALMASK, separators=(",", ":"))

    links: list[tuple[str, str]] = [
        (
            "VLESS-Reality (прямой с маскировкой + TCP-фрагментация)",
            build_vless_uri(
                args.uuid,
                args.server_ip,
                443,
                {
                    "encryption": "none",
                    "type": "tcp",
                    "security": "reality",
                    "pbk": args.reality_public_key,
                    "fp": "chrome",
                    "sni": args.reality_sni,
                    "sid": args.reality_short_id,
                    "spx": "/",
                    "flow": "xtls-rprx-vision",
                    "fm": fm_json,
                },
                _tag("Combain-Reality"),
            ),
        )
    ]

    if args.base_domain:
        if args.ya_xhttp_path:
            direct_params = {
                "encryption": "none",
                "type": "xhttp",
                "security": "tls",
                "sni": args.base_domain,
                "host": args.base_domain,
                "fp": "chrome",
                "alpn": "h2",
                "path": f"/{args.ya_xhttp_path.lstrip('/')}",
                "mode": "stream-one",
                "fm": fm_json,
            }
        else:
            direct_params = {
                "encryption": "none",
                "type": "xhttp",
                "security": "tls",
                "sni": args.base_domain,
                "host": args.base_domain,
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
                    _tag("Combain-Direct-XHTTP"),
                ),
            )
        )
        if args.ya_ws_path:
            links.append(
                (
                    "VLESS-WS (резервный WebSocket через домен)",
                    build_vless_uri(
                        args.uuid,
                        args.base_domain,
                        443,
                        {
                            "encryption": "none",
                            "type": "ws",
                            "security": "tls",
                            "sni": args.base_domain,
                            "host": args.base_domain,
                            "fp": "chrome",
                            "path": f"/{args.ya_ws_path.lstrip('/')}",
                        },
                        _tag("Combain-Direct-WS"),
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
                        "encryption": "none",
                        "type": "xhttp",
                        "security": "tls",
                        "sni": args.vk_cdn_domain,
                        "host": args.vk_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.vk_xhttp_path.lstrip('/')}",
                        "mode": "packet-up",
                        "extra": json.dumps(VK_GET_XHTTP_EXTRA, separators=(",", ":")),
                    },
                    _tag("VK-CDN-XHTTP"),
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
                        "encryption": "none",
                        "type": "xhttp",
                        "security": "tls",
                        "sni": args.ya_cdn_domain,
                        "host": args.ya_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.ya_xhttp_path.lstrip('/')}",
                    },
                    _tag("Yandex-CDN-XHTTP"),
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
                        "encryption": "none",
                        "type": "ws",
                        "security": "tls",
                        "sni": args.ya_cdn_domain,
                        "host": args.ya_cdn_domain,
                        "fp": "chrome",
                        "path": f"/{args.ya_ws_path.lstrip('/')}",
                    },
                    _tag("Yandex-CDN-WS"),
                ),
            )
        )

    return links


def cmd_export_links(args: argparse.Namespace) -> int:
    for label, uri in _collect_vless_links(args, append_domain_label=False):
        print(f"{label}: {uri}")
    return 0


def _wrap_client_xray_doc(remark: str, proxy_outbound: dict) -> dict:
    """Собирает полный клиентский JSON-конфиг Xray (формат 3x-ui /json/ для v2RayTun, v2rayNG, Happ)."""
    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "dns": {
            "tag": "dns_out",
            "queryStrategy": "UseIPv4",
            "servers": ["1.1.1.1", "8.8.8.8"],
        },
        "inbounds": [
            {
                "tag": "mixed",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic", "fakedns"],
                },
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"userLevel": 8},
            },
        ],
        "outbounds": [
            proxy_outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
        },
    }


def _parse_external_vless_to_doc(uri: str) -> dict | None:
    """Конвертирует внешнюю vless:// ссылку (из extra_sub_links.list) в клиентский JSON с анти-ТСПУ finalmask."""
    if not uri.startswith("vless://"):
        return None
    try:
        parsed = urllib.parse.urlsplit(uri)
        if not parsed.username or not parsed.hostname:
            return None
        port = parsed.port or 443
        qs = dict(urllib.parse.parse_qsl(parsed.query))
        remark = urllib.parse.unquote(parsed.fragment) or f"Node {parsed.hostname}"
        net = qs.get("type", "tcp")
        sec = qs.get("security", "none")
        flow = qs.get("flow", "")
        user_obj: dict[str, object] = {
            "id": parsed.username,
            "encryption": qs.get("encryption", "none"),
        }
        if flow:
            user_obj["flow"] = flow

        stream: dict[str, object] = {
            "network": net,
            "security": sec,
            "finalmask": json.loads(json.dumps(ANTI_TSPU_FINALMASK)),
        }
        if sec == "reality":
            stream["realitySettings"] = {
                "serverName": qs.get("sni", ""),
                "fingerprint": qs.get("fp", "chrome"),
                "publicKey": qs.get("pbk", ""),
                "shortId": qs.get("sid", ""),
                "spiderX": qs.get("spx", "/"),
            }
        elif sec == "tls":
            tls_s: dict[str, object] = {
                "serverName": qs.get("sni", parsed.hostname),
                "fingerprint": qs.get("fp", "chrome"),
            }
            if qs.get("alpn"):
                tls_s["alpn"] = [x.strip() for x in qs["alpn"].split(",") if x.strip()]
            stream["tlsSettings"] = tls_s

        if net == "ws":
            stream["wsSettings"] = {
                "path": qs.get("path", "/"),
                "host": qs.get("host", qs.get("sni", parsed.hostname)),
            }
        elif net == "xhttp":
            xh: dict[str, object] = {
                "path": qs.get("path", "/"),
                "host": qs.get("host", qs.get("sni", parsed.hostname)),
                "mode": qs.get("mode", "auto"),
            }
            if qs.get("extra"):
                try:
                    ext_extra = json.loads(qs["extra"])
                    if isinstance(ext_extra, dict):
                        xh.update(ext_extra)
                except Exception:
                    pass
            stream["xhttpSettings"] = xh

        ob = {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": parsed.hostname, "port": port, "users": [user_obj]}]},
            "streamSettings": stream,
        }
        return _wrap_client_xray_doc(remark, ob)
    except Exception:
        return None


def _build_xray_json_configs(args: argparse.Namespace) -> list[dict]:
    """Строит массив клиентских JSON-конфигов Xray со встроенной TCP 1-1 фрагментацией (аналог zapret)."""
    def _tag(base_name: str) -> str:
        if args.base_domain:
            return f"{base_name} [{args.base_domain}]"
        return base_name

    fm_copy = lambda: json.loads(json.dumps(ANTI_TSPU_FINALMASK))
    docs: list[dict] = []

    # 1. Combain-Reality (Self-Steal + TCP 1-1 фрагментация)
    docs.append(
        _wrap_client_xray_doc(
            _tag("Combain-Reality"),
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": args.server_ip,
                            "port": 443,
                            "users": [
                                {
                                    "id": args.uuid,
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": args.reality_sni,
                        "fingerprint": "chrome",
                        "publicKey": args.reality_public_key,
                        "shortId": args.reality_short_id,
                        "spiderX": "/",
                    },
                    "finalmask": fm_copy(),
                },
            },
        )
    )

    # 2. Combain-Direct-XHTTP (stream-one h2 + xmux 1-2 + TCP 1-1 фрагментация)
    if args.base_domain and args.ya_xhttp_path:
        docs.append(
            _wrap_client_xray_doc(
                _tag("Combain-Direct-XHTTP"),
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": args.base_domain,
                                "port": 443,
                                "users": [{"id": args.uuid, "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": args.base_domain,
                            "fingerprint": "chrome",
                            "alpn": ["h2"],
                        },
                        "xhttpSettings": {
                            "path": f"/{args.ya_xhttp_path.lstrip('/')}",
                            "host": args.base_domain,
                            "mode": "stream-one",
                            "xmux": json.loads(json.dumps(DIRECT_XHTTP_XMUX)),
                        },
                        "finalmask": fm_copy(),
                    },
                },
            )
        )

    # 3. Combain-Direct-WS (WebSocket HTTP/1.1 + TCP 1-1 фрагментация)
    if args.base_domain and args.ya_ws_path:
        docs.append(
            _wrap_client_xray_doc(
                _tag("Combain-Direct-WS"),
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": args.base_domain,
                                "port": 443,
                                "users": [{"id": args.uuid, "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": args.base_domain,
                            "fingerprint": "chrome",
                            "alpn": ["http/1.1"],
                        },
                        "wsSettings": {
                            "path": f"/{args.ya_ws_path.lstrip('/')}",
                            "host": args.base_domain,
                        },
                        "finalmask": fm_copy(),
                    },
                },
            )
        )

    # 4. Yandex Cloud CDN (если задан) — без TCP фрагментации на стороне клиента или с ней (CDN поддерживает TCP сегментацию)
    if args.ya_cdn_domain and args.ya_ws_path:
        docs.append(
            _wrap_client_xray_doc(
                _tag("Yandex-CDN-WS"),
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": args.ya_cdn_domain,
                                "port": 443,
                                "users": [{"id": args.uuid, "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": args.ya_cdn_domain,
                            "fingerprint": "chrome",
                            "alpn": ["http/1.1"],
                        },
                        "wsSettings": {
                            "path": f"/{args.ya_ws_path.lstrip('/')}",
                            "host": args.ya_cdn_domain,
                        },
                    },
                },
            )
        )

    if args.extra_links_file and args.extra_links_file.is_file():
        for raw_line in args.extra_links_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                ext_doc = _parse_external_vless_to_doc(line)
                if ext_doc:
                    docs.append(ext_doc)

    return docs


def cmd_export_sub(args: argparse.Namespace) -> int:
    """Генерирует Base64 и JSON полезную нагрузку единой подписки (с внешними нодами при наличии)."""
    uris = [uri for _, uri in _collect_vless_links(args, append_domain_label=True)]
    if args.extra_links_file and args.extra_links_file.is_file():
        for raw_line in args.extra_links_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#"):
                uris.append(line)

    payload_b64 = base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(payload_b64, encoding="utf-8")

    if getattr(args, "json_out", None):
        json_docs = _build_xray_json_configs(args)
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(json_docs, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def _add_common_link_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--base-domain", default="")
    parser.add_argument("--uuid", required=True)
    parser.add_argument("--reality-sni", required=True)
    parser.add_argument("--reality-public-key", required=True)
    parser.add_argument("--reality-short-id", required=True)
    parser.add_argument("--vk-cdn-domain", default="")
    parser.add_argument("--vk-xhttp-path", default="")
    parser.add_argument("--vk-ws-path", default="")
    parser.add_argument("--ya-cdn-domain", default="")
    parser.add_argument("--ya-xhttp-path", default="")
    parser.add_argument("--ya-ws-path", default="")


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
    p_init.add_argument("--reality-dest", default="")
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
    _add_common_link_args(p_links)

    p_sub = subparsers.add_parser("export-sub", help="Сформировать Base64 и JSON файлы подписки")
    _add_common_link_args(p_sub)
    p_sub.add_argument("--extra-links-file", type=Path, default=None)
    p_sub.add_argument("--out", type=Path, required=True)
    p_sub.add_argument("--json-out", type=Path, default=None)

    args = parser.parse_args()
    handlers = {
        "gen-keys": cmd_gen_keys,
        "init-all": cmd_init_all,
        "export-links": cmd_export_links,
        "export-sub": cmd_export_sub,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
