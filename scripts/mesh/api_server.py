#!/usr/bin/env python3
"""
Combain-Mesh threaded HTTP API server.

Endpoints:
  - Mesh peer (HMAC-SHA256 authenticated via X-Mesh-Sig + X-Mesh-Timestamp):
      GET  /mesh/health
      POST /mesh/sync
  - Client (token + optional X-HWID device enforcement):
      GET  /api/v1/client/bootstrap
      GET  /u-json/<sub_token>
      GET  /u/<sub_token>
"""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any
import urllib.parse

from .mesh_db import MeshDB, now_ms
from .mesh_sync import (
    DEFAULT_API_PORT,
    DEFAULT_MAX_SKEW_SEC,
    MeshSyncEngine,
    verify_mesh_request,
)


# Anti-TSPU constants (aligned with scripts/py_helpers/xui_db_manager.py)
DIRECT_XHTTP_XMUX = {
    "maxConcurrency": "4-8",
    "cMaxLifetimeMs": "300000-600000",
    "hMaxRequestTimes": "200-400",
    "hMaxReusableSecs": "600-1200",
}

BROWSER_MASK_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

ANTI_TSPU_FINALMASK = {
    "tcp": [
        {
            "type": "fragment",
            "settings": {
                "packets": "1-1",
                "length": "10-25",
                "delay": "5-10",
                "lengths": ["10-25"],
                "delays": ["5-10"],
            },
        }
    ]
}

FALLBACK_PRIVATE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

FALLBACK_RU_BYPASS_DOMAINS = [
    "gosuslugi.ru",
    "esia.gosuslugi.ru",
    "gu-st.ru",
    "nalog.ru",
    "mos.ru",
    "gov.ru",
    "pochta.ru",
    "max.ru",
    "oneme.ru",
    "vk.com",
    "vk.me",
    "vk.ru",
    "vkvideo.ru",
    "userapi.com",
    "mail.ru",
    "ok.ru",
    "sberbank.ru",
    "sberbank.com",
    "sber.ru",
    "tbank.ru",
    "tinkoff.ru",
    "alfabank.ru",
    "vtb.ru",
    "gazprombank.ru",
    "raiffeisen.ru",
    "nspk.ru",
    "mirpay.ru",
    "yoomoney.ru",
    "ozon.ru",
    "wildberries.ru",
    "wb.ru",
    "yandex.ru",
    "ya.ru",
    "kinopoisk.ru",
    "dzen.ru",
    "rutube.ru",
    "avito.ru",
    "2gis.ru",
    "rzd.ru",
    "mts.ru",
    "megafon.ru",
    "beeline.ru",
    "t2.ru",
    "rt.ru",
]


def _load_ru_bypass_rules_builder():
    """Import `build_ru_bypass_routing_rules` from xui_db_manager if available."""
    repo_root = Path(__file__).resolve().parents[2]
    root_str = str(repo_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    try:
        from scripts.py_helpers import xui_db_manager  # type: ignore

        fn = getattr(xui_db_manager, "build_ru_bypass_routing_rules", None)
        if callable(fn):
            return fn
    except Exception:
        pass
    return None


def get_ru_bypass_routing_rules(exclude_domains: list[str] | None = None) -> list[dict[str, Any]]:
    """Return Xray routing rules for direct RU/MAX/Gosuslugi/banks & LAN split-tunneling."""
    builder = _load_ru_bypass_rules_builder()
    if builder is not None:
        try:
            rules = builder(exclude_domains=exclude_domains)
            if isinstance(rules, list) and rules:
                return rules
        except Exception:
            pass

    rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "ip": list(FALLBACK_PRIVATE_CIDRS),
            "outboundTag": "direct",
        }
    ]
    clean_excludes = [d.strip().lower() for d in (exclude_domains or []) if d and d.strip()]
    if clean_excludes:
        rules.append(
            {
                "type": "field",
                "domain": [f"domain:{d}" for d in clean_excludes],
                "outboundTag": "proxy",
            }
        )
    rules.append(
        {
            "type": "field",
            "domain": [f"domain:{d}" for d in FALLBACK_RU_BYPASS_DOMAINS]
            + [r"regexp:.*\.(ru|su|xn--p1ai)$"],
            "outboundTag": "direct",
        }
    )
    return rules


def build_vless_encryption(pub_key: str) -> str:
    """Build native VLESS Encryption client parameter (`mlkem768x25519plus.random.0rtt.<pub>`)."""
    key = (pub_key or "").strip()
    if not key:
        return "none"
    if key.startswith("mlkem768x25519plus."):
        return key
    return f"mlkem768x25519plus.random.0rtt.{key}"


def _wrap_client_xray_doc(
    remark: str,
    proxy_outbound: dict[str, Any],
    ru_rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a full client Xray JSON config doc (compatible with v2RayTun, v2rayNG, Happ)."""
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
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic", "fakedns"],
                },
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
                *json.loads(json.dumps(ru_rules)),
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ],
        },
    }


def _country_to_flag(country_code: str, role: str = "") -> str:
    cc = (country_code or "").strip().upper()
    if not cc and role == "ru_relay":
        cc = "RU"
    if len(cc) == 2 and cc.isascii() and cc.isalpha():
        return chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))
    return "🌐"


def _node_label(node: dict[str, Any]) -> str:
    name = str(node.get("name") or "").strip()
    domain = str(node.get("base_domain") or "").strip()
    if name and domain:
        return f"{name} | {domain}"
    return name or domain or str(node.get("node_id") or "node")


def build_xray_json_subscription(
    user: dict[str, Any],
    healthy_nodes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generate multi-node Xray JSON array for all healthy mesh nodes (with country flags & IPv6 fallback)."""
    ru_rules = get_ru_bypass_routing_rules()
    docs: list[dict[str, Any]] = []
    client_uuid = str(user["uuid"])

    for node in healthy_nodes:
        domain = str(node.get("base_domain") or "").strip()
        if not domain:
            continue
        flag = _country_to_flag(str(node.get("country_code") or ""), str(node.get("role") or ""))
        label = _node_label(node)
        vless_enc = build_vless_encryption(str(node.get("vless_pub_key") or ""))
        xhttp_path = str(node.get("xhttp_path") or "").strip()
        ws_path = str(node.get("ws_path") or "").strip()
        ipv6 = str(node.get("public_ipv6") or "").strip()

        endpoints = [(domain, "")]
        if ipv6:
            endpoints.append((ipv6, "-IPv6"))

        for addr, suffix in endpoints:
            if xhttp_path:
                docs.append(
                    _wrap_client_xray_doc(
                        f"{flag} Combain-Direct-XHTTP{suffix} [{label}]",
                        {
                            "tag": "proxy",
                            "protocol": "vless",
                            "settings": {
                                "vnext": [
                                    {
                                        "address": addr,
                                        "port": 443,
                                        "users": [{"id": client_uuid, "encryption": vless_enc}],
                                    }
                                ]
                            },
                            "streamSettings": {
                                "network": "xhttp",
                                "security": "tls",
                                "tlsSettings": {
                                    "serverName": domain,
                                    "fingerprint": "chrome",
                                    "alpn": ["h2"],
                                },
                                "xhttpSettings": {
                                    "path": f"/{xhttp_path.lstrip('/')}",
                                    "host": domain,
                                    "mode": "stream-one",
                                    "xPaddingBytes": "150-900",
                                    "headers": dict(BROWSER_MASK_HEADERS),
                                    "xmux": json.loads(json.dumps(DIRECT_XHTTP_XMUX)),
                                },
                                "finalmask": json.loads(json.dumps(ANTI_TSPU_FINALMASK)),
                            },
                        },
                        ru_rules,
                    )
                )

            if ws_path:
                docs.append(
                    _wrap_client_xray_doc(
                        f"{flag} Combain-Direct-WS{suffix} [{label}]",
                        {
                            "tag": "proxy",
                            "protocol": "vless",
                            "settings": {
                                "vnext": [
                                    {
                                        "address": addr,
                                        "port": 443,
                                        "users": [{"id": client_uuid, "encryption": vless_enc}],
                                    }
                                ]
                            },
                            "streamSettings": {
                                "network": "ws",
                                "security": "tls",
                                "tlsSettings": {
                                    "serverName": domain,
                                    "fingerprint": "chrome",
                                    "alpn": ["http/1.1"],
                                },
                                "wsSettings": {
                                    "path": f"/{ws_path.lstrip('/')}",
                                    "host": domain,
                                    "headers": dict(BROWSER_MASK_HEADERS),
                                },
                                "finalmask": json.loads(json.dumps(ANTI_TSPU_FINALMASK)),
                            },
                        },
                        ru_rules,
                    )
                )

    return docs


def _build_vless_uri(
    client_uuid: str,
    address: str,
    port: int,
    params: dict[str, str],
    name: str,
) -> str:
    host = address.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    qs = urllib.parse.urlencode(params, safe="")
    frag = urllib.parse.quote(name, safe="")
    return f"vless://{client_uuid}@{host}:{port}?{qs}#{frag}"


def build_vless_base64_subscription(
    user: dict[str, Any],
    healthy_nodes: list[dict[str, Any]],
) -> str:
    """Generate Base64-encoded newline-separated `vless://` URI list for all healthy mesh nodes."""
    uris: list[str] = []
    client_uuid = str(user["uuid"])
    fm_json = json.dumps(ANTI_TSPU_FINALMASK, separators=(",", ":"))

    for node in healthy_nodes:
        domain = str(node.get("base_domain") or "").strip()
        if not domain:
            continue
        flag = _country_to_flag(str(node.get("country_code") or ""), str(node.get("role") or ""))
        label = _node_label(node)
        vless_enc = build_vless_encryption(str(node.get("vless_pub_key") or ""))
        xhttp_path = str(node.get("xhttp_path") or "").strip()
        ws_path = str(node.get("ws_path") or "").strip()
        ipv6 = str(node.get("public_ipv6") or "").strip()

        endpoints = [(domain, "")]
        if ipv6:
            endpoints.append((ipv6, "-IPv6"))

        for addr, suffix in endpoints:
            if xhttp_path:
                uris.append(
                    _build_vless_uri(
                        client_uuid,
                        addr,
                        443,
                        {
                            "encryption": vless_enc,
                            "type": "xhttp",
                            "security": "tls",
                            "sni": domain,
                            "host": domain,
                            "fp": "chrome",
                            "alpn": "h2",
                            "mode": "stream-one",
                            "path": f"/{xhttp_path.lstrip('/')}",
                            "fm": fm_json,
                        },
                        f"{flag} Combain-Direct-XHTTP{suffix} [{label}]",
                    )
                )

            if ws_path:
                uris.append(
                    _build_vless_uri(
                        client_uuid,
                        addr,
                        443,
                        {
                            "encryption": vless_enc,
                            "type": "ws",
                            "security": "tls",
                            "sni": domain,
                            "host": domain,
                            "fp": "chrome",
                            "alpn": "http/1.1",
                            "path": f"/{ws_path.lstrip('/')}",
                            "fm": fm_json,
                        },
                        f"{flag} Combain-Direct-WS{suffix} [{label}]",
                    )
                )

    return base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")


# ----------------------------------------------------------------------
# Threaded HTTP Server
# ----------------------------------------------------------------------


class _MeshHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        db: MeshDB,
        local_node_id: str,
        mesh_secret: str,
        sync_engine: MeshSyncEngine | None = None,
        max_skew_sec: int = DEFAULT_MAX_SKEW_SEC,
    ) -> None:
        self.db = db
        self.local_node_id = local_node_id
        self.mesh_secret = mesh_secret
        self.sync_engine = sync_engine
        self.max_skew_sec = int(max_skew_sec)
        super().__init__(server_address, handler_class)


class MeshRequestHandler(BaseHTTPRequestHandler):
    server: _MeshHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy default stderr logging unless explicitly enabled
        if os.environ.get("COMBAIN_MESH_DEBUG") == "1":
            super().log_message(format, *args)

    def _send_json(
        self,
        status_code: int,
        payload: Any,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(
        self,
        status_code: int,
        text: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For") or self.headers.get("X-Real-IP")
        if xff:
            return xff.split(",")[0].strip()
        return str(self.client_address[0])

    def _verify_peer_hmac(self, method: str, path: str, body: bytes) -> bool:
        sig = self.headers.get("X-Mesh-Sig")
        ts = self.headers.get("X-Mesh-Timestamp")
        return verify_mesh_request(
            self.server.mesh_secret,
            method,
            path,
            body,
            sig,
            ts,
            max_skew_sec=self.server.max_skew_sec,
        )

    def _authenticate_client(
        self,
        sub_token: str,
        hwid: str,
    ) -> tuple[dict[str, Any] | None, int, dict[str, Any] | None]:
        """
        Validate client token, enabled state, expiration, and optional HWID device limit.

        Returns `(user, used_devices, error_response_tuple_or_none)`.
        """
        clean_token = (sub_token or "").strip()
        if not clean_token:
            return None, 0, {"status": 401, "body": {"error": "missing_token"}}

        user = self.server.db.get_user_by_token(clean_token)
        if not user:
            return None, 0, {"status": 404, "body": {"error": "user_not_found"}}

        if int(user.get("enabled") or 0) != 1:
            return None, 0, {"status": 403, "body": {"error": "user_disabled"}}

        exp = int(user.get("expires_at") or 0)
        if exp > 0 and exp <= now_ms():
            return None, 0, {"status": 403, "body": {"error": "user_expired", "expires_at": exp}}

        max_dev = int(user.get("max_devices") or 0)
        clean_hwid = (hwid or "").strip()
        if clean_hwid:
            allowed, used, changed = self.server.db.register_or_check_device(
                user["user_id"],
                clean_hwid,
                last_ip=self._client_ip(),
                max_devices=max_dev,
            )
            if not allowed:
                return (
                    None,
                    used,
                    {
                        "status": 403,
                        "body": {
                            "error": "device_limit_exceeded",
                            "max_devices": max_dev,
                            "used_devices": used,
                        },
                    },
                )
            if changed and self.server.sync_engine is not None:
                self.server.sync_engine.trigger_sync_async()
        else:
            used = self.server.db.count_active_devices(user["user_id"])

        return user, used, None

    def _sub_headers(self, user: dict[str, Any]) -> dict[str, str]:
        exp_sec = int(user.get("expires_at") or 0) // 1000
        title = base64.b64encode(f"Combain ({user['username']})".encode("utf-8")).decode("ascii")
        return {
            "profile-title": f"base64:{title}",
            "profile-update-interval": "6",
            "subscription-userinfo": f"upload=0; download=0; total=0; expire={exp_sec}",
            "announce": "base64:"
            + base64.b64encode(
                "Совет: исключите MAX, Госуслуги и банки в Настройки -> Приложения".encode("utf-8")
            ).decode("ascii"),
        }

    # ------------------------------------------------------------------
    # HTTP verbs
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        if path == "/mesh/health":
            if not self._verify_peer_hmac("GET", path, b""):
                self._send_json(401, {"error": "unauthorized"})
                return
            sender_id = (self.headers.get("X-Mesh-Node-Id") or "").strip()
            if sender_id:
                self.server.db.mark_node_status(sender_id, "online", last_seen=now_ms())
            self._send_json(
                200,
                {
                    "ok": True,
                    "node_id": self.server.local_node_id,
                    "status": "online",
                    "time_ms": now_ms(),
                    "nodes_count": len(self.server.db.list_nodes(include_deleted=False)),
                    "users_count": len(self.server.db.list_users(include_deleted=False)),
                },
            )
            return

        if path == "/api/v1/client/bootstrap":
            token = self.headers.get("X-Sub-Token") or qs.get("token", "")
            hwid = self.headers.get("X-HWID") or qs.get("hwid", "")
            user, used_devices, err = self._authenticate_client(token, hwid)
            if err is not None:
                self._send_json(err["status"], err["body"])
                return
            assert user is not None

            healthy = self.server.db.get_healthy_nodes(local_node_id=self.server.local_node_id)
            smart_dns: list[dict[str, Any]] = []
            mirrors: list[str] = []
            for n in healthy:
                base_dom = str(n.get("base_domain") or "").strip()
                dns_dom = str(n.get("dns_domain") or "").strip() or base_dom
                pub_ip = str(n.get("public_ip") or "").strip()
                if base_dom:
                    mirrors.append(f"https://{base_dom}")
                if dns_dom or pub_ip:
                    smart_dns.append(
                        {
                            "node_id": n["node_id"],
                            "name": n["name"],
                            "role": n["role"],
                            "doh": f"https://{dns_dom}/dns-query" if dns_dom else "",
                            "dot": f"tls://{dns_dom}" if dns_dom else "",
                            "ip": pub_ip,
                        }
                    )

            if mirrors:
                primary_base = mirrors[0]
            else:
                host_hdr = self.headers.get("Host") or f"127.0.0.1:{self.server.server_port}"
                primary_base = f"http://{host_hdr}"

            sub_tok = user["sub_token"]
            self._send_json(
                200,
                {
                    "account": {
                        "username": user["username"],
                        "expires_at": int(user["expires_at"]),
                        "max_devices": int(user["max_devices"]),
                        "used_devices": int(used_devices),
                        "enabled": bool(user["enabled"]),
                    },
                    "smart_dns": smart_dns,
                    "mirrors": mirrors,
                    "sub_url": f"{primary_base}/u/{sub_tok}",
                    "sub_json_url": f"{primary_base}/u-json/{sub_tok}",
                },
            )
            return

        if path.startswith("/u-json/"):
            token = urllib.parse.unquote(path[len("/u-json/"):]).strip("/")
            hwid = self.headers.get("X-HWID") or qs.get("hwid", "")
            user, _used, err = self._authenticate_client(token, hwid)
            if err is not None:
                self._send_json(err["status"], err["body"])
                return
            assert user is not None
            healthy = self.server.db.get_healthy_nodes(local_node_id=self.server.local_node_id)
            docs = build_xray_json_subscription(user, healthy)
            self._send_json(200, docs, extra_headers=self._sub_headers(user))
            return

        if path.startswith("/u/"):
            token = urllib.parse.unquote(path[len("/u/"):]).strip("/")
            hwid = self.headers.get("X-HWID") or qs.get("hwid", "")
            user, _used, err = self._authenticate_client(token, hwid)
            if err is not None:
                self._send_json(err["status"], err["body"])
                return
            assert user is not None
            healthy = self.server.db.get_healthy_nodes(local_node_id=self.server.local_node_id)
            b64_payload = build_vless_base64_subscription(user, healthy)
            self._send_text(200, b64_payload, extra_headers=self._sub_headers(user))
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/mesh/sync":
            if not self._verify_peer_hmac("POST", path, body):
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                self._send_json(400, {"error": "invalid_json"})
                return

            incoming_delta = data.get("delta") or {}
            since_ms = int(data.get("since_ms") or 0)
            sender_id = str(
                data.get("sender_node_id") or self.headers.get("X-Mesh-Node-Id") or ""
            ).strip()

            stats = self.server.db.merge_delta(incoming_delta)
            if sender_id:
                self.server.db.mark_node_status(sender_id, "online", last_seen=now_ms())
            if stats.get("users_applied", 0) > 0 and self.server.sync_engine is not None:
                self.server.sync_engine.sync_xui()

            local_delta = self.server.db.export_delta(since_ms=since_ms)
            self._send_json(
                200,
                {
                    "ok": True,
                    "node_id": self.server.local_node_id,
                    "server_time": now_ms(),
                    "applied": stats,
                    "delta": local_delta,
                },
            )
            return

        if path == "/mesh/update":
            if not self._verify_peer_hmac("POST", path, body):
                self._send_json(401, {"error": "unauthorized"})
                return
            import shutil
            import subprocess

            combain_bin = shutil.which("combain") or "/usr/local/bin/combain"
            if not os.path.exists(combain_bin):
                self._send_json(200, {"ok": False, "node_id": self.server.local_node_id, "error": "combain_not_found"})
                return
            try:
                subprocess.Popen(
                    [combain_bin, "update"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self._send_json(200, {"ok": True, "node_id": self.server.local_node_id, "started": True})
            except Exception as exc:
                self._send_json(500, {"ok": False, "node_id": self.server.local_node_id, "error": str(exc)})
            return

        self._send_json(404, {"error": "not_found"})


class MeshAPIServer:
    """Manages one or two threaded HTTP listeners (localhost + optional WireGuard mesh IP)."""

    def __init__(
        self,
        db: MeshDB,
        local_node_id: str,
        mesh_secret: str,
        *,
        bind_host: str = "127.0.0.1",
        port: int = DEFAULT_API_PORT,
        mesh_bind_host: str | None = None,
        sync_engine: MeshSyncEngine | None = None,
        max_skew_sec: int = DEFAULT_MAX_SKEW_SEC,
    ) -> None:
        self.db = db
        self.local_node_id = local_node_id
        self.mesh_secret = mesh_secret
        self.bind_host = bind_host
        self.port = int(port)
        self.mesh_bind_host = (mesh_bind_host or "").strip() or None
        self.sync_engine = sync_engine
        self.max_skew_sec = int(max_skew_sec)

        self._servers: list[_MeshHTTPServer] = []
        self._threads: list[threading.Thread] = []

    @property
    def actual_port(self) -> int:
        if self._servers:
            return int(self._servers[0].server_address[1])
        return self.port

    def start(self) -> None:
        if self._servers:
            return
        primary = _MeshHTTPServer(
            (self.bind_host, self.port),
            MeshRequestHandler,
            db=self.db,
            local_node_id=self.local_node_id,
            mesh_secret=self.mesh_secret,
            sync_engine=self.sync_engine,
            max_skew_sec=self.max_skew_sec,
        )
        self._servers.append(primary)
        bound_port = int(primary.server_address[1])

        if (
            self.mesh_bind_host
            and self.mesh_bind_host != self.bind_host
            and self.bind_host != "0.0.0.0"
        ):
            secondary = _MeshHTTPServer(
                (self.mesh_bind_host, bound_port),
                MeshRequestHandler,
                db=self.db,
                local_node_id=self.local_node_id,
                mesh_secret=self.mesh_secret,
                sync_engine=self.sync_engine,
                max_skew_sec=self.max_skew_sec,
            )
            self._servers.append(secondary)

        for idx, srv in enumerate(self._servers):
            t = threading.Thread(
                target=srv.serve_forever,
                kwargs={"poll_interval": 0.2},
                name=f"combain-mesh-http-{idx}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        for t in self._threads:
            t.join(timeout=3.0)
        self._servers.clear()
        self._threads.clear()
