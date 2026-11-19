#!/usr/bin/env python3
"""
Combain-Mesh P2P gossip, healthcheck failover, HMAC auth, and local 3x-ui sync hook.

Uses Python 3 stdlib only (`hmac`, `hashlib`, `json`, `sqlite3`, `threading`, `time`, `urllib`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable
import urllib.error
import urllib.request

from .mesh_db import MeshDB, now_ms


DEFAULT_API_PORT = 22777
DEFAULT_SYNC_INTERVAL_SEC = 15.0
DEFAULT_OFFLINE_THRESHOLD_SEC = 45.0
DEFAULT_MAX_SKEW_SEC = 60
DEFAULT_XUI_DB_PATH = "/etc/x-ui/x-ui.db"
MESH_CLIENT_EMAIL_PREFIX = "mesh_"


# ----------------------------------------------------------------------
# HMAC-SHA256 peer authentication with timestamp replay protection
# ----------------------------------------------------------------------


def sign_mesh_request(
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
    timestamp: int | None = None,
) -> tuple[str, str]:
    """Compute `(X-Mesh-Sig, X-Mesh-Timestamp)` for a peer-to-peer HTTP request."""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    ts_str = str(ts)
    prefix = f"{ts_str}.{method.upper()}.{path}.".encode("utf-8")
    digest = hmac.new(
        secret.encode("utf-8"),
        prefix + body,
        hashlib.sha256,
    ).hexdigest()
    return digest, ts_str


def verify_mesh_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    signature: str | None,
    timestamp_str: str | None,
    max_skew_sec: int = DEFAULT_MAX_SKEW_SEC,
) -> bool:
    """Validate HMAC-SHA256 signature and timestamp replay window."""
    if not secret or not signature or not timestamp_str:
        return False
    try:
        ts = int(timestamp_str.strip())
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > int(max_skew_sec):
        return False
    expected, _ = sign_mesh_request(secret, method, path, body, timestamp=ts)
    return hmac.compare_digest(expected, signature.strip().lower())


# ----------------------------------------------------------------------
# Local 3x-ui (/etc/x-ui/x-ui.db) client synchronization
# ----------------------------------------------------------------------


def _get_table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def sync_local_xui_clients(
    db: MeshDB,
    xui_db_path: str | Path | None = DEFAULT_XUI_DB_PATH,
    callback: Callable[[list[dict[str, Any]]], None] | None = None,
) -> int:
    """
    Sync active, non-expired mesh users' UUIDs into local `/etc/x-ui/x-ui.db` (if present)
    and/or invoke an optional callback.

    Non-mesh clients (whose email does not start with `mesh_`) are preserved untouched.
    Disabled, expired, or deleted mesh users are removed from active Xray inbound client lists
    so they immediately lose VPN access across all nodes.
    """
    active_users = db.get_active_users()
    if callback is not None:
        callback(active_users)

    if not xui_db_path:
        return len(active_users)

    xui_path = Path(xui_db_path)
    if not xui_path.is_file():
        return len(active_users)

    active_by_email: dict[str, dict[str, Any]] = {
        f"{MESH_CLIENT_EMAIL_PREFIX}{u['username']}": u for u in active_users
    }
    ts_now = now_ms()

    conn = sqlite3.connect(str(xui_path), timeout=10.0)
    try:
        with conn:
            inb_cols = _get_table_columns(conn, "inbounds")
            if not inb_cols:
                return len(active_users)

            inbounds = conn.execute(
                "SELECT id, protocol, settings FROM inbounds WHERE protocol = 'vless'"
            ).fetchall()

            inbound_ids: list[int] = []
            for inb_id, _proto, raw_settings in inbounds:
                inbound_ids.append(int(inb_id))
                try:
                    settings_obj = json.loads(raw_settings or "{}")
                except Exception:
                    settings_obj = {}
                if not isinstance(settings_obj, dict):
                    settings_obj = {}

                existing_clients = settings_obj.get("clients")
                if not isinstance(existing_clients, list):
                    existing_clients = []

                # Preserve non-mesh clients (e.g. default combain admin client)
                preserved: list[dict[str, Any]] = []
                default_flow = ""
                for cl in existing_clients:
                    if not isinstance(cl, dict):
                        continue
                    email = str(cl.get("email") or "")
                    if not email.startswith(MESH_CLIENT_EMAIL_PREFIX):
                        preserved.append(cl)
                        if not default_flow and cl.get("flow"):
                            default_flow = str(cl["flow"])

                # Append all active mesh users
                for email, user in active_by_email.items():
                    preserved.append(
                        {
                            "id": user["uuid"],
                            "flow": default_flow,
                            "email": email,
                            "limitIp": int(user["max_devices"]),
                            "totalGB": 0,
                            "expiryTime": int(user["expires_at"]),
                            "enable": True,
                            "tgId": 0,
                            "subId": user["sub_token"],
                            "reset": 0,
                        }
                    )

                settings_obj["clients"] = preserved
                conn.execute(
                    "UPDATE inbounds SET settings = ? WHERE id = ?",
                    (json.dumps(settings_obj, separators=(",", ":")), inb_id),
                )

            # Sync client_traffics table if present
            ct_cols = _get_table_columns(conn, "client_traffics")
            if ct_cols and inbound_ids:
                # Disable all mesh_ entries first, then enable/insert active ones
                if "enable" in ct_cols:
                    conn.execute(
                        "UPDATE client_traffics SET enable = 0 WHERE email LIKE ?",
                        (f"{MESH_CLIENT_EMAIL_PREFIX}%",),
                    )
                for inb_id in inbound_ids:
                    for email, user in active_by_email.items():
                        row = conn.execute(
                            "SELECT id FROM client_traffics WHERE inbound_id = ? AND email = ?",
                            (inb_id, email),
                        ).fetchone()
                        if row:
                            upd = {"enable": 1, "expiry_time": int(user["expires_at"])}
                            upd_f = {k: v for k, v in upd.items() if k in ct_cols}
                            if upd_f:
                                set_sql = ", ".join(f"{k} = ?" for k in upd_f)
                                conn.execute(
                                    f"UPDATE client_traffics SET {set_sql} WHERE id = ?",
                                    (*upd_f.values(), row[0]),
                                )
                        else:
                            ins = {
                                "inbound_id": inb_id,
                                "enable": 1,
                                "email": email,
                                "up": 0,
                                "down": 0,
                                "expiry_time": int(user["expires_at"]),
                                "total": 0,
                                "reset": 0,
                                "last_online": 0,
                                "all_time": 0,
                            }
                            ins_f = {k: v for k, v in ins.items() if k in ct_cols}
                            cols_sql = ", ".join(ins_f.keys())
                            qs_sql = ", ".join("?" for _ in ins_f)
                            conn.execute(
                                f"INSERT INTO client_traffics ({cols_sql}) VALUES ({qs_sql})",
                                tuple(ins_f.values()),
                            )

            # Sync 3x-ui v3.x relational `clients` + `client_inbounds` tables if present
            cl_cols = _get_table_columns(conn, "clients")
            if cl_cols:
                if "enable" in cl_cols:
                    conn.execute(
                        "UPDATE clients SET enable = 0, updated_at = ? WHERE email LIKE ?",
                        (ts_now, f"{MESH_CLIENT_EMAIL_PREFIX}%"),
                    )
                ci_cols = _get_table_columns(conn, "client_inbounds")
                for email, user in active_by_email.items():
                    row = conn.execute(
                        "SELECT id FROM clients WHERE email = ?", (email,)
                    ).fetchone()
                    if row:
                        client_id = int(row[0])
                        upd = {
                            "sub_id": user["sub_token"],
                            "uuid": user["uuid"],
                            "limit_ip": int(user["max_devices"]),
                            "expiry_time": int(user["expires_at"]),
                            "enable": 1,
                            "updated_at": ts_now,
                        }
                        upd_f = {k: v for k, v in upd.items() if k in cl_cols}
                        if upd_f:
                            set_sql = ", ".join(f"{k} = ?" for k in upd_f)
                            conn.execute(
                                f"UPDATE clients SET {set_sql} WHERE id = ?",
                                (*upd_f.values(), client_id),
                            )
                    else:
                        ins = {
                            "email": email,
                            "sub_id": user["sub_token"],
                            "uuid": user["uuid"],
                            "password": "",
                            "flow": "",
                            "limit_ip": int(user["max_devices"]),
                            "limit_hwid": 0,
                            "total_gb": 0,
                            "expiry_time": int(user["expires_at"]),
                            "enable": 1,
                            "tg_id": 0,
                            "group_name": "mesh",
                            "comment": user.get("note", ""),
                            "reset": 0,
                            "traffic_reset": "never",
                            "traffic_reset_day": 1,
                            "created_at": ts_now,
                            "updated_at": ts_now,
                        }
                        ins_f = {k: v for k, v in ins.items() if k in cl_cols}
                        cols_sql = ", ".join(ins_f.keys())
                        qs_sql = ", ".join("?" for _ in ins_f)
                        cur = conn.execute(
                            f"INSERT INTO clients ({cols_sql}) VALUES ({qs_sql})",
                            tuple(ins_f.values()),
                        )
                        client_id = int(cur.lastrowid)

                    if ci_cols and inbound_ids:
                        for inb_id in inbound_ids:
                            exists = conn.execute(
                                "SELECT 1 FROM client_inbounds WHERE client_id = ? AND inbound_id = ?",
                                (client_id, inb_id),
                            ).fetchone()
                            if not exists:
                                ci_ins = {
                                    "client_id": client_id,
                                    "inbound_id": inb_id,
                                    "flow_override": "",
                                    "created_at": ts_now,
                                }
                                ci_f = {k: v for k, v in ci_ins.items() if k in ci_cols}
                                cols_sql = ", ".join(ci_f.keys())
                                qs_sql = ", ".join("?" for _ in ci_f)
                                conn.execute(
                                    f"INSERT INTO client_inbounds ({cols_sql}) VALUES ({qs_sql})",
                                    tuple(ci_f.values()),
                                )
    finally:
        conn.close()

    return len(active_users)


# ----------------------------------------------------------------------
# P2P Gossip & Healthcheck Engine
# ----------------------------------------------------------------------


class MeshSyncEngine:
    """
    Background P2P gossip and healthcheck coordinator.

    - Pulls and pushes LWW deltas with every known peer every `sync_interval_sec` (default 15s).
    - Supports immediate push via `trigger_sync_async()` on local admin writes.
    - Marks peers `offline` if unreachable for longer than `offline_threshold_sec` (default 45s).
    - Syncs active users to local 3x-ui DB whenever user state changes.
    """

    def __init__(
        self,
        db: MeshDB,
        local_node_id: str,
        mesh_secret: str,
        *,
        api_port: int = DEFAULT_API_PORT,
        sync_interval_sec: float = DEFAULT_SYNC_INTERVAL_SEC,
        offline_threshold_sec: float = DEFAULT_OFFLINE_THRESHOLD_SEC,
        request_timeout_sec: float = 5.0,
        xui_db_path: str | Path | None = DEFAULT_XUI_DB_PATH,
        xui_sync_callback: Callable[[list[dict[str, Any]]], None] | None = None,
        peer_url_resolver: Callable[[dict[str, Any]], str] | None = None,
    ) -> None:
        self.db = db
        self.local_node_id = local_node_id
        self.mesh_secret = mesh_secret
        self.api_port = int(api_port)
        self.sync_interval_sec = float(sync_interval_sec)
        self.offline_threshold_sec = float(offline_threshold_sec)
        self.request_timeout_sec = float(request_timeout_sec)
        self.xui_db_path = xui_db_path
        self.xui_sync_callback = xui_sync_callback
        self.peer_url_resolver = peer_url_resolver

        self._stop_event = threading.Event()
        self._wakeup_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._sync_lock = threading.Lock()
        # Track last successful sync timestamp per peer for incremental pull
        self._peer_since_ms: dict[str, int] = {}

    def resolve_peer_url(self, peer: dict[str, Any]) -> str:
        """Build base HTTP URL for a peer node over the WireGuard mesh."""
        if self.peer_url_resolver is not None:
            return self.peer_url_resolver(peer).rstrip("/")
        mesh_ip = str(peer.get("mesh_ip") or "").strip()
        if not mesh_ip:
            return ""
        if mesh_ip.startswith("http://") or mesh_ip.startswith("https://"):
            return mesh_ip.rstrip("/")
        if ":" in mesh_ip and not mesh_ip.startswith("["):
            # Host:port already embedded (e.g. 127.0.0.1:22801 in tests)
            return f"http://{mesh_ip}"
        return f"http://{mesh_ip}:{self.api_port}"

    def _signed_request(
        self,
        base_url: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else b""
        )
        sig, ts_str = sign_mesh_request(self.mesh_secret, method, path, body)
        headers = {
            "X-Mesh-Sig": sig,
            "X-Mesh-Timestamp": ts_str,
            "X-Mesh-Node-Id": self.local_node_id,
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            f"{base_url}{path}",
            data=body if method.upper() != "GET" else None,
            headers=headers,
            method=method.upper(),
        )
        with urllib.request.urlopen(req, timeout=self.request_timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def check_peer_health(self, peer: dict[str, Any]) -> bool:
        """Probe `GET /mesh/health` on a single peer and update its status/last_seen."""
        peer_id = str(peer["node_id"])
        base_url = self.resolve_peer_url(peer)
        if not base_url:
            return False
        try:
            res = self._signed_request(base_url, "GET", "/mesh/health")
            if res.get("ok"):
                self.db.mark_node_status(peer_id, "online", last_seen=now_ms())
                return True
        except Exception:
            pass
        self._handle_peer_unreachable(peer)
        return False

    def _handle_peer_unreachable(self, peer: dict[str, Any]) -> None:
        peer_id = str(peer["node_id"])
        fresh = self.db.get_node(peer_id) or peer
        last_seen = int(fresh.get("last_seen") or 0)
        elapsed_ms = now_ms() - last_seen
        if elapsed_ms >= int(self.offline_threshold_sec * 1000):
            self.db.mark_node_status(peer_id, "offline")

    def sync_with_peer(self, peer: dict[str, Any]) -> dict[str, Any] | None:
        """Push full/incremental delta to `peer` and merge the delta it returns."""
        peer_id = str(peer["node_id"])
        base_url = self.resolve_peer_url(peer)
        if not base_url:
            return None

        since_ms = self._peer_since_ms.get(peer_id, 0)
        # Always push full delta on first sync or incremental if known;
        # full LWW export is tiny for 50-100 devices (<20KB), so sending since_ms=0 guarantees convergence.
        local_delta = self.db.export_delta(since_ms=0)
        req_body = {
            "sender_node_id": self.local_node_id,
            "since_ms": since_ms,
            "delta": local_delta,
        }
        try:
            resp = self._signed_request(base_url, "POST", "/mesh/sync", req_body)
            remote_delta = resp.get("delta") or {}
            stats = self.db.merge_delta(remote_delta)
            self.db.mark_node_status(peer_id, "online", last_seen=now_ms())
            if resp.get("server_time"):
                self._peer_since_ms[peer_id] = int(resp["server_time"])
            if stats.get("users_applied", 0) > 0:
                self.sync_xui()
            return stats
        except Exception:
            self._handle_peer_unreachable(peer)
            return None

    def sync_all_peers(self) -> dict[str, bool]:
        """Run one gossip + healthcheck pass against every known peer."""
        results: dict[str, bool] = {}
        with self._sync_lock:
            # Keep local node fresh as online
            if self.local_node_id:
                self.db.mark_node_status(self.local_node_id, "online", last_seen=now_ms())

            peers = [
                n
                for n in self.db.list_nodes(include_deleted=False)
                if n["node_id"] != self.local_node_id and n.get("mesh_ip")
            ]
            for peer in peers:
                stats = self.sync_with_peer(peer)
                results[peer["node_id"]] = stats is not None

            self._update_cascade_state()
        return results

    def _update_cascade_state(self) -> None:
        """Persist active local role & healthy exit failover target next to mesh.db."""
        if not self.local_node_id:
            return
        local_node = self.db.get_node(self.local_node_id)
        if not local_node:
            return
        try:
            target_exit = (
                self.db.select_cascade_exit(local_node_id=self.local_node_id)
                if local_node.get("role") == "ru_relay"
                else None
            )
            state_out = {
                "local_node_id": self.local_node_id,
                "local_role": local_node.get("role"),
                "updated_at": now_ms(),
                "cascade_exit": {
                    "node_id": target_exit["node_id"],
                    "name": target_exit["name"],
                    "mesh_ip": target_exit["mesh_ip"],
                    "base_domain": target_exit["base_domain"],
                }
                if target_exit
                else None,
            }
            out_path = self.db.db_path.parent / "mesh_cascade_target.json"
            out_path.write_text(json.dumps(state_out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except Exception:
            pass

    def sync_xui(self) -> int:
        """Sync active mesh users into local 3x-ui DB / callback."""
        return sync_local_xui_clients(
            self.db,
            xui_db_path=self.xui_db_path,
            callback=self.xui_sync_callback,
        )

    def trigger_sync_async(self) -> None:
        """Wake the background loop immediately (or run a one-shot push thread if daemon not started)."""
        if self._thread is not None and self._thread.is_alive():
            self._wakeup_event.set()
        else:
            t = threading.Thread(target=self.sync_all_peers, daemon=True)
            t.start()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.sync_all_peers()
            except Exception:
                pass
            self._wakeup_event.wait(timeout=self.sync_interval_sec)
            self._wakeup_event.clear()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._wakeup_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="combain-mesh-sync", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        self._wakeup_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
