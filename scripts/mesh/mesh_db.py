#!/usr/bin/env python3
"""
Combain-Mesh SQLite state store with Last-Write-Wins (LWW) replication and tombstones.

Every node holds a full copy of `nodes`, `users`, and `user_devices`.
Any node can create, update, disable, or delete records without a single master;
conflicts are resolved deterministically by `updated_at` (Unix epoch milliseconds).
"""

from __future__ import annotations

from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Any
import uuid


SCHEMA_PATH = Path(__file__).with_name("schema.sql")

NODE_COLUMNS = (
    "node_id",
    "name",
    "role",
    "public_ip",
    "mesh_ip",
    "base_domain",
    "dns_domain",
    "xhttp_path",
    "ws_path",
    "vless_pub_key",
    "awg_port",
    "status",
    "last_seen",
    "updated_at",
    "deleted",
)

USER_COLUMNS = (
    "user_id",
    "username",
    "uuid",
    "sub_token",
    "max_devices",
    "expires_at",
    "enabled",
    "note",
    "updated_at",
    "deleted",
)

DEVICE_COLUMNS = (
    "user_id",
    "hwid",
    "last_ip",
    "last_seen",
    "updated_at",
    "deleted",
)


def now_ms() -> int:
    """Return current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)


class MeshDB:
    """Thread-safe SQLite database wrapper for Combain-Mesh state."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._last_ts = 0
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
            self._conn.executescript(schema_sql)
            # Ensure `deleted` column exists on user_devices for older schemas
            dev_cols = {
                r[1] for r in self._conn.execute("PRAGMA table_info(user_devices)").fetchall()
            }
            if "deleted" not in dev_cols:
                self._conn.execute(
                    "ALTER TABLE user_devices ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0"
                )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None  # type: ignore[assignment]

    def __enter__(self) -> "MeshDB":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _next_ts(self, min_ts: int = 0) -> int:
        """Return a strictly increasing millisecond timestamp for local writes."""
        ts = max(now_ms(), self._last_ts + 1, min_ts + 1)
        self._last_ts = ts
        return ts

    # ------------------------------------------------------------------
    # Meta helpers (local node identity / config)
    # ------------------------------------------------------------------

    def get_meta(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, str(value)),
                )

    # ------------------------------------------------------------------
    # Nodes CRUD
    # ------------------------------------------------------------------

    def upsert_node(
        self,
        *,
        node_id: str | None = None,
        name: str = "",
        role: str = "exit",
        public_ip: str = "",
        mesh_ip: str = "",
        base_domain: str = "",
        dns_domain: str = "",
        xhttp_path: str = "",
        ws_path: str = "",
        vless_pub_key: str = "",
        awg_port: int = 0,
        status: str = "online",
        last_seen: int | None = None,
        updated_at: int | None = None,
        deleted: int = 0,
    ) -> dict[str, Any]:
        if role not in ("ru_relay", "exit"):
            raise ValueError(f"Invalid node role: {role!r} (expected 'ru_relay' or 'exit')")
        nid = (node_id or "").strip() or str(uuid.uuid4())
        with self._lock:
            existing = self._conn.execute(
                "SELECT updated_at, last_seen FROM nodes WHERE node_id = ?", (nid,)
            ).fetchone()
            prev_ts = int(existing["updated_at"]) if existing else 0
            ts = int(updated_at) if updated_at is not None else self._next_ts(prev_ts)
            seen = int(last_seen) if last_seen is not None else now_ms()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO nodes (
                        node_id, name, role, public_ip, mesh_ip, base_domain, dns_domain,
                        xhttp_path, ws_path, vless_pub_key, awg_port, status, last_seen,
                        updated_at, deleted
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id) DO UPDATE SET
                        name = excluded.name,
                        role = excluded.role,
                        public_ip = excluded.public_ip,
                        mesh_ip = excluded.mesh_ip,
                        base_domain = excluded.base_domain,
                        dns_domain = excluded.dns_domain,
                        xhttp_path = excluded.xhttp_path,
                        ws_path = excluded.ws_path,
                        vless_pub_key = excluded.vless_pub_key,
                        awg_port = excluded.awg_port,
                        status = excluded.status,
                        last_seen = excluded.last_seen,
                        updated_at = excluded.updated_at,
                        deleted = excluded.deleted
                    """,
                    (
                        nid,
                        name,
                        role,
                        public_ip,
                        mesh_ip,
                        base_domain,
                        dns_domain,
                        xhttp_path,
                        ws_path,
                        vless_pub_key,
                        int(awg_port),
                        status,
                        seen,
                        ts,
                        int(deleted),
                    ),
                )
            row = self.get_node(nid)
            assert row is not None
            return row

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?", (node_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_nodes(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if include_deleted:
                rows = self._conn.execute(
                    "SELECT * FROM nodes ORDER BY role ASC, name ASC, node_id ASC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM nodes WHERE deleted = 0 ORDER BY role ASC, name ASC, node_id ASC"
                ).fetchall()
            return [dict(r) for r in rows]

    def get_healthy_nodes(self, local_node_id: str | None = None) -> list[dict[str, Any]]:
        """Return non-deleted nodes currently marked online (always treating local node as online if not deleted)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM nodes WHERE deleted = 0 AND (status = 'online' OR node_id = ?) "
                "ORDER BY CASE role WHEN 'exit' THEN 0 ELSE 1 END, name ASC, node_id ASC",
                (local_node_id or "",),
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_node_status(
        self,
        node_id: str,
        status: str,
        last_seen: int | None = None,
    ) -> bool:
        """Update local health observation (status / last_seen) without clobbering metadata LWW."""
        with self._lock:
            row = self._conn.execute(
                "SELECT last_seen FROM nodes WHERE node_id = ?", (node_id,)
            ).fetchone()
            if not row:
                return False
            new_seen = int(last_seen) if last_seen is not None else int(row["last_seen"])
            with self._conn:
                self._conn.execute(
                    "UPDATE nodes SET status = ?, last_seen = ? WHERE node_id = ?",
                    (status, new_seen, node_id),
                )
            return True

    def delete_node(self, node_id: str) -> bool:
        """Mark a node as deleted (tombstone) for P2P propagation."""
        with self._lock:
            row = self._conn.execute(
                "SELECT updated_at FROM nodes WHERE node_id = ?", (node_id,)
            ).fetchone()
            if not row:
                return False
            ts = self._next_ts(int(row["updated_at"]))
            with self._conn:
                self._conn.execute(
                    "UPDATE nodes SET deleted = 1, status = 'offline', updated_at = ? WHERE node_id = ?",
                    (ts, node_id),
                )
            return True

    # ------------------------------------------------------------------
    # Users CRUD
    # ------------------------------------------------------------------

    def create_user(
        self,
        *,
        username: str,
        max_devices: int = 3,
        expires_at: int = 0,
        days: int | None = None,
        enabled: int = 1,
        note: str = "",
        user_id: str | None = None,
        user_uuid: str | None = None,
        sub_token: str | None = None,
        updated_at: int | None = None,
    ) -> dict[str, Any]:
        uname = username.strip()
        if not uname:
            raise ValueError("username must not be empty")
        uid = (user_id or "").strip() or str(uuid.uuid4())
        u_uuid = (user_uuid or "").strip() or str(uuid.uuid4())
        token = (sub_token or "").strip() or secrets.token_urlsafe(18)
        exp = int(expires_at)
        if days is not None and days > 0:
            exp = now_ms() + int(days) * 86_400_000

        with self._lock:
            ts = int(updated_at) if updated_at is not None else self._next_ts()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO users (
                        user_id, username, uuid, sub_token, max_devices,
                        expires_at, enabled, note, updated_at, deleted
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        uid,
                        uname,
                        u_uuid,
                        token,
                        int(max_devices),
                        exp,
                        1 if enabled else 0,
                        note,
                        ts,
                    ),
                )
            row = self.get_user_by_id(uid)
            assert row is not None
            return row

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_token(self, sub_token: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE sub_token = ? AND deleted = 0", (sub_token,)
            ).fetchone()
            return dict(row) if row else None

    def list_users(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            if include_deleted:
                rows = self._conn.execute(
                    "SELECT * FROM users ORDER BY username ASC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM users WHERE deleted = 0 ORDER BY username ASC"
                ).fetchall()
            return [dict(r) for r in rows]

    def get_active_users(self, current_ms: int | None = None) -> list[dict[str, Any]]:
        """Return enabled, non-deleted, non-expired users."""
        ts_now = now_ms() if current_ms is None else int(current_ms)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users WHERE deleted = 0 AND enabled = 1 "
                "AND (expires_at = 0 OR expires_at > ?) ORDER BY username ASC",
                (ts_now,),
            ).fetchall()
            return [dict(r) for r in rows]

    def update_user(
        self,
        username_or_id: str,
        *,
        max_devices: int | None = None,
        expires_at: int | None = None,
        enabled: int | None = None,
        note: str | None = None,
        deleted: int | None = None,
        updated_at: int | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE user_id = ? OR username = ?",
                (username_or_id, username_or_id),
            ).fetchone()
            if not row:
                return None
            fields: dict[str, Any] = {}
            if max_devices is not None:
                fields["max_devices"] = int(max_devices)
            if expires_at is not None:
                fields["expires_at"] = int(expires_at)
            if enabled is not None:
                fields["enabled"] = 1 if enabled else 0
            if note is not None:
                fields["note"] = note
            if deleted is not None:
                fields["deleted"] = 1 if deleted else 0

            ts = (
                int(updated_at)
                if updated_at is not None
                else self._next_ts(int(row["updated_at"]))
            )
            fields["updated_at"] = ts
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            with self._conn:
                self._conn.execute(
                    f"UPDATE users SET {set_clause} WHERE user_id = ?",
                    (*fields.values(), row["user_id"]),
                )
            return self.get_user_by_id(row["user_id"])

    def set_user_enabled(self, username_or_id: str, enabled: bool) -> dict[str, Any] | None:
        return self.update_user(username_or_id, enabled=1 if enabled else 0)

    def extend_user(self, username_or_id: str, days: int) -> dict[str, Any] | None:
        if days <= 0:
            raise ValueError("days must be positive")
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE user_id = ? OR username = ?",
                (username_or_id, username_or_id),
            ).fetchone()
            if not row:
                return None
            base_ms = max(now_ms(), int(row["expires_at"]))
            new_exp = base_ms + int(days) * 86_400_000
            return self.update_user(row["user_id"], expires_at=new_exp)

    def delete_user(self, username_or_id: str) -> dict[str, Any] | None:
        """Mark a user as deleted (tombstone) for P2P propagation."""
        return self.update_user(username_or_id, enabled=0, deleted=1)

    # ------------------------------------------------------------------
    # User Devices (HWID enforcement)
    # ------------------------------------------------------------------

    def list_user_devices(
        self, user_id: str, include_deleted: bool = False
    ) -> list[dict[str, Any]]:
        with self._lock:
            if include_deleted:
                rows = self._conn.execute(
                    "SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM user_devices WHERE user_id = ? AND deleted = 0 "
                    "ORDER BY last_seen DESC",
                    (user_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def count_active_devices(self, user_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM user_devices WHERE user_id = ? AND deleted = 0",
                (user_id,),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def register_or_check_device(
        self,
        user_id: str,
        hwid: str,
        last_ip: str = "",
        max_devices: int = 3,
    ) -> tuple[bool, int, bool]:
        """
        Check HWID against user's `max_devices` limit and register/touch the device if allowed.

        Returns `(allowed, used_devices, changed)`.
        """
        clean_hwid = hwid.strip()
        if not clean_hwid:
            return True, self.count_active_devices(user_id), False

        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM user_devices WHERE user_id = ? AND hwid = ?",
                (user_id, clean_hwid),
            ).fetchone()
            active_count = self.count_active_devices(user_id)

            if existing and int(existing["deleted"]) == 0:
                ts = self._next_ts(int(existing["updated_at"]))
                seen = now_ms()
                with self._conn:
                    self._conn.execute(
                        "UPDATE user_devices SET last_ip = ?, last_seen = ?, updated_at = ? "
                        "WHERE user_id = ? AND hwid = ?",
                        (last_ip, seen, ts, user_id, clean_hwid),
                    )
                return True, active_count, False

            if max_devices > 0 and active_count >= max_devices:
                return False, active_count, False

            prev_ts = int(existing["updated_at"]) if existing else 0
            ts = self._next_ts(prev_ts)
            seen = now_ms()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO user_devices (user_id, hwid, last_ip, last_seen, updated_at, deleted)
                    VALUES (?, ?, ?, ?, ?, 0)
                    ON CONFLICT(user_id, hwid) DO UPDATE SET
                        last_ip = excluded.last_ip,
                        last_seen = excluded.last_seen,
                        updated_at = excluded.updated_at,
                        deleted = 0
                    """,
                    (user_id, clean_hwid, last_ip, seen, ts),
                )
            return True, active_count + 1, True

    def reset_user_devices(self, username_or_id: str) -> int:
        """Tombstone all active devices for a user so device slots reset across the mesh."""
        with self._lock:
            user = self._conn.execute(
                "SELECT user_id FROM users WHERE user_id = ? OR username = ?",
                (username_or_id, username_or_id),
            ).fetchone()
            if not user:
                return 0
            uid = user["user_id"]
            rows = self._conn.execute(
                "SELECT hwid, updated_at FROM user_devices WHERE user_id = ? AND deleted = 0",
                (uid,),
            ).fetchall()
            if not rows:
                return 0
            with self._conn:
                for r in rows:
                    ts = self._next_ts(int(r["updated_at"]))
                    self._conn.execute(
                        "UPDATE user_devices SET deleted = 1, updated_at = ? "
                        "WHERE user_id = ? AND hwid = ?",
                        (ts, uid, r["hwid"]),
                    )
            return len(rows)

    # ------------------------------------------------------------------
    # LWW Delta Export & Idempotent Merge
    # ------------------------------------------------------------------

    def export_delta(self, since_ms: int = 0) -> dict[str, Any]:
        """Export all rows modified after `since_ms` (or all rows if `since_ms <= 0`)."""
        since = int(since_ms)
        op = ">=" if since <= 0 else ">"
        with self._lock:
            nodes = [
                dict(r)
                for r in self._conn.execute(
                    f"SELECT * FROM nodes WHERE updated_at {op} ? ORDER BY updated_at ASC",
                    (since,),
                ).fetchall()
            ]
            users = [
                dict(r)
                for r in self._conn.execute(
                    f"SELECT * FROM users WHERE updated_at {op} ? ORDER BY updated_at ASC",
                    (since,),
                ).fetchall()
            ]
            devices = [
                dict(r)
                for r in self._conn.execute(
                    f"SELECT * FROM user_devices WHERE updated_at {op} ? ORDER BY updated_at ASC",
                    (since,),
                ).fetchall()
            ]
        return {
            "exported_at": now_ms(),
            "nodes": nodes,
            "users": users,
            "user_devices": devices,
        }

    def merge_delta(self, payload: dict[str, Any]) -> dict[str, int]:
        """
        Idempotent LWW merge of incoming delta (`nodes`, `users`, `user_devices`).
        Higher `updated_at` wins; on exact tie, `deleted=1` (tombstone) wins deterministically.
        """
        nodes_in = payload.get("nodes") or []
        users_in = payload.get("users") or []
        devices_in = payload.get("user_devices") or []

        stats = {"nodes_applied": 0, "users_applied": 0, "devices_applied": 0}

        with self._lock:
            with self._conn:
                for item in nodes_in:
                    if self._merge_node(item):
                        stats["nodes_applied"] += 1
                for item in users_in:
                    if self._merge_user(item):
                        stats["users_applied"] += 1
                for item in devices_in:
                    if self._merge_device(item):
                        stats["devices_applied"] += 1
        return stats

    def _should_apply_lww(
        self,
        existing_updated_at: int,
        existing_deleted: int,
        incoming_updated_at: int,
        incoming_deleted: int,
    ) -> bool:
        if incoming_updated_at > existing_updated_at:
            return True
        if incoming_updated_at == existing_updated_at:
            if incoming_deleted > existing_deleted:
                return True
        return False

    def _merge_node(self, item: dict[str, Any]) -> bool:
        nid = str(item.get("node_id") or "").strip()
        role = str(item.get("role") or "")
        if not nid or role not in ("ru_relay", "exit"):
            return False

        in_ts = int(item.get("updated_at") or 0)
        in_del = 1 if int(item.get("deleted") or 0) else 0
        in_seen = int(item.get("last_seen") or 0)
        in_status = str(item.get("status") or "online")

        existing = self._conn.execute(
            "SELECT * FROM nodes WHERE node_id = ?", (nid,)
        ).fetchone()

        if existing is None:
            self._conn.execute(
                """
                INSERT INTO nodes (
                    node_id, name, role, public_ip, mesh_ip, base_domain, dns_domain,
                    xhttp_path, ws_path, vless_pub_key, awg_port, status, last_seen,
                    updated_at, deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    nid,
                    str(item.get("name") or ""),
                    role,
                    str(item.get("public_ip") or ""),
                    str(item.get("mesh_ip") or ""),
                    str(item.get("base_domain") or ""),
                    str(item.get("dns_domain") or ""),
                    str(item.get("xhttp_path") or ""),
                    str(item.get("ws_path") or ""),
                    str(item.get("vless_pub_key") or ""),
                    int(item.get("awg_port") or 0),
                    in_status,
                    in_seen or now_ms(),
                    in_ts,
                    in_del,
                ),
            )
            return True

        if not self._should_apply_lww(
            int(existing["updated_at"]), int(existing["deleted"]), in_ts, in_del
        ):
            return False

        # Preserve local health status unless node is being deleted
        merged_status = "offline" if in_del else str(existing["status"])
        merged_seen = max(int(existing["last_seen"]), in_seen)
        self._conn.execute(
            """
            UPDATE nodes SET
                name = ?, role = ?, public_ip = ?, mesh_ip = ?, base_domain = ?,
                dns_domain = ?, xhttp_path = ?, ws_path = ?, vless_pub_key = ?,
                awg_port = ?, status = ?, last_seen = ?, updated_at = ?, deleted = ?
            WHERE node_id = ?
            """,
            (
                str(item.get("name") or ""),
                role,
                str(item.get("public_ip") or ""),
                str(item.get("mesh_ip") or ""),
                str(item.get("base_domain") or ""),
                str(item.get("dns_domain") or ""),
                str(item.get("xhttp_path") or ""),
                str(item.get("ws_path") or ""),
                str(item.get("vless_pub_key") or ""),
                int(item.get("awg_port") or 0),
                merged_status,
                merged_seen,
                in_ts,
                in_del,
                nid,
            ),
        )
        return True

    def _merge_user(self, item: dict[str, Any]) -> bool:
        uid = str(item.get("user_id") or "").strip()
        uname = str(item.get("username") or "").strip()
        u_uuid = str(item.get("uuid") or "").strip()
        token = str(item.get("sub_token") or "").strip()
        if not uid or not uname or not u_uuid or not token:
            return False

        in_ts = int(item.get("updated_at") or 0)
        in_del = 1 if int(item.get("deleted") or 0) else 0

        existing = self._conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (uid,)
        ).fetchone()

        if existing is not None:
            if not self._should_apply_lww(
                int(existing["updated_at"]), int(existing["deleted"]), in_ts, in_del
            ):
                return False
        else:
            # Resolve rare UNIQUE(username) or UNIQUE(sub_token) conflict from concurrent creations
            conflict = self._conn.execute(
                "SELECT * FROM users WHERE (username = ? OR sub_token = ?) AND user_id != ?",
                (uname, token, uid),
            ).fetchone()
            if conflict is not None:
                if self._should_apply_lww(
                    int(conflict["updated_at"]), int(conflict["deleted"]), in_ts, in_del
                ):
                    self._conn.execute(
                        "DELETE FROM users WHERE user_id = ?", (conflict["user_id"],)
                    )
                else:
                    return False

        self._conn.execute(
            """
            INSERT INTO users (
                user_id, username, uuid, sub_token, max_devices,
                expires_at, enabled, note, updated_at, deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                uuid = excluded.uuid,
                sub_token = excluded.sub_token,
                max_devices = excluded.max_devices,
                expires_at = excluded.expires_at,
                enabled = excluded.enabled,
                note = excluded.note,
                updated_at = excluded.updated_at,
                deleted = excluded.deleted
            """,
            (
                uid,
                uname,
                u_uuid,
                token,
                int(item.get("max_devices") if item.get("max_devices") is not None else 3),
                int(item.get("expires_at") or 0),
                1 if int(item.get("enabled") if item.get("enabled") is not None else 1) else 0,
                str(item.get("note") or ""),
                in_ts,
                in_del,
            ),
        )
        return True

    def _merge_device(self, item: dict[str, Any]) -> bool:
        uid = str(item.get("user_id") or "").strip()
        hwid = str(item.get("hwid") or "").strip()
        if not uid or not hwid:
            return False

        in_ts = int(item.get("updated_at") or 0)
        in_del = 1 if int(item.get("deleted") or 0) else 0
        in_seen = int(item.get("last_seen") or 0)
        in_ip = str(item.get("last_ip") or "")

        existing = self._conn.execute(
            "SELECT * FROM user_devices WHERE user_id = ? AND hwid = ?",
            (uid, hwid),
        ).fetchone()

        if existing is not None:
            if not self._should_apply_lww(
                int(existing["updated_at"]), int(existing["deleted"]), in_ts, in_del
            ):
                return False

        self._conn.execute(
            """
            INSERT INTO user_devices (user_id, hwid, last_ip, last_seen, updated_at, deleted)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, hwid) DO UPDATE SET
                last_ip = excluded.last_ip,
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at,
                deleted = excluded.deleted
            """,
            (uid, hwid, in_ip, in_seen, in_ts, in_del),
        )
        return True
