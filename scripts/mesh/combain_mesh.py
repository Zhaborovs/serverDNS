#!/usr/bin/env python3
"""
Combain-Mesh CLI entrypoint.

Subcommands:
  init-node, join-peer, daemon,
  user-add, user-list, user-disable, user-enable, user-extend, user-reset-devices,
  node-list, sync-now
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any

# Allow running directly as `python3 scripts/mesh/combain_mesh.py` as well as `-m scripts.mesh.combain_mesh`
if __package__ in (None, ""):
    _repo_root = str(Path(__file__).resolve().parents[2])
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from scripts.mesh.api_server import MeshAPIServer
    from scripts.mesh.mesh_db import MeshDB, now_ms
    from scripts.mesh.mesh_sync import (
        DEFAULT_API_PORT,
        DEFAULT_OFFLINE_THRESHOLD_SEC,
        DEFAULT_SYNC_INTERVAL_SEC,
        DEFAULT_XUI_DB_PATH,
        MeshSyncEngine,
        sync_local_xui_clients,
    )
else:
    from .api_server import MeshAPIServer
    from .mesh_db import MeshDB, now_ms
    from .mesh_sync import (
        DEFAULT_API_PORT,
        DEFAULT_OFFLINE_THRESHOLD_SEC,
        DEFAULT_SYNC_INTERVAL_SEC,
        DEFAULT_XUI_DB_PATH,
        MeshSyncEngine,
        sync_local_xui_clients,
    )


DEFAULT_STATE_DIR = "/var/lib/combain-mesh"


def _resolve_db_path(args: argparse.Namespace) -> Path:
    explicit_db = getattr(args, "db", None)
    if explicit_db:
        return Path(explicit_db)
    state_dir = getattr(args, "state_dir", None) or os.environ.get("COMBAIN_MESH_STATE_DIR")
    if state_dir:
        return Path(state_dir) / "mesh.db"
    env_db = os.environ.get("COMBAIN_MESH_DB")
    if env_db:
        return Path(env_db)
    return Path(DEFAULT_STATE_DIR) / "mesh.db"


def _resolve_secret(args: argparse.Namespace, db: MeshDB) -> str:
    sec = getattr(args, "secret", None) or os.environ.get("MESH_SECRET") or ""
    if sec:
        return sec
    return db.get_meta("mesh_secret", "")


def _resolve_port(args: argparse.Namespace, db: MeshDB) -> int:
    port = getattr(args, "port", None)
    if port is not None:
        return int(port)
    env_port = os.environ.get("MESH_API_PORT")
    if env_port:
        return int(env_port)
    meta_port = db.get_meta("api_port", "")
    if meta_port:
        return int(meta_port)
    return DEFAULT_API_PORT


def _resolve_xui_db(args: argparse.Namespace) -> str | None:
    xui_db = getattr(args, "xui_db", None)
    if xui_db is not None:
        return xui_db or None
    return os.environ.get("COMBAIN_XUI_DB", DEFAULT_XUI_DB_PATH)


def _best_effort_post_write_sync(args: argparse.Namespace, db: MeshDB) -> None:
    sync_local_xui_clients(db, xui_db_path=_resolve_xui_db(args))
    if getattr(args, "no_sync", False):
        return
    secret = _resolve_secret(args, db)
    local_node_id = db.get_meta("local_node_id", "")
    if not secret or not local_node_id:
        return
    peers = [
        n
        for n in db.list_nodes(include_deleted=False)
        if n["node_id"] != local_node_id and n.get("mesh_ip")
    ]
    if not peers:
        return
    engine = MeshSyncEngine(
        db,
        local_node_id,
        secret,
        api_port=_resolve_port(args, db),
        request_timeout_sec=2.0,
        xui_db_path=_resolve_xui_db(args),
    )
    engine.sync_all_peers()


def _format_expiry(expires_at: int) -> str:
    if not expires_at:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expires_at / 1000))


def cmd_init_node(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        node = db.upsert_node(
            node_id=args.node_id or db.get_meta("local_node_id") or None,
            name=args.name,
            role=args.role,
            public_ip=args.public_ip,
            mesh_ip=args.mesh_ip,
            base_domain=args.base_domain,
            dns_domain=args.dns_domain,
            xhttp_path=args.xhttp_path,
            ws_path=args.ws_path,
            vless_pub_key=args.vless_pub_key,
            awg_port=args.awg_port,
            status="online",
            last_seen=now_ms(),
        )
        db.set_meta("local_node_id", node["node_id"])
        arg_secret = getattr(args, "secret", None)
        if arg_secret or os.environ.get("MESH_SECRET"):
            db.set_meta("mesh_secret", arg_secret or os.environ["MESH_SECRET"])
        arg_port = getattr(args, "port", None)
        if arg_port is not None:
            db.set_meta("api_port", str(arg_port))
        if getattr(args, "json", False):
            print(json.dumps(node, ensure_ascii=False, indent=2))
        else:
            print(
                f"[OK] Node initialized: id={node['node_id']} name={node['name']} "
                f"role={node['role']} mesh_ip={node['mesh_ip']} domain={node['base_domain']}"
            )
    return 0


def cmd_join_peer(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        mesh_ip = (args.mesh_ip or "").strip()
        if not mesh_ip and args.peer_url:
            mesh_ip = args.peer_url.strip()
        if not mesh_ip:
            print("[ERR] Either --mesh-ip or --peer-url is required.", file=sys.stderr)
            return 2

        peer = db.upsert_node(
            node_id=args.peer_node_id or None,
            name=args.name or mesh_ip,
            role=args.role,
            public_ip=args.public_ip,
            mesh_ip=mesh_ip,
            base_domain=args.base_domain,
            dns_domain=args.dns_domain,
            xhttp_path=args.xhttp_path,
            ws_path=args.ws_path,
            vless_pub_key=args.vless_pub_key,
            awg_port=args.awg_port,
            status="online",
            last_seen=now_ms(),
        )
        synced = False
        secret = _resolve_secret(args, db)
        local_node_id = db.get_meta("local_node_id", "")
        if secret and local_node_id and not args.no_sync:
            engine = MeshSyncEngine(
                db,
                local_node_id,
                secret,
                api_port=_resolve_port(args, db),
                xui_db_path=_resolve_xui_db(args),
            )
            stats = engine.sync_with_peer(peer)
            synced = stats is not None

        if getattr(args, "json", False):
            print(json.dumps({"peer": peer, "synced": synced}, ensure_ascii=False, indent=2))
        else:
            print(
                f"[OK] Peer added: id={peer['node_id']} mesh_ip={peer['mesh_ip']} "
                f"role={peer['role']} synced={synced}"
            )
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    db = MeshDB(db_path)
    local_node_id = args.node_id or db.get_meta("local_node_id", "")
    secret = _resolve_secret(args, db)
    port = _resolve_port(args, db)

    if not secret:
        print("[ERR] MESH_SECRET (or --secret) is required to run daemon.", file=sys.stderr)
        db.close()
        return 2

    mesh_bind = args.mesh_bind
    if not mesh_bind and local_node_id:
        local_node = db.get_node(local_node_id)
        if local_node:
            cand = str(local_node.get("mesh_ip") or "").strip()
            if cand and "://" not in cand and ":" not in cand:
                mesh_bind = cand

    engine = MeshSyncEngine(
        db,
        local_node_id,
        secret,
        api_port=port,
        sync_interval_sec=args.sync_interval,
        offline_threshold_sec=args.offline_threshold,
        xui_db_path=_resolve_xui_db(args),
    )
    server = MeshAPIServer(
        db,
        local_node_id,
        secret,
        bind_host=args.bind,
        port=port,
        mesh_bind_host=mesh_bind,
        sync_engine=engine,
    )

    stop_flag = False

    def _handle_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_flag
        stop_flag = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    server.start()
    engine.start()
    print(
        f"[OK] Combain-Mesh daemon listening on {args.bind}:{server.actual_port}"
        + (f" and {mesh_bind}:{server.actual_port}" if mesh_bind and mesh_bind != args.bind else "")
        + f" (node_id={local_node_id or 'unset'})",
        flush=True,
    )

    try:
        while not stop_flag:
            time.sleep(0.5)
    finally:
        engine.stop()
        server.stop()
        db.close()
    return 0


def cmd_user_add(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        user = db.create_user(
            username=args.username,
            max_devices=args.max_devices,
            days=args.days if args.days > 0 else None,
            note=args.note,
            user_uuid=args.uuid or None,
            sub_token=args.sub_token or None,
        )
        _best_effort_post_write_sync(args, db)
        if getattr(args, "json", False):
            print(json.dumps(user, ensure_ascii=False, indent=2))
        else:
            print(
                f"[OK] User created: username={user['username']} "
                f"uuid={user['uuid']} sub_token={user['sub_token']} "
                f"max_devices={user['max_devices']} expires={_format_expiry(user['expires_at'])}"
            )
    return 0


def cmd_user_list(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        users = db.list_users(include_deleted=args.all)
        enriched = []
        for u in users:
            item = dict(u)
            item["used_devices"] = db.count_active_devices(u["user_id"])
            enriched.append(item)
        if getattr(args, "json", False):
            print(json.dumps(enriched, ensure_ascii=False, indent=2))
        else:
            if not enriched:
                print("(no users)")
            else:
                for u in enriched:
                    state = "deleted" if u["deleted"] else ("enabled" if u["enabled"] else "disabled")
                    print(
                        f"{u['username']:<18} state={state:<8} "
                        f"devices={u['used_devices']}/{u['max_devices']} "
                        f"expires={_format_expiry(u['expires_at']):<20} "
                        f"token={u['sub_token']}"
                    )
    return 0


def cmd_user_set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        user = db.set_user_enabled(args.username, enabled)
        if not user:
            print(f"[ERR] User not found: {args.username}", file=sys.stderr)
            return 1
        _best_effort_post_write_sync(args, db)
        if getattr(args, "json", False):
            print(json.dumps(user, ensure_ascii=False, indent=2))
        else:
            action = "enabled" if enabled else "disabled"
            print(f"[OK] User {user['username']} {action}.")
    return 0


def cmd_user_extend(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        user = db.extend_user(args.username, args.days)
        if not user:
            print(f"[ERR] User not found: {args.username}", file=sys.stderr)
            return 1
        _best_effort_post_write_sync(args, db)
        if getattr(args, "json", False):
            print(json.dumps(user, ensure_ascii=False, indent=2))
        else:
            print(
                f"[OK] User {user['username']} extended by {args.days}d -> "
                f"expires={_format_expiry(user['expires_at'])}"
            )
    return 0


def cmd_user_reset_devices(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        user = db.get_user_by_username(args.username) or db.get_user_by_id(args.username)
        if not user:
            print(f"[ERR] User not found: {args.username}", file=sys.stderr)
            return 1
        count = db.reset_user_devices(user["user_id"])
        _best_effort_post_write_sync(args, db)
        if getattr(args, "json", False):
            print(json.dumps({"username": user["username"], "devices_reset": count}, indent=2))
        else:
            print(f"[OK] Reset {count} device(s) for user {user['username']}.")
    return 0


def cmd_node_list(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        nodes = db.list_nodes(include_deleted=args.all)
        if getattr(args, "json", False):
            print(json.dumps(nodes, ensure_ascii=False, indent=2))
        else:
            if not nodes:
                print("(no nodes)")
            else:
                for n in nodes:
                    state = "deleted" if n["deleted"] else n["status"]
                    print(
                        f"{n['name'] or n['node_id']:<18} role={n['role']:<8} "
                        f"status={state:<8} mesh_ip={n['mesh_ip']:<16} "
                        f"domain={n['base_domain']}"
                    )
    return 0


def cmd_sync_now(args: argparse.Namespace) -> int:
    db_path = _resolve_db_path(args)
    with MeshDB(db_path) as db:
        local_node_id = args.node_id or db.get_meta("local_node_id", "")
        secret = _resolve_secret(args, db)
        if not secret:
            print("[ERR] MESH_SECRET (or --secret) is required for sync-now.", file=sys.stderr)
            return 2
        engine = MeshSyncEngine(
            db,
            local_node_id,
            secret,
            api_port=_resolve_port(args, db),
            xui_db_path=_resolve_xui_db(args),
        )
        results = engine.sync_all_peers()
        synced_users = engine.sync_xui()
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {"peers": results, "active_xui_users": synced_users},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            ok_cnt = sum(1 for v in results.values() if v)
            print(
                f"[OK] Sync complete: {ok_cnt}/{len(results)} peer(s) reachable; "
                f"{synced_users} active user(s) synced to 3x-ui."
            )
    return 0


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", default=argparse.SUPPRESS, help="Path to mesh.db SQLite file")
    parser.add_argument(
        "--state-dir", default=argparse.SUPPRESS, help="State directory containing mesh.db"
    )
    parser.add_argument(
        "--secret", default=argparse.SUPPRESS, help="Shared MESH_SECRET for HMAC auth"
    )
    parser.add_argument(
        "--port", type=int, default=argparse.SUPPRESS, help="Mesh HTTP API port (default 22777)"
    )
    parser.add_argument("--xui-db", default=argparse.SUPPRESS, help="Path to local 3x-ui x-ui.db")
    parser.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="Output machine-readable JSON"
    )


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    _add_common_args(common)

    parser = argparse.ArgumentParser(
        prog="combain_mesh.py",
        description="Combain-Mesh decentralized P2P control plane CLI",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init-node
    p_init = sub.add_parser("init-node", parents=[common], help="Initialize local mesh node")
    p_init.add_argument("--node-id", default="", help="Explicit node ID (default: auto UUID)")
    p_init.add_argument("--name", default="node", help="Human-readable node name")
    p_init.add_argument("--role", choices=("ru_relay", "exit"), default="exit")
    p_init.add_argument("--public-ip", default="")
    p_init.add_argument("--mesh-ip", default="")
    p_init.add_argument("--base-domain", default="")
    p_init.add_argument("--dns-domain", default="")
    p_init.add_argument("--xhttp-path", default="")
    p_init.add_argument("--ws-path", default="")
    p_init.add_argument("--vless-pub-key", default="")
    p_init.add_argument("--awg-port", type=int, default=0)

    # join-peer
    p_join = sub.add_parser("join-peer", parents=[common], help="Register a peer node and sync")
    p_join.add_argument("--peer-node-id", default="", help="Known peer node_id (optional)")
    p_join.add_argument("--peer-url", default="", help="Peer URL (e.g. http://10.77.0.2:22777)")
    p_join.add_argument("--mesh-ip", default="", help="Peer WireGuard mesh IP")
    p_join.add_argument("--name", default="")
    p_join.add_argument("--role", choices=("ru_relay", "exit"), default="exit")
    p_join.add_argument("--public-ip", default="")
    p_join.add_argument("--base-domain", default="")
    p_join.add_argument("--dns-domain", default="")
    p_join.add_argument("--xhttp-path", default="")
    p_join.add_argument("--ws-path", default="")
    p_join.add_argument("--vless-pub-key", default="")
    p_join.add_argument("--awg-port", type=int, default=0)
    p_join.add_argument("--no-sync", action="store_true", help="Do not sync immediately")

    # daemon
    p_daemon = sub.add_parser("daemon", parents=[common], help="Run P2P sync & HTTP API daemon")
    p_daemon.add_argument("--node-id", default="", help="Override local_node_id")
    p_daemon.add_argument("--bind", default="127.0.0.1", help="Primary HTTP bind host")
    p_daemon.add_argument("--mesh-bind", default="", help="Optional WireGuard mesh IP bind host")
    p_daemon.add_argument(
        "--sync-interval", type=float, default=DEFAULT_SYNC_INTERVAL_SEC, help="Sync period (sec)"
    )
    p_daemon.add_argument(
        "--offline-threshold",
        type=float,
        default=DEFAULT_OFFLINE_THRESHOLD_SEC,
        help="Mark peer offline after N unreachable seconds",
    )

    # user-add
    p_uadd = sub.add_parser("user-add", parents=[common], help="Create a VPN user")
    p_uadd.add_argument("--username", required=True)
    p_uadd.add_argument("--max-devices", type=int, default=3)
    p_uadd.add_argument("--days", type=int, default=0, help="Validity in days (0 = unlimited)")
    p_uadd.add_argument("--note", default="")
    p_uadd.add_argument("--uuid", default="")
    p_uadd.add_argument("--sub-token", default="")
    p_uadd.add_argument("--no-sync", action="store_true")

    # user-list
    p_ulist = sub.add_parser("user-list", parents=[common], help="List VPN users")
    p_ulist.add_argument("--all", action="store_true", help="Include deleted users")

    # user-disable
    p_udis = sub.add_parser("user-disable", parents=[common], help="Disable a VPN user")
    p_udis.add_argument("--username", required=True)
    p_udis.add_argument("--no-sync", action="store_true")

    # user-enable
    p_uen = sub.add_parser("user-enable", parents=[common], help="Enable a VPN user")
    p_uen.add_argument("--username", required=True)
    p_uen.add_argument("--no-sync", action="store_true")

    # user-extend
    p_uext = sub.add_parser("user-extend", parents=[common], help="Extend user expiration")
    p_uext.add_argument("--username", required=True)
    p_uext.add_argument("--days", type=int, required=True)
    p_uext.add_argument("--no-sync", action="store_true")

    # user-reset-devices
    p_urst = sub.add_parser("user-reset-devices", parents=[common], help="Reset bound HWIDs")
    p_urst.add_argument("--username", required=True)
    p_urst.add_argument("--no-sync", action="store_true")

    # node-list
    p_nlist = sub.add_parser("node-list", parents=[common], help="List mesh nodes")
    p_nlist.add_argument("--all", action="store_true", help="Include deleted nodes")

    # sync-now
    p_sync = sub.add_parser("sync-now", parents=[common], help="Trigger immediate P2P sync")
    p_sync.add_argument("--node-id", default="")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cmd = args.command
    if cmd == "init-node":
        return cmd_init_node(args)
    if cmd == "join-peer":
        return cmd_join_peer(args)
    if cmd == "daemon":
        return cmd_daemon(args)
    if cmd == "user-add":
        return cmd_user_add(args)
    if cmd == "user-list":
        return cmd_user_list(args)
    if cmd == "user-disable":
        return cmd_user_set_enabled(args, enabled=False)
    if cmd == "user-enable":
        return cmd_user_set_enabled(args, enabled=True)
    if cmd == "user-extend":
        return cmd_user_extend(args)
    if cmd == "user-reset-devices":
        return cmd_user_reset_devices(args)
    if cmd == "node-list":
        return cmd_node_list(args)
    if cmd == "sync-now":
        return cmd_sync_now(args)
    parser.error(f"Unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
