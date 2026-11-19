#!/usr/bin/env python3
"""Comprehensive unit and integration tests for Combain-Mesh P2P control plane."""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.mesh import combain_mesh
from scripts.mesh.api_server import MeshAPIServer
from scripts.mesh.mesh_db import MeshDB, now_ms
from scripts.mesh.mesh_sync import (
    MeshSyncEngine,
    sign_mesh_request,
    sync_local_xui_clients,
)


TEST_SECRET = "test-combain-mesh-secret-32bytes!"
SAMPLE_VLESS_PUB = "AAAAAAAAAAAAAAAAAAAAAA"


def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


class _MeshNodeHarness:
    """Helper wrapping a temp SQLite MeshDB + real local MeshAPIServer + MeshSyncEngine."""

    def __init__(
        self,
        tmpdir: Path,
        *,
        node_id: str,
        name: str,
        role: str,
        public_ip: str,
        base_domain: str,
        dns_domain: str = "",
        xhttp_path: str = "xhttp-mesh",
        ws_path: str = "ws-mesh",
        vless_pub_key: str = SAMPLE_VLESS_PUB,
        offline_threshold_sec: float = 45.0,
        port: int = 0,
    ) -> None:
        self.node_id = node_id
        self.db_path = tmpdir / f"{node_id}.db"
        self.db = MeshDB(self.db_path)
        self.db.set_meta("local_node_id", node_id)
        self.db.set_meta("mesh_secret", TEST_SECRET)
        self.engine = MeshSyncEngine(
            self.db,
            node_id,
            TEST_SECRET,
            offline_threshold_sec=offline_threshold_sec,
            xui_db_path=None,
        )
        self.server = MeshAPIServer(
            self.db,
            node_id,
            TEST_SECRET,
            bind_host="127.0.0.1",
            port=port,
            sync_engine=self.engine,
        )
        self.server.start()
        self.port = self.server.actual_port
        self.mesh_ip = f"127.0.0.1:{self.port}"
        self.base_url = f"http://{self.mesh_ip}"
        self.node_record = self.db.upsert_node(
            node_id=node_id,
            name=name,
            role=role,
            public_ip=public_ip,
            mesh_ip=self.mesh_ip,
            base_domain=base_domain,
            dns_domain=dns_domain or base_domain,
            xhttp_path=xhttp_path,
            ws_path=ws_path,
            vless_pub_key=vless_pub_key,
            awg_port=51820,
            status="online",
            last_seen=now_ms(),
        )

    def add_peer(self, other: "_MeshNodeHarness") -> None:
        self.db.merge_delta({"nodes": [other.node_record], "users": [], "user_devices": []})

    def stop_server(self) -> None:
        self.server.stop()

    def restart_server(self) -> None:
        self.server = MeshAPIServer(
            self.db,
            self.node_id,
            TEST_SECRET,
            bind_host="127.0.0.1",
            port=self.port,
            sync_engine=self.engine,
        )
        self.server.start()

    def close(self) -> None:
        self.engine.stop()
        self.server.stop()
        self.db.close()


class TestCombainMesh(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._tmp.name)
        self._harnesses: list[_MeshNodeHarness] = []

    def tearDown(self) -> None:
        for h in self._harnesses:
            h.close()
        self._tmp.cleanup()

    def _spawn_node(self, **kwargs) -> _MeshNodeHarness:
        h = _MeshNodeHarness(self.tmpdir, **kwargs)
        self._harnesses.append(h)
        return h

    # ------------------------------------------------------------------
    # 1. 3-Node P2P LWW Merge & Tombstone Propagation + HMAC Auth
    # ------------------------------------------------------------------

    def test_three_node_lww_merge_and_tombstone_propagation(self) -> None:
        n1 = self._spawn_node(
            node_id="ru-relay-1",
            name="RU-Relay",
            role="ru_relay",
            public_ip="185.10.10.1",
            base_domain="ru.example.net",
        )
        n2 = self._spawn_node(
            node_id="exit-nl-1",
            name="NL-Exit",
            role="exit",
            public_ip="45.20.20.2",
            base_domain="nl.example.net",
        )
        n3 = self._spawn_node(
            node_id="exit-de-1",
            name="DE-Exit",
            role="exit",
            public_ip="95.30.30.3",
            base_domain="de.example.net",
        )

        # Ring/mesh peer discovery: n1 <-> n2 <-> n3
        n1.add_peer(n2)
        n2.add_peer(n3)

        alice = n1.db.create_user(username="alice", max_devices=3, note="family")
        bob = n2.db.create_user(username="bob", max_devices=2, note="friend")

        # Gossip round 1 & 2 across 3 nodes
        n1.engine.sync_all_peers()
        n2.engine.sync_all_peers()
        n3.engine.sync_all_peers()
        n1.engine.sync_all_peers()

        for node in (n1, n2, n3):
            self.assertEqual(len(node.db.list_nodes()), 3)
            self.assertIsNotNone(node.db.get_user_by_username("alice"))
            self.assertIsNotNone(node.db.get_user_by_username("bob"))

        # Concurrent updates on different nodes:
        # - Node 3 updates alice.max_devices -> 5 with newer timestamp
        # - Node 1 deletes bob (tombstone)
        time.sleep(0.01)
        n3.db.update_user("alice", max_devices=5, note="upgraded-on-de")
        n1.db.delete_user("bob")

        # Propagate via gossip
        n3.engine.sync_all_peers()
        n1.engine.sync_all_peers()
        n2.engine.sync_all_peers()

        for node in (n1, n2, n3):
            a = node.db.get_user_by_username("alice")
            b = node.db.get_user_by_username("bob")
            self.assertIsNotNone(a)
            self.assertEqual(a["max_devices"], 5)
            self.assertEqual(a["note"], "upgraded-on-de")
            self.assertIsNotNone(b)
            self.assertEqual(b["deleted"], 1)
            self.assertIsNone(node.db.get_user_by_token(bob["sub_token"]))

        # Idempotency check: re-merging same delta applies 0 changes
        delta_from_n1 = n1.db.export_delta(since_ms=0)
        stats = n3.db.merge_delta(delta_from_n1)
        self.assertEqual(stats, {"nodes_applied": 0, "users_applied": 0, "devices_applied": 0})

    def test_hmac_auth_and_replay_protection(self) -> None:
        n1 = self._spawn_node(
            node_id="exit-nl-auth",
            name="NL-Auth",
            role="exit",
            public_ip="45.20.20.2",
            base_domain="nl.example.net",
        )
        # Missing signature -> 401
        code, _, _ = _http_request(f"{n1.base_url}/mesh/health")
        self.assertEqual(code, 401)

        # Invalid signature -> 401
        code, _, _ = _http_request(
            f"{n1.base_url}/mesh/health",
            headers={"X-Mesh-Sig": "deadbeef", "X-Mesh-Timestamp": str(int(time.time()))},
        )
        self.assertEqual(code, 401)

        # Expired timestamp (replay protection) -> 401
        old_ts = int(time.time()) - 120
        old_sig, old_ts_str = sign_mesh_request(TEST_SECRET, "GET", "/mesh/health", b"", old_ts)
        code, _, _ = _http_request(
            f"{n1.base_url}/mesh/health",
            headers={"X-Mesh-Sig": old_sig, "X-Mesh-Timestamp": old_ts_str},
        )
        self.assertEqual(code, 401)

        # Valid signature -> 200
        sig, ts_str = sign_mesh_request(TEST_SECRET, "GET", "/mesh/health", b"")
        code, _, raw = _http_request(
            f"{n1.base_url}/mesh/health",
            headers={"X-Mesh-Sig": sig, "X-Mesh-Timestamp": ts_str},
        )
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(raw)["ok"])

    # ------------------------------------------------------------------
    # 2. Healthcheck Failover & Multi-Node Subscription Generation
    # ------------------------------------------------------------------

    def test_healthcheck_failover_excludes_offline_node(self) -> None:
        n1 = self._spawn_node(
            node_id="exit-nl-1",
            name="NL-Exit",
            role="exit",
            public_ip="45.20.20.2",
            base_domain="nl.example.net",
            offline_threshold_sec=1.0,
        )
        n2 = self._spawn_node(
            node_id="exit-de-1",
            name="DE-Exit",
            role="exit",
            public_ip="95.30.30.3",
            base_domain="de.example.net",
            offline_threshold_sec=1.0,
        )
        n1.add_peer(n2)
        user = n1.db.create_user(username="ivan", max_devices=3)
        n1.engine.sync_all_peers()

        # Both nodes healthy -> /u-json/<token> has 4 profiles (XHTTP + WS per node)
        code, _, raw = _http_request(f"{n1.base_url}/u-json/{user['sub_token']}")
        self.assertEqual(code, 200)
        docs = json.loads(raw)
        self.assertEqual(len(docs), 4)
        remarks = [d["remarks"] for d in docs]
        self.assertTrue(any("nl.example.net" in r and "XHTTP" in r for r in remarks))
        self.assertTrue(any("nl.example.net" in r and "WS" in r for r in remarks))
        self.assertTrue(any("de.example.net" in r and "XHTTP" in r for r in remarks))
        self.assertTrue(any("de.example.net" in r and "WS" in r for r in remarks))

        # Validate anti-TSPU + VLESS Encryption + RU bypass routing inside generated Xray JSON
        xhttp_doc = next(d for d in docs if "XHTTP" in d["remarks"])
        proxy_ob = xhttp_doc["outbounds"][0]
        self.assertEqual(
            proxy_ob["settings"]["vnext"][0]["users"][0]["encryption"],
            f"mlkem768x25519plus.random.0rtt.{SAMPLE_VLESS_PUB}",
        )
        stream = proxy_ob["streamSettings"]
        self.assertEqual(stream["xhttpSettings"]["xmux"]["maxConcurrency"], "4-8")
        self.assertEqual(stream["finalmask"]["tcp"][0]["settings"]["packets"], "1-1")
        self.assertEqual(stream["finalmask"]["tcp"][0]["settings"]["length"], "10-25")

        rules = xhttp_doc["routing"]["rules"]
        self.assertEqual(rules[0], {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"})
        direct_domains = []
        for r in rules:
            if r.get("outboundTag") == "direct" and "domain" in r:
                direct_domains.extend(r["domain"])
        self.assertIn("domain:gosuslugi.ru", direct_domains)
        self.assertIn("domain:max.ru", direct_domains)
        self.assertIn("domain:sberbank.ru", direct_domains)
        self.assertIn("domain:tbank.ru", direct_domains)

        # Also validate /u/<token> Base64 output
        code_b64, _, raw_b64 = _http_request(f"{n1.base_url}/u/{user['sub_token']}")
        self.assertEqual(code_b64, 200)
        uris = base64.b64decode(raw_b64).decode("utf-8").splitlines()
        self.assertEqual(len(uris), 4)
        self.assertTrue(all(u.startswith("vless://") for u in uris))

        # Simulate DE-Exit failure (> offline_threshold_sec unreachable)
        n2.stop_server()
        n1.db.mark_node_status(n2.node_id, "online", last_seen=now_ms() - 5000)
        n1.engine.sync_all_peers()

        n2_state = n1.db.get_node(n2.node_id)
        self.assertIsNotNone(n2_state)
        self.assertEqual(n2_state["status"], "offline")

        # Offline node MUST be excluded from /u-json/<token> and /api/v1/client/bootstrap
        code, _, raw = _http_request(f"{n1.base_url}/u-json/{user['sub_token']}")
        self.assertEqual(code, 200)
        docs_after = json.loads(raw)
        self.assertEqual(len(docs_after), 2)
        self.assertTrue(all("de.example.net" not in d["remarks"] for d in docs_after))
        self.assertTrue(all("nl.example.net" in d["remarks"] for d in docs_after))

        # Recovery: restart DE-Exit -> healthcheck restores it to online
        n2.restart_server()
        n1.engine.sync_all_peers()
        self.assertEqual(n1.db.get_node(n2.node_id)["status"], "online")
        code, _, raw = _http_request(f"{n1.base_url}/u-json/{user['sub_token']}")
        self.assertEqual(code, 200)
        self.assertEqual(len(json.loads(raw)), 4)

    # ------------------------------------------------------------------
    # 3. HWID max_devices, expires_at, enabled & Bootstrap Schema
    # ------------------------------------------------------------------

    def test_hwid_max_devices_and_expiration_and_bootstrap_schema(self) -> None:
        n1 = self._spawn_node(
            node_id="exit-nl-boot",
            name="NL-Boot",
            role="exit",
            public_ip="45.20.20.2",
            base_domain="nl.example.net",
            dns_domain="dns.nl.example.net",
        )
        user = n1.db.create_user(username="maria", max_devices=3, days=30)
        tok = user["sub_token"]

        # Register 3 distinct devices -> all 200 OK
        for idx in (1, 2, 3):
            code, _, raw = _http_request(
                f"{n1.base_url}/api/v1/client/bootstrap",
                headers={"X-Sub-Token": tok, "X-HWID": f"device-{idx}"},
            )
            self.assertEqual(code, 200)
            body = json.loads(raw)
            # Validate full bootstrap response schema
            self.assertIn("account", body)
            self.assertEqual(body["account"]["username"], "maria")
            self.assertEqual(body["account"]["max_devices"], 3)
            self.assertEqual(body["account"]["used_devices"], idx)
            self.assertGreater(body["account"]["expires_at"], now_ms())
            self.assertEqual(body["mirrors"], ["https://nl.example.net"])
            self.assertEqual(body["sub_url"], f"https://nl.example.net/u/{tok}")
            self.assertEqual(body["sub_json_url"], f"https://nl.example.net/u-json/{tok}")
            self.assertEqual(len(body["smart_dns"]), 1)
            dns_entry = body["smart_dns"][0]
            self.assertEqual(dns_entry["doh"], "https://dns.nl.example.net/dns-query")
            self.assertEqual(dns_entry["dot"], "tls://dns.nl.example.net")
            self.assertEqual(dns_entry["ip"], "45.20.20.2")

        # Re-using existing HWID via query param ?token= -> 200 OK, still 3 used
        code, _, raw = _http_request(
            f"{n1.base_url}/api/v1/client/bootstrap?token={tok}",
            headers={"X-HWID": "device-2"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["account"]["used_devices"], 3)

        # 4th device rejected with 403 on both bootstrap and /u-json/
        code, _, raw = _http_request(
            f"{n1.base_url}/api/v1/client/bootstrap",
            headers={"X-Sub-Token": tok, "X-HWID": "device-4"},
        )
        self.assertEqual(code, 403)
        self.assertEqual(json.loads(raw)["error"], "device_limit_exceeded")

        code_sub, _, raw_sub = _http_request(
            f"{n1.base_url}/u-json/{tok}",
            headers={"X-HWID": "device-4"},
        )
        self.assertEqual(code_sub, 403)
        self.assertEqual(json.loads(raw_sub)["error"], "device_limit_exceeded")

        # Reset devices -> device-4 is now allowed
        reset_cnt = n1.db.reset_user_devices("maria")
        self.assertEqual(reset_cnt, 3)
        code, _, raw = _http_request(
            f"{n1.base_url}/api/v1/client/bootstrap",
            headers={"X-Sub-Token": tok, "X-HWID": "device-4"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["account"]["used_devices"], 1)

        # Expired user -> 403 across all client endpoints
        expired = n1.db.create_user(
            username="expired_user",
            max_devices=3,
            expires_at=now_ms() - 60_000,
        )
        for endpoint in (
            f"{n1.base_url}/api/v1/client/bootstrap?token={expired['sub_token']}",
            f"{n1.base_url}/u-json/{expired['sub_token']}",
            f"{n1.base_url}/u/{expired['sub_token']}",
        ):
            c, _, r = _http_request(endpoint)
            self.assertEqual(c, 403)
            self.assertEqual(json.loads(r)["error"], "user_expired")

        # Disabled user -> 403 across all client endpoints
        n1.db.set_user_enabled("maria", False)
        c, _, r = _http_request(f"{n1.base_url}/u-json/{tok}")
        self.assertEqual(c, 403)
        self.assertEqual(json.loads(r)["error"], "user_disabled")

    # ------------------------------------------------------------------
    # 4. Local 3x-ui Sync Hook & CLI Subcommands
    # ------------------------------------------------------------------

    def test_sync_local_xui_clients_and_cli(self) -> None:
        mesh_db_path = self.tmpdir / "cli_mesh.db"
        xui_db_path = self.tmpdir / "x-ui.db"

        # Seed a minimal 3x-ui DB with one existing non-mesh admin client
        conn = sqlite3.connect(str(xui_db_path))
        with conn:
            conn.executescript(
                """
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT,
                    settings TEXT
                );
                CREATE TABLE client_traffics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    inbound_id INTEGER,
                    enable INTEGER DEFAULT 1,
                    email TEXT,
                    expiry_time INTEGER DEFAULT 0
                );
                CREATE TABLE clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    sub_id TEXT,
                    uuid TEXT,
                    limit_ip INTEGER DEFAULT 0,
                    expiry_time INTEGER DEFAULT 0,
                    enable INTEGER DEFAULT 1,
                    updated_at INTEGER DEFAULT 0
                );
                CREATE TABLE client_inbounds (
                    client_id INTEGER,
                    inbound_id INTEGER,
                    flow_override TEXT DEFAULT '',
                    created_at INTEGER DEFAULT 0,
                    PRIMARY KEY (client_id, inbound_id)
                );
                """
            )
            admin_settings = json.dumps(
                {
                    "clients": [{"id": "admin-uuid-000", "email": "combain-admin", "enable": True}],
                    "decryption": "none",
                }
            )
            conn.execute(
                "INSERT INTO inbounds (protocol, settings) VALUES ('vless', ?)",
                (admin_settings,),
            )
        conn.close()

        # Exercise CLI commands
        def _run_cli(*argv: str) -> str:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = combain_mesh.main(
                    ["--db", str(mesh_db_path), "--xui-db", str(xui_db_path), *argv]
                )
            self.assertEqual(rc, 0)
            return buf.getvalue()

        _run_cli(
            "init-node",
            "--name", "Exit-1",
            "--role", "exit",
            "--mesh-ip", "10.77.0.2",
            "--base-domain", "exit1.example.net",
            "--secret", TEST_SECRET,
        )
        _run_cli("user-add", "--username", "active1", "--max-devices", "3", "--days", "30", "--no-sync")
        _run_cli("user-add", "--username", "disabled1", "--max-devices", "2", "--no-sync")
        _run_cli("user-disable", "--username", "disabled1", "--no-sync")
        _run_cli("user-extend", "--username", "active1", "--days", "15", "--no-sync")
        _run_cli("user-reset-devices", "--username", "active1", "--no-sync")
        out_users = _run_cli("user-list", "--json")
        out_nodes = _run_cli("node-list", "--json")

        self.assertEqual(len(json.loads(out_users)), 2)
        self.assertEqual(len(json.loads(out_nodes)), 1)

        # Verify callback & x-ui.db contents
        seen_cb: list[str] = []
        with MeshDB(mesh_db_path) as db:
            cnt = sync_local_xui_clients(
                db,
                xui_db_path=xui_db_path,
                callback=lambda users: seen_cb.extend(u["username"] for u in users),
            )
        self.assertEqual(cnt, 1)
        self.assertEqual(seen_cb, ["active1"])

        conn = sqlite3.connect(str(xui_db_path))
        raw_settings = conn.execute("SELECT settings FROM inbounds WHERE id = 1").fetchone()[0]
        clients = json.loads(raw_settings)["clients"]
        emails = {c["email"] for c in clients}
        self.assertIn("combain-admin", emails)
        self.assertIn("mesh_active1", emails)
        self.assertNotIn("mesh_disabled1", emails)

        disabled_ct = conn.execute(
            "SELECT enable FROM client_traffics WHERE email = 'mesh_disabled1'"
        ).fetchone()
        self.assertIsNotNone(disabled_ct)
        self.assertEqual(disabled_ct[0], 0)
        conn.close()

    def test_invite_token_remote_role_switch_and_cascade_failover(self) -> None:
        """Verify 1-line invite token, auto mesh IP allocation, remote LWW role switch, and cascade failover."""
        from scripts.mesh.combain_mesh import decode_invite_token, main as cli_main
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            db_a_path = tdp / "inv_a.db"
            db_b_path = tdp / "inv_b.db"

            def _run_cli(dbp: Path, *argv: str) -> str:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main([*argv, "--db", str(dbp)])
                self.assertEqual(rc, 0, f"CLI failed for {argv}")
                return buf.getvalue().strip()

            _run_cli(
                db_a_path, "init-node", "--node-id", "ru-1", "--name", "ru-msk",
                "--role", "ru_relay", "--public-ip", "1.2.3.4", "--mesh-ip", "10.99.0.1",
                "--wg-pubkey", "WG_PUB_RU1", "--wg-port", "51829", "--secret", TEST_SECRET,
            )
            token = _run_cli(db_a_path, "invite-create")
            self.assertTrue(token.startswith("combain-join://"))
            decoded = decode_invite_token(token)
            self.assertEqual(decoded["secret"], TEST_SECRET)
            self.assertEqual(decoded["assigned_mesh_ip"], "10.99.0.2")
            self.assertEqual(decoded["peers"][0]["wg_pubkey"], "WG_PUB_RU1")

            # Simulate remote role change on node B and LWW merge back to node A
            with MeshDB(db_a_path) as dba, MeshDB(db_b_path) as dbb:
                dba.upsert_node(node_id="de-1", name="de-1", role="exit", mesh_ip="10.99.0.2", status="online")
                dba.upsert_node(node_id="nl-1", name="nl-1", role="exit", mesh_ip="10.99.0.3", status="online")
                dbb.merge_delta(dba.export_delta(0))

                # Remote node B switches de-1 -> ru_relay
                dbb.set_node_role("de-1", "ru_relay")
                dba.merge_delta(dbb.export_delta(0))
                self.assertEqual(dba.get_node("de-1")["role"], "ru_relay")

                # Cascade exit on ru-1 must now pick nl-1 (only remaining online exit)
                target = dba.select_cascade_exit(local_node_id="ru-1")
                self.assertIsNotNone(target)
                self.assertEqual(target["node_id"], "nl-1")

                # Mark nl-1 offline -> no online exit left
                dba.mark_node_status("nl-1", "offline")
                self.assertIsNone(dba.select_cascade_exit(local_node_id="ru-1"))


if __name__ == "__main__":
    unittest.main()
