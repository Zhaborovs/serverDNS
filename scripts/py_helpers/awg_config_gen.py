#!/usr/bin/env python3
"""
Server-Combain — Генератор конфигураций и ключей AmneziaWG 3.1 (amneziavpn/amneziawg-go).

Назначение:
  - Автономная генерация ключей Curve25519 (формат WireGuard/AWG)
  - Генерация полного профиля параметров обфускации AmneziaWG 3.1:
      * Jc, Jmin, Jmax
      * S1..S4 (с проверкой попарного различия 148+S1, 92+S2, 64+S3, 32+S4)
      * H1..H4 (уникальные непересекающиеся диапазоны 32-bit заголовков)
      * HeaderProtectionKey, ContentPaddingAddition, RekeyAfterTime, RekeyTimeout,
        RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts, RandomTrailers, DisableCookies
      * I1 (CPS-сигнатура имитации DNS-запроса icloud.com)
  - Инициализация серверного конфига /etc/amnezia/amneziawg/awg0.conf и JSON-реестра
  - Автоматический апгрейд устаревших Legacy-реестров до AWG 3.1
  - Генерация клиентских .conf (DNS = 10.8.1.1) и нативного URI vpn://
    с корректным JSON в last_config (совместимость с AmneziaVPN 4.x / 3.1)
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import struct
import sys
import zlib

_P = (1 << 255) - 19
_A24 = 121665

_AWG3_DEFAULT_I1 = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"


def _x25519_clamp(scalar_bytes: bytes) -> int:
    b = bytearray(scalar_bytes)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    dummy = swap * (x_2 ^ x_3)
    return x_2 ^ dummy, x_3 ^ dummy


def _curve25519_base(priv_bytes: bytes) -> bytes:
    k = _x25519_clamp(priv_bytes)
    x_1 = 9
    x_2, z_2 = 1, 0
    x_3, z_3 = 9, 1
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


def generate_wg_keypair() -> tuple[str, str]:
    """Генерирует пару ключей (private, public) в формате WireGuard/AmneziaWG."""
    priv_raw = bytearray(os.urandom(32))
    priv_raw[0] &= 248
    priv_raw[31] &= 127
    priv_raw[31] |= 64
    priv_bytes = bytes(priv_raw)
    pub_bytes = _curve25519_base(priv_bytes)
    return base64.b64encode(priv_bytes).decode("ascii"), base64.b64encode(pub_bytes).decode("ascii")


def generate_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def generate_awg3_params() -> dict[str, str | int]:
    """Генерирует валидный набор параметров обфускации AmneziaWG 3.1."""
    while True:
        s1 = random.randint(15, 110)
        s2 = random.randint(15, 110)
        s3 = random.randint(12, 60)
        s4 = random.randint(12, 32)
        if len({148 + s1, 92 + s2, 64 + s3, 32 + s4}) == 4:
            break

    b1 = random.randint(100000, 400000)
    b2 = random.randint(600000, 900000)
    b3 = random.randint(1100000, 1400000)
    b4 = random.randint(1600000, 1900000)

    return {
        "Jc": random.randint(3, 6),
        "Jmin": 20,
        "Jmax": 80,
        "S1": s1,
        "S2": s2,
        "S3": s3,
        "S4": s4,
        "H1": f"{b1}-{b1 + 40000}",
        "H2": f"{b2}-{b2 + 40000}",
        "H3": f"{b3}-{b3 + 40000}",
        "H4": f"{b4}-{b4 + 40000}",
        "HeaderProtectionKey": generate_psk(),
        "ContentPaddingAddition": "10-100",
        "RekeyAfterTime": "100-120",
        "RekeyTimeout": "3-7",
        "RejectAfterTime": "150-180",
        "KeepaliveTimeout": "5-15",
        "MaxHandshakeAttempts": "15-20",
        "RandomTrailers": "on",
        "DisableCookies": "on",
        "I1": _AWG3_DEFAULT_I1,
        "I2": "",
        "I3": "",
        "I4": "",
        "I5": "",
    }


generate_awg2_params = generate_awg3_params


def encode_amnezia_vpn_uri(
    client_conf_text: str,
    registry: dict,
    client: dict,
) -> str:
    """Кодирует профиль AWG 3.1 в нативный формат vpn:// для приложения AmneziaVPN."""
    p = registry["params"]
    server_ip = registry["endpoint_ip"]
    port = int(registry["port"])
    dns_ip = registry["dns_ip"]
    net = ipaddress.ip_network(registry["subnet"], strict=False)

    client_json = {
        "config": client_conf_text,
        "hostName": server_ip,
        "port": port,
        "client_ip": client["ip"],
        "client_priv_key": client["private_key"],
        "client_pub_key": client["public_key"],
        "server_pub_key": registry["server_public_key"],
        "psk_key": client["psk"],
        "mtu": "1280",
        "persistent_keep_alive": "25",
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "Jc": str(p["Jc"]),
        "Jmin": str(p["Jmin"]),
        "Jmax": str(p["Jmax"]),
        "S1": str(p["S1"]),
        "S2": str(p["S2"]),
        "S3": str(p["S3"]),
        "S4": str(p["S4"]),
        "H1": str(p["H1"]),
        "H2": str(p["H2"]),
        "H3": str(p["H3"]),
        "H4": str(p["H4"]),
        "I1": str(p["I1"]),
        "HeaderProtectionKey": str(p["HeaderProtectionKey"]),
        "ContentPaddingAddition": str(p["ContentPaddingAddition"]),
        "RekeyAfterTime": str(p["RekeyAfterTime"]),
        "RekeyTimeout": str(p["RekeyTimeout"]),
        "RejectAfterTime": str(p["RejectAfterTime"]),
        "KeepaliveTimeout": str(p["KeepaliveTimeout"]),
        "MaxHandshakeAttempts": str(p["MaxHandshakeAttempts"]),
        "RandomTrailers": str(p["RandomTrailers"]),
        "DisableCookies": str(p["DisableCookies"]),
    }

    awg_obj = {
        "protocol_version": "3.1",
        "port": str(port),
        "transport_proto": "udp",
        "subnet_address": str(net.network_address),
        "subnet_cidr": str(net.prefixlen),
        "Jc": str(p["Jc"]),
        "Jmin": str(p["Jmin"]),
        "Jmax": str(p["Jmax"]),
        "S1": str(p["S1"]),
        "S2": str(p["S2"]),
        "S3": str(p["S3"]),
        "S4": str(p["S4"]),
        "H1": str(p["H1"]),
        "H2": str(p["H2"]),
        "H3": str(p["H3"]),
        "H4": str(p["H4"]),
        "I1": str(p["I1"]),
        "I2": str(p.get("I2", "")),
        "I3": str(p.get("I3", "")),
        "I4": str(p.get("I4", "")),
        "I5": str(p.get("I5", "")),
        "HeaderProtectionKey": str(p["HeaderProtectionKey"]),
        "ContentPaddingAddition": str(p["ContentPaddingAddition"]),
        "RekeyAfterTime": str(p["RekeyAfterTime"]),
        "RekeyTimeout": str(p["RekeyTimeout"]),
        "RejectAfterTime": str(p["RejectAfterTime"]),
        "KeepaliveTimeout": str(p["KeepaliveTimeout"]),
        "MaxHandshakeAttempts": str(p["MaxHandshakeAttempts"]),
        "RandomTrailers": str(p["RandomTrailers"]),
        "DisableCookies": str(p["DisableCookies"]),
        "last_config": json.dumps(client_json, separators=(",", ":"), ensure_ascii=False),
    }

    payload = {
        "containers": [{"awg": awg_obj, "container": "amnezia-awg"}],
        "defaultContainer": "amnezia-awg",
        "description": f"Server-Combain AWG 3.1 ({client['name']})",
        "dns1": dns_ip,
        "dns2": dns_ip,
        "hostName": server_ip,
    }
    raw_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    compressed = struct.pack(">I", len(raw_json)) + zlib.compress(raw_json, level=9)
    b64 = base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
    return f"vpn://{b64}"


def load_registry(registry_path: Path) -> dict:
    if not registry_path.exists():
        raise FileNotFoundError(f"Реестр AWG не найден: {registry_path}. Сначала выполните init-server.")
    return json.loads(registry_path.read_text(encoding="utf-8"))


def save_registry(registry_path: Path, data: dict) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_server_conf(registry: dict, conf_path: Path) -> None:
    """Пересобирает серверный конфиг /etc/amnezia/amneziawg/awg0.conf в формате AWG 3.1."""
    p = registry["params"]
    iface = registry["interface"]
    lines = [
        "[Interface]",
        f"PrivateKey = {registry['server_private_key']}",
        f"Address = {registry['server_ip_cidr']}",
        f"ListenPort = {registry['port']}",
        f"Jc = {p['Jc']}",
        f"Jmin = {p['Jmin']}",
        f"Jmax = {p['Jmax']}",
        f"S1 = {p['S1']}",
        f"S2 = {p['S2']}",
        f"S3 = {p['S3']}",
        f"S4 = {p['S4']}",
        f"H1 = {p['H1']}",
        f"H2 = {p['H2']}",
        f"H3 = {p['H3']}",
        f"H4 = {p['H4']}",
        f"HeaderProtectionKey = {p['HeaderProtectionKey']}",
        f"ContentPaddingAddition = {p['ContentPaddingAddition']}",
        f"RekeyAfterTime = {p['RekeyAfterTime']}",
        f"RekeyTimeout = {p['RekeyTimeout']}",
        f"RejectAfterTime = {p['RejectAfterTime']}",
        f"KeepaliveTimeout = {p['KeepaliveTimeout']}",
        f"MaxHandshakeAttempts = {p['MaxHandshakeAttempts']}",
        f"RandomTrailers = {p['RandomTrailers']}",
        f"DisableCookies = {p['DisableCookies']}",
        f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT; iptables -A FORWARD -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {registry['subnet']} -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {registry['subnet']} -j MASQUERADE",
        "",
    ]
    for client in registry.get("clients", []):
        lines.extend(
            [
                f"# Client: {client['name']}",
                "[Peer]",
                f"PublicKey = {client['public_key']}",
                f"PresharedKey = {client['psk']}",
                f"AllowedIPs = {client['ip']}/32",
                "",
            ]
        )

    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text("\n".join(lines), encoding="utf-8")
    try:
        os.chmod(conf_path, 0o600)
    except OSError:
        pass


def render_client_artifacts(registry: dict, client: dict, clients_dir: Path) -> tuple[Path, Path]:
    """Создает файлы <name>.conf и <name>.vpn для конкретного клиента в формате AWG 3.1."""
    p = registry["params"]
    conf_lines = [
        "[Interface]",
        f"Address = {client['ip']}/32",
        f"DNS = {registry['dns_ip']}",
        "MTU = 1280",
        f"PrivateKey = {client['private_key']}",
        f"Jc = {p['Jc']}",
        f"Jmin = {p['Jmin']}",
        f"Jmax = {p['Jmax']}",
        f"S1 = {p['S1']}",
        f"S2 = {p['S2']}",
        f"S3 = {p['S3']}",
        f"S4 = {p['S4']}",
        f"H1 = {p['H1']}",
        f"H2 = {p['H2']}",
        f"H3 = {p['H3']}",
        f"H4 = {p['H4']}",
        f"I1 = {p['I1']}",
        f"HeaderProtectionKey = {p['HeaderProtectionKey']}",
        f"ContentPaddingAddition = {p['ContentPaddingAddition']}",
        f"RekeyAfterTime = {p['RekeyAfterTime']}",
        f"RekeyTimeout = {p['RekeyTimeout']}",
        f"RejectAfterTime = {p['RejectAfterTime']}",
        f"KeepaliveTimeout = {p['KeepaliveTimeout']}",
        f"MaxHandshakeAttempts = {p['MaxHandshakeAttempts']}",
        f"RandomTrailers = {p['RandomTrailers']}",
        f"DisableCookies = {p['DisableCookies']}",
        "",
        "[Peer]",
        f"PublicKey = {registry['server_public_key']}",
        f"PresharedKey = {client['psk']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {registry['endpoint_ip']}:{registry['port']}",
        "PersistentKeepalive = 25",
        "",
    ]
    conf_text = "\n".join(conf_lines)
    clients_dir.mkdir(parents=True, exist_ok=True)
    conf_file = clients_dir / f"awg_{client['name']}.conf"
    vpn_file = clients_dir / f"awg_{client['name']}.vpn"

    conf_file.write_text(conf_text, encoding="utf-8")
    vpn_uri = encode_amnezia_vpn_uri(conf_text, registry, client)
    vpn_file.write_text(vpn_uri, encoding="utf-8")
    return conf_file, vpn_file


def cmd_gen_params(_: argparse.Namespace) -> int:
    params = generate_awg3_params()
    for k, v in params.items():
        if v != "":
            print(f"{k}={v}")
    return 0


def cmd_init_server(args: argparse.Namespace) -> int:
    upgraded = False
    if args.registry.exists():
        reg = load_registry(args.registry)
        reg["endpoint_ip"] = args.endpoint_ip
        reg["port"] = int(args.port)
        # Автоматический апгрейд старого Legacy-реестра до AWG 3.1
        if "HeaderProtectionKey" not in reg.get("params", {}) or reg.get("legacy_s12"):
            reg["params"] = generate_awg3_params()
            reg["legacy_s12"] = False
            upgraded = True
    else:
        priv, pub = generate_wg_keypair()
        net = ipaddress.ip_network(args.subnet, strict=False)
        hosts = list(net.hosts())
        server_ip = str(hosts[0])
        reg = {
            "interface": args.interface,
            "subnet": str(net),
            "server_ip_cidr": f"{server_ip}/{net.prefixlen}",
            "dns_ip": args.dns_ip or server_ip,
            "endpoint_ip": args.endpoint_ip,
            "port": int(args.port),
            "server_private_key": priv,
            "server_public_key": pub,
            "params": generate_awg3_params(),
            "clients": [],
        }
    save_registry(args.registry, reg)
    write_server_conf(reg, args.server_conf)
    if upgraded:
        for client in reg.get("clients", []):
            render_client_artifacts(reg, client, args.clients_dir)
        print(f"[OK] Существующий реестр обновлен до AmneziaWG 3.1 (перегенерировано клиентов: {len(reg.get('clients', []))}).")
    else:
        print(f"[OK] Серверный конфиг AmneziaWG 3.1 создан: {args.server_conf}")
    return 0


def cmd_add_client(args: argparse.Namespace) -> int:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", args.name.strip())
    if not safe_name:
        raise ValueError("Имя клиента не может быть пустым.")

    reg = load_registry(args.registry)
    for existing in reg["clients"]:
        if existing["name"] == safe_name:
            conf_f, vpn_f = render_client_artifacts(reg, existing, args.clients_dir)
            print(f"[OK] Клиент '{safe_name}' уже существует. Файлы обновлены: {conf_f}, {vpn_f}")
            return 0

    net = ipaddress.ip_network(reg["subnet"], strict=False)
    used_ips = {reg["server_ip_cidr"].split("/")[0]} | {c["ip"] for c in reg["clients"]}
    assigned_ip = None
    for host in net.hosts():
        if str(host) not in used_ips:
            assigned_ip = str(host)
            break
    if not assigned_ip:
        raise RuntimeError(f"В подсети {reg['subnet']} закончились свободные адреса.")

    priv, pub = generate_wg_keypair()
    client = {
        "name": safe_name,
        "ip": assigned_ip,
        "private_key": priv,
        "public_key": pub,
        "psk": generate_psk(),
    }
    reg["clients"].append(client)
    save_registry(args.registry, reg)
    write_server_conf(reg, args.server_conf)
    conf_f, vpn_f = render_client_artifacts(reg, client, args.clients_dir)
    print(f"[OK] Клиент '{safe_name}' ({assigned_ip}) создан: {conf_f} | {vpn_f}")
    return 0


def cmd_update_endpoint(args: argparse.Namespace) -> int:
    reg = load_registry(args.registry)
    reg["endpoint_ip"] = args.new_ip
    save_registry(args.registry, reg)
    for client in reg.get("clients", []):
        render_client_artifacts(reg, client, args.clients_dir)
    print(f"[OK] Обновлены Endpoint ({args.new_ip}) и .vpn ссылки для {len(reg.get('clients', []))} клиентов AWG.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AmneziaWG 3.1 Config & vpn:// Generator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-params", help="Сгенерировать и вывести параметры AWG 3.1")

    p_init = subparsers.add_parser("init-server", help="Инициализировать серверный конфиг AWG 3.1")
    p_init.add_argument("--registry", type=Path, default=Path("/etc/server-combain/awg/registry.json"))
    p_init.add_argument("--server-conf", type=Path, default=Path("/etc/amnezia/amneziawg/awg0.conf"))
    p_init.add_argument("--clients-dir", type=Path, default=Path("/etc/server-combain/clients"))
    p_init.add_argument("--interface", default="awg0")
    p_init.add_argument("--subnet", default="10.8.1.0/24")
    p_init.add_argument("--dns-ip", default="10.8.1.1")
    p_init.add_argument("--endpoint-ip", required=True)
    p_init.add_argument("--port", type=int, required=True)

    p_add = subparsers.add_parser("add-client", help="Создать профиль клиента .conf и .vpn")
    p_add.add_argument("name", help="Имя клиента")
    p_add.add_argument("--registry", type=Path, default=Path("/etc/server-combain/awg/registry.json"))
    p_add.add_argument("--server-conf", type=Path, default=Path("/etc/amnezia/amneziawg/awg0.conf"))
    p_add.add_argument("--clients-dir", type=Path, default=Path("/etc/server-combain/clients"))

    p_upd = subparsers.add_parser("update-endpoint", help="Обновить IP сервера у всех клиентов AWG")
    p_upd.add_argument("--registry", type=Path, default=Path("/etc/server-combain/awg/registry.json"))
    p_upd.add_argument("--clients-dir", type=Path, default=Path("/etc/server-combain/clients"))
    p_upd.add_argument("--new-ip", required=True)

    args = parser.parse_args()
    handlers = {
        "gen-params": cmd_gen_params,
        "init-server": cmd_init_server,
        "add-client": cmd_add_client,
        "update-endpoint": cmd_update_endpoint,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
