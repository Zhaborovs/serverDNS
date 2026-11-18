#!/usr/bin/env python3
"""
Server-Combain — Генератор конфигураций и ключей AmneziaWG (AWG 2.0+ / 3.0 compatible).

Назначение:
  - Автономная генерация ключей Curve25519 (классический Base64 формат WireGuard/AWG)
  - Генерация непересекающихся параметров обфускации AWG 2.0+:
      * Jc, Jmin, Jmax
      * S1..S4 (соблюдение инварианта S1 + 56 != S2)
      * H1..H4 (уникальные динамические диапазоны 32-bit заголовков)
      * I1..I5 (CPS сигнатуры имитации QUIC/TLS/DNS)
  - Инициализация серверного конфига /etc/amnezia/amneziawg/<iface>.conf и JSON-реестра
  - Добавление клиентов с автовыделением IP, обновлением серверного конфига,
    генерацией клиентского .conf (с DNS = 10.8.1.1) и нативного URI vpn://...
  - Массовое обновление Endpoint IP при переезде / быстрой смене IP
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


def generate_awg2_params() -> dict[str, str | int]:
    """Генерирует валидный набор параметров обфускации AWG 2.0+ (с обратной совместимостью)."""
    s1 = random.randint(15, 110)
    s2 = random.randint(15, 110)
    while s1 + 56 == s2 or s1 == s2:
        s2 = random.randint(15, 110)

    base = random.randint(100000, 900000)
    return {
        "Jc": random.randint(4, 8),
        "Jmin": 40,
        "Jmax": 120,
        "S1": s1,
        "S2": s2,
        "S3": random.randint(8, 64),
        "S4": random.randint(4, 32),
        "H1": f"{base}-{base + 45000}",
        "H2": f"{base + 100000}-{base + 145000}",
        "H3": f"{base + 200000}-{base + 245000}",
        "H4": f"{base + 300000}-{base + 345000}",
        "I1": "<b 0xc0000000><r 16><t><r 24>",
        "I2": "<b 0x16030100><rc 6><r 20>",
        "I3": "<rc 8><t><r 18>",
        "I4": "<rd 6><r 16>",
        "I5": "<r 32>",
    }


def encode_amnezia_vpn_uri(
    client_conf_text: str,
    params: dict[str, str | int],
    server_ip: str,
    port: int,
    dns_ip: str,
    client_name: str,
) -> str:
    """Кодирует конфиг в нативный формат vpn:// (qCompress + URL-safe Base64) для приложения AmneziaVPN."""
    payload = {
        "containers": [
            {
                "awg": {
                    "H1": str(params["H1"]),
                    "H2": str(params["H2"]),
                    "H3": str(params["H3"]),
                    "H4": str(params["H4"]),
                    "Jc": str(params["Jc"]),
                    "Jmin": str(params["Jmin"]),
                    "Jmax": str(params["Jmax"]),
                    "S1": str(params["S1"]),
                    "S2": str(params["S2"]),
                    "S3": str(params["S3"]),
                    "S4": str(params["S4"]),
                    "I1": str(params["I1"]),
                    "I2": str(params["I2"]),
                    "I3": str(params["I3"]),
                    "I4": str(params["I4"]),
                    "I5": str(params["I5"]),
                    "last_config": client_conf_text,
                    "port": str(port),
                    "transport_proto": "udp",
                },
                "container": "amnezia-awg",
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": f"Server-Combain AWG ({client_name})",
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
    """Пересобирает серверный конфиг /etc/amnezia/amneziawg/awg0.conf из реестра."""
    p = registry["params"]
    iface = registry["interface"]
    lines = [
        "[Interface]",
        f"Address = {registry['server_ip_cidr']}",
        f"ListenPort = {registry['port']}",
        f"PrivateKey = {registry['server_private_key']}",
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
    """Создает файлы <name>.conf и <name>.vpn для конкретного клиента."""
    p = registry["params"]
    conf_lines = [
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {client['ip']}/32",
        f"DNS = {registry['dns_ip']}",
        "MTU = 1380",
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
        f"I2 = {p['I2']}",
        f"I3 = {p['I3']}",
        f"I4 = {p['I4']}",
        f"I5 = {p['I5']}",
        "",
        "[Peer]",
        f"PublicKey = {registry['server_public_key']}",
        f"PresharedKey = {client['psk']}",
        f"Endpoint = {registry['endpoint_ip']}:{registry['port']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        "",
    ]
    conf_text = "\n".join(conf_lines)
    clients_dir.mkdir(parents=True, exist_ok=True)
    conf_file = clients_dir / f"awg_{client['name']}.conf"
    vpn_file = clients_dir / f"awg_{client['name']}.vpn"

    conf_file.write_text(conf_text, encoding="utf-8")
    vpn_uri = encode_amnezia_vpn_uri(
        conf_text,
        p,
        registry["endpoint_ip"],
        int(registry["port"]),
        registry["dns_ip"],
        client["name"],
    )
    vpn_file.write_text(vpn_uri, encoding="utf-8")
    return conf_file, vpn_file


def cmd_gen_params(_: argparse.Namespace) -> int:
    params = generate_awg2_params()
    for k, v in params.items():
        print(f"{k}={v}")
    return 0


def cmd_init_server(args: argparse.Namespace) -> int:
    if args.registry.exists():
        reg = load_registry(args.registry)
        reg["endpoint_ip"] = args.endpoint_ip
        reg["port"] = int(args.port)
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
            "params": generate_awg2_params(),
            "clients": [],
        }
    save_registry(args.registry, reg)
    write_server_conf(reg, args.server_conf)
    print(f"[OK] Серверный конфиг AmneziaWG 2.0+ создан: {args.server_conf}")
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
    parser = argparse.ArgumentParser(description="AmneziaWG 2.0+ Config & vpn:// Generator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-params", help="Сгенерировать и вывести параметры AWG 2.0+")

    p_init = subparsers.add_parser("init-server", help="Инициализировать серверный конфиг AWG")
    p_init.add_argument("--registry", type=Path, default=Path("/etc/server-combain/awg/registry.json"))
    p_init.add_argument("--server-conf", type=Path, default=Path("/etc/amnezia/amneziawg/awg0.conf"))
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
