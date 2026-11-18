#!/usr/bin/env python3
"""
Server-Combain — Менеджер конфигурации AdGuardHome.yaml.

Назначение:
  - Создание/обновление /opt/AdGuardHome/AdGuardHome.yaml с защищенным DoH/DoT/DoQ
  - Применение пресета доменов из config/presets/geo_domains.list + custom_geo_domains.list
    (исключая домены из excluded_geo_domains.list)
  - Формирование 3 правил на каждый домен:
      ||domain^$dnsrewrite=NOERROR;A;<SERVER_IP>
      ||domain^$dnstype=AAAA
      ||domain^$dnstype=HTTPS
  - Идемпотентное добавление/удаление доменов и массовая замена IP при переезде

ВАЖНО: Перед изменением AdGuardHome.yaml вызывающий скрипт ОБЯЗАН остановить
сервис AdGuard Home (`/opt/AdGuardHome/AdGuardHome -s stop`).
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

BEGIN_MARKER = "! --- BEGIN COMBAIN GEO RULES ---"
END_MARKER = "! --- END COMBAIN GEO RULES ---"


def _require_yaml() -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Требуется пакет PyYAML (python3-yaml). Установите его через apt: apt-get install -y python3-yaml"
        ) from exc
    return yaml


def hash_password_bcrypt(password: str) -> str:
    """Генерирует bcrypt-хеш пароля для AdGuard Home."""
    try:
        import bcrypt  # type: ignore

        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    except ImportError:
        proc = subprocess.run(
            ["htpasswd", "-nbBC", "10", "", password],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and ":" in proc.stdout:
            return proc.stdout.strip().split(":", 1)[1]
        raise RuntimeError(
            "Не найден ни python3-bcrypt, ни htpasswd для хеширования пароля AdGuard Home."
        )


def read_domain_file(path: Path) -> list[str]:
    """Читает список доменов из файла, игнорируя пустые строки и комментарии."""
    if not path.exists():
        return []
    result: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        result.append(line)
    return result


def write_domain_file(path: Path, domains: list[str], header: str) -> None:
    """Записывает список доменов в файл с шапкой."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [header.rstrip(), ""]
    lines.extend(domains)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_effective_domains(
    preset_path: Path,
    custom_path: Path | None = None,
    excluded_path: Path | None = None,
) -> list[str]:
    """Объединяет базовый пресет и пользовательские домены с учетом исключений."""
    excluded = set(read_domain_file(excluded_path)) if excluded_path else set()
    combined: list[str] = []
    seen: set[str] = set()

    for src in (preset_path, custom_path):
        if src is None:
            continue
        for dom in read_domain_file(src):
            if dom in excluded or dom in seen:
                continue
            seen.add(dom)
            combined.append(dom)
    return combined


def build_user_rules(domains: list[str], server_ip: str) -> list[str]:
    """Формирует блок правил DNS-подмены с блокировкой утечек AAAA и HTTPS/SVCB."""
    rules: list[str] = [BEGIN_MARKER]
    for domain in domains:
        rules.append(f"||{domain}^$dnsrewrite=NOERROR;A;{server_ip}")
        rules.append(f"||{domain}^$dnstype=AAAA")
        rules.append(f"||{domain}^$dnstype=HTTPS")
    rules.append(END_MARKER)
    return rules


def merge_user_rules(existing_rules: list[str] | None, managed_block: list[str]) -> list[str]:
    """Заменяет управляемый блок правил, сохраняя ручные правила пользователя."""
    if not existing_rules:
        return managed_block

    preserved: list[str] = []
    inside_block = False
    for rule in existing_rules:
        stripped = str(rule).strip()
        if stripped == BEGIN_MARKER:
            inside_block = True
            continue
        if stripped == END_MARKER:
            inside_block = False
            continue
        if not inside_block:
            preserved.append(str(rule))

    return preserved + managed_block


def load_yaml_safe(config_path: Path) -> dict[str, Any]:
    yaml = _require_yaml()
    if not config_path.exists():
        return {}
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def save_yaml_with_backup(config_path: Path, data: dict[str, Any]) -> None:
    yaml = _require_yaml()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        bak_path = config_path.with_suffix(config_path.suffix + ".bak")
        shutil.copy2(config_path, bak_path)
    dumped = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)
    config_path.write_text(dumped, encoding="utf-8")


def cmd_init_config(args: argparse.Namespace) -> int:
    data = load_yaml_safe(args.config)

    if "schema_version" not in data:
        data["schema_version"] = 29

    # Веб-админка: внутренний HTTP порт 3000 закрыт iptables, вход через sniproxy -> HTTPS
    data["http"] = data.get("http", {})
    data["http"]["address"] = "127.0.0.1:3000"
    data["http"]["session_ttl"] = "720h"

    if args.user and args.password:
        data["users"] = [{"name": args.user, "password": hash_password_bcrypt(args.password)}]

    dns_cfg = data.get("dns", {})
    dns_cfg["bind_hosts"] = ["0.0.0.0"]
    dns_cfg["port"] = 53
    dns_cfg["upstream_dns"] = [
        "https://dns.cloudflare.com/dns-query",
        "https://dns.google/dns-query",
        "tls://1.1.1.1",
        "tls://8.8.8.8",
    ]
    dns_cfg["bootstrap_dns"] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    dns_cfg["upstream_mode"] = "parallel"
    dns_cfg["fastest_timeout"] = "1s"
    dns_cfg["ratelimit"] = 0
    dns_cfg["cache_size"] = 16777216
    dns_cfg["cache_ttl_min"] = 60
    dns_cfg["cache_ttl_max"] = 3600
    dns_cfg["cache_optimistic"] = True
    dns_cfg["edns_client_subnet"] = {"enabled": False}
    data["dns"] = dns_cfg

    tls_cfg = data.get("tls", {})
    tls_cfg["enabled"] = True
    tls_cfg["server_name"] = args.dns_domain
    tls_cfg["force_https"] = False
    tls_cfg["port_https"] = args.https_port
    tls_cfg["port_dns_over_tls"] = args.dot_port
    tls_cfg["port_dns_over_quic"] = args.dot_port
    tls_cfg["strict_sni_check"] = False
    tls_cfg["certificate_path"] = str(args.cert)
    tls_cfg["private_key_path"] = str(args.key)
    data["tls"] = tls_cfg

    if args.preset:
        domains = collect_effective_domains(args.preset, args.custom, args.excluded)
        managed_block = build_user_rules(domains, args.ip)
        data["user_rules"] = merge_user_rules(data.get("user_rules"), managed_block)

    save_yaml_with_backup(args.config, data)
    print(f"[OK] AdGuardHome.yaml инициализирован ({len(data.get('user_rules', []))} правил).")
    return 0


def cmd_apply_preset(args: argparse.Namespace) -> int:
    data = load_yaml_safe(args.config)
    domains = collect_effective_domains(args.preset, args.custom, args.excluded)
    managed_block = build_user_rules(domains, args.ip)
    data["user_rules"] = merge_user_rules(data.get("user_rules"), managed_block)
    save_yaml_with_backup(args.config, data)
    print(f"[OK] Применено {len(domains)} доменов ({len(domains) * 3} правил) в {args.config}.")
    return 0


def cmd_add_domain(args: argparse.Namespace) -> int:
    domain = args.domain.strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        raise ValueError(f"Некорректный формат домена: {domain}")

    # Убираем из списка исключений, если ранее удалялся
    if args.excluded and args.excluded.exists():
        excl = [d for d in read_domain_file(args.excluded) if d != domain]
        write_domain_file(args.excluded, excl, "# Исключенные из базового пресета домены")

    custom = read_domain_file(args.custom)
    if domain not in custom:
        custom.append(domain)
        write_domain_file(args.custom, custom, "# Пользовательские домены обхода геоблокировок")

    return cmd_apply_preset(args)


def cmd_remove_domain(args: argparse.Namespace) -> int:
    domain = args.domain.strip().lower()
    if args.custom and args.custom.exists():
        custom = [d for d in read_domain_file(args.custom) if d != domain]
        write_domain_file(args.custom, custom, "# Пользовательские домены обхода геоблокировок")

    base_domains = set(read_domain_file(args.preset)) if args.preset else set()
    if domain in base_domains and args.excluded:
        excl = read_domain_file(args.excluded)
        if domain not in excl:
            excl.append(domain)
            write_domain_file(args.excluded, excl, "# Исключенные из базового пресета домены")

    return cmd_apply_preset(args)


def cmd_replace_ip(args: argparse.Namespace) -> int:
    data = load_yaml_safe(args.config)
    rules = data.get("user_rules") or []
    updated: list[str] = []
    replaced_count = 0

    if args.old_ip == "any":
        pattern = re.compile(r"(\$dnsrewrite=NOERROR;A;)\d+\.\d+\.\d+\.\d+")
    else:
        pattern = re.compile(rf"(\$dnsrewrite=NOERROR;A;){re.escape(args.old_ip)}(?=$|\s)")

    for rule in rules:
        new_rule, cnt = pattern.subn(rf"\g<1>{args.new_ip}", str(rule))
        replaced_count += cnt
        updated.append(new_rule)

    data["user_rules"] = updated
    save_yaml_with_backup(args.config, data)
    print(f"[OK] Обновлено {replaced_count} DNS-правил на IP {args.new_ip}.")
    return 0


def cmd_list_effective(args: argparse.Namespace) -> int:
    domains = collect_effective_domains(args.preset, args.custom, args.excluded)
    for dom in domains:
        print(dom)
    return 0


def _add_preset_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--config", type=Path, required=True, help="Путь к AdGuardHome.yaml")
    subparser.add_argument("--preset", type=Path, required=True, help="Путь к geo_domains.list")
    subparser.add_argument("--custom", type=Path, default=None, help="Путь к custom_geo_domains.list")
    subparser.add_argument("--excluded", type=Path, default=None, help="Путь к excluded_geo_domains.list")
    subparser.add_argument("--ip", required=True, help="Внешний IPv4 сервера")


def main() -> int:
    parser = argparse.ArgumentParser(description="AdGuardHome.yaml Manager for Server-Combain")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init-config", help="Создать или обновить полную конфигурацию AdGuardHome.yaml")
    p_init.add_argument("--config", type=Path, required=True)
    p_init.add_argument("--preset", type=Path)
    p_init.add_argument("--custom", type=Path)
    p_init.add_argument("--excluded", type=Path)
    p_init.add_argument("--ip", required=True)
    p_init.add_argument("--dns-domain", required=True)
    p_init.add_argument("--https-port", type=int, default=8444)
    p_init.add_argument("--dot-port", type=int, default=853)
    p_init.add_argument("--cert", type=Path, default=Path("/opt/AdGuardHome/fullchain.pem"))
    p_init.add_argument("--key", type=Path, default=Path("/opt/AdGuardHome/privkey.pem"))
    p_init.add_argument("--user", default="")
    p_init.add_argument("--password", default="")

    p_apply = subparsers.add_parser("apply-preset", help="Применить список доменов к AdGuardHome.yaml")
    _add_preset_args(p_apply)

    p_add = subparsers.add_parser("add-domain", help="Добавить пользовательский домен и применить")
    _add_preset_args(p_add)
    p_add.add_argument("--domain", required=True)

    p_rm = subparsers.add_parser("remove-domain", help="Удалить домен из обхода и применить")
    _add_preset_args(p_rm)
    p_rm.add_argument("--domain", required=True)

    p_list = subparsers.add_parser("list-effective", help="Вывести итоговый список активных доменов")
    p_list.add_argument("--preset", type=Path, required=True)
    p_list.add_argument("--custom", type=Path)
    p_list.add_argument("--excluded", type=Path)

    p_replace = subparsers.add_parser("replace-ip", help="Заменить старый IP на новый в user_rules")
    p_replace.add_argument("--config", type=Path, required=True)
    p_replace.add_argument("--old-ip", default="any", help="Старый IPv4 или 'any'")
    p_replace.add_argument("--new-ip", required=True)

    args = parser.parse_args()
    handlers = {
        "init-config": cmd_init_config,
        "apply-preset": cmd_apply_preset,
        "add-domain": cmd_add_domain,
        "remove-domain": cmd_remove_domain,
        "list-effective": cmd_list_effective,
        "replace-ip": cmd_replace_ip,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
