#!/usr/bin/env python3
"""
Server-Combain — Временный Drag&Drop веб-сервер миграции (TTL: 1 час).

Назначение:
  - Авторизация по одноразовому токену (?token=...)
  - Режим 'upload': принимает потоково архив .tar.gz.enc / .tar.gz в --dest-dir,
    записывает путь принятого файла в --done-file и автоматически завершает работу.
  - Режим 'download': потоково отдает указанный --file для скачивания через браузер.
  - Автоматический останов по таймеру ровно через --ttl секунд (по умолчанию 3600 с = 1 час).
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import shutil
import sys
import threading
import time
import urllib.parse


class PortalConfig:
    mode: str = "upload"
    token: str = ""
    start_ts: float = 0.0
    ttl: int = 3600
    html_template: Path = Path("web/backup_portal/index.html")
    target_file: Path | None = None
    dest_dir: Path = Path("/var/backups/server-combain")
    done_file: Path | None = None
    httpd: ThreadingHTTPServer | None = None


def _sanitize_filename(raw_name: str) -> str:
    decoded = urllib.parse.unquote(raw_name or "backup.tar.gz.enc")
    base = Path(decoded).name
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    if not safe or safe in {".", ".."}:
        return "combain-backup-uploaded.tar.gz.enc"
    return safe


class BackupDropHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Подавляем стандартный подробный лог с токенами в URL
        return

    def _extract_token(self) -> tuple[str, str]:
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("token", [""])[0]
        return parsed.path, token

    def _is_authorized(self, token: str) -> bool:
        return bool(token) and secrets.compare_digest(token, PortalConfig.token)

    def _send_error_text(self, code: int, msg: str) -> None:
        data = msg.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        path, token = self._extract_token()
        if not self._is_authorized(token):
            self._send_error_text(403, "Access denied: invalid or missing token")
            return

        if path.endswith("/download"):
            if PortalConfig.mode != "download" or not PortalConfig.target_file or not PortalConfig.target_file.exists():
                self._send_error_text(404, "Backup file not available")
                return

            fsize = PortalConfig.target_file.stat().st_size
            fname = PortalConfig.target_file.name
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(fsize))
            self.end_headers()

            with PortalConfig.target_file.open("rb") as fh:
                shutil.copyfileobj(fh, self.wfile, length=65536)
            return

        # Отдаем HTML страницу портала
        if not PortalConfig.html_template.exists():
            self._send_error_text(500, "Portal template missing")
            return

        remaining = max(0, int(PortalConfig.ttl - (time.time() - PortalConfig.start_ts)))
        html = PortalConfig.html_template.read_text(encoding="utf-8")
        html = (
            html.replace("__UPLOAD_CLASS__", "" if PortalConfig.mode == "upload" else "hidden")
            .replace("__DOWNLOAD_CLASS__", "" if PortalConfig.mode == "download" else "hidden")
            .replace("__FILENAME__", PortalConfig.target_file.name if PortalConfig.target_file else "")
            .replace("__TOKEN__", PortalConfig.token)
            .replace("__REMAINING_SEC__", str(remaining))
        )
        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802
        path, token = self._extract_token()
        if not self._is_authorized(token):
            self._send_error_text(403, "Access denied: invalid or missing token")
            return

        if PortalConfig.mode != "upload" or not path.endswith("/upload"):
            self._send_error_text(405, "Upload not allowed in current mode")
            return

        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0:
            self._send_error_text(400, "Empty upload body")
            return

        safe_name = _sanitize_filename(self.headers.get("X-Filename", "combain-backup.tar.gz.enc"))
        PortalConfig.dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = PortalConfig.dest_dir / safe_name

        bytes_left = content_len
        with dest_file.open("wb") as out_f:
            while bytes_left > 0:
                chunk = self.rfile.read(min(65536, bytes_left))
                if not chunk:
                    break
                out_f.write(chunk)
                bytes_left -= len(chunk)

        if bytes_left != 0:
            dest_file.unlink(missing_ok=True)
            self._send_error_text(400, "Incomplete upload stream")
            return

        if PortalConfig.done_file:
            PortalConfig.done_file.write_text(str(dest_file), encoding="utf-8")

        resp = json.dumps({"ok": True, "filename": safe_name, "path": str(dest_file)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)
        print(f"[OK] Получен архив миграции: {dest_file} ({content_len} байт)")

        # Завершаем портал через 2 секунды, чтобы браузер гарантированно получил ответ
        if PortalConfig.httpd:
            threading.Timer(2.0, PortalConfig.httpd.shutdown).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Temporary 1-hour Drag&Drop Backup Server")
    parser.add_argument("--mode", choices=["upload", "download"], default="upload")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20999)
    parser.add_argument("--token", required=True)
    parser.add_argument("--ttl", type=int, default=3600, help="Время жизни в секундах (по умолч. 3600)")
    parser.add_argument("--template", type=Path, required=True, help="Путь к web/backup_portal/index.html")
    parser.add_argument("--file", type=Path, help="Путь к архиву (для режима download)")
    parser.add_argument("--dest-dir", type=Path, default=Path("/var/backups/server-combain"))
    parser.add_argument("--done-file", type=Path, help="Файл-маркер пути принятого архива")
    args = parser.parse_args()

    PortalConfig.mode = args.mode
    PortalConfig.token = args.token
    PortalConfig.ttl = args.ttl
    PortalConfig.start_ts = time.time()
    PortalConfig.html_template = args.template
    PortalConfig.target_file = args.file
    PortalConfig.dest_dir = args.dest_dir
    PortalConfig.done_file = args.done_file

    httpd = ThreadingHTTPServer((args.bind, args.port), BackupDropHandler)
    PortalConfig.httpd = httpd

    def auto_shutdown() -> None:
        print(f"\n[TTL] Время жизни портала ({args.ttl} сек) истекло. Остановка сервера...")
        httpd.shutdown()

    timer = threading.Timer(args.ttl, auto_shutdown)
    timer.daemon = True
    timer.start()

    print(f"[OK] Портал миграции запущен на {args.bind}:{args.port} (режим={args.mode}, TTL={args.ttl}s)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        timer.cancel()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
