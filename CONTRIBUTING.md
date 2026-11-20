# 🤝 Участие в разработке Server-Combain

Спасибо за интерес к **Server-Combain**! Мы рады любым улучшениям — от исправления опечаток в документации и пополнения пресетов доменов до новых модулей, автотестов и оптимизаций Combain-Mesh.

---

## 🧭 Быстрый старт для контрибьютора

1. Сделайте **Fork** репозитория [Zhaborovs/serverDNS](https://github.com/Zhaborovs/serverDNS) и склонируйте его локально:
   ```bash
   git clone https://github.com/<your-username>/serverDNS.git
   cd serverDNS
   ```
2. Создайте отдельную ветку под задачу:
   ```bash
   git checkout -b feat/my-improvement
   ```
3. Внесите изменения, проверьте тесты и синтаксис (инструкции ниже) и откройте **Pull Request** в ветку `main`.

---

## 🧪 Запуск тестов и локальные проверки

Перед отправкой PR обязательно прогоните автоматические проверки:

### 1. Юнит- и интеграционные тесты (`tests/`)

Проект использует стандартный `unittest` из Python 3 (без внешних зависимостей):

```bash
python3 -m unittest discover -s tests -v
```

> На Windows используйте `python -m unittest discover -s tests -v`.

Тесты в [`tests/test_mesh.py`](tests/test_mesh.py) проверяют P2P-синхронизацию Combain-Mesh, HMAC-авторизацию и защиту от replay-атак, LWW-слияние и tombstone-удаления, лимиты HWID/сроков действия пользователей, 1-строчные инвайты `combain-join://`, каскадный failover и синхронизацию клиентов 3x-ui.

### 2. Проверка синтаксиса Bash и Python

```bash
# Проверка синтаксиса всех Bash-скриптов
bash -n install.sh combain.sh scripts/lib/*.sh scripts/modules/*.sh

# Опционально: статический анализ ShellCheck (если установлен)
shellcheck -x install.sh combain.sh scripts/lib/*.sh scripts/modules/*.sh

# Проверка компиляции всех Python-скриптов
python3 -m py_compile scripts/py_helpers/*.py scripts/mesh/*.py tests/*.py
```

---

## 📐 Стандарты кода

### Bash (`install.sh`, `combain.sh`, `scripts/lib/`, `scripts/modules/`)
- Используйте `#!/usr/bin/env bash` и строгий режим `set -Eeuo pipefail` в точках входа.
- Все модули должны быть **идемпотентными**: повторный запуск модуля или `comb update` не должен ломать существующую конфигурацию, дублировать правила `iptables` или стирать пользовательские данные.
- Правила фаервола для Combain-Mesh добавляйте строго внутри изолированной цепочки `COMBAIN-PROTECT` — не сбрасывайте чужие правила `INPUT`/`FORWARD` целиком.
- Всегда заключайте переменные в двойные кавычки (`"$var"`), используйте `local` внутри функций и общие хелперы логирования (`log_info`, `log_ok`, `log_warn`, `log_err`) из [`scripts/lib/common.sh`](scripts/lib/common.sh).
- Не хардкодьте версии образов и релизов, где предусмотрено динамическое определение (`latest` / GitHub API).

### Python (`scripts/py_helpers/`, `scripts/mesh/`, `tests/`)
- Совместимость с **Python 3.10+** (базовый Python в Ubuntu 24.04 LTS — Python 3.12).
- Предпочитайте стандартную библиотеку Python (`sqlite3`, `urllib`, `http.server`, `json`, `pathlib`, `hmac`, `hashlib`), чтобы не усложнять установку на чистый VPS.
- Используйте аннотации типов (`from __future__ import annotations`) и понятные docstrings.
- При добавлении новой логики в `scripts/mesh/` или `scripts/py_helpers/` добавляйте соответствующие тесты в `tests/`.

---

## 📄 Окончания строк (строго LF)

Серверные скрипты запускаются на Linux (Ubuntu 24.04 LTS), где окончания строк Windows (`CRLF`) ломают shebang и парсинг.

В корне репозитория настроен [`.gitattributes`](.gitattributes), принудительно задающий **`eol=lf`** для всех текстовых файлов:
- `*.sh`, `*.py`, `*.tpl`, `*.list`, `*.example`, `*.md`, `*.json`, `*.html`, `*.css`, `*.js`.

Если вы разрабатываете на Windows:
- Убедитесь, что редактор (VS Code / JetBrains / др.) сохраняет файлы с окончаниями **LF (`\n`)**.
- Не добавляйте в коммит файлы с `\r\n` — при необходимости проверьте через `git diff --check`.

---

## 🔒 Правило нулевых секретов (Zero-Secrets Rule)

> **Никогда не коммитьте реальные секреты, личные домены, IP-адреса, ключи, пароли или токены!**

В документации, примерах, шаблонах (`templates/`), конфигах (`config/default.env.example`) и тестах (`tests/`) используйте **исключительно** зарезервированные RFC-плейсхолдеры:
- **Домены (RFC 2606):** `vpn.example.com`, `dns.vpn.example.com`, `cdn.example.com`
- **IPv4-адреса (RFC 5737):** `203.0.113.10`, `198.51.100.20`, `192.0.2.30`
- **IPv6-адреса (RFC 3849):** `2001:db8::1`, `2001:db8::2`
- **Секреты / токены / UUID:** очевидные заглушки вида `<SUB_TOKEN>`, `<MESH_SECRET>`, `00000000-0000-4000-8000-000000000000`

Перед коммитом проверьте `git diff`, чтобы убедиться, что туда не попали файлы из `/etc/server-combain/`, `state.env`, ключи WireGuard/Reality или приватные бэкапы.

---

## ✅ Чеклист перед открытием Pull Request

- [ ] Изменения проверены и не ломают существующие сценарии установки и обновления (`comb install`, `comb update`).
- [ ] Пройдены юнит-тесты: `python3 -m unittest discover -s tests -v`.
- [ ] Проверен синтаксис изменённых `.sh` (`bash -n`) и `.py` (`py_compile`) файлов.
- [ ] Все изменённые текстовые файлы имеют окончания строк **LF (`\n`)** в соответствии с `.gitattributes`.
- [ ] В диффе **нет** реальных IP-адресов, личных доменов, паролей, ключей или токенов.
- [ ] Если изменились CLI-команды, порты, пункты меню или архитектура — обновлена соответствующая документация ([`README.md`](README.md) и `docs/`).
- [ ] В описании PR кратко указано, **что** изменено, **зачем** и **как** это было проверено.

---

[← Вернуться на главную (README.md)](README.md)
