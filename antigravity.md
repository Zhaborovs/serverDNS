# Server Context & Architecture Reference (Ubuntu 24.04 VPS — Germany)

Данный документ предназначен для AI-агента в **Google Antigravity** и описывает полную конфигурацию сервера, схему маршрутизации трафика, списки обхода геоблокировок и строгие инварианты, которые нельзя нарушать при внесении изменений.

---

## 1. Общие сведения о сервере

* **ОС:** Ubuntu 24.04 LTS
* **Локация:** Германия
* **Текущий внешний IPv4 (`<SERVER_IP>`):** определить динамически на хосте командой:
  `ip -4 route get 1.1.1.1 | awk '{print $7; exit}'`
  *(Примечание: предыдущий IP `185.227.174.13` был заблокирован ТСПУ/РКН и заменен у хостинг-провайдера на новый чистый IP).*
* **Основные домены:**
  * `dns.germany.danyaspace.ru` — публичная точка входа для DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), DNS-over-QUIC (DoQ) и защищенной веб-панели AdGuard Home.
  * `api.germany.danyaspace.ru` — обратный прокси в Nginx Proxy Manager (используется для проксирования API-запросов, в т.ч. к Google APIs).
  * Остальные поддомены `*.danyaspace.ru` — обслуживаются через Nginx Proxy Manager (`npm_app_1`).

---

## 2. Схема портов и маршрутизации трафика

Ключевая особенность сервера — **совместное использование порта `443/tcp`** между SNI-прокси (для обхода геоблокировок), AdGuard Home (DoH) и Nginx Proxy Manager без расшифровки чужого трафика на пограничном узле.

### Карта слушающих портов

| Порт / Протокол | Сервис / Контейнер | Назначение и доступность |
| :--- | :--- | :--- |
| **`443/tcp`** | `sniproxy` (systemd) | Главный мультиплексор TLS по заголовку `SNI` (открыт снаружи). |
| **`80/tcp`** | `npm_app_1` (Docker) | Nginx Proxy Manager — HTTP-трафик и редиректы (открыт снаружи). |
| **`8443/tcp`** | `npm_app_1` (Docker) | Внутренний HTTPS-порт Nginx Proxy Manager (трафик приходит от `sniproxy` на `127.0.0.1:8443`). |
| **`8444/tcp`** | `AdGuardHome` (systemd) | Внутренний HTTPS / DoH порт AdGuard Home (трафик приходит от `sniproxy` на `127.0.0.1:8444`). |
| **`853/tcp`, `853/udp`** | `AdGuardHome` (systemd) | DNS-over-TLS (Android Private DNS) и DNS-over-QUIC (открыт снаружи). |
| **`53/tcp`, `53/udp`** | `AdGuardHome` (systemd) | Обычный незашифрованный DNS. **Закрыт снаружи через `iptables`** (разрешен `127.0.0.0/8` и при необходимости белый список IP), чтобы исключить DNS Amplification атаки. |
| **`3000/tcp`** | `AdGuardHome` (systemd) | Резервный HTTP веб-интерфейс AdGuard Home. **Закрыт снаружи через `iptables`** (`! -s 127.0.0.0/8 -j DROP`), вход в админку идет через `https://dns.germany.danyaspace.ru`. |
| **`8445/tcp`** | `mtproto-proxy` (Docker) | *(Опционально)* Telegram MTProto Fake-TLS прокси (`nineseconds/mtg:2`, маскировка под `dl.google.com`). |
| **`10808/tcp`** | `tg-socks5` (Docker) | *(Опционально)* SOCKS5-прокси с авторизацией (`serjs/go-socks5-proxy`, логин `tguser`) для чатов и голосовых звонков в Telegram. |
| **Порты AmneziaVPN** | Контейнеры `amnezia-*` | Рабочие контейнеры AmneziaVPN (AmneziaWG, WireGuard, OpenVPN, Socks5), сетевой мост `amn0`. **Не трогать!** |

### Логика работы связки AdGuard Home + SNI Proxy
1. Клиент (Windows 11 DoH, браузер, Android Private DNS на порту `853` или iOS `.mobileconfig`) отправляет DNS-запрос к `dns.germany.danyaspace.ru`.
2. Если запрашивается обычный сайт — AdGuard Home возвращает его реальный IP, и клиент идет напрямую без участия VPS.
3. Если запрашивается геоблокируемый сервис из списка правил:
   * AdGuard Home переписывает `A`-запись (IPv4) на `<SERVER_IP>` через модификатор `$dnsrewrite=NOERROR;A;<SERVER_IP>`.
   * Одновременно AdGuard Home **блокирует записи `AAAA` (IPv6) и `HTTPS` (Type 65 SVCB)** через `$dnstype=AAAA` и `$dnstype=HTTPS`, чтобы браузеры (Chrome/Edge) не обходили подмену через `ipv4hint` / `ipv6hint` или прямой IPv6.
4. Клиент открывает TLS-соединение к `<SERVER_IP>:443`, передавая целевой домен в открытом поле `SNI`.
5. `sniproxy` сверяет `SNI` со своей таблицей `/etc/sniproxy.conf`:
   * `dns.germany.danyaspace.ru` -> `127.0.0.1:8444` (AdGuard Home)
   * `api.germany.danyaspace.ru` (и др. поддомены `danyaspace.ru`) -> `127.0.0.1:8443` (Nginx Proxy Manager)
   * Разрешенные домены из белого списка -> пробрасываются прозрачно (`*:443`) к реальным зарубежным серверам с немецкого IP сервера.
   * Любые неизвестные домены отклоняются (защита от использования сервера чужими ботами как открытого прокси).

---

## 3. Ключевые пути, сервисы и команды управления

### AdGuard Home
* **Директория и бинарник:** `/opt/AdGuardHome/AdGuardHome`
* **Главный конфиг:** `/opt/AdGuardHome/AdGuardHome.yaml`
* **Резервная копия конфига:** `/opt/AdGuardHome/AdGuardHome.yaml.bak`
* **Локальные копии SSL-сертификатов:**
  * `/opt/AdGuardHome/fullchain.pem`
  * `/opt/AdGuardHome/privkey.pem` (права `600`)
  *(Используются реальные копии через `cp -L` вместо симлинков Let's Encrypt во избежание проблем с правами доступа, параметр `strict_sni_check: false`).*
* **Управление сервисом:**
  ```bash
  /opt/AdGuardHome/AdGuardHome -s status
  /opt/AdGuardHome/AdGuardHome -s stop
  /opt/AdGuardHome/AdGuardHome -s start
  /opt/AdGuardHome/AdGuardHome -s restart
  ```
  *(Важно: перед программным редактированием `/opt/AdGuardHome/AdGuardHome.yaml` через Python/sed сервис нужно **обязательно остановить** `-s stop`, иначе при рестарте AdGuard Home перезапишет файл состоянием из оперативной памяти!).*

### SNI Proxy
* **Конфиг:** `/etc/sniproxy.conf`
* **Управление сервисом:**
  ```bash
  systemctl status sniproxy
  systemctl restart sniproxy
  ```
  *(При зависании старого воркера: `killall sniproxy 2>/dev/null || true && systemctl restart sniproxy`).*

### Nginx Proxy Manager (Docker)
* **Рабочая директория:** `/root/npm`
* **Имя контейнера:** `npm_app_1`
* **Управление:** `docker ps`, `docker stop npm_app_1`, `docker start npm_app_1`

### Автопродление SSL-сертификата Let's Encrypt (Certbot)
Сертификат для `dns.germany.danyaspace.ru` выпущен на хосте через `certbot certonly --standalone`. Для бесконфликтного продления каждые 3 месяца настроены хуки:
* **Pre-hook:** `/etc/letsencrypt/renewal-hooks/pre/stop-npm.sh` — временно останавливает `npm_app_1`, освобождая порт `80`.
* **Post-hook:** `/etc/letsencrypt/renewal-hooks/post/update-agh-cert.sh` — запускает `npm_app_1` обратно, копирует свежие сертификаты (`cp -L`) в `/opt/AdGuardHome/`, выставляет `chmod 600` на ключ и перезапускает AdGuard Home.

### Файрвол (`iptables`)
* Используется `iptables` + пакет `iptables-persistent` (`netfilter-persistent save`).
* **Внимание:** на сервере присутствуют цепочки Docker и правила маршрутизации/NAT от контейнеров **AmneziaVPN**. Никогда не делать `iptables -F` (полный сброс таблиц) и не включать `ufw enable` поверх работающих правил Docker/Amnezia! Добавлять или удалять правила только точечно.

---

## 4. Полный список прописанных доменов обхода геоблокировок

Все перечисленные ниже домены настроены в двух местах:
1. В `user_rules` внутри `/opt/AdGuardHome/AdGuardHome.yaml` (по 3 правила на каждый базовый домен: `$dnsrewrite=NOERROR;A;<SERVER_IP>`, `$dnstype=AAAA`, `$dnstype=HTTPS`).
2. В белом списке блока `table { ... }` внутри `/etc/sniproxy.conf`.

### OpenAI / ChatGPT / Sora
* `openai.com`
* `chatgpt.com`
* `oaistatic.com`
* `oaiusercontent.com`
* `sora.com`
* `auth0.com`

### Google Gemini / AI Studio / NotebookLM / Labs / DeepMind
* `gemini.google.com`
* `aistudio.google.com`
* `makersuite.google.com`
* `clients6.google.com` *(включая `alkalimakersuite-pa.clients6.google.com`, `geminiweb-pa.clients6.google.com`, `signaler-pa.clients6.google.com`, `ogads-pa.clients6.google.com`, `push.clients6.google.com`)*
* `generativelanguage.googleapis.com`
* `proactivebackend-pa.googleapis.com`
* `aisandbox-pa.googleapis.com`
* `robinfrontend-pa.googleapis.com`
* `geller-pa.googleapis.com`
* `notebooklm.google`
* `notebooklm.google.com`
* `labs.google`
* `jules.google.com`
* `idx.dev`
* `ai.google.dev`
* `deepmind.google`
* `ogs.google.com`
* `apis.google.com`
* `play.google.com`

### Google Antigravity IDE
* `daily-cloudcode-pa.googleapis.com`
* `cloudcode-pa.googleapis.com`
* `antigravity.google`
* `antigravity-unleash.goog`
* `aicode.googleapis.com`
* `businessaicode.googleapis.com`
* `oauth2.googleapis.com`

### Anthropic / Claude
* `claude.ai`
* `anthropic.com`

### xAI / Grok
* `grok.com`
* `x.ai`

### Microsoft Copilot / Bing AI / GitHub Copilot
* `copilot.microsoft.com`
* `sydney.bing.com`
* `edgeservices.bing.com`
* `api.githubcopilot.com`
* `copilot-proxy.githubusercontent.com`

### Другие ИИ-сервисы (Perplexity, ElevenLabs)
* `perplexity.ai`
* `elevenlabs.io`

### Музыка и продуктивность (Spotify, JetBrains, Notion, Canva)
* `spotify.com`
* `scdn.co`
* `spotifycdn.com`
* `jetbrains.com`
* `notion.so`
* `canva.com`

### Autodesk Fusion (Fusion 360)
* `autodesk.com`
* `autodesk360.com`
* `autodesk.net`
* `autodesk.io`
* `a360.co`
* `damassets.net`
* `library.io`
* `launchdarkly.com`
* `pubnub.com`
* `pndsn.com`

### Опциональные / Веб-клиент Telegram и тестовые домены
* Веб-версия Telegram (если активна): `telegram.org`, `t.me`, `telesco.pe`, `cdn-telegram.org`
* Тестовые определители IP (при проверке подмены): `2ip.ru`, `2ip.io`, `ifconfig.me`, `icanhazip.com`

*(В `/etc/sniproxy.conf` многие поддомены Google и Microsoft агрегированы широкими регулярными выражениями вида `.*google\.com$ *:443`, `.*googleapis\.com$ *:443`, `.*google$ *:443`, `.*goog$ *:443`, `.*gstatic\.com$ *:443`, `.*microsoft\.com$ *:443`).*

---

## 5. Стандартные инструкции для AI-агента (SOP)

### А. Как правильно добавить новый сайт для обхода геоблокировок
**КРИТИЧЕСКОЕ ПРАВИЛО:** Любой новый домен `example.com` должен добавляться **одновременно и в AdGuard Home, и в `sniproxy.conf`**. Если добавить домен только в AdGuard Home и забыть про `sniproxy.conf`, браузер выдаст ошибку `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`.

1. **Проверить / добавить регулярное выражение в `/etc/sniproxy.conf` внутри блока `table { ... }`:**
   ```text
       .*example\.com$ *:443
   ```
   Затем перезапустить: `systemctl restart sniproxy`.
2. **Остановить AdGuard Home, добавить 3 правила в `user_rules` в `/opt/AdGuardHome/AdGuardHome.yaml` и запустить сервис:**
   ```text
   ||example.com^$dnsrewrite=NOERROR;A;<SERVER_IP>
   ||example.com^$dnstype=AAAA
   ||example.com^$dnstype=HTTPS
   ```
   *(Не использовать старый блок `rewrites`, так как правила в `user_rules` блокируют утечки `AAAA` и `HTTPS/SVCB` и имеют высший приоритет).*

### Б. Как выполнить смену IP-адреса сервера (при блокировке IP со стороны РКН)
1. Проверить обновление сетевого интерфейса в `/etc/netplan/` (`ip -4 addr show scope global`).
2. Обновить `A`-записи в DNS регистратора для `dns.germany.danyaspace.ru` и `api.germany.danyaspace.ru`.
3. Выполнить замену старого IP на новый в конфиге AdGuard Home при остановленном сервисе:
   ```bash
   NEW_IP=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
   /opt/AdGuardHome/AdGuardHome -s stop
   cp /opt/AdGuardHome/AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml.bak
   sed -i "s/СТАРЫЙ_IP/$NEW_IP/g" /opt/AdGuardHome/AdGuardHome.yaml
   /opt/AdGuardHome/AdGuardHome -s start
   systemctl restart sniproxy
   ```
4. Перевыпускать SSL-сертификаты не требуется (они привязаны к домену).
5. На клиентах Windows 11 обновить регистрацию системного DoH в PowerShell (Администратор):
   ```powershell
   Add-DnsClientDohServerAddress -ServerAddress '<NEW_IP>' -DohTemplate 'https://dns.germany.danyaspace.ru/dns-query' -AllowFallbackToUdp $False -AutoUpgrade $True
   Clear-DnsClientCache
   ```

### В. Быстрая диагностика работоспособности на сервере
* Проверка локальной перезаписи DNS:
  `dig @127.0.0.1 gemini.google.com A +short` -> должен вернуть `<SERVER_IP>`.
* Проверка блокировки утечки HTTPS/SVCB:
  `dig @127.0.0.1 gemini.google.com HTTPS +short` -> должен вернуть пустой ответ.
* Проверка прохождения внешнего трафика через `sniproxy` (порт `443`) -> `AdGuardHome` (порт `8444`):
  `curl -I https://dns.germany.danyaspace.ru/dns-query` -> должен вернуть `HTTP/2 405` или `HTTP/2 400` (подтверждает валидный TLS и рабочий маршрут).

---

## 6. Ограничения безопасности (Инварианты — НЕ НАРУШАТЬ)

1. **Не занимать порт `443` напрямую** веб-серверами (Nginx, Caddy, Traefik и др.) — порт `0.0.0.0:443` обязан принадлежать исключительно `sniproxy`. Любые новые веб-проекты размещать за `npm_app_1` (`127.0.0.1:8443`) и прописывать их SNI-маршрут в `/etc/sniproxy.conf`.
2. **Не возвращать глобальный шаблон `.* *:443` в `/etc/sniproxy.conf`** — сервер работает для 10+ пользователей с мобильных сетей без IP-фильтрации на 443 порту, поэтому безопасность держится на строгом белом списке доменов в `sniproxy.conf`.
3. **Не открывать порт `53` для всего интернета (`0.0.0.0/0`)** и не сбрасывать таблицы `iptables`, чтобы не нарушить работу контейнеров AmneziaVPN.