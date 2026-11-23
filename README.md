# Sherlock Hub — Единый агрегатор открытых OSINT-источников

Сервис объединяет популярные open-source OSINT-инструменты в единый веб-интерфейс, REST API (с SSE-стримингом) и CLI с автоматической дедупликацией результатов, сбором сводного досье и экспортом в JSON / CSV / Markdown.

> **Важно:** Sherlock Hub работает **только с открытыми публичными источниками (OSINT)** — публичными профилями, официальными API, DNS/MX/RDAP и открытыми метаданными. Закрытые/утекшие базы данных и инструменты авторизованного скрейпинга (GHunt, Osintgram и др.) намеренно не включены.

## Подключённые движки

| Движок | Тип запроса | Описание | Статус |
| :--- | :--- | :--- | :--- |
| **Direct Public APIs** | `username` | Параллельные запросы к GitHub, GitLab, Reddit, Hacker News, Dev.to, Keybase, Bluesky, Mastodon, Docker Hub, PyPI, npm, Gravatar, Wikipedia, Telegram | Встроен |
| **Sherlock** | `username` | `sherlock-project/sherlock` (400+ сайтов) | Предустановлен |
| **Maigret** | `username` | `soxoj/maigret` (до 3000+ сайтов + `socid-extractor`) | Предустановлен |
| **Email Passive OSINT** | `email` | DNS/MX/SPF/DMARC, почтовый провайдер, Gravatar, OpenPGP keyserver, публичный GitHub + кросс-проверка никнейма | Встроен |
| **Phone Metadata & PhoneInfoga** | `phone` | Валидация, страна, регион, оператор, тип линии, часовые пояса, поисковые дорки + автоподхват CLI `phoneinfoga` | Встроен |
| **Domain DNS / TLS / RDAP** | `domain` | A/AAAA/MX/NS/TXT, TLS-сертификат (CN/SAN/Issuer), RDAP/WHOIS, `security.txt` | Встроен |
| **Blackbird / Social Analyzer / theHarvester** | `username`, `email`, `domain` | Плагины-адаптеры: автоматически активируются, если соответствующие CLI установлены в `PATH` | Опционально |

## Быстрый запуск

### Прямо с GitHub (Codespaces — веб-интерфейс в браузере)
Нажмите **Code → Codespaces → Create codespace on main**. Контейнер автоматически установит зависимости и запустит веб-интерфейс на порту `8000` (`.devcontainer/devcontainer.json`).

### Прямо с GitHub (GitHub Actions — запуск поиска без локальной установки)
Откройте вкладку **Actions → Run OSINT Search → Run workflow**, введите запрос (никнейм, email, телефон или домен) и глубину — готовый отчёт отобразится прямо в сводке запуска и будет доступен для скачивания в артефактах.

### Локально (Python 3.12+)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Через Docker
```bash
docker compose up --build
```

### Через CLI
```bash
python cli.py engines
python cli.py search torvalds --depth fast -o report.md
python cli.py search +16502530000
python cli.py search github.com
```

## REST API
Интерактивная документация Swagger доступна по адресу `/docs`.
- `GET /api/engines` — список всех движков и их статус
- `POST /api/search` — синхронный поиск, возвращает JSON-отчёт
- `GET /api/search/stream?q=...&depth=standard` — SSE-поток результатов в реальном времени
- `GET /api/history` — история сохранённых поисков (SQLite)
- `GET /api/reports/{id}/export?fmt=json|csv|md` — экспорт отчёта
