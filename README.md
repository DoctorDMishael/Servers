# Servers

# sub-feed

Проверяет несколько VPN-подписок, оставляет только живые не-RU узлы,
публикует результат в Cloudflare R2 и отдаёт по секретной ссылке через Worker.

## Что понадобится

- Аккаунт GitHub (бесплатный, приватный репозиторий).
- Аккаунт Cloudflare (бесплатный). Для R2 может потребоваться привязать карту,
  но 10 ГБ и базовые квоты операций бесплатны.
- Node.js (для `wrangler`) локально — один раз.

## 1. Бакет R2

Cloudflare Dashboard → R2 → Create bucket → имя `sub-store`.
Публичный доступ НЕ включать.

## 2. R2 API-токен

R2 → Manage R2 API Tokens → Create API token:
- Permissions: `Object Read & Write`
- Bucket: только `sub-store`

Сохрани:
- Account ID (правый верхний угол дашборда)
- Access Key ID
- Secret Access Key

## 3. Развернуть Worker

```bash
npm i -g wrangler
wrangler login
wrangler r2 bucket create sub-store     # если ещё не создан

openssl rand -hex 32                    # скопируй вывод — это SUB_TOKEN

wrangler secret put SUB_TOKEN           # вставь токен
wrangler deploy
