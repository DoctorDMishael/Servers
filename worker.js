const enc = new TextEncoder();

async function safeEqual(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const u = new Uint8Array(x), v = new Uint8Array(y);
  let d = 0;
  for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
  return d === 0;
}

function toBase64(text) {
  const bytes = enc.encode(text);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

const deny = (msg) => new Response(msg, { status: 403, headers: { "Cache-Control": "no-store" } });

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") return deny("Method not allowed");
    const parts = new URL(request.url).pathname.split("/").filter(Boolean);
    const token = parts[0] || "";
    
    if (!token) return deny("Not found");

    let isAuthorized = false;

    // 1. Проверяем, не является ли это ТВОИМ ЛИЧНЫМ токеном (VIP-пропуск)
    const adminToken = env.ADMIN_TOKEN || "";
    if (adminToken.length >= 32 && (await safeEqual(token, adminToken))) {
        isAuthorized = true;
    } else {
        // 2. Если это не ты, проверяем базу клиентов и дату
        const expireDateStr = await env.KV.get(`token_${token}`);
        if (expireDateStr) {
            const expireDate = new Date(expireDateStr);
            const today = new Date();
            if (today <= expireDate) {
                isAuthorized = true;
            } else {
                return deny("Ваша подписка истекла! Продлите её в Telegram-боте.");
            }
        } else {
            return deny("Ошибка: Неверная ссылка. Купите подписку в боте.");
        }
    }

    // 3. Если доступ разрешен (тобой или оплатившим клиентом), отдаем сервера
    const pathOk = parts.length === 1 || (parts.length === 2 && parts[1] === "plain");
    if (!pathOk) return deny("Not found");

    const text = await env.KV.get("sub.txt");
    if (!text) return new Response("Подписка временно обновляется", { status: 503 });

    const body = parts[1] === "plain" ? text : toBase64(text);
    const headers = {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "Profile-Update-Interval": "2",
    };
    return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
  },
};
