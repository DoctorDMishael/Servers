// Отдаёт подписку из Workers KV по пути /<SUB_TOKEN> (Base64) или /<SUB_TOKEN>/plain (обычный текст).
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

const deny = () => new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") return deny();
    const parts = new URL(request.url).pathname.split("/").filter(Boolean);
    const secret = env.SUB_TOKEN || "";
    const tokenOk = secret.length >= 32 && (await safeEqual(parts[0] || "", secret));
    const pathOk = parts.length === 1 || (parts.length === 2 && parts[1] === "plain");
    if (!tokenOk || !pathOk) return deny();

    const text = await env.KV.get("sub.txt");
    if (!text) return new Response("Subscription not ready", { status: 503, headers: { "Cache-Control": "no-store" } });

    const body = parts[1] === "plain" ? text : toBase64(text);
    const headers = {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex",
      "Profile-Update-Interval": "2",
    };
    return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
  },
};
