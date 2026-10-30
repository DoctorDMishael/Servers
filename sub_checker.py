#!/usr/bin/env python3
"""Сборка и реальная проверка VPN-подписок через sing-box."""
import argparse
import base64
import concurrent.futures as cf
import gzip
import hashlib
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, namedtuple
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlsplit, urlparse

import maxminddb
import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
SINGBOX = os.environ.get("SINGBOX_BIN", "sing-box")
BASE_PORT = 20800
UA = "Mozilla/5.0 (compatible; sub-checker/1.0)"
Node = namedtuple("Node", "link ob key host proto")


class Unsupported(Exception):
    def __init__(self, reason):
        super().__init__(re.sub(r"[^a-z0-9_]", "_", str(reason).lower())[:32])


# ---------------------------------------------------------------- настройки
DEFAULTS = {
    "timeout_sec": 8, "attempts": 3, "min_success_attempts": 2, "max_concurrency": 30,
    "min_targets_ok": 1, "targets": [], "blocked_protocols": [], "blocked_countries": ["RU"],
    "global_deadline_sec": 240, "min_nodes_to_publish": 1, "shrink_threshold": 0.5,
    "shrink_retries": 1, "fetch_timeout_sec": 20, "max_source_bytes": 20000000,
    "use_proxy": True
}


def load_settings():
    s = dict(DEFAULTS)
    with open(os.path.join(ROOT, "settings.json"), encoding="utf-8") as f:
        s.update(json.load(f))
    s["blocked_protocols"] = [p.lower() for p in s["blocked_protocols"]]
    s["blocked_countries"] = [c.upper() for c in s["blocked_countries"]]
    return s


# ---------------------------------------------------------------- разбор ссылок
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8")


def split_hostport(s):
    s = s.strip().rstrip("/")
    if s.startswith("["):
        h, _, p = s[1:].partition("]")
        p = p.lstrip(":")
    else:
        h, _, p = s.rpartition(":")
    return h, int(p)


def clean(d):
    return {k: v for k, v in d.items() if v not in (None, "", [])}


def flag(v):
    return str(v).lower() in ("1", "true", "yes")


def tls_obj(q, default_security, alpn_default=None):
    sec = q.get("security", default_security)
    if sec == "none":
        return None
    if sec not in ("tls", "reality"):
        raise Unsupported("security_" + sec)
    t = {"enabled": True,
         "server_name": q.get("sni") or q.get("peer") or q.get("host"),
         "insecure": True if flag(q.get("allowInsecure", q.get("insecure", "0"))) else None}
    alpn = [a for a in q.get("alpn", "").split(",") if a] or alpn_default
    t["alpn"] = alpn
    fp = q.get("fp")
    if sec == "reality":
        if not q.get("pbk"):
            raise Unsupported("reality_no_pbk")
        t["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": q.get("sid", "")}
        fp = fp or "chrome"
    if fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    return clean(t)


def transport_obj(q):
    net = (q.get("type") or "tcp").lower()
    path, host = q.get("path", ""), q.get("host", "")
    if net in ("tcp", "raw"):
        if q.get("headerType", "none") not in ("none", ""):
            raise Unsupported("tcp_http_header")
        return None
    if net == "ws":
        return clean({"type": "ws", "path": path or "/", "headers": {"Host": host} if host else None})
    if net == "grpc":
        return clean({"type": "grpc", "service_name": q.get("serviceName") or path})
    if net in ("h2", "http"):
        return clean({"type": "http", "path": path or "/", "host": host.split(",") if host else None})
    if net == "httpupgrade":
        return clean({"type": "httpupgrade", "path": path or "/", "host": host})
    raise Unsupported("transport_" + net)


def parse_std(link):
    u = urlsplit(link)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    host, port = u.hostname, u.port
    if not host or not port:
        raise Unsupported("malformed")
    userinfo = unquote(u.netloc.rpartition("@")[0])
    return host, port, userinfo, q


def parse_ss(link):
    body = link[5:].split("#", 1)[0]
    main, _, query = body.partition("?")
    if parse_qs(query).get("plugin"):
        raise Unsupported("ss_plugin")
    main = main.rstrip("/")
    if "@" in main:
        userinfo, hostport = main.rsplit("@", 1)
        ui = unquote(userinfo) if ":" in unquote(userinfo) else b64d(userinfo)
    else:
        ui, hostport = b64d(main).rsplit("@", 1)
    method, password = ui.split(":", 1)
    host, port = split_hostport(hostport)
    return {"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}


def parse_vmess(link):
    j = json.loads(b64d(link[8:].split("#", 1)[0]))
    net = str(j.get("net") or "tcp")
    q = {"type": net, "host": j.get("host", ""), "path": j.get("path", ""),
         "headerType": j.get("type") or "none", "serviceName": j.get("path", ""),
         "security": "tls" if j.get("tls") == "tls" else "none", "sni": j.get("sni", ""),
         "alpn": j.get("alpn", ""), "fp": j.get("fp", ""), "allowInsecure": str(j.get("allowInsecure", "0"))}
    ob = {"type": "vmess", "server": str(j["add"]), "server_port": int(j["port"]), "uuid": j["id"],
          "security": j.get("scy") or "auto", "alter_id": int(j.get("aid") or 0),
          "tls": tls_obj(q, "none"), "transport": transport_obj(q)}
    return clean(ob)


def parse_vless(link):
    host, port, uuid, q = parse_std(link)
    if q.get("encryption", "none") not in ("none", ""):
        raise Unsupported("vless_encryption")
    return clean({"type": "vless", "server": host, "server_port": port, "uuid": uuid,
                  "flow": q.get("flow"), "tls": tls_obj(q, "none"), "transport": transport_obj(q)})


def parse_trojan(link):
    host, port, pw, q = parse_std(link)
    return clean({"type": "trojan", "server": host, "server_port": port, "password": pw,
                  "tls": tls_obj(q, "tls"), "transport": transport_obj(q)})


def parse_hy2(link):
    host, port, pw, q = parse_std(link)
    ob = {"type": "hysteria2", "server": host, "server_port": port, "password": pw,
          "tls": tls_obj(dict(q, security="tls"), "tls", ["h3"])}
    if q.get("obfs"):
        if q["obfs"] != "salamander":
            raise Unsupported("hy2_obfs")
        ob["obfs"] = {"type": "salamander", "password": q.get("obfs-password", "")}
    if q.get("mport"):
        ob["server_ports"] = [x.strip().replace("-", ":") for x in q["mport"].split(",") if x.strip()]
    return clean(ob)


def parse_tuic(link):
    host, port, ui, q = parse_std(link)
    uuid, _, pw = ui.partition(":")
    q = dict(q, security="tls")
    return clean({"type": "tuic", "server": host, "server_port": port, "uuid": uuid, "password": pw,
                  "congestion_control": q.get("congestion_control"), "udp_relay_mode": q.get("udp_relay_mode"),
                  "tls": tls_obj(q, "tls", ["h3"])})


PARSERS = {"ss": parse_ss, "vmess": parse_vmess, "vless": parse_vless, "trojan": parse_trojan,
           "hysteria2": parse_hy2, "hy2": parse_hy2, "tuic": parse_tuic}


def parse_link(link):
    scheme = link.split("://", 1)[0].lower()
    fn = PARSERS.get(scheme)
    if not fn:
        raise Unsupported("scheme_" + scheme)
    try:
        ob = fn(link)
    except Unsupported:
        raise
    except Exception:
        raise Unsupported("malformed_" + scheme)
    key = hashlib.sha256(json.dumps(ob, sort_keys=True).encode()).hexdigest()
    return Node(link, ob, key, ob["server"], ob["type"])


# ---------------------------------------------------------------- источники
LINK_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://.+$")


def decode_sub(text):
    def links(t):
        return [x.strip() for x in t.splitlines() if LINK_RE.match(x.strip())]
    got = links(text)
    if got:
        return got
    try:
        got = links(b64d("".join(text.split())))
    except Exception:
        got = []
    return got or None


def fetch_sources(urls, S):
    lines, errs = [], Counter()
    for i, u in enumerate(urls, 1):
        text, err = None, "error"
        for _ in range(2):
            try:
                data = b""
                with requests.get(u, timeout=S["fetch_timeout_sec"], headers={"User-Agent": UA}, stream=True) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(65536):
                        data += chunk
                        if len(data) > S["max_source_bytes"]:
                            raise ValueError("too_big")
                text = data.decode("utf-8", "replace")
                break
            except Exception as e:
                err = type(e).__name__
        if text is None:
            errs[f"источник #{i}: {err}"] += 1
            continue
        got = decode_sub(text)
        if got is None:
            errs[f"источник #{i}: неподдерживаемый формат"] += 1
            continue
        lines += got
    return lines, errs


# ---------------------------------------------------------------- геолокация (DB-IP Lite Country, офлайн)
class Geo:
    def __init__(self, path):
        self.r = maxminddb.open_database(path)

    def country(self, ip):
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None
            rec = self.r.get(ip) or {}
        except Exception:
            return None
        c = (rec.get("country") or {}).get("iso_code")
        return c.upper() if isinstance(c, str) and len(c) == 2 and c.isalpha() else None


def load_geo(tmp):
    now = datetime.now(timezone.utc)
    for back in (0, 1):
        y, m = now.year, now.month - back
        if m < 1:
            y, m = y - 1, 12
        url = f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.mmdb.gz"
        try:
            r = requests.get(url, timeout=90)
            if r.status_code != 200 or len(r.content) < 500000:
                continue
            path = os.path.join(tmp, "geo.mmdb")
            with open(path, "wb") as f:
                f.write(gzip.decompress(r.content))
            g = Geo(path)
            if g.country("8.8.8.8") == "US" and g.country("77.88.8.8") == "RU":
                return g
        except Exception:
            continue
    raise RuntimeError("не удалось загрузить базу геолокации")


def resolve_all(hosts):
    def one(h):
        try:
            ipaddress.ip_address(h)
            return h, [h]
        except ValueError:
            pass
        try:
            return h, sorted({ai[4][0].split("%")[0] for ai in socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)})
        except Exception:
            return h, []
    with cf.ThreadPoolExecutor(32) as ex: # Увеличили с 16 до 32
        return dict(ex.map(one, hosts))


# ---------------------------------------------------------------- Получение бесплатных прокси
def get_working_proxy(S):
    if not S.get("use_proxy"):
        return None
        
    print("Ищу рабочий российский прокси...")
    proxies = []
    
    # Загружаем списки параллельно
    def fetch_api(url, extractor):
        try:
            r = requests.get(url, timeout=10)
            for p in extractor(r.json()):
                proxies.append(p)
        except Exception:
            pass

    apis = [
        ("https://api.proxora.io/api/tools/free-proxies?country=ru&protocol=socks5", lambda j: [f"socks5://{p['ip']}:{p['port']}" for p in j.get("data", [])]),
        ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=ru&protocol=socks5&format=json", lambda j: [f"socks5://{p['ip']}:{p['port']}" for p in j.get("proxies", [])]),
        ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=ru&protocol=http&format=json", lambda j: [f"http://{p['ip']}:{p['port']}" for p in j.get("proxies", [])])
    ]
    
    with cf.ThreadPoolExecutor(3) as ex:
        for url, ex_func in apis:
            ex.submit(fetch_api, url, ex_func)

    proxies = list(set(proxies))
    random.shuffle(proxies)
    
    # Параллельная проверка прокси
    def test_proxy(proxy):
        try:
            r = requests.get("https://api.ipify.org?format=json", proxies={"http": proxy, "https": proxy}, timeout=2)
            if r.status_code == 200:
                return proxy
        except Exception:
            pass
        return None

    # Проверяем первые 40 прокси одновременно
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        futures = [ex.submit(test_proxy, p) for p in proxies[:40]]
        for future in cf.as_completed(futures):
            res = future.result()
            if res:
                print(f"  Найден рабочий прокси: {res}")
                return res
                
    print("  Не удалось найти рабочий прокси (будет прямая проверка).")
    return None


# ---------------------------------------------------------------- ядро и проверка
def core_config(ob, port, user, pw, proxy_url):
    outbounds = []
    
    if proxy_url:
        u = urlparse(proxy_url)
        outbound_type = "socks" if u.scheme.startswith("socks") else "http"
        
        relay_ob = {
            "type": outbound_type,
            "tag": "relay",
            "server": u.hostname,
            "server_port": u.port
        }
        outbounds.append(relay_ob)
        
        target_ob = dict(ob)
        target_ob["detour"] = "relay"
    else:
        target_ob = dict(ob)

    outbounds.append(dict(target_ob, tag="out", domain_resolver="local"))

    return {
        "log": {"level": "fatal"},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
                      "users": [{"username": user, "password": pw}]}],
        "outbounds": outbounds,
        "route": {"rules": [{"inbound": ["in"], "action": "route", "outbound": "out"}, {"action": "reject"}],
                  "final": "out", "default_domain_resolver": "local"},
    }


def start_core(ob, port, tmp, user, pw, proxy_url):
    cfg = os.path.join(tmp, f"c{port}.json")
    fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(core_config(ob, port, user, pw, proxy_url), f)
    proc = subprocess.Popen([SINGBOX, "run", "-c", cfg], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0, err = time.monotonic(), "core_start_timeout"
    try:
        while time.monotonic() - t0 < 3: # Уменьшили ожидание с 6 до 3 секунд
            if proc.poll() is not None:
                err = "core_rejected_config"
                break
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return proc, None
            except OSError:
                time.sleep(0.05)
        stop_core(proc)
        return None, err
    finally:
        try:
            os.remove(cfg)
        except OSError:
            pass


def stop_core(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def parse_target(kind, text):
    try:
        if kind == "trace":
            d = dict(x.split("=", 1) for x in text.splitlines() if "=" in x)
            return {"ip": str(ipaddress.ip_address(d["ip"].strip())), "loc": d.get("loc", "").strip().upper()}
        if kind == "json_ip":
            return {"ip": str(ipaddress.ip_address(json.loads(text)["ip"])), "loc": ""}
    except Exception:
        pass
    return None


def probe(target, proxies, timeout):
    t0 = time.perf_counter()
    try:
        r = requests.get(target["url"], proxies=proxies, timeout=timeout, verify=True,
                         allow_redirects=False, headers={"User-Agent": UA, "Connection": "close"})
    except requests.exceptions.SSLError:
        return {"ok": False, "why": "tls"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "why": type(e).__name__}
    ms = (time.perf_counter() - t0) * 1000
    info = parse_target(target["parser"], r.text) if r.status_code == 200 else None
    if info is None:
        return {"ok": False, "why": "status_or_content"}
    if ms > timeout * 1000:
        return {"ok": False, "why": "slow"}
    return {"ok": True, "ms": ms, **info}


def direct_ip(S):
    try:
        r = requests.get(S["targets"][0]["url"], timeout=S["timeout_sec"], headers={"User-Agent": UA})
        info = parse_target(S["targets"][0]["parser"], r.text)
        return info["ip"] if info else None
    except Exception:
        return None


class Ctx:
    def __init__(self, S, geo, direct, tmp, deadline, proxy):
        self.S, self.geo, self.direct, self.tmp, self.deadline = S, geo, direct, tmp, deadline
        self.proxy = proxy
        self.user, self.pw = secrets.token_hex(8), secrets.token_hex(16)
        self.target_ok, self.lock = Counter(), threading.Lock()


def check_node(n, port, ctx):
    S = ctx.S
    proc, err = start_core(n.ob, port, ctx.tmp, ctx.user, ctx.pw, ctx.proxy)
    if err:
        return {"status": "core_rejected", "why": err}
    proxy = f"socks5h://{ctx.user}:{ctx.pw}@127.0.0.1:{port}"
    proxies = {"http": proxy, "https": proxy}
    need = min(S["min_targets_ok"], len(S["targets"]))
    times, ips, locs, ok_rounds = [], set(), set(), 0
    try:
        with cf.ThreadPoolExecutor(len(S["targets"])) as ex:
            for i in range(S["attempts"]):
                res = list(ex.map(lambda t: probe(t, proxies, S["timeout_sec"]), S["targets"]))
                with ctx.lock:
                    for t, r in zip(S["targets"], res):
                        ctx.target_ok[t["name"]] += r["ok"]
                good = [r for r in res if r["ok"]]
                if ctx.direct and any(r["ip"] == ctx.direct for r in good):
                    return {"status": "leak"}
                if len(good) >= need:
                    ok_rounds += 1
                    times += [r["ms"] for r in good]
                    ips |= {r["ip"] for r in good}
                    locs |= {r["loc"] for r in good if r["loc"]}
                if ok_rounds + (S["attempts"] - i - 1) < S["min_success_attempts"]:
                    break
    finally:
        stop_core(proc)
    if ok_rounds < S["min_success_attempts"]:
        return {"status": "failed"}
    codes = {c for c in locs if len(c) == 2 and c.isalpha() and c not in ("XX", "T1")}
    codes |= {c for c in (ctx.geo.country(ip) for ip in ips) if c}
    if codes & set(S["blocked_countries"]):
        return {"status": "ru_exit"}
    if not codes:
        return {"status": "geo_unknown"}
    return {"status": "ok", "median": statistics.median(times)}


def run_checks(nodes, ctx):
    S = ctx.S
    slots = queue.Queue()
    for i in range(S["max_concurrency"]):
        slots.put(BASE_PORT + i)

    def work(n):
        if time.monotonic() > ctx.deadline:
            return n.key, {"status": "not_checked"}
        port = slots.get()
        try:
            return n.key, check_node(n, port, ctx)
        finally:
            slots.put(port)

    with cf.ThreadPoolExecutor(S["max_concurrency"]) as ex:
        return dict(ex.map(work, nodes))


# ---------------------------------------------------------------- Cloudflare KV
def kv_api(method, data=None):
    account = os.environ["CF_ACCOUNT_ID"].strip()
    ns = os.environ["CF_KV_NAMESPACE_ID"].strip()
    token = os.environ["CF_API_TOKEN"].strip()
    url = f"https://api.cloudflare.com/client/v4/accounts/{account}/storage/kv/namespaces/{ns}/values/sub.txt"
    headers = {"Authorization": f"Bearer {token}"}
    if method == "GET":
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return [x.strip() for x in r.text.splitlines() if x.strip()]
    elif method == "PUT":
        r = requests.put(url, headers=headers, data=data.encode("utf-8"), timeout=30)
        r.raise_for_status()


# ---------------------------------------------------------------- самопроверка
def selftest(S):
    print("SELFTEST: проверяю, что нерабочий прокси не проходит за счёт прямого выхода")
    d = direct_ip(S)
    if not d:
        print("SELFTEST FAIL: нет прямого доступа в интернет с раннера, тест бессмыслен")
        return 1
    tmp = tempfile.mkdtemp()
    try:
        geo = load_geo(tmp)
        ctx = Ctx(S, geo, d, tmp, time.monotonic() + 300, None)
        bad = [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": 9, "method": "aes-256-gcm", "password": "x"},
               {"type": "shadowsocks", "server": "192.0.2.1", "server_port": 8388, "method": "aes-256-gcm", "password": "x"}]
        ok = True
        for i, ob in enumerate(bad, 1):
            n = Node("", ob, str(i), ob["server"], "shadowsocks")
            st = check_node(n, BASE_PORT, ctx)["status"]
            print(f"  мёртвый узел #{i}: статус={st} (ожидается failed)")
            ok &= st == "failed"
        r = probe(S["targets"][0], {"http": "socks5h://127.0.0.1:1", "https": "socks5h://127.0.0.1:1"}, 5)
        print(f"  запрос через закрытый прокси-порт: ok={r['ok']} (ожидается False)")
        ok &= not r["ok"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("SELFTEST OK" if ok else "SELFTEST FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------- основной процесс
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--no-upload", action="store_true", help="локально: записать out/sub.txt")
    args = ap.parse_args()
    S = load_settings()
    if args.selftest:
        return selftest(S)

    start = time.monotonic()
    deadline = start + S["global_deadline_sec"]
    urls = [x.strip() for x in os.environ.get("SUBSCRIPTION_URLS", "").splitlines() if x.strip().lower().startswith("http")]
    if not urls:
        print("Нет ссылок в SUBSCRIPTION_URLS")
        return 1
        
    tmp = tempfile.mkdtemp()
    try:
        prev_lines = []
        if not args.no_upload:
            prev_lines = kv_api("GET")
        prev_keys = set()
        for ln in prev_lines:
            try:
                prev_keys.add(parse_link(ln).key)
            except Unsupported:
                pass

        working_proxy = get_working_proxy(S)

        lines, src_errs = fetch_sources(urls, S)
        rep = Counter(received=len(lines))
        unsupported, seen, nodes = Counter(), set(), []
        for ln in lines:
            try:
                n = parse_link(ln)
            except Unsupported as e:
                unsupported[str(e)] += 1
                continue
            if n.key in seen:
                rep["duplicates"] += 1
            else:
                seen.add(n.key)
                nodes.append(n)
        keep = []
        for n in nodes:
            if n.proto in S["blocked_protocols"]:
                rep["blocked"] += 1
            else:
                keep.append(n)
        nodes = keep

        geo = load_geo(tmp)
        resolved = resolve_all({n.host for n in nodes})
        country_cnt, keep = Counter(), []
        for n in nodes:
            ips = resolved.get(n.host) or []
            codes = [geo.country(ip) for ip in ips]
            if any(c in S["blocked_countries"] for c in codes):
                country_cnt["подключение RU"] += 1
            elif not ips or any(c is None for c in codes):
                country_cnt["страна не определена"] += 1
            else:
                keep.append(n)
        nodes = sorted(keep, key=lambda n: (n.key not in prev_keys, random.random()))

        d = direct_ip(S)
        if not d:
            print("Предупреждение: не удалось получить прямой IP раннера, защита отключена")
            
        ctx = Ctx(S, geo, d, tmp, deadline, working_proxy)
        results = run_checks(nodes, ctx)

        def passed():
            return [n for n in nodes if results[n.key]["status"] == "ok"]

        prev_count = len(prev_lines)
        force = flag(os.environ.get("FORCE_PUBLISH", "0"))
        tries = 0
        while (prev_count and len(passed()) < prev_count * S["shrink_threshold"] and tries < S["shrink_retries"]
               and time.monotonic() < deadline):
            tries += 1
            print(f"Список сократился ({len(passed())} из {prev_count}), повторная проверка")
            again = [n for n in nodes if results[n.key]["status"] in ("failed", "not_checked")]
            results.update(run_checks(again, ctx))

        st = Counter(r["status"] for r in results.values())
        
        good = sorted(passed(), key=lambda n: results[n.key]["median"])
        seen_ips = set()
        unique_good = []
        for n in good:
            if n.host not in seen_ips:
                unique_good.append(n)
                seen_ips.add(n.host)
        good = unique_good

        report = [
            f"Получено: {rep['received']}",
            f"Дубликатов: {rep['duplicates']}",
            f"Запрещено настройками: {rep['blocked']}",
            f"Не поддерживается: {sum(unsupported.values()) + st['core_rejected']}",
            f"Исключено по стране: {sum(country_cnt.values()) + st['ru_exit'] + st['geo_unknown']}"
            f" (подключение RU: {country_cnt['подключение RU']}, выход RU: {st['ru_exit']},"
            f" не определена: {country_cnt['страна не определена'] + st['geo_unknown']})",
            f"Не прошло реальную проверку: {st['failed'] + st['leak']}",
            f"Не проверено из-за лимита времени: {st['not_checked']}",
            f"Опубликовано: {len(good)}",
        ]
        details = [f"  не поддерживается — {k}: {v}" for k, v in sorted(unsupported.items())]
        details += [f"  {k}" for k in src_errs]
        
        if working_proxy:
            details.append(f"  Проверка выполнена через прокси: {working_proxy}")
        else:
            details.append("  ВНИМАНИЕ: проверка выполнена напрямую (прокси не найден)")

        for t in S["targets"]:
            if nodes and ctx.target_ok[t["name"]] == 0 and any(r["status"] != "not_checked" for r in results.values()):
                details.append(f"  ВНИМАНИЕ: контрольный адрес «{t['name']}» не ответил ни разу")
                
        out = "\n".join(report + details)
        print(out)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
                f.write("```\n" + out + "\n```\n")

        text = "\n".join(n.link for n in good) + "\n"
        ok_text = len(good) >= max(1, S["min_nodes_to_publish"]) and all(LINK_RE.match(x) for x in text.split("\n") if x)
        if not ok_text:
            print("Результат пуст или некорректен — прежняя подписка сохранена")
            return 0

        if prev_count and len(good) < prev_count * S["shrink_threshold"] and not force:
            print(f"Список сократился слишком резко ({len(good)} из {prev_count}) — прежняя подписка сохранена. "
                  "Для принудительной публикации запустите вручную с force=true")
            return 0

        updated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if args.no_upload:
            os.makedirs(os.path.join(ROOT, "out"), exist_ok=True)
            with open(os.path.join(ROOT, "out", "sub.txt"), "w", encoding="utf-8") as f:
                f.write(text)
            with open(os.path.join(ROOT, "out", "sub.b64"), "w") as f:
                f.write(base64.b64encode(text.encode()).decode())
        else:
            kv_api("PUT", text)
        print(f"Обновлено: {updated}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
