from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import (
    urlparse, urlsplit, urlunsplit, parse_qs, urlencode, urljoin
)

# ======== NEW: Visual libs (safe fallbacks) ========
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _Dummy:
        RESET_ALL = ""
    class _DummyFore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = ""
    class _DummyStyle:
        BRIGHT = NORMAL = DIM = ""
    Fore = _DummyFore()
    Style = _Dummy()
    def colorama_init(*a, **k): pass

try:
    from pyfiglet import figlet_format
except Exception:
    def figlet_format(text, font="standard"):  
        return f"{text}\n"


try:
    import requests
    from bs4 import BeautifulSoup  
except ImportError:
    print("[!] Missing dependency: requests & beautifulsoup4 required.")
    print("    pip install requests beautifulsoup4")
    sys.exit(1)

try:
    import dns.resolver
except Exception:
    dns = None  

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import track
    from rich.markdown import Markdown
    from rich import box
except Exception:
    Console = None
    Panel = None
    Table = None
    track = None
    Markdown = None
    box = None

try:
    from jinja2 import Template 
except Exception:
    Template = None


SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; WebPentestAllActive/1.0)"
})
DEFAULT_TIMEOUT = 10

DEFAULT_DIRS = [
    "/", "/robots.txt", "/sitemap.xml", "/admin", "/login", "/logout",
    "/dashboard", "/wp-admin/", "/wp-login.php", "/phpinfo.php",
    "/server-status", "/api", "/uploads", "/static", "/assets", "/backup",
    "/backups", "/.git/", "/.env", "/config", "/console"
]
SENSITIVE_FILES = [
    "/.env", "/.git/config", "/.git/HEAD", "/backup.zip", "/db.sql",
    "/config.php.bak", "/composer.lock", "/phpinfo.php"
]
DEFAULT_SUBS = ["www", "dev", "test", "staging", "api", "beta", "admin", "mail", "cdn", "img"]
ADMIN_PANELS = ["/admin/", "/administrator/", "/cpanel/", "/phpmyadmin/", "/wp-admin/"]

OPEN_REDIRECT_KEYS = ["next", "url", "return", "redirect", "dest", "destination", "continue", "goto"]


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1"
]
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax", "mysql", "mariadb",
    "ora-", "postgresql", "sqlite", "sql syntax", "warning: mysql"
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>"
]
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd"
]
PORTS_COMMON = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 6379, 27017, 8080, 8443]
SEC_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"
]
CSRF_TOKEN_KEYS = ["csrf", "xsrf", "token", "authenticity_token"]

WAF_SIGNS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "cloudflare"]),
    ("Akamai", ["akamai", "x-akamai"]),
    ("Sucuri", ["x-sucuri-id", "sucuri"]),
    ("Incapsula/Imperva", ["incap_ses", "visid_incap", "incapsula"]),
    ("Fastly", ["fastly", "x-served-by"]),
    ("Varnish", ["x-varnish", "varnish"]),
    ("AWS/CloudFront/ELB", ["x-amz-cf-id", "cloudfront", "awselb", "elb"])
]

SEVERITY_WEIGHT = {"High": 5, "Medium": 3, "Low": 1, "Info": 0}

# --------- Dataclasses ----------
@dataclass
class ReconResult:
    target: str
    ip: Optional[str]
    dns: Dict[str, List[str]]
    headers: Dict[str, str]
    tech: List[str]
    js_libs: List[str]
    title: Optional[str] = None
    resp_ms: Optional[int] = None
    waf_cdn: List[str] = field(default_factory=list)
    meta_generator: Optional[str] = None

@dataclass
class Finding:
    category: str
    title: str
    detail: str
    severity: str
    url: Optional[str] = None
    evidence: Optional[str] = None

@dataclass
class Report:
    started_at: str
    finished_at: str
    target: str
    recon: Optional[ReconResult]
    findings: List[Finding] = field(default_factory=list)
    header_score: Optional[int] = None
    risk_percent: Optional[int] = None

# --------- Utilitas Visual (NEW) ----------
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def banner_anonymous():
    try:
        art = figlet_format("Anonymous", font="abstract")
    except Exception:
        art = figlet_format("Anonymous")
    print(Fore.RED + Style.BRIGHT + art)
    print(Fore.RED + Style.BRIGHT + "Tools by ghost_root".center(60, " "))
    print(Style.RESET_ALL)

def spooky_loading(msg="Initializing attack module...", seconds=2.0):
    print(Fore.MAGENTA + msg)
    t0 = time.time()
    dots = "........"
    i = 0
    while time.time() - t0 < seconds:
        print(Fore.CYAN + "[" + "." * (i % len(dots)) + "]", end="\r")
        time.sleep(0.12)
        i += 1
    print(" " * 40, end="\r")

def access_granted():
    try:
        art = figlet_format("ACCESS GRANTED", font="abstract")
    except Exception:
        art = figlet_format("ACCESS GRANTED")
    print(Fore.RED + Style.BRIGHT + art)

def breach_detected():
    try:
        art = figlet_format("BREACH DETECTED", font="abstract")
    except Exception:
        art = figlet_format("BREACH DETECTED")
    print(Fore.RED + Style.BRIGHT + art)

def draw_progress(percent: int):
    percent = max(0, min(100, percent))
    total_blocks = 25
    filled = int(round(percent / 100 * total_blocks))
    bar = "▓" * filled + "░" * (total_blocks - filled)
    print(Fore.CYAN + f"[{bar}] {percent:3d}% SCANNING...", end="\r")

def step_progress(step_idx: int, total_steps: int, animate: bool = True):
    # hitung target persentase per langkah dan animasikan sedikit
    base = int((step_idx / max(1, total_steps)) * 100)
    target = int(((step_idx + 1) / max(1, total_steps)) * 100)
    if not animate:
        draw_progress(target)
        print()
        return
    for p in range(base, target + 1, max(1, (target - base) // 10 or 1)):
        draw_progress(p)
        time.sleep(0.03)
    draw_progress(target)
    print()


def normalize(u: str) -> str:
    u = u.strip()
    if not re.match(r"^https?://", u):
        u = "http://" + u
    return u.rstrip("/")

def get_domain(u: str) -> str:
    return urlparse(u).netloc.split(":")[0]

def fetch(
    url: str,
    method: str = "GET",
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
    timeout: Optional[int] = None
) -> Optional[requests.Response]:
    t = timeout or DEFAULT_TIMEOUT
    try:
        h = dict(SESSION.headers)
        if headers:
            h.update(headers)
        if method.upper() == "POST":
            return SESSION.post(url, data=data, headers=h, timeout=t, allow_redirects=allow_redirects)
        return SESSION.get(url, headers=h, timeout=t, allow_redirects=allow_redirects)
    except requests.RequestException:
        return None

def parse_ports(arg: Optional[str]) -> List[int]:
    if not arg:
        return PORTS_COMMON[:]
    parts = [p.strip() for p in arg.split(",") if p.strip()]
    ports: set[int] = set()
    for p in parts:
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a); b = int(b)
                lo, hi = min(a, b), max(a, b)
                for x in range(max(1, lo), min(65535, hi) + 1):
                    ports.add(x)
            except Exception:
                continue
        else:
            try:
                x = int(p)
                if 1 <= x <= 65535:
                    ports.add(x)
            except Exception:
                continue
    return sorted(ports)

def split_params(url: str) -> Tuple[str, Dict[str, List[str]]]:
    p = urlsplit(url)
    base = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    return base, parse_qs(p.query)

def build_url(base: str, params: Dict[str, List[str]]) -> str:
    items: List[Tuple[str, str]] = []
    for k, vals in params.items():
        for v in vals:
            items.append((k, v))
    qs = urlencode(items)
    return base + (("?" + qs) if qs else "")

def similarity(a: str, b: str) -> float:
    import difflib
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def detect_waf_cdn(headers: Dict[str, str]) -> List[str]:
    out: List[str] = []
    hlower = "\n".join([f"{k.lower()}: {str(v).lower()}" for k, v in headers.items()])
    for name, keys in WAF_SIGNS:
        for k in keys:
            if k.lower() in hlower:
                out.append(name)
                break
    return sorted(set(out))

def module_recon(target: str) -> ReconResult:
    url = normalize(target)
    domain = get_domain(url)
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = None

    dns_records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    if dns is not None:
        try:
            res = dns.resolver.Resolver()
            for t in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    answers = res.resolve(domain, t, lifetime=3)
                    for a in answers:
                        dns_records[t].append(str(a))
                except Exception:
                    pass
        except Exception:
            pass

    headers: Dict[str, str] = {}
    tech: List[str] = []
    js_libs: List[str] = []
    title = None
    resp_ms = None
    waf_cdn: List[str] = []
    meta_gen = None

    start = time.time()
    r = fetch(url)
    if r is not None:
        resp_ms = int((time.time() - start) * 1000)
        headers = dict(r.headers)
        server = headers.get("Server")
        if server:
            tech.append(f"Server:{server}")
        xpb = headers.get("X-Powered-By")
        if xpb:
            tech.append(f"X-Powered-By:{xpb}")
        waf_cdn = detect_waf_cdn(headers)
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.title and soup.title.text:
                title = soup.title.text.strip()
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                meta_gen = gen.get("content").strip()
            for s in soup.find_all("script", src=True):
                src = (s.get("src") or "").lower()
                if "jquery" in src and "jQuery" not in js_libs:
                    js_libs.append("jQuery")
                if "react" in src and "React" not in js_libs:
                    js_libs.append("React")
                if "vue" in src and "Vue" not in js_libs:
                    js_libs.append("Vue")
        except Exception:
            pass

    return ReconResult(
        target=url, ip=ip, dns=dns_records, headers=headers, tech=tech, js_libs=js_libs,
        title=title, resp_ms=resp_ms, waf_cdn=waf_cdn, meta_generator=meta_gen
    )

def module_subdomain(target: str, words: List[str]) -> List[Finding]:
    out: List[Finding] = []
    domain = get_domain(normalize(target))
    if dns is None:
        return out
    res = dns.resolver.Resolver()
    for w in words:
        sub = f"{w}.{domain}"
        try:
            _ = res.resolve(sub, "A", lifetime=2)
            out.append(Finding(category="Subdomain", title="Subdomain ditemukan", detail=sub, severity="Info", url="http://" + sub))
        except Exception:
            pass
    return out

def _dir_check(base: str, p: str, baseline_text: str, timeout: int) -> Optional[Finding]:
    url = urljoin(base + "/", p.lstrip("/"))
    r = fetch(url, timeout=timeout)
    if r is None:
        return None
    suspect = r.status_code in (200, 204, 301, 302, 401, 403)
    if not suspect:
        sim = similarity(getattr(r, "text", "")[:1500], baseline_text[:1500])
        if sim < 0.82:
            suspect = True
    if suspect:
        sev = "Medium" if r.status_code in (200, 401, 403) else "Info"
        return Finding(category="Path", title=f"{p} -> {r.status_code}", detail=f"Ukuran {len(r.content)} byte", severity=sev, url=url)
    return None

def module_dirs(target: str, paths: List[str], threads: int = 20, timeout: int = 6) -> List[Finding]:
    out: List[Finding] = []
    base = normalize(target)
    baseline = fetch(urljoin(base + "/", f"__not_exist__{int(time.time())}"), timeout=timeout)
    baseline_text = baseline.text if baseline is not None else ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(_dir_check, base, p, baseline_text, timeout) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                out.append(r)
    return out

def module_headers(target: str) -> Tuple[List[Finding], int]:
    out: List[Finding] = []
    r = fetch(normalize(target))
    if r is None:
        return out, 0
    present = set(k for k in r.headers.keys())
    missing = 0
    for h in SEC_HEADERS:
        if h not in present:
            out.append(Finding(category="Header", title=f"Header hilang: {h}", detail="Pertimbangkan menambahkan header ini", severity="Low"))
            missing += 1
    score = int(round(100 * (len(SEC_HEADERS) - missing) / max(1, len(SEC_HEADERS))))
    return out, score

def module_cors(target: str) -> List[Finding]:
    out: List[Finding] = []
    test_origin = "https://evil.example"
    r = fetch(normalize(target), headers={"Origin": test_origin})
    if r is None:
        return out
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        out.append(Finding(category="CORS", title="CORS wildcard (*)", detail="Access-Control-Allow-Origin: *", severity="Medium"))
    if acao == test_origin and acac and acac.lower() == "true":
        out.append(Finding(category="CORS", title="CORS berisiko (reflect + credentials)", detail=f"Origin: {acao}", severity="High"))
    return out

def module_open_redirect(target: str) -> List[Finding]:
    out: List[Finding] = []
    base, params = split_params(normalize(target))
    if not params:
        return out
    for k in params.keys():
        if k.lower() in OPEN_REDIRECT_KEYS:
            mod = {kk: list(vv) for kk, vv in params.items()}
            mod[k] = ["http://example.com"]
            test_url = build_url(base, mod)
            r = fetch(test_url, allow_redirects=False)
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and loc.startswith("http://example.com"):
                out.append(Finding(category="OpenRedirect", title=f"Param {k} rentan redirect", detail="Redirect eksternal terdeteksi", severity="Medium", url=test_url, evidence=loc))
    return out

def module_sqli(target: str, timeout: int = 8, boolean_probe: bool = True, time_probe: bool = True) -> List[Finding]:
    out: List[Finding] = []
    base, params = split_params(normalize(target))
    if not params:
        return out
    baseline = fetch(normalize(target), timeout=timeout)
    bl_len = len(baseline.content) if baseline is not None else -1

    for k in list(params.keys()):
        # Error-based + size anomaly
        for payload in SQLI_PAYLOADS:
            mod = {kk: list(vv) for kk, vv in params.items()}
            original = mod[k][0] if mod[k] else ""
            mod[k] = [original + payload]
            test_url = build_url(base, mod)
            r = fetch(test_url, timeout=timeout)
            if r is None:
                continue
            txt = r.text.lower()
            if any(pat in txt for pat in SQL_ERROR_PATTERNS):
                out.append(Finding(category="SQLi", title=f"Kemungkinan SQLi (error) pada param {k}", detail="Pola error SQL terdeteksi", severity="High", url=test_url, evidence="error pattern"))
                break
            if bl_len > 0 and abs(len(r.content) - bl_len) > max(800, int(bl_len * 0.3)):
                out.append(Finding(category="SQLi", title=f"Anomali ukuran respon pada {k}", detail="Perubahan ukuran respon signifikan", severity="Medium", url=test_url))
                break

        
        if boolean_probe:
            mod_true = {kk: list(vv) for kk, vv in params.items()}
            mod_false = {kk: list(vv) for kk, vv in params.items()}
            mod_true[k] = [(params[k][0] if params[k] else "") + "' OR '1'='1' -- "]
            mod_false[k] = [(params[k][0] if params[k] else "") + "' OR '1'='2' -- "]
            url_true = build_url(base, mod_true)
            url_false = build_url(base, mod_false)
            r1 = fetch(url_true, timeout=timeout)
            r2 = fetch(url_false, timeout=timeout)
            if r1 is not None and r2 is not None:
                s = similarity(r1.text[:2000], r2.text[:2000])
                if s < 0.9:
                    out.append(Finding(category="SQLi", title=f"Kemungkinan SQLi (boolean) pada {k}", detail="Respon berbeda untuk payload true/false", severity="High", url=url_true))

        
        if time_probe:
            probe_sleep = 4
            payload_time = "' OR IF(1=1,SLEEP(%d),0) -- " % probe_sleep
            mod_time = {kk: list(vv) for kk, vv in params.items()}
            mod_time[k] = [(params[k][0] if params[k] else "") + payload_time]
            test_url = build_url(base, mod_time)
            t0 = time.time()
            r = fetch(test_url, timeout=timeout + probe_sleep + 2)
            t1 = time.time()
            if r is not None:
                delta = t1 - t0
                if delta > probe_sleep + 1.5:
                    out.append(Finding(category="SQLi", title=f"Kemungkinan SQLi (time-based) pada {k}", detail=f"Respon lambat ~{int(delta)}s setelah payload sleep({probe_sleep})", severity="High", url=test_url))
    return out

def module_xss(target: str, timeout: int = 8) -> List[Finding]:
    out: List[Finding] = []
    base, params = split_params(normalize(target))
    if not params:
        return out
    for k in list(params.keys()):
        for payload in XSS_PAYLOADS:
            mod = {kk: list(vv) for kk, vv in params.items()}
            mod[k] = [(params[k][0] if params[k] else "") + payload]
            test_url = build_url(base, mod)
            r = fetch(test_url, timeout=timeout)
            if r is None:
                continue
            if payload in r.text:
                out.append(Finding(category="XSS", title=f"Reflected XSS pada {k}", detail="Payload terefleksi tanpa encoding", severity="High", url=test_url, evidence=payload))
                break
    return out

def module_lfi(target: str, timeout: int = 6) -> List[Finding]:
    out: List[Finding] = []
    base, params = split_params(normalize(target))
    if not params:
        return out
    for k in list(params.keys()):
        for payload in LFI_PAYLOADS:
            mod = {kk: list(vv) for kk, vv in params.items()}
            mod[k] = [payload]
            test_url = build_url(base, mod)
            r = fetch(test_url, timeout=timeout)
            if r is None:
                continue
            low = r.text.lower()
            if "root:x:" in low or "daemon:" in low or "nologin" in low:
                out.append(Finding(category="LFI", title=f"Kemungkinan LFI pada {k}", detail="Indikasi konten file sistem ditemukan", severity="High", url=test_url))
                break
    return out

def module_portscan(domain: str, ports: List[int], threads: int = 400, timeout: float = 0.6) -> List[Finding]:
    out: List[Finding] = []
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return out

    def scan_port(p: int) -> Optional[Finding]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((ip, p))
            if res == 0:
                return Finding(category="Port", title=f"Port terbuka: {p}/tcp", detail=f"Host {ip}", severity="Info", url=f"{ip}:{p}")
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 1000)) as ex:
        futures = [ex.submit(scan_port, p) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                out.append(r)
    return out

def module_ssl(domain: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
                not_after = cert.get("notAfter")
                subj = cert.get("subject", [])
                cn = None
                for tupl in subj:
                    for k, v in tupl:
                        if k == "commonName":
                            cn = v
                detail = f"CN={cn or '-'}; Kadaluarsa={not_after}"
                out.append(Finding(category="SSL", title="Info sertifikat", detail=detail, severity="Info"))
    except Exception as e:
        out.append(Finding(category="SSL", title="Gagal ambil sertifikat", detail=str(e), severity="Info"))
    return out

def module_cookie_flags(target: str) -> List[Finding]:
    out: List[Finding] = []
    r = fetch(normalize(target))
    if r is None:
        return out
    sc = r.headers.get("Set-Cookie", "")
    if not sc:
        return out
    
    items = [sc]
    for raw in items:
        name = raw.split(";", 1)[0].split("=", 1)[0].strip()
        lower = raw.lower()
        missing: List[str] = []
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "secure" not in lower and normalize(target).startswith("https"):
            missing.append("Secure")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            out.append(Finding(category="Cookie", title=f"Cookie {name} kurang aman", detail="Kurang: " + ", ".join(missing), severity="Low"))
    return out

def module_ratelimit(target: str, attempts: int = 6) -> List[Finding]:
    out: List[Finding] = []
    count429 = 0
    for _ in range(attempts):
        r = fetch(normalize(target))
        if r is not None and r.status_code == 429:
            count429 += 1
    if count429 == 0:
        out.append(Finding(category="RateLimit", title="Kemungkinan tidak ada rate limit", detail=f"{attempts} request cepat tanpa 429", severity="Info"))
    return out

def module_csrf(target: str) -> List[Finding]:
    out: List[Finding] = []
    r = fetch(normalize(target))
    if r is None:
        return out
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for f in forms:
            method = (f.get("method") or "get").lower()
            if method == "post":
                inputs = f.find_all("input")
                names = [(i.get("name") or "").lower() for i in inputs]
                if not any(any(k in n for k in CSRF_TOKEN_KEYS) for n in names):
                    out.append(Finding(category="CSRF", title="Form POST tanpa token", detail="Tidak ditemukan token CSRF umum", severity="Medium"))
    except Exception:
        pass
    return out


def render_md(report: Report) -> str:
    md: List[str] = []
    md.append("# Laporan Pengujian Keamanan Web\n\n")
    md.append(f"**Target:** {report.target}  \n")
    md.append(f"**Mulai:** {report.started_at}  \n")
    md.append(f"**Selesai:** {report.finished_at}  \n\n")
    if report.recon:
        r = report.recon
        md.append("## Informasi Awal (Recon)\n")
        md.append(f"- IP: {r.ip or '-'}\n")
        if r.resp_ms is not None:
            md.append(f"- Waktu Respon (ms): {r.resp_ms}\n")
        if r.title:
            md.append(f"- Judul Halaman: {r.title}\n")
        if r.meta_generator:
            md.append(f"- Meta Generator: {r.meta_generator}\n")
        if r.waf_cdn:
            md.append(f"- WAF/CDN Terdeteksi: {', '.join(r.waf_cdn)}\n")
        md.append("- DNS:\n")
        for k, v in r.dns.items():
            if v:
                md.append(f"  - {k}: {', '.join(v)}\n")
        if r.headers:
            md.append("- Cuplikan header:\n")
            for k, v in list(r.headers.items())[:12]:
                md.append(f"  - {k}: {v}\n")
        if r.tech:
            md.append("- Teknologi (perkiraan): " + ", ".join(r.tech) + "\n")
        if r.js_libs:
            md.append("- JS Libraries: " + ", ".join(r.js_libs) + "\n")
        md.append("\n")
    if report.header_score is not None:
        md.append(f"**Skor Header Keamanan:** {report.header_score}%  \n")
    if report.risk_percent is not None:
        md.append(f"**Persentase Risiko (0% aman — 100% berbahaya):** {report.risk_percent}%  \n\n")
    if report.findings:
        md.append("## Temuan\n")
        for idx, f in enumerate(report.findings, 1):
            md.append(f"- **{idx}. [{f.category}] {f.severity}**  \n")
            md.append(f"  - Judul: {f.title}  \n")
            md.append(f"  - Detail: {f.detail}  \n")
            md.append(f"  - URL: {f.url or '-'}  \n")
            md.append(f"  - Bukti: {f.evidence or '-'}  \n")
    else:
        md.append("Tidak ada temuan berarti.\n")
    md.append("\n---\n")
    md.append("*Dibuat oleh Web Pentest Tool - untuk keperluan edukasi dan pengujian legal.*\n")
    return "".join(md)

HTML_TEMPLATE = """<!doctype html>
<html lang="id"><head><meta charset="utf-8"/><title>Laporan Pentest - {{target}}</title>
<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;padding:20px}h1{color:#b22}ul{line-height:1.4}</style></head><body>
<h1>Laporan Pengujian Keamanan Web</h1>
<p><strong>Target:</strong> {{target}}<br><strong>Mulai:</strong> {{started}}<br><strong>Selesai:</strong> {{finished}}</p>
{% if header_score is not none %}<p><strong>Skor Header Keamanan:</strong> {{header_score}}%</p>{% endif %}
{% if risk is not none %}<p><strong>Risiko:</strong> {{risk}}%</p>{% endif %}
{% if recon %}
<h2>Recon</h2>
<ul>
  {% if recon.ip %}<li>IP: {{recon.ip}}</li>{% endif %}
  {% if recon.resp_ms %}<li>Waktu respon: {{recon.resp_ms}} ms</li>{% endif %}
  {% if recon.title %}<li>Title: {{recon.title}}</li>{% endif %}
  {% if recon.meta_generator %}<li>Generator: {{recon.meta_generator}}</li>{% endif %}
  {% if recon.waf_cdn %}<li>WAF/CDN: {{', '.join(recon.waf_cdn)}}</li>{% endif %}
</ul>
{% endif %}
<h2>Temuan</h2>
{% if findings %}
  <ul>
    {% for f in findings %}
      <li><strong>[{{f.category}}] {{f.severity}}</strong>
        <ul>
          <li>Judul: {{f.title}}</li>
          <li>Detail: {{f.detail}}</li>
          <li>URL: {{f.url or '-'}}</li>
          <li>Bukti: {{f.evidence or '-'}}</li>
        </ul>
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p>Tidak ada temuan berarti.</p>
{% endif %}
</body></html>"""

def save_report(report: Report, outdir: str, export_html: bool = False) -> Tuple[str, str, Optional[str]]:
    os.makedirs(outdir, exist_ok=True)
    md = render_md(report)
    md_path = os.path.join(outdir, "laporan.md")
    json_path = os.path.join(outdir, "laporan.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2, ensure_ascii=False)
    html_path = None
    if export_html:
        if Template is None:
            print("[!] jinja2 tidak terpasang; lewati export HTML")
        else:
            tmpl = Template(HTML_TEMPLATE)
            html = tmpl.render(
                target=report.target, started=report.started_at,
                finished=report.finished_at, recon=report.recon,
                findings=report.findings, header_score=report.header_score,
                risk=report.risk_percent
            )
            html_path = os.path.join(outdir, "laporan.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
    return md_path, json_path, html_path

def compute_risk_percent(findings: List[Finding]) -> int:
    if not findings:
        return 0
    total = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    percent = int(min(100, round(100 * total / (len(findings) * 5 + 1))))
    return percent

def print_report_terminal(report: Report):
    
    md_content = render_md(report)
    if Console and Markdown:
        console = Console()
        console.print(Markdown(md_content))
    else:
        print(md_content)

def summarize_attacks(findings: List[Finding]) -> List[str]:
    attacks: set[str] = set()
    for f in findings:
        cat = f.category.lower()
        title = (f.title or "").lower()
        if "sqli" in cat:
            attacks.add("SQL Injection")
        if "xss" in cat:
            attacks.add("Cross-Site Scripting (XSS)")
        if "lfi" in cat:
            attacks.add("Local File Inclusion (LFI)")
        if "cors" in cat:
            attacks.add("CORS misconfiguration")
        if "openredirect" in cat or "redirect" in title:
            attacks.add("Open Redirect")
        if "header" in cat:
            attacks.add("Missing Security Headers")
        if "port" in cat:
            attacks.add("Port exposure")
        if "ratelimit" in cat:
            attacks.add("Lack of rate limiting")
        if "cookie" in cat:
            attacks.add("Weak cookie flags")
        if "csrf" in cat:
            attacks.add("CSRF")
    return sorted(attacks)

# --------- Main ----------
def main():
    clear_screen()
    banner_anonymous()
    spooky_loading()

    if Console and Panel:
        banner = Panel.fit(
            "[bold green]WEB PENTEST TOOL (ALL ACTIVE)\n[/bold green][bold red]Tools by ghost_root[/bold red]",
            style="bold green"
        )
        Console().print(banner)

    ap = argparse.ArgumentParser(description="Web Pentest Tool - All active (deep)")
    ap.add_argument("--target", help="Target URL (contoh: https://example.com)")
    ap.add_argument("--confirm", action="store_true", help="Konfirmasi Anda memiliki izin pengujian")
    ap.add_argument("--out", default="pentest_output", help="Folder output laporan")
    ap.add_argument("--ports", default=None, help='Port list atau range, contoh: "1-1024,8080"')
    ap.add_argument("--threads", type=int, default=200, help="Jumlah threads (scan paralel)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout (detik)")
    ap.add_argument("--no-subdomain", action="store_true", help="Lewati pemindaian subdomain")
    ap.add_argument("--html", action="store_true", help="Export laporan HTML (butuh jinja2)")
    ap.add_argument("--boolean-sqli", action="store_true", help="Aktifkan boolean SQLi probes (default: aktif)")
    ap.add_argument("--time-sqli", action="store_true", help="Aktifkan time-based SQLi probes (default: aktif)")
    args = ap.parse_args()

    if not args.target:
        target = input(Fore.CYAN + "Masukkan target web (contoh: https://example.com): " + Style.RESET_ALL).strip()
    else:
        target = args.target.strip()

    if not target:
        print(Fore.RED + "[!] Target harus diisi.")
        sys.exit(1)
    if not target.startswith("http"):
        target = "http://" + target


    if not args.confirm:
        print(Fore.YELLOW + "[!] Pastikan Anda memiliki izin untuk menguji target ini.")
        yn = input(Fore.CYAN + "Ketik 'ya' untuk konfirmasi lalu lanjutkan, atau lainnya untuk batal: " + Style.RESET_ALL).strip().lower()
        if yn != "ya":
            print(Fore.YELLOW + "Dibatalkan.")
            sys.exit(1)

    access_granted()

    started = datetime.utcnow().isoformat() + "Z"
    findings: List[Finding] = []

    steps = [
        "Recon",
        "Subdomain",
        "Direktori & File",
        "Header Keamanan",
        "CORS",
        "Open Redirect",
        "SQL Injection",
        "XSS",
        "LFI",
        "Port Scan",
        "SSL/TLS",
        "Cookie Flags",
        "Rate Limit",
        "CSRF",
        "Generate Report"
    ]
    step_index = 0

    # Recon
    print(Fore.CYAN + "[*] Menjalankan recon...")
    recon = module_recon(target)
    print(Fore.MAGENTA + "    IP:", recon.ip or "-")
    if recon.title:
        print(Fore.MAGENTA + "    Title:", recon.title)
    if recon.resp_ms is not None:
        print(Fore.MAGENTA + "    Waktu respon (ms):", recon.resp_ms)
    if recon.waf_cdn:
        print(Fore.MAGENTA + "    WAF/CDN:", ", ".join(recon.waf_cdn))
    if recon.tech:
        print(Fore.MAGENTA + "    Teknologi (perkiraan):", ", ".join(recon.tech))
    step_progress(step_index, len(steps)); step_index += 1

    # Subdomain
    if not args.no_subdomain:
        print(Fore.CYAN + "[*] Memindai subdomain (wordlist kecil)...")
        if dns is None:
            print(Fore.YELLOW + "    [!] dnspython tidak terpasang; lewati subdomain")
        else:
            findings += module_subdomain(target, DEFAULT_SUBS)
    else:
        print(Fore.YELLOW + "    [!] Opsi --no-subdomain diaktifkan; lewati subdomain")
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memindai direktori & file sensitif...")
    findings += module_dirs(target, DEFAULT_DIRS + SENSITIVE_FILES, threads=args.threads, timeout=args.timeout)
    step_progress(step_index, len(steps)); step_index += 1

    # Header
    print(Fore.CYAN + "[*] Memeriksa header keamanan...")
    hdr_findings, header_score = module_headers(target)
    findings += hdr_findings

    if header_score >= 80:
        print(Fore.GREEN + f"    [+] Skor header: {header_score}% (Aman)")
    elif header_score >= 50:
        print(Fore.YELLOW + f"    [~] Skor header: {header_score}% (Perlu perhatian)")
    else:
        print(Fore.RED + f"    [!] Skor header: {header_score}% (Berbahaya)")
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memeriksa CORS...")
    findings += module_cors(target)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memeriksa open redirect...")
    findings += module_open_redirect(target)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Menguji SQL Injection (error/boolean/time-based)...")
    findings += module_sqli(
        target,
        timeout=args.timeout,
        boolean_probe=True,
        time_probe=True   
    )
    step_progress(step_index, len(steps)); step_index += 1

    # XSS
    print(Fore.CYAN + "[*] Menguji Reflected XSS...")
    findings += module_xss(target, timeout=args.timeout)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Menguji LFI...")
    findings += module_lfi(target, timeout=args.timeout)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memindai port (threaded)...")
    ports = parse_ports(args.ports)
    findings += module_portscan(get_domain(target), ports, threads=args.threads)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Mengambil info SSL/TLS...")
    findings += module_ssl(get_domain(target))
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memeriksa cookie flags...")
    findings += module_cookie_flags(target)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memeriksa rate limit sederhana...")
    findings += module_ratelimit(target)
    step_progress(step_index, len(steps)); step_index += 1


    print(Fore.CYAN + "[*] Memeriksa CSRF (form POST tanpa token)...")
    findings += module_csrf(target)
    step_progress(step_index, len(steps)); step_index += 1

    finished = datetime.utcnow().isoformat() + "Z"
    risk_percent = compute_risk_percent(findings)

    report = Report(
        started_at=started, finished_at=finished, target=target,
        recon=recon, findings=findings, header_score=header_score,
        risk_percent=risk_percent
    )

    outdir = os.path.join(args.out, re.sub(r"[^a-zA-Z0-9_.-]", "_", get_domain(target)))
    md_path, json_path, html_path = save_report(report, outdir, export_html=args.html)
    step_progress(step_index, len(steps)); step_index += 1

    # ======== Visual status akhir ========
    high_exists = any(f.severity.lower() == "high" for f in findings)
    if high_exists:
        breach_detected()

    print(Fore.GREEN + "\n[+] Laporan tersimpan:")
    print(Fore.GREEN + "    " + md_path)
    print(Fore.GREEN + "    " + json_path)
    if html_path:
        print(Fore.GREEN + "    " + html_path)

    print(Fore.CYAN + "\n========== LAPORAN (ringkasan) ==========")
    print_report_terminal(report)
    attacks = summarize_attacks(findings)
    if attacks:
        print(Fore.RED + "\n[!] Lemah terhadap serangan: " + ", ".join(attacks))
    else:
        print(Fore.GREEN + "\n[+] Tidak ditemukan kerentanan besar pada heuristik tool ini.")

if __name__ == "__main__":
    main()