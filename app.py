"""
SOC v16.0 — Ubuntu SIEM / HIDS для самохостинга
================================================
Источники данных:
  - /var/log/auth.log          (SSH bruteforce, sudo abuse)
  - /var/log/ufw.log           (fw deny events)
  - /var/log/nginx/access.log  (HTTP атаки)
  - ss -tun                    (connection flood)

Функции:
  - Автоблокировка через UFW при превышении порога угрозы
  - GeoIP через ip-api.com (без регистрации, с кешированием)
  - SQLite персистентность (данные сохраняются при перезапуске)
  - Исторические графики атак
  - Ручная блокировка/разблокировка IP через веб-интерфейс
  - Белый список IP
  - Статистика по типам атак
  - Экспорт логов в CSV
  - Rate limiting страницы входа
  - Интеграция с fail2ban

Установка: см. README.md
"""

import time
import threading
import subprocess
import re
import os
import hashlib
import sqlite3
import csv
import io
import requests
from collections import defaultdict, deque
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, redirect, session, jsonify, Response
from functools import wraps

# =========================
# КОНФИГУРАЦИЯ
# Все параметры берутся из переменных окружения.
# Скопируйте .env.example в .env и заполните значения.
# =========================
APP_PORT   = int(os.environ.get("SOC_PORT", "5050"))
APP_HOST   = os.environ.get("SOC_HOST", "0.0.0.0")
DB_PATH    = os.environ.get("SOC_DB_PATH", os.path.join(os.path.dirname(__file__), "soc.db"))

USERNAME = os.environ.get("SOC_USERNAME", "admin")

# Пароль задаётся как SHA-256 хэш в переменной SOC_PASSWORD_HASH.
# Сгенерировать: python3 -c "import hashlib; print(hashlib.sha256(b'ВАШ_ПАРОЛЬ').hexdigest())"
# По умолчанию пароль: changeme  (ОБЯЗАТЕЛЬНО смените перед использованием!)
_default_hash = hashlib.sha256(b"changeme").hexdigest()
PASSWORD_HASH = os.environ.get("SOC_PASSWORD_HASH", _default_hash)

# Порог очков угрозы для автоблокировки IP
AUTO_BLOCK_THRESHOLD = int(os.environ.get("SOC_BLOCK_THRESHOLD", "15"))

# Включить реальную блокировку через UFW (False = только логировать)
ENABLE_UFW_BLOCKING = os.environ.get("SOC_UFW_BLOCKING", "true").lower() == "true"

# Rate limiting страницы входа
LOGIN_MAX_ATTEMPTS = int(os.environ.get("SOC_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SEC   = int(os.environ.get("SOC_LOGIN_WINDOW_SEC", "600"))

# Белый список IP — никогда не блокировать (через запятую)
# Пример: SOC_WHITELIST="192.168.1.1,10.0.0.1"
_whitelist_env = os.environ.get("SOC_WHITELIST", "")
WHITELIST_EXTRA = {ip.strip() for ip in _whitelist_env.split(",") if ip.strip()}

# =========================
# FLASK
# =========================
app = Flask(__name__)
# Secret key для сессий — задайте случайную строку в переменной SOC_SECRET_KEY
app.secret_key = os.environ.get(
    "SOC_SECRET_KEY",
    hashlib.sha256(os.urandom(32)).hexdigest()
)

# =========================
# IN-MEMORY КЕШИ
# =========================
logs         = deque(maxlen=500)
events       = deque(maxlen=500)
threat_score = defaultdict(int)
blacklist    = set()
ufw_blocked  = set()
whitelist    = {"127.0.0.1", "::1"} | WHITELIST_EXTRA

geo_cache      = {}
login_attempts = defaultdict(list)
attack_stats   = defaultdict(int)
attack_history = deque(maxlen=288)  # 288 * 5мин = 24 часа
_history_counter   = 0
total_events_count = 0
total_logs_count   = 0

lock = threading.Lock()

# =========================
# БАЗА ДАННЫХ SQLite
# =========================
_db_lock = threading.Lock()
_db_con  = None

def db_connect():
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con

def get_db():
    global _db_con
    if _db_con is None:
        _db_con = db_connect()
    return _db_con

def db_execute(sql, params=()):
    """Потокобезопасное выполнение запроса на запись."""
    with _db_lock:
        try:
            get_db().execute(sql, params)
            get_db().commit()
        except sqlite3.OperationalError:
            global _db_con
            _db_con = None
            get_db().execute(sql, params)
            get_db().commit()

def db_init():
    with _db_lock:
        con = get_db()
        con.executescript("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            score INTEGER DEFAULT 0,
            ufw INTEGER DEFAULT 0,
            blocked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_scores (
            ip TEXT PRIMARY KEY,
            score INTEGER DEFAULT 0,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            added_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            event_type TEXT,
            ip TEXT,
            port TEXT,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS attack_history (
            ts TEXT PRIMARY KEY,
            count INTEGER
        );
        CREATE TABLE IF NOT EXISTS attack_stats (
            event_type TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS counters (
            key TEXT PRIMARY KEY,
            value INTEGER DEFAULT 0
        );
        INSERT OR IGNORE INTO counters(key, value) VALUES('total_events', 0);
        INSERT OR IGNORE INTO counters(key, value) VALUES('total_logs', 0);
        """)

def db_load_state():
    global threat_score, blacklist, ufw_blocked, whitelist, attack_stats
    global total_events_count, total_logs_count
    with _db_lock:
        con = get_db()
        for row in con.execute("SELECT ip, score FROM threat_scores"):
            threat_score[row[0]] = row[1]
        for row in con.execute("SELECT ip, ufw FROM blacklist"):
            blacklist.add(row[0])
            if row[1]:
                ufw_blocked.add(row[0])
        for row in con.execute("SELECT ip FROM whitelist"):
            whitelist.add(row[0])
        for row in con.execute("SELECT event_type, count FROM attack_stats"):
            attack_stats[row[0]] = row[1]
        for row in con.execute("SELECT ts, count FROM attack_history ORDER BY ts DESC LIMIT 288"):
            attack_history.appendleft({"ts": row[0], "count": row[1]})
        for row in con.execute("SELECT key, value FROM counters"):
            if row[0] == 'total_events':
                total_events_count = row[1]
            elif row[0] == 'total_logs':
                total_logs_count = row[1]

def db_save_threat(ip, score):
    db_execute("""
        INSERT INTO threat_scores(ip, score, last_seen) VALUES(?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET score=excluded.score, last_seen=excluded.last_seen
    """, (ip, score, datetime.now().isoformat()))

def db_save_block(ip, score, ufw_ok):
    db_execute("""
        INSERT INTO blacklist(ip, score, ufw, blocked_at) VALUES(?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET score=excluded.score, ufw=excluded.ufw
    """, (ip, score, 1 if ufw_ok else 0, datetime.now().isoformat()))

def db_delete_block(ip):
    db_execute("DELETE FROM blacklist WHERE ip=?", (ip,))

def db_save_whitelist(ip, add=True):
    if add:
        db_execute("INSERT OR IGNORE INTO whitelist(ip, added_at) VALUES(?, ?)",
                   (ip, datetime.now().isoformat()))
    else:
        db_execute("DELETE FROM whitelist WHERE ip=?", (ip,))

def db_save_event(event_type, ip, port, description):
    db_execute("""
        INSERT INTO events_log(ts, event_type, ip, port, description) VALUES(?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), event_type, ip, port or "", description[:300]))

def db_save_attack_stat(event_type):
    db_execute("""
        INSERT INTO attack_stats(event_type, count) VALUES(?, 1)
        ON CONFLICT(event_type) DO UPDATE SET count=count+1
    """, (event_type,))

def db_increment_counters(events_n, logs_n):
    if events_n:
        db_execute("UPDATE counters SET value=value+? WHERE key='total_events'", (events_n,))
    if logs_n:
        db_execute("UPDATE counters SET value=value+? WHERE key='total_logs'", (logs_n,))

def db_save_history_point(ts_str, count):
    db_execute("INSERT OR REPLACE INTO attack_history(ts, count) VALUES(?, ?)", (ts_str, count))

def db_export_events(hours=24):
    since = (datetime.now() - timedelta(hours=hours)).isoformat()
    with _db_lock:
        rows = get_db().execute("""
            SELECT ts, event_type, ip, port, description
            FROM events_log WHERE ts >= ? ORDER BY ts DESC
        """, (since,)).fetchall()
    return rows

# =========================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================
IP_REGEX   = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
PORT_REGEX = re.compile(r":(\d{2,5})\b")

def safe_run(cmd, timeout=3):
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return result.stdout
    except Exception as e:
        print(f"[safe_run ERROR] cmd={cmd} err={e}", flush=True)
        return ""

def is_private_ip(ip):
    prefixes = (
        "127.", "0.", "10.", "192.168.", "169.254.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    return any(ip.startswith(p) for p in prefixes)

def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def block_ip(ip):
    if not ENABLE_UFW_BLOCKING:
        return False
    if ip in ufw_blocked:
        return True
    result = subprocess.run(
        ["/usr/bin/sudo", "/usr/sbin/ufw", "deny", "from", ip, "to", "any"],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode == 0:
        ufw_blocked.add(ip)
        return True
    print(f"[ufw ERROR] block {ip}: {result.stderr}", flush=True)
    return False

def ts():
    return datetime.now().strftime("%H:%M:%S")

# =========================
# GEOIP (ip-api.com, с кешем)
# =========================
_geo_lock = threading.Lock()

def get_geo(ip):
    with _geo_lock:
        if ip in geo_cache:
            return geo_cache[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org",
            timeout=3
        )
        data = r.json()
        result = (
            f"{data.get('countryCode','?')} / {data.get('city','?')} / {data.get('isp','?')}"
            if data.get("status") == "success" else ""
        )
    except Exception:
        result = ""
    with _geo_lock:
        geo_cache[ip] = result
    return result

def get_geo_async(ip):
    threading.Thread(target=get_geo, args=(ip,), daemon=True).start()

# =========================
# FAIL2BAN ИНТЕГРАЦИЯ
# =========================
def get_fail2ban_status():
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/fail2ban-client", "status"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
    except Exception:
        return {"available": False}

    if not output or "Jail list" not in output:
        return {"available": False}

    jail_match = re.search(r"Jail list:\s*(.+)", output)
    if not jail_match:
        return {"available": False}

    jails = []
    total_banned = 0
    for jail in [j.strip() for j in jail_match.group(1).split(",") if j.strip()]:
        try:
            info = subprocess.run(
                ["/usr/bin/sudo", "/usr/bin/fail2ban-client", "status", jail],
                capture_output=True, text=True, timeout=5
            ).stdout
        except Exception:
            continue
        if not info:
            continue
        bm = re.search(r"Currently banned:\s*(\d+)", info)
        tm = re.search(r"Total banned:\s*(\d+)", info)
        banned_now   = int(bm.group(1)) if bm else 0
        banned_total = int(tm.group(1)) if tm else 0
        total_banned += banned_now
        jails.append({"name": jail, "banned_now": banned_now, "banned_total": banned_total})

    return {"available": True, "jails": jails, "total_banned": total_banned}

# =========================
# ПАРСЕРЫ ИСТОЧНИКОВ УГРОЗ
# =========================
def extract_port(line):
    m = re.search(r"DPT=(\d+)", line)
    if m:
        return m.group(1)
    m = re.search(r"(?::\d+\.\d+\.\d+\.\d+|localhost):(\d+)", line)
    return m.group(1) if m else None

def parse_auth_log():
    found = []
    log_file = "/var/log/auth.log"
    if not os.path.exists(log_file):
        return found
    try:
        output = safe_run(["tail", "-n", "200", log_file])
        for line in output.splitlines():
            ips = IP_REGEX.findall(line)
            if not ips:
                continue
            ip = ips[0]
            if not is_valid_ip(ip) or is_private_ip(ip):
                continue
            if "Failed password" in line:
                found.append((ip, "SSH_FAIL", 3, "22", line.strip()))
            elif "Invalid user" in line:
                found.append((ip, "SSH_INVALID_USER", 4, "22", line.strip()))
            elif "BREAK-IN ATTEMPT" in line:
                found.append((ip, "SSH_BREAKIN", 10, "22", line.strip()))
            elif "authentication failure" in line:
                found.append((ip, "AUTH_FAIL", 2, "22", line.strip()))
            elif "sudo" in line and "FAILED" in line:
                found.append((ip, "SUDO_FAIL", 5, None, line.strip()))
    except Exception:
        pass
    return found

def parse_ufw_log():
    found = []
    log_file = "/var/log/ufw.log"
    if not os.path.exists(log_file):
        return found
    try:
        output = safe_run(["tail", "-n", "100", log_file])
        for line in output.splitlines():
            if "[UFW BLOCK]" not in line:
                continue
            m = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue
            ip = m.group(1)
            if not is_valid_ip(ip) or is_private_ip(ip):
                continue
            found.append((ip, "UFW_BLOCK", 2, extract_port(line), line.strip()))
    except Exception:
        pass
    return found

def parse_nginx_log():
    found = []
    suspicious_patterns = [
        (r"\.\./",                                       "PATH_TRAVERSAL", 8),
        (r"(?:union|select|insert|drop|exec)\s",         "SQL_INJECTION",  9),
        (r"<script",                                     "XSS_ATTEMPT",    7),
        (r"(?:etc/passwd|etc/shadow|proc/self)",         "LFI_ATTEMPT",    9),
        (r"(?:\.php\?|\.asp\?|\.jsp\?).{0,50}(?:=http|=//)", "RFI_ATTEMPT", 9),
        (r'" 4[0-9]{2} ',                                "HTTP_ERROR",     1),
        (r'" 5[0-9]{2} ',                                "HTTP_5XX",       2),
    ]
    for log_file in ["/var/log/nginx/access.log", "/var/log/apache2/access.log"]:
        if not os.path.exists(log_file):
            continue
        try:
            output = safe_run(["tail", "-n", "100", log_file])
            for line in output.splitlines():
                ips = IP_REGEX.findall(line)
                if not ips:
                    continue
                ip = ips[0]
                if not is_valid_ip(ip) or is_private_ip(ip):
                    continue
                port_m = re.search(r'"[A-Z]+ [^ ]+ HTTP[^"]*" \d+ \d+.*:(\d+)', line)
                port = port_m.group(1) if port_m else "80"
                for pattern, event_type, severity in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        found.append((ip, event_type, severity, port, line.strip()[:200]))
                        break
        except Exception:
            pass
    return found

def parse_active_connections():
    found = []
    try:
        output = safe_run(["ss", "-tun"])
        conn_count = defaultdict(int)
        conn_ports = defaultdict(set)
        for line in output.splitlines():
            ips = IP_REGEX.findall(line)
            if len(ips) < 2:
                continue
            remote_ip = ips[-2]
            if is_valid_ip(remote_ip) and not is_private_ip(remote_ip):
                conn_count[remote_ip] += 1
                ports = PORT_REGEX.findall(line)
                if ports:
                    conn_ports[remote_ip].add(ports[0])
        for ip, count in conn_count.items():
            if count >= 10:
                ports_str = ",".join(sorted(conn_ports[ip]))
                found.append((ip, "CONN_FLOOD", count // 5, ports_str or None,
                              f"Активных соединений: {count}, порты: {ports_str}"))
    except Exception:
        pass
    return found

# =========================
# ГЛАВНЫЙ ДВИЖОК SIEM
# =========================
_seen_lines = deque(maxlen=2000)

def collector():
    global _history_counter, total_events_count, total_logs_count
    last_history_save = time.time()

    while True:
        all_events = []
        all_events.extend(parse_auth_log())
        all_events.extend(parse_ufw_log())
        all_events.extend(parse_nginx_log())
        all_events.extend(parse_active_connections())

        new_attacks = 0
        _pending_db_saves = []

        with lock:
            for ip, event_type, severity, port, raw_line in all_events:
                line_hash = hash(raw_line)
                if line_hash in _seen_lines:
                    continue
                _seen_lines.append(line_hash)

                if ip in whitelist:
                    continue

                threat_score[ip] += severity
                attack_stats[event_type] += 1
                new_attacks += 1

                if ip not in geo_cache:
                    get_geo_async(ip)

                geo = geo_cache.get(ip, "")
                geo_str = f" [{geo}]" if geo else ""

                logs.append(
                    f"[{ts()}] {event_type} | {ip}{geo_str}"
                    + (f":{port}" if port else "")
                    + f" | {raw_line[:120]}"
                )
                total_logs_count += 1

                events.append(
                    f"[{ts()}] [{event_type}] {ip}{geo_str}"
                    + (f" порт:{port}" if port else "")
                    + f" +{severity}пт"
                )
                total_events_count += 1

                _pending_db_saves.append((event_type, ip, port, raw_line, threat_score[ip]))

                if threat_score[ip] >= AUTO_BLOCK_THRESHOLD and ip not in blacklist:
                    blacklist.add(ip)
                    blocked_ok = block_ip(ip)
                    status = "UFW_ЗАБЛОКИРОВАН" if blocked_ok else "ТОЛЬКО_ЛОГ"
                    events.append(
                        f"[{ts()}] 🚫 АВТОБЛОК [{status}] {ip}{geo_str} "
                        f"(счёт={threat_score[ip]})"
                    )
                    _pending_db_saves.append(("__block__", ip, None, None, threat_score[ip], blocked_ok))

            _history_counter += new_attacks

        for item in _pending_db_saves:
            try:
                if item[0] == "__block__":
                    _, ip, _, _, score, ufw_ok = item
                    db_save_block(ip, score, ufw_ok)
                else:
                    event_type, ip, port, raw_line, score = item
                    db_save_threat(ip, score)
                    db_save_event(event_type, ip, port, raw_line)
                    db_save_attack_stat(event_type)
            except Exception:
                pass
        if _pending_db_saves:
            n = sum(1 for x in _pending_db_saves if x[0] != "__block__")
            db_increment_counters(n, n)

        now = time.time()
        if now - last_history_save >= 300:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M")
            with lock:
                count = _history_counter
                _history_counter = 0
                attack_history.append({"ts": ts_str, "count": count})
            try:
                db_save_history_point(ts_str, count)
            except Exception:
                pass
            last_history_save = now

        time.sleep(5)

def load_existing_ufw_blocks():
    output = safe_run(["/usr/bin/sudo", "/usr/sbin/ufw", "status", "numbered"])
    ips = IP_REGEX.findall(output)
    with lock:
        for ip in ips:
            if is_valid_ip(ip) and not is_private_ip(ip):
                ufw_blocked.add(ip)

# =========================
# RATE LIMITING ЛОГИНА
# =========================
def check_login_rate(ip):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < LOGIN_WINDOW_SEC]
    if len(login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS:
        return False
    login_attempts[ip].append(now)
    return True

def get_login_wait(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    if not attempts:
        return 0
    return max(0, int(LOGIN_WINDOW_SEC - (now - min(attempts))))

# =========================
# AUTH DECORATOR
# =========================
def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

# =========================
# HTML ИНТЕРФЕЙС
# =========================
HTML = r"""
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC v16.0 | Панель мониторинга</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:     #080c10;
  --panel:  #0d1520;
  --border: #1a2d45;
  --accent: #00d4ff;
  --danger: #ff3c5c;
  --warn:   #ffaa00;
  --ok:     #00ff99;
  --text:   #c8dff0;
  --muted:  #4a6a8a;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 12px; min-height: 100vh; }

.topbar { display:flex; align-items:center; justify-content:space-between; padding:10px 20px; background:var(--panel); border-bottom:1px solid var(--border); position:sticky; top:0; z-index:100; }
.topbar .logo { font-family:'Rajdhani',sans-serif; font-size:20px; font-weight:700; color:var(--accent); letter-spacing:2px; }
.topbar .status { display:flex; gap:20px; align-items:center; }
.dot { width:8px; height:8px; border-radius:50%; background:var(--ok); animation:pulse 2s infinite; display:inline-block; margin-right:5px; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.topbar a { color:var(--muted); text-decoration:none; font-size:11px; }
.topbar a:hover { color:var(--danger); }

.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:1px; background:var(--border); border-bottom:1px solid var(--border); }
.stat { background:var(--panel); padding:12px 16px; text-align:center; }
.stat .val { font-family:'Rajdhani',sans-serif; font-size:28px; font-weight:700; line-height:1; }
.stat .lbl { color:var(--muted); font-size:10px; margin-top:3px; letter-spacing:1px; }
.stat.danger .val { color:var(--danger); }
.stat.warn .val   { color:var(--warn); }
.stat.ok .val     { color:var(--ok); }
.stat.info .val   { color:var(--accent); }

.tabs { display:flex; gap:0; background:var(--panel); border-bottom:1px solid var(--border); }
.tab { padding:10px 20px; cursor:pointer; color:var(--muted); font-size:12px; border-bottom:2px solid transparent; transition:all .2s; user-select:none; }
.tab:hover { color:var(--text); }
.tab.active { color:var(--accent); border-bottom-color:var(--accent); }

.page { display:none; padding:10px; }
.page.active { display:block; }

.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.card { background:var(--panel); padding:14px; border-radius:4px; border:1px solid var(--border); }
.card h3 { font-family:'Rajdhani',sans-serif; font-size:13px; font-weight:700; letter-spacing:2px; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:8px; margin-bottom:10px; text-transform:uppercase; }

.scroll { max-height:300px; overflow-y:auto; }
.scroll::-webkit-scrollbar { width:4px; }
.scroll::-webkit-scrollbar-thumb { background:var(--border); }

.threat-row { display:flex; justify-content:space-between; align-items:center; padding:4px 6px; border-bottom:1px solid var(--border); gap:8px; }
.threat-ip { color:var(--text); font-size:11px; min-width:100px; }
.threat-geo { color:var(--muted); font-size:10px; flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.bar { height:3px; background:var(--border); width:60px; border-radius:2px; overflow:hidden; flex-shrink:0; }
.bar-fill { height:100%; border-radius:2px; transition:width .5s; }
.threat-score { font-family:'Rajdhani',sans-serif; font-size:15px; font-weight:700; min-width:35px; text-align:right; }
.score-low  { color:var(--warn); }
.score-mid  { color:#ff7700; }
.score-high { color:var(--danger); }

table { width:100%; border-collapse:collapse; }
td, th { padding:5px 8px; border-bottom:1px solid var(--border); text-align:left; font-size:11px; }
th { color:var(--muted); font-size:10px; letter-spacing:1px; }
.bl-ip { color:var(--danger); }
.bl-geo { color:var(--muted); font-size:10px; }
.bl-score { color:var(--warn); text-align:right; }
.bl-badge { background:var(--danger); color:#fff; font-size:9px; padding:1px 4px; border-radius:2px; font-weight:700; }

.event-line { padding:3px 0; border-bottom:1px solid rgba(26,45,69,.5); word-break:break-all; line-height:1.5; }
.event-line.block { color:var(--danger); font-weight:700; }
.event-line.ssh   { color:var(--warn); }
.event-line.http  { color:#aa88ff; }
.event-line.ufw   { color:var(--muted); }
.event-line.conn  { color:var(--ok); }

.btn { background:none; border:1px solid var(--border); color:var(--text); font-family:'JetBrains Mono',monospace; font-size:11px; padding:4px 10px; cursor:pointer; border-radius:2px; transition:all .2s; }
.btn:hover { border-color:var(--accent); color:var(--accent); }
.btn.danger { border-color:var(--danger); color:var(--danger); }
.btn.danger:hover { background:var(--danger); color:#fff; }
.btn.ok { border-color:var(--ok); color:var(--ok); }
.btn.ok:hover { background:var(--ok); color:#080c10; }

.input-row { display:flex; gap:8px; margin-bottom:10px; }
input.ifield { flex:1; padding:6px 10px; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:'JetBrains Mono',monospace; font-size:12px; border-radius:2px; }
input.ifield:focus { outline:none; border-color:var(--accent); }

canvas { width:100%; max-height:160px; }

.pie-container { display:flex; gap:20px; align-items:center; flex-wrap:wrap; }
.pie-legend { display:flex; flex-direction:column; gap:5px; }
.pie-item { display:flex; align-items:center; gap:6px; font-size:11px; }
.pie-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }

.f2b-jail { display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border); font-size:11px; }
.f2b-name { color:var(--accent); }
.f2b-num  { color:var(--warn); }

@media (max-width:900px) {
  .grid2 { grid-template-columns:1fr; }
  .stats { grid-template-columns:repeat(3,1fr); }
}
</style>

<script>
let maxScore = 1;
const PIE_COLORS = ['#ff3c5c','#ffaa00','#00d4ff','#aa88ff','#00ff99','#ff7700','#4488ff','#ff44aa'];

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function scoreClass(s) { return s < 20 ? 'score-low' : s < 50 ? 'score-mid' : 'score-high'; }
function eventClass(line) {
  if (line.includes('АВТОБЛОК') || line.includes('UFW_BLOCK')) return 'block';
  if (line.includes('SSH')) return 'ssh';
  if (line.includes('HTTP') || line.includes('XSS') || line.includes('SQL') || line.includes('LFI')) return 'http';
  if (line.includes('UFW')) return 'ufw';
  if (line.includes('CONN')) return 'conn';
  return '';
}
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
}

async function blockIp() {
  const ip = document.getElementById('block-input').value.trim();
  if (!ip) return;
  const r = await fetch('/api/block', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip})});
  const d = await r.json();
  if (d.ok) { document.getElementById('block-input').value = ''; load(); }
  else alert('Ошибка: ' + (d.error || 'неизвестно'));
}

async function unblockIp(ip) {
  if (!confirm('Разблокировать ' + ip + '?')) return;
  await fetch('/api/unblock', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip})});
  load();
}

async function addWhitelist() {
  const ip = document.getElementById('wl-input').value.trim();
  if (!ip) return;
  const r = await fetch('/api/whitelist', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip, action:'add'})});
  const d = await r.json();
  if (d.ok) { document.getElementById('wl-input').value = ''; load(); }
  else alert('Ошибка: ' + (d.error || ''));
}

async function removeWhitelist(ip) {
  if (!confirm('Удалить ' + ip + ' из белого списка?')) return;
  await fetch('/api/whitelist', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip, action:'remove'})});
  load();
}

function drawChart(history) {
  const canvas = document.getElementById('chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth || 600;
  const H = 140;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);
  if (!history || history.length < 2) {
    ctx.fillStyle = '#4a6a8a'; ctx.font = '12px JetBrains Mono';
    ctx.fillText('Недостаточно данных', 20, H/2); return;
  }
  const maxVal = Math.max(...history.map(h => h.count), 1);
  const pad = {top:10, right:10, bottom:30, left:35};
  const cW = W - pad.left - pad.right, cH = H - pad.top - pad.bottom;
  const step = cW / (history.length - 1);
  ctx.strokeStyle = '#1a2d45'; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (cH/4) * i;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left+cW, y); ctx.stroke();
    ctx.fillStyle = '#4a6a8a'; ctx.font = '10px JetBrains Mono';
    ctx.fillText(Math.round(maxVal - (maxVal/4)*i), 2, y+4);
  }
  ctx.beginPath(); ctx.strokeStyle = '#00d4ff'; ctx.lineWidth = 2;
  history.forEach((h, i) => {
    const x = pad.left + i*step, y = pad.top + cH - (h.count/maxVal)*cH;
    i === 0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
  });
  ctx.stroke();
  ctx.lineTo(pad.left+(history.length-1)*step, pad.top+cH);
  ctx.lineTo(pad.left, pad.top+cH); ctx.closePath();
  const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top+cH);
  grad.addColorStop(0,'rgba(0,212,255,0.3)'); grad.addColorStop(1,'rgba(0,212,255,0)');
  ctx.fillStyle = grad; ctx.fill();
  ctx.fillStyle = '#4a6a8a'; ctx.font = '9px JetBrains Mono';
  const sl = Math.max(1, Math.floor(history.length/6));
  history.forEach((h,i) => { if(i%sl===0) ctx.fillText(h.ts.slice(11), pad.left+i*step-12, H-5); });
}

function drawPie(stats) {
  const canvas = document.getElementById('pie');
  if (!canvas) return;
  const entries = Object.entries(stats).sort((a,b)=>b[1]-a[1]).slice(0,8);
  if (!entries.length) return;
  const total = entries.reduce((s,e)=>s+e[1],0);
  const size = 120; canvas.width = size; canvas.height = size;
  const ctx = canvas.getContext('2d');
  const cx = size/2, cy = size/2, r = size/2-5;
  let angle = -Math.PI/2;
  entries.forEach(([,count],i) => {
    const slice = (count/total)*2*Math.PI;
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,angle,angle+slice);
    ctx.closePath(); ctx.fillStyle = PIE_COLORS[i%PIE_COLORS.length]; ctx.fill();
    angle += slice;
  });
  document.getElementById('pie-legend').innerHTML = entries.map(([type,count],i) =>
    `<div class="pie-item"><div class="pie-dot" style="background:${PIE_COLORS[i%PIE_COLORS.length]}"></div><span>${esc(type)}: <b>${count}</b></span></div>`
  ).join('');
}

async function load() {
  try {
    const r = await fetch('/api');
    const d = await r.json();
    const scores = Object.values(d.threat);
    maxScore = Math.max(maxScore, ...scores, 1);
    document.getElementById('stat-threats').textContent = scores.length;
    document.getElementById('stat-blocked').textContent = d.blacklist.length;
    document.getElementById('stat-events').textContent  = d.event_count;
    document.getElementById('stat-logs').textContent    = d.log_count;
    document.getElementById('stat-f2b').textContent     = d.f2b_banned != null ? d.f2b_banned : '—';
    const sorted = Object.entries(d.threat).sort((a,b)=>b[1]-a[1]).slice(0,40);
    document.getElementById('threat').innerHTML = sorted.map(([ip,sc]) => {
      const pct = Math.min(100, Math.round(sc/maxScore*100));
      const geo = d.geo[ip] || '';
      return `<div class="threat-row"><span class="threat-ip">${esc(ip)}</span><span class="threat-geo">${esc(geo)}</span><div class="bar"><div class="bar-fill" style="width:${pct}%;background:${sc>=50?'#ff3c5c':sc>=20?'#ff7700':'#ffaa00'}"></div></div><span class="threat-score ${scoreClass(sc)}">${sc}</span></div>`;
    }).join('') || '<div style="color:var(--muted);padding:8px">Нет угроз</div>';
    document.getElementById('blacklist').innerHTML =
      '<tr><th>IP-адрес</th><th>Геолокация</th><th>Счёт</th><th>UFW</th><th></th></tr>' +
      d.blacklist.map(({ip,score,ufw}) =>
        `<tr><td class="bl-ip">${esc(ip)}</td><td class="bl-geo">${esc(d.geo[ip]||'')}</td><td class="bl-score">${score||'—'}</td><td>${ufw?'<span class="bl-badge">UFW</span>':'<span style="color:var(--muted)">лог</span>'}</td><td><button class="btn danger" onclick="unblockIp('${esc(ip)}')">разблок.</button></td></tr>`
      ).join('') || '<tr><td colspan="5" style="color:var(--muted)">Нет заблокированных</td></tr>';
    document.getElementById('events').innerHTML =
      d.events.slice(-60).reverse().map(e=>`<div class="event-line ${eventClass(e)}">${esc(e)}</div>`).join('');
    document.getElementById('logs').innerHTML =
      d.logs.slice(-40).reverse().map(l=>`<div class="event-line">${esc(l)}</div>`).join('');
    document.getElementById('whitelist-table').innerHTML =
      '<tr><th>IP-адрес</th><th></th></tr>' +
      d.whitelist.map(ip=>`<tr><td>${esc(ip)}</td><td><button class="btn danger" onclick="removeWhitelist('${esc(ip)}')">удалить</button></td></tr>`).join('') ||
      '<tr><td colspan="2" style="color:var(--muted)">Список пуст</td></tr>';
    if (d.f2b && d.f2b.available) {
      document.getElementById('f2b-status').innerHTML =
        d.f2b.jails.map(j=>`<div class="f2b-jail"><span class="f2b-name">${esc(j.name)}</span><span>сейчас: <span class="f2b-num">${j.banned_now}</span></span><span>всего: <span class="f2b-num">${j.banned_total}</span></span></div>`).join('') ||
        '<div style="color:var(--muted)">Нет активных jail</div>';
    } else {
      document.getElementById('f2b-status').innerHTML = '<div style="color:var(--muted)">fail2ban не установлен или недоступен</div>';
    }
    drawChart(d.history);
    drawPie(d.attack_stats);
  } catch(e) { console.error('API error:', e); }
}
setInterval(load, 5000);
</script>
</head>
<body onload="load()">
<div class="topbar">
  <div class="logo">⬡ SOC v16.0 SIEM</div>
  <div class="status">
    <span><span class="dot"></span>В СЕТИ</span>
    <span id="clock" style="color:var(--muted)"></span>
    <a href="/logout">[ выход ]</a>
  </div>
</div>
<div class="stats">
  <div class="stat warn"><div class="val" id="stat-threats">—</div><div class="lbl">АКТИВНЫЕ УГРОЗЫ</div></div>
  <div class="stat danger"><div class="val" id="stat-blocked">—</div><div class="lbl">ЗАБЛОКИРОВАНО IP</div></div>
  <div class="stat info"><div class="val" id="stat-events">—</div><div class="lbl">СОБЫТИЙ ВСЕГО</div></div>
  <div class="stat ok"><div class="val" id="stat-logs">—</div><div class="lbl">ЗАПИСЕЙ В ЖУРНАЛЕ</div></div>
  <div class="stat warn"><div class="val" id="stat-f2b">—</div><div class="lbl">FAIL2BAN БАНОВ</div></div>
</div>
<div class="tabs">
  <div class="tab active" data-tab="main"    onclick="showTab('main')">📊 Обзор</div>
  <div class="tab"        data-tab="threats" onclick="showTab('threats')">🎯 Угрозы</div>
  <div class="tab"        data-tab="logs"    onclick="showTab('logs')">📜 Журнал</div>
  <div class="tab"        data-tab="manage"  onclick="showTab('manage')">⚙️ Управление</div>
</div>
<div class="page active" id="page-main">
  <div class="grid2" style="margin-bottom:10px">
    <div class="card"><h3>📈 История атак (24ч)</h3><canvas id="chart"></canvas></div>
    <div class="card"><h3>🥧 Типы атак</h3><div class="pie-container"><canvas id="pie" style="width:120px;height:120px;flex-shrink:0"></canvas><div class="pie-legend" id="pie-legend"></div></div></div>
  </div>
  <div class="grid2">
    <div class="card"><h3>⚡ Последние события</h3><div class="scroll" id="events"></div></div>
    <div class="card"><h3>🛡️ fail2ban</h3><div id="f2b-status"></div></div>
  </div>
</div>
<div class="page" id="page-threats">
  <div class="grid2">
    <div class="card"><h3>🎯 Оценка угроз</h3><div class="scroll" id="threat"></div></div>
    <div class="card"><h3>🚫 Чёрный список</h3><div class="scroll"><table id="blacklist"></table></div></div>
  </div>
</div>
<div class="page" id="page-logs">
  <div class="card" style="margin-bottom:10px">
    <h3>📜 Журнал событий</h3>
    <div style="margin-bottom:8px">
      <a href="/api/export?hours=24" class="btn">⬇ Экспорт CSV (24ч)</a>
      <a href="/api/export?hours=168" class="btn" style="margin-left:8px">⬇ Экспорт CSV (7 дней)</a>
    </div>
    <div class="scroll" id="logs"></div>
  </div>
</div>
<div class="page" id="page-manage">
  <div class="grid2">
    <div class="card">
      <h3>🔒 Заблокировать IP вручную</h3>
      <div class="input-row">
        <input class="ifield" id="block-input" placeholder="Введите IP-адрес" type="text">
        <button class="btn danger" onclick="blockIp()">Заблокировать</button>
      </div>
      <div style="color:var(--muted);font-size:11px">Немедленно добавит правило в UFW</div>
    </div>
    <div class="card">
      <h3>✅ Белый список</h3>
      <div class="input-row">
        <input class="ifield" id="wl-input" placeholder="Добавить IP в белый список" type="text">
        <button class="btn ok" onclick="addWhitelist()">Добавить</button>
      </div>
      <div class="scroll"><table id="whitelist-table"></table></div>
    </div>
  </div>
</div>
<script>setInterval(()=>{ document.getElementById('clock').textContent=new Date().toLocaleTimeString('ru-RU'); },1000);</script>
</body>
</html>
"""

LOGIN = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SOC — Вход</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
body{background:#080c10;color:#c8dff0;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
.box{background:#0d1520;border:1px solid #1a2d45;padding:40px;width:320px;border-radius:4px;}
h2{color:#00d4ff;font-size:18px;letter-spacing:3px;margin-bottom:24px;}
input{width:100%;padding:10px;margin-bottom:12px;background:#080c10;border:1px solid #1a2d45;color:#c8dff0;font-family:'JetBrains Mono',monospace;font-size:13px;border-radius:2px;}
input:focus{outline:none;border-color:#00d4ff;}
button{width:100%;padding:10px;background:#00d4ff;color:#080c10;border:none;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:13px;letter-spacing:2px;cursor:pointer;border-radius:2px;}
button:hover{background:#00aacc;}
.err{color:#ff3c5c;margin-top:10px;font-size:12px;}
.warn{color:#ffaa00;margin-top:10px;font-size:12px;}
</style>
</head>
<body>
<div class="box">
  <h2>⬡ ВХОД В СИСТЕМУ</h2>
  <form method="post">
    <input name="user" placeholder="логин" autocomplete="off" required>
    <input name="pass" type="password" placeholder="пароль" required>
    <button type="submit">ВОЙТИ</button>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    {% if locked %}<div class="warn">Слишком много попыток. Подождите {{ wait }}с.</div>{% endif %}
  </form>
</div>
</body>
</html>
"""

# =========================
# РОУТЫ
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None; locked = False; wait = 0
    client_ip = request.remote_addr or "unknown"
    if request.method == "POST":
        if not check_login_rate(client_ip):
            locked = True; wait = get_login_wait(client_ip)
        else:
            user = request.form.get("user", "")
            pwd  = request.form.get("pass", "")
            if user == USERNAME and hashlib.sha256(pwd.encode()).hexdigest() == PASSWORD_HASH:
                session["auth"] = True
                login_attempts.pop(client_ip, None)
                return redirect("/")
            error = "Неверный логин или пароль"
            time.sleep(1)
    return render_template_string(LOGIN, error=error, locked=locked, wait=wait)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@auth_required
def index():
    return render_template_string(HTML)

@app.route("/api")
@auth_required
def api():
    f2b = get_fail2ban_status()
    with lock:
        blacklist_data = [
            {"ip": ip, "score": threat_score.get(ip, 0), "ufw": ip in ufw_blocked}
            for ip in sorted(blacklist, key=lambda x: threat_score.get(x, 0), reverse=True)
        ]
        f2b_banned = f2b.get("total_banned") if f2b and f2b.get("available") else None
        return jsonify({
            "threat":       dict(sorted(threat_score.items(), key=lambda x: x[1], reverse=True)),
            "blacklist":    blacklist_data,
            "events":       list(events),
            "logs":         list(logs),
            "event_count":  total_events_count,
            "log_count":    total_logs_count,
            "whitelist":    sorted(whitelist),
            "geo":          dict(geo_cache),
            "attack_stats": dict(attack_stats),
            "history":      list(attack_history),
            "f2b":          f2b,
            "f2b_banned":   f2b_banned,
        })

@app.route("/api/unblock", methods=["POST"])
@auth_required
def api_unblock():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "Неверный IP"}), 400
    with lock:
        blacklist.discard(ip)
        if ip in ufw_blocked:
            safe_run(["/usr/bin/sudo", "/usr/sbin/ufw", "delete", "deny", "from", ip, "to", "any"])
            ufw_blocked.discard(ip)
        events.append(f"[{ts()}] РУЧНАЯ_РАЗБЛОКИРОВКА {ip}")
    db_delete_block(ip)
    return jsonify({"ok": True})

@app.route("/api/block", methods=["POST"])
@auth_required
def api_block_manual():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "Неверный IP"}), 400
    if ip in whitelist:
        return jsonify({"ok": False, "error": "IP в белом списке"}), 400
    with lock:
        blacklist.add(ip)
        blocked_ok = block_ip(ip)
        events.append(f"[{ts()}] РУЧНАЯ_БЛОКИРОВКА {ip} (ufw={blocked_ok})")
    db_save_block(ip, threat_score.get(ip, 0), blocked_ok)
    return jsonify({"ok": True, "ufw": blocked_ok})

@app.route("/api/whitelist", methods=["POST"])
@auth_required
def api_whitelist():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    action = data.get("action", "add")
    if not ip or not is_valid_ip(ip):
        return jsonify({"ok": False, "error": "Неверный IP"}), 400
    with lock:
        if action == "add":
            whitelist.add(ip); events.append(f"[{ts()}] БЕЛЫЙ_СПИСОК_ДОБАВЛЕН {ip}")
        else:
            whitelist.discard(ip); events.append(f"[{ts()}] БЕЛЫЙ_СПИСОК_УДАЛЁН {ip}")
    db_save_whitelist(ip, action == "add")
    return jsonify({"ok": True})

@app.route("/api/export")
@auth_required
def api_export():
    hours = int(request.args.get("hours", 24))
    rows  = db_export_events(hours)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Дата/время", "Тип события", "IP", "Порт", "Описание"])
    writer.writerows(rows)
    filename = f"soc_events_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# =========================
# СТАРТ
# =========================
if __name__ == "__main__":
    print("[SOC v16.0] Запуск...")
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    db_init()
    print(f"[SOC] База данных: {DB_PATH}")
    db_load_state()
    print(f"[SOC] Загружено из БД: угроз={len(threat_score)}, заблокировано={len(blacklist)}, белый список={len(whitelist)}")
    load_existing_ufw_blocks()
    print(f"[SOC] UFW правил загружено: {len(ufw_blocked)}")
    print(f"[SOC] Хост: {APP_HOST}:{APP_PORT}")
    print(f"[SOC] UFW блокировка: {'ВКЛЮЧЕНА' if ENABLE_UFW_BLOCKING else 'ВЫКЛЮЧЕНА'}")
    print(f"[SOC] Порог автоблокировки: {AUTO_BLOCK_THRESHOLD} очков")
    t = threading.Thread(target=collector, daemon=True)
    t.start()
    print("[SOC] Коллектор событий запущен")
    print(f"[SOC] Дашборд: http://{APP_HOST}:{APP_PORT}")
    app.run(host=APP_HOST, port=APP_PORT, debug=False)
