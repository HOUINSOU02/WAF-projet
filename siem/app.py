from flask import Flask, render_template, jsonify, request, send_from_directory
import requests
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__, template_folder='templates', static_folder='static')

LOKI_URL   = os.getenv("LOKI_URL",   "http://loki:3100")
IA_URL     = os.getenv("IA_URL",     "http://ia-module:8000")
PROXY_URL  = os.getenv("PROXY_URL",  "http://waf-ia-proxy:9000")

# Utilisation d'une session pour réutiliser les connexions TCP
http_session = requests.Session()

# ─── Utilitaires ──────────────────────────────────────────────────────────────

PERIODS = {
    "15m":  timedelta(minutes=15),
    "30m":  timedelta(minutes=30),
    "1h":   timedelta(hours=1),
    "3h":   timedelta(hours=3),
    "6h":   timedelta(hours=6),
    "12h":  timedelta(hours=12),
    "24h":  timedelta(hours=24),
    "2d":   timedelta(days=2),
    "7d":   timedelta(days=7),
    "14d":  timedelta(days=14),
    "30d":  timedelta(days=30),
}

def get_time_range(period="24h"):
    """Retourne (start_ns, end_ns) selon la période choisie."""
    delta = PERIODS.get(period, timedelta(hours=24))
    start = int((datetime.now() - delta).timestamp() * 1e9)
    end   = int(datetime.now().timestamp() * 1e9)
    return start, end

def query_loki(query, period="24h", limit=500):
    start, end = get_time_range(period)
    try:
        resp = http_session.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={"query": query, "start": start, "end": end, "limit": limit},
            timeout=5
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"data": {"result": []}}

def get_blocked_requests(period="24h"):
    data = query_loki('{container="waf-project-bunkerweb-1"} |~ "403|429"', period=period)
    out = []
    for stream in data.get("data", {}).get("result", []):
        for ts, line in stream.get("values", []):
            out.append({"timestamp": ts, "line": line})
    return out

def feed_logs_to_ia(logs):
    """Envoie les logs bloqués au module IA pour enrichissement des stats."""
    for log in logs:
        info = parse_attack_log_quick(log["line"])
        if info["ip"] == "unknown":
            continue
        try:
            http_session.post(f"{IA_URL}/analyze", json={
                "ip":     info["ip"],
                "method": info["method"],
                "url":    info["url"],
                "headers": {},
                "body":   ""
            }, timeout=1)
        except Exception:
            pass

def parse_attack_log_quick(line):
    """Version rapide pour extract ip/method/url."""
    info = {"ip": "unknown", "method": "GET", "url": "/"}
    m = re.search(
        r'(?:[\w-]+\s+)?(\d+\.\d+\.\d+\.\d+)\s+-\s+\S+\s+-\s+\[[^\]]+\]\s+"(\w+)\s+([^\s"]+)',
        line
    )
    if m:
        info["ip"]     = m.group(1)
        info["method"] = m.group(2)
        info["url"]    = m.group(3)
    return info

def parse_attack_log(line):
    info = {
        "ip": "unknown", "method": "GET", "url": "/",
        "status": "403", "attack_type": "UNKNOWN",
        "timestamp": datetime.now().isoformat()
    }
    m = re.search(
        r'(?:[\w-]+\s+)?(\d+\.\d+\.\d+\.\d+)\s+-\s+\S+\s+-\s+\[[^\]]+\]\s+"(\w+)\s+([^\s"]+)\s+[^"]+"\s+(\d{3})',
        line
    )
    if m:
        info["ip"]     = m.group(1)
        info["method"] = m.group(2)
        info["url"]    = m.group(3)
        info["status"] = m.group(4)

    url  = info["url"].replace("+", " ").lower()
    full = line.lower()

    if info["status"] == "429":
        info["attack_type"] = "Rate-Limit"
    elif any(k in url for k in ["union", "select", "drop", "insert", "delete", "from", "where", " or ", " and "]):
        info["attack_type"] = "SQLi"
    elif any(k in url for k in ["script", "alert", "onerror", "javascript", "onclick"]):
        info["attack_type"] = "XSS"
    elif any(k in url for k in ["../", "..%2f", "passwd"]):
        info["attack_type"] = "LFI"
    elif any(k in url for k in ["shadow", ";cat", ";id", ";ls", "whoami", "cmd="]):
        info["attack_type"] = "RCE"
    elif any(k in url for k in ["169.254", "localhost", "127.0.0", "ssrf"]):
        info["attack_type"] = "SSRF"
    elif re.search(r'%[0-9a-f]{2}', url) and url.count('%') > 5:
        info["attack_type"] = "Zero-Day"
    elif "modsecurity" in full and "access denied" in full:
        info["attack_type"] = "ModSec-Block"

    return info

def geolocate_ip(ip):
    if ip.startswith(("10.", "192.168.", "127.", "172.")):
        return {"country": "Réseau local", "city": "Interne",
                "lat": 48.8566, "lon": 2.3522, "flag": "🏠"}
    try:
        r = http_session.get(
            f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,countryCode",
            timeout=3
        )
        d = r.json()
        if d.get("status") == "success":
            return {
                "country": d.get("country", "Inconnu"),
                "city":    d.get("city", "Inconnu"),
                "lat":     d.get("lat", 0),
                "lon":     d.get("lon", 0),
                "flag":    _flag(d.get("countryCode", ""))
            }
    except Exception:
        pass
    return {"country": "Inconnu", "city": "Inconnu", "lat": 0, "lon": 0, "flag": "🌐"}

def _flag(cc):
    if not cc or len(cc) != 2:
        return "🌐"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)

# ─── Parsing log générique pour l'explorateur ─────────────────────────────────

CONTAINERS = [
    "waf-project-bunkerweb-1",
    "waf-project-bw-scheduler-1",
    "waf-project-ia-module-1",
    "waf-project-promtail-1",
    "waf-project-loki-1",
    "waf-project-grafana-1",
    "waf-project-siem-1",
    "bwapp",
]

def parse_log_line(ts_ns, line, container):
    """Parse une ligne de log brute et retourne un dict enrichi."""
    ts_sec = int(ts_ns) // int(1e9)
    try:
        dt = datetime.fromtimestamp(ts_sec)
        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = "?"

    # Niveau de log
    level = "INFO"
    if re.search(r'\b(error|crit|emerg|alert)\b', line, re.I):
        level = "ERROR"
    elif re.search(r'\b(warn|warning)\b', line, re.I):
        level = "WARN"
    elif re.search(r'\b(notice|blocked|denied|403)\b', line, re.I):
        level = "NOTICE"

    # Type d'attaque / statut
    attack_type = ""
    if "403" in line:
        attack_type = "BLOCKED"
    elif "429" in line:
        attack_type = "RATE-LIMIT"
    elif "200" in line:
        attack_type = "200"
    if re.search(r'(UNION|SELECT)', line, re.I) and "403" in line:
        attack_type = "SQLi"
    elif re.search(r'(<script|onerror)', line, re.I) and "403" in line:
        attack_type = "XSS"
    elif re.search(r'(\.\./|passwd)', line, re.I) and "403" in line:
        attack_type = "LFI"

    return {
        "timestamp": timestamp,
        "ts_ns": ts_ns,
        "level": level,
        "attack_type": attack_type,
        "container": container,
        "line": line
    }

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/logs')
def logs_page():
    return render_template('logs.html')

# --- Stats globales avec période ---
@app.route('/api/stats')
def api_stats():
    period = request.args.get('period', '24h')
    logs   = get_blocked_requests(period)

    attack_types   = defaultdict(int)
    ips            = defaultdict(int)
    timeline       = defaultdict(int)
    parsed_attacks = []

    for log in logs:
        info = parse_attack_log(log["line"])
        attack_types[info["attack_type"]] += 1
        if info["ip"] != "unknown":
            ips[info["ip"]] += 1

        try:
            ts_sec   = int(log["timestamp"]) // int(1e9)
            dt       = datetime.fromtimestamp(ts_sec)
            hour_key = dt.strftime("%d/%m %H:00")
            timeline[hour_key] += 1
        except Exception:
            pass

        parsed_attacks.append(info)

    top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]

    # Envoie les logs au module IA pour alimenter ses stats
    feed_logs_to_ia(logs)

    ia_stats = {}
    try:
        r        = http_session.get(f"{IA_URL}/stats", timeout=3)
        raw      = r.json()
        ia_stats = {
            "total_blocked":  raw.get("total_blocked", 0),
            "total_requests": raw.get("total_requests", 0),
            "block_rate":     raw.get("block_rate", "0%"),
            "attack_types":   raw.get("attack_distribution", {})
        }
    except Exception:
        ia_stats = {"total_blocked": 0, "block_rate": "0%"}

    return jsonify({
        "period":         period,
        "total_blocked":  len(logs),
        "attack_types":   dict(attack_types),
        "top_ips":        top_ips,
        "timeline":       dict(sorted(timeline.items())),
        "ia_stats":       ia_stats,
        "recent_attacks": parsed_attacks[-20:][::-1]
    })

# --- Logs live (dernières 20 attaques) ---
@app.route('/api/live')
def api_live():
    period = request.args.get('period', '1h')
    data   = query_loki('{container="waf-project-bunkerweb-1"} |~ "403|429"',
                        period=period, limit=20)
    attacks = []
    for stream in data.get("data", {}).get("result", []):
        for ts, line in stream.get("values", [])[-10:]:
            info        = parse_attack_log(line)
            if info["ip"] == "unknown": continue  # Ignore les logs mal formés
            info["raw"] = line[:120]
            attacks.append(info)

    attacks.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(attacks[:10])

# --- Géo des top IPs ---
@app.route('/api/top_ips_geo')
def api_top_ips_geo():
    period = request.args.get('period', '24h')
    logs   = get_blocked_requests(period)
    ips    = defaultdict(int)

    for log in logs:
        info = parse_attack_log(log["line"])
        if info["ip"] != "unknown":
            ips[info["ip"]] += 1

    result = []
    for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        geo = geolocate_ip(ip)
        result.append({"ip": ip, "count": count, **geo})

    return jsonify(result)

# --- GeoIP d'une IP ---
@app.route('/api/geoip/<ip>')
def api_geoip(ip):
    return jsonify(geolocate_ip(ip))

# --- Explorateur de logs Loki ---
@app.route('/api/logs')
def api_logs():
    """
    Paramètres :
      container : nom du container (défaut : waf-project-bunkerweb-1)
      period    : fenêtre temporelle (défaut : 1h)
      search    : filtre texte libre (optionnel)
      limit     : nombre max de lignes (défaut : 200)
    """
    container = request.args.get('container', 'waf-project-bunkerweb-1')
    period    = request.args.get('period', '1h')
    search    = request.args.get('search', '').strip()
    limit     = int(request.args.get('limit', 200))

    # Construit la requête LogQL
    if search:
        # Échappe les guillemets dans la recherche
        safe_search = search.replace('"', '\\"')
        lql = f'{{container="{container}"}} |= "{safe_search}"'
    else:
        lql = f'{{container="{container}"}}'

    data = query_loki(lql, period=period, limit=limit)

    result = []
    for stream in data.get("data", {}).get("result", []):
        for ts_ns, line in stream.get("values", []):
            result.append(parse_log_line(ts_ns, line, container))

    # Tri antéchronologique
    result.sort(key=lambda x: x["ts_ns"], reverse=True)
    return jsonify(result[:limit])

# --- Liste des containers disponibles ---
@app.route('/api/containers')
def api_containers():
    return jsonify(CONTAINERS)

# --- Santé du SIEM ---
@app.route('/api/health')
def api_health():
    loki_ok = False
    ia_ok   = False
    try:
        http_session.get(f"{LOKI_URL}/ready", timeout=2)
        loki_ok = True
    except Exception:
        pass
    try:
        http_session.get(f"{PROXY_URL}/ia/health", timeout=2)
        ia_ok = True
    except Exception:
        try:
            http_session.get(f"{IA_URL}/health", timeout=2)
            ia_ok = True
        except Exception:
            pass
    return jsonify({
        "siem": True,
        "loki": loki_ok,
        "ia":   ia_ok,
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(host='10.89.1.50', port=5000, debug=False)
