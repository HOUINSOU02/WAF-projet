"""
Proxy WAF-IA — s'intercale entre BunkerWeb et bWAPP
Chaque requête est analysée par le module IA avant d'être transmise.
Si score >= 25 → 403 bloqué
Sinon         → forwarded vers bWAPP
"""

from flask import Flask, request, Response, jsonify
import requests
import os
import logging
import json
from datetime import datetime

app = Flask(__name__)

IA_URL    = os.getenv("IA_URL", "http://ia-module:8000")
BWAPP_URL = os.getenv("BWAPP_URL", "http://bwapp:80")

# Stats en mémoire
stats = {
    "total_requests": 0,
    "total_blocked":  0,
    "total_allowed":  0,
    "attack_types":   {},
    "recent_blocks":  []   # dernières 100 attaques bloquées
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [PROXY-IA] %(levelname)s %(message)s'
)
log = logging.getLogger(__name__)


def analyze(ip, method, url, headers, body):
    """Appelle le module IA et retourne le résultat."""
    try:
        r = requests.post(f"{IA_URL}/analyze", json={
            "ip":      ip,
            "method":  method,
            "url":     url,
            "headers": dict(headers),
            "body":    body
        }, timeout=2)
        res = r.json()
        log.info(f"IA Result: score={res.get('anomaly_score')} blocked={res.get('blocked')} for {url}")
        return res
    except Exception as e:
        log.error(f"CRITICAL: Module IA injoignable à {IA_URL}. Error: {e}")
        return None


def record_block(ip, url, method, result):
    """Enregistre une attaque bloquée dans les stats."""
    stats["total_blocked"] += 1
    for t in result.get("attack_types", ["UNKNOWN"]):
        stats["attack_types"][t] = stats["attack_types"].get(t, 0) + 1

    entry = {
        "timestamp":     datetime.now().isoformat(),
        "ip":            ip,
        "method":        method,
        "url":           url,
        "score":         result.get("anomaly_score", 0),
        "attack_types":  result.get("attack_types", []),
        "zero_day":      result.get("zero_day_candidate", False),
    }
    stats["recent_blocks"].insert(0, entry)
    if len(stats["recent_blocks"]) > 100:
        stats["recent_blocks"].pop()

    log.warning(
        f"BLOCKED ip={ip} method={method} url={url} "
        f"score={result.get('anomaly_score')} "
        f"types={result.get('attack_types')} "
        f"zero_day={result.get('zero_day_candidate')}"
    )


@app.route('/ia/stats')
def ia_stats():
    """Endpoint de stats pour le SIEM."""
    total = stats["total_requests"]
    blocked = stats["total_blocked"]
    return jsonify({
        "total_requests": total,
        "total_blocked":  blocked,
        "total_allowed":  stats["total_allowed"],
        "block_rate":     f"{(blocked/total*100):.1f}%" if total > 0 else "0%",
        "attack_types":   stats["attack_types"],
        "recent_blocks":  stats["recent_blocks"][:20]
    })


@app.route('/ia/health')
def ia_health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
@app.route('/<path:path>',            methods=['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
def proxy(path):
    """Intercepte toutes les requêtes, analyse via IA, forward ou bloque."""
    stats["total_requests"] += 1

    client_ip = (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        or request.remote_addr
        or '0.0.0.0'
    )
    method = request.method
    url    = request.full_path if request.query_string else request.path
    body   = request.get_data(as_text=True)

    # ── Analyse IA ──
    result = analyze(client_ip, method, url, request.headers, body)

    if result and result.get("blocked"):
        record_block(client_ip, url, method, result)
        # Réponse 403 avec détails
        resp_body = json.dumps({
            "error":        "Blocked by WAF-IA",
            "score":        result.get("anomaly_score"),
            "attack_types": result.get("attack_types"),
            "zero_day":     result.get("zero_day_candidate")
        })
        return Response(resp_body, status=403, mimetype='application/json',
                        headers={"X-WAF-IA": "blocked",
                                 "X-Anomaly-Score": str(result.get("anomaly_score", 0))})

    # ── Forward vers bWAPP ──
    stats["total_allowed"] += 1
    try:
        target_url = f"{BWAPP_URL}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string.decode('utf-8')}"

        # Nettoie les headers pour éviter les conflits
        fwd_headers = {
            k: v for k, v in request.headers
            if k.lower() not in ('host', 'content-length', 'transfer-encoding')
        }
        fwd_headers['X-Forwarded-For'] = client_ip
        fwd_headers['X-WAF-IA']        = 'allowed'
        if result:
            fwd_headers['X-Anomaly-Score'] = str(result.get("anomaly_score", 0))

        resp = requests.request(
            method     = method,
            url        = target_url,
            headers    = fwd_headers,
            data       = body,
            cookies    = request.cookies,
            allow_redirects = False,
            timeout    = 10
        )

        # Retransmet la réponse au client
        excluded = ('content-encoding', 'content-length',
                    'transfer-encoding', 'connection')
        response_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in excluded
        }

        return Response(
            resp.content,
            status  = resp.status_code,
            headers = response_headers
        )

    except requests.exceptions.Timeout:
        log.error(f"Timeout forwarding to bWAPP: {url}")
        return Response("Gateway Timeout", status=504)
    except Exception as e:
        log.error(f"Proxy error: {e}")
        return Response("Bad Gateway", status=502)


if __name__ == '__main__':
    log.info("Proxy WAF-IA démarré sur 10.89.1.45:9000")
    log.info(f"  → Module IA  : {IA_URL}")
    log.info(f"  → bWAPP      : {BWAPP_URL}")
    app.run(host='10.89.1.45', port=9000, threaded=True)
