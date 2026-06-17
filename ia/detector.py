import re
import numpy as np
from collections import defaultdict
import time
from urllib.parse import unquote_plus

PATTERNS = {
    "SQLi": [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from)",
        r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s+or\s+'|--\s*$)",
        r"(?i)(exec\s*\(|execute\s*\(|xp_cmdshell|sp_executesql)",
    ],
    "XSS": [
        r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=)",
        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie)",
        r"(?i)(<iframe|<img\s+src|<svg\s+onload)",
    ],
    "LFI": [
        r"(\.\./){2,}",
        r"(?i)(etc/passwd|etc/shadow|proc/self|win\.ini|boot\.ini)",
        r"(?i)(php://filter|php://input|data://text)",
    ],
    "RCE": [
        r"(?i)(;cat\s|;ls\s|;id\s|;whoami|;uname)",
        r"(?i)(\|cat\s|\|ls\s|\|id\s|&&\s*cat|&&\s*ls)",
        r"(?i)(system\s*\(|exec\s*\(|passthru\s*\(|shell_exec)",
    ],
    "SSRF": [
        r"(?i)(localhost|127\.0\.0\.1|169\.254\.169\.254)",
        r"(?i)(file://|gopher://|dict://|tftp://)",
        r"(?i)(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)",
    ]
}

ip_behavior = defaultdict(lambda: {
    "request_count": 0,
    "blocked_count": 0,
    "attack_types": [],
    "last_request": 0
})

def extract_features(url: str, body: str, headers: dict) -> dict:
    text = unquote_plus(f"{url} {body}")
    features = {
        "length": len(text),
        "special_chars": len(re.findall(r'[<>\'";(){}=#\-*+./]', text)),
        "encoded_chars": len(re.findall(r'%[0-9a-fA-F]{2}', text)),
        "sql_keywords": len(re.findall(r'(?i)\b(select|union|insert|delete|drop|update|where|and|or|from|limit|information_schema|table_name|into)\b', text)),
        "js_keywords": len(re.findall(r'(?i)(script|alert|onerror|onload|javascript|cookie)', text)),
        "path_traversal": len(re.findall(r'\.\./', text)),
        "cmd_injection": len(re.findall(r'[;&|`$]', text)),
        "ssrf_indicators": len(re.findall(r'(?i)(169\.254|localhost|127\.0\.0\.1)', text)),
    }
    return features

def calculate_anomaly_score(features: dict) -> float:
    score = 0.0

    if features["special_chars"] > 1:
        score += features["special_chars"] * 5
    if features["encoded_chars"] > 3:
        score += features["encoded_chars"] * 3
    if features["sql_keywords"] > 0:
        score += features["sql_keywords"] * 30
    if features["js_keywords"] > 0:
        score += features["js_keywords"] * 13
    if features["path_traversal"] > 1:
        score += features["path_traversal"] * 20
    if features["cmd_injection"] > 0:
        score += features["cmd_injection"] * 18
    if features["ssrf_indicators"] > 0:
        score += features["ssrf_indicators"] * 30
    if features["length"] > 500:
        score += 5

    return min(score, 100.0)

def detect_attack_type(url: str, body: str) -> list:
    text = unquote_plus(f"{url} {body}")
    detected = []
    for attack_type, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                detected.append(attack_type)
                break
    return detected if detected else ["UNKNOWN"]

def is_zero_day_candidate(features: dict, attack_types: list) -> bool:
    if "UNKNOWN" in attack_types and features["anomaly_score"] > 30:
        return True
    if features["encoded_chars"] > 10 and not any(t != "UNKNOWN" for t in attack_types):
        return True
    return False

def analyze_request(ip: str, method: str, url: str,
                    headers: dict, body: str) -> dict:
    current_time = time.time()
    ip_behavior[ip]["request_count"] += 1
    
    # Calcul de la vitesse (requêtes par seconde)
    time_diff = current_time - ip_behavior[ip]["last_request"]
    ip_behavior[ip]["last_request"] = current_time

    features = extract_features(url, body, headers)
    anomaly_score = calculate_anomaly_score(features)
    
    # Pénalité si l'IP bombarde (vitesse élevée)
    if time_diff < 0.2: # Plus de 5 req/s
        anomaly_score += 20

    features["anomaly_score"] = anomaly_score
    attack_types = detect_attack_type(url, body)
    if time_diff < 0.2:
        attack_types.append("BRUTE-FORCE")

    false_positive_risk = "low"
    if anomaly_score > 50 and len(attack_types) == 1 and "UNKNOWN" in attack_types:
        false_positive_risk = "high"
    elif anomaly_score > 30:
        false_positive_risk = "medium"

    zero_day = is_zero_day_candidate(features, attack_types)
    blocked = anomaly_score >= 25

    if blocked:
        ip_behavior[ip]["blocked_count"] += 1
        ip_behavior[ip]["attack_types"].extend(attack_types)

    return {
        "blocked": blocked,
        "anomaly_score": round(anomaly_score, 2),
        "attack_types": attack_types,
        "false_positive_risk": false_positive_risk,
        "zero_day_candidate": zero_day,
        "features": features,
        "ip_reputation": {
            "total_requests": ip_behavior[ip]["request_count"],
            "blocked_requests": ip_behavior[ip]["blocked_count"],
            "known_attack_types": list(set(ip_behavior[ip]["attack_types"]))
        }
    }
