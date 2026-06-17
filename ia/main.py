from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict
from detector import analyze_request, ip_behavior
import uvicorn
from datetime import datetime

app = FastAPI(
    title="WAF AI Module",
    description="Module IA de détection zero-day pour BunkerWeb",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class RequestAnalysis(BaseModel):
    ip: str
    method: str = "GET"
    url: str
    headers: Optional[Dict] = {}
    body: Optional[str] = ""

class AnalysisResult(BaseModel):
    blocked: bool
    anomaly_score: float
    attack_types: list
    false_positive_risk: str
    zero_day_candidate: bool
    features: dict
    ip_reputation: dict
    timestamp: str

@app.get("/")
def root():
    return {
        "name": "WAF AI Module",
        "version": "1.0.0",
        "status": "running",
        "description": "Détection zero-day par IA pour BunkerWeb"
    }

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

@app.post("/analyze", response_model=AnalysisResult)
def analyze(req: RequestAnalysis):
    """Analyse une requête HTTP pour détecter des attaques."""
    result = analyze_request(
        ip=req.ip,
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body
    )
    result["timestamp"] = datetime.now().isoformat()
    return result

@app.get("/stats")
def stats():
    """Statistiques globales de détection."""
    total_ips = len(ip_behavior)
    total_requests = sum(v["request_count"] for v in ip_behavior.values())
    total_blocked = sum(v["blocked_count"] for v in ip_behavior.values())
    
    attack_counts = {}
    for v in ip_behavior.values():
        for t in v["attack_types"]:
            attack_counts[t] = attack_counts.get(t, 0) + 1
    
    return {
        "total_ips_seen": total_ips,
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "block_rate": f"{(total_blocked/total_requests*100):.1f}%" if total_requests > 0 else "0%",
        "attack_distribution": attack_counts
    }

@app.get("/ip/{ip_address}")
def ip_info(ip_address: str):
    """Informations sur une IP spécifique."""
    if ip_address not in ip_behavior:
        return {"ip": ip_address, "status": "unknown", "requests": 0}
    
    info = ip_behavior[ip_address]
    return {
        "ip": ip_address,
        "total_requests": info["request_count"],
        "blocked_requests": info["blocked_count"],
        "attack_types": list(set(info["attack_types"])),
        "threat_level": "high" if info["blocked_count"] > 5 else "medium" if info["blocked_count"] > 0 else "low"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="10.89.1.40", port=8000)
