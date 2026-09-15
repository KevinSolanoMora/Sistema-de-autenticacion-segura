import os
from fastapi import FastAPI
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.request import urlopen
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Login Risk Service", version="1.0.0")
SUSPICIOUS_LIST = Path(__file__).with_name("suspicious_ips.txt")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL")


class LoginRiskRequest(BaseModel):
    email: EmailStr | None = None
    ip_address: str | None = None
    user_agent: str | None = None


def load_suspicious_networks():
    lines = []

    if THREAT_INTEL_URL:
        try:
            with urlopen(THREAT_INTEL_URL, timeout=2) as response:
                lines = response.read().decode("utf-8").splitlines()
        except Exception:
            lines = []

    if not lines and SUSPICIOUS_LIST.exists():
        lines = SUSPICIOUS_LIST.read_text(encoding="utf-8").splitlines()

    networks = []
    for line in lines:
        value = line.strip()
        if value and not value.startswith("#"):
            networks.append(ip_network(value, strict=False))
    return networks


def is_suspicious_ip(value: str | None) -> bool:
    if not value:
        return False

    clean_value = value.replace("::ffff:", "")
    try:
      candidate = ip_address(clean_value)
    except ValueError:
      return False

    return any(candidate in network for network in load_suspicious_networks())


@app.get("/health")
def health():
    return {"status": "ok", "service": "login-risk-service"}


@app.post("/risk/login")
def score_login_risk(payload: LoginRiskRequest):
    score = 10
    reasons = []

    if not payload.email:
        score += 30
        reasons.append("missing-email")

    if not payload.user_agent:
        score += 20
        reasons.append("missing-user-agent")

    if payload.ip_address and payload.ip_address.startswith(("10.", "127.", "::1")):
        reasons.append("local-network")
    else:
        score += 15
        reasons.append("external-network")

    if is_suspicious_ip(payload.ip_address):
        score += 60
        reasons.append("suspicious-ip")

    return {
        "score": min(score, 100),
        "reason": ",".join(reasons) if reasons else "normal-login"
    }
