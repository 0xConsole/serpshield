"""
SerpShield Agent — Threat Intelligence from Real-Time Search Data
Core agent logic with MCP-style tools powered by SerpApi.
"""
from __future__ import annotations

import os
import json
import time
import random
import httpx
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field


# ---------- Config ----------

SERPAPI_KEY = os.getenv("SERPAPI_API_KEY", "")
SERPAPI_BASE = "https://serpapi.com/search"


# ---------- Models ----------

class ThreatSignal(BaseModel):
    """A single threat intelligence signal extracted from search results."""
    source: str = Field(description="Where the signal came from (organic, news, answer_box, etc.)")
    title: str
    url: str
    snippet: str
    threat_type: str = Field(description="phishing, vulnerability, scam, impersonation, defi_risk, reputation")
    severity: str = Field(description="critical, high, medium, low, info")
    confidence: float = Field(description="0.0–1.0 confidence this is a real threat")
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MonitoringReport(BaseModel):
    """Full monitoring cycle report."""
    target: str
    timestamp: str
    signals: list[ThreatSignal] = []
    threat_score: float = 0.0
    summary: str = ""
    recommendations: list[str] = []


# ---------- SerpApi Integration ----------

def _serpapi_search(query: str, engine: str = "google") -> dict:
    """Execute a SerpApi search. Returns raw JSON. Falls back to mock data if no key."""
    if not SERPAPI_KEY:
        return _mock_search_results(query)
    params = {
        "engine": engine,
        "q": query,
        "api_key": SERPAPI_KEY,
        "num": 10,
    }
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(SERPAPI_BASE, params=params)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        return {"error": str(e), "mock": True, **_mock_search_results(query)}


def _mock_search_results(query: str) -> dict:
    """Generate realistic mock search results for demo mode (no SerpApi key)."""
    q_lower = query.lower()
    results = []
    # Generate contextually relevant mock results
    mock_pool = [
        ("Critical vulnerability disclosed in DeFi protocol — $2.3M drained",
         "https://rekt.news/example-defi-exploit",
         "Security researchers discovered an unchecked arithmetic overflow allowing an attacker to drain the protocol's liquidity pools...",
         "vulnerability", "critical"),
        ("Phishing campaign targets {brand} users with fake login pages",
         "https://security-alert.example.com/phishing-report",
         "A coordinated phishing campaign is using lookalike domains to harvest credentials from users of the target platform...",
         "phishing", "high"),
        ("Rug pull alert: anonymous dev team disappears with $890K from liquidity pool",
         "https://defi-watch.example/rug-pull-alert",
         "The project's Telegram and Twitter accounts were deleted simultaneously while liquidity was removed from the DEX pool...",
         "defi_risk", "critical"),
        ("Brand impersonation: fake social media accounts spreading crypto scams",
         "https://brand-protection.example/impersonation-report",
         "Multiple verified-looking accounts are impersonating the official brand to promote fraudulent airdrop links...",
         "impersonation", "high"),
        ("New security audit reveals medium-risk findings in smart contract",
         "https://audit-firm.example/audit-report",
         "The audit identified reentrancy risks and centralization concerns in the protocol's governance module...",
         "vulnerability", "medium"),
        ("Reputation risk: negative sentiment trending across forums and social media",
         "https://sentiment-tracker.example/trend-report",
         "Community discussions show a 40% increase in negative sentiment over the past 72 hours, driven by delayed roadmap milestones...",
         "reputation", "medium"),
    ]
    for title, url, snippet, t_type, severity in mock_pool:
        results.append({
            "title": title.replace("{brand}", q_lower.split()[0] if q_lower.split() else "target"),
            "link": url,
            "snippet": snippet,
            "source": "organic",
            "position": len(results) + 1,
            "detected_type": t_type,
            "detected_severity": severity,
        })
    # Add a news result
    results.append({
        "title": "Industry report: AI-powered threat intelligence adoption grows 300% YoY",
        "link": "https://news.example.com/ai-threat-intel-growth",
        "snippet": "Organizations using real-time search data for threat detection are identifying security incidents 4x faster than traditional methods...",
        "source": "news",
        "position": 7,
        "detected_type": "reputation",
        "detected_severity": "info",
    })
    return {"organic_results": results, "mock": True}


# ---------- Threat Analysis ----------

THREAT_KEYWORDS = {
    "defi_risk": ["rug pull", "rug", "drained", "exit scam", "liquidity removed", "flash loan attack", "MEV"],
    "impersonation": ["impersonation", "fake account", "scam account", "impersonating"],
    "phishing": ["phishing", "scam", "fake login", "lookalike", "credential"],
    "vulnerability": ["vulnerability", "exploit", "CVE", "unpatched", "0-day", "overflow", "reentrancy", "audit"],
    "reputation": ["negative sentiment", "backlash", "controversy", "complaint", "fraud alert"],
}

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}


def _classify_threat(snippet: str, title: str) -> tuple[str, str, float]:
    """Classify a search result snippet into threat type and severity."""
    text = f"{title} {snippet}".lower()
    for threat_type, keywords in THREAT_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                # Determine severity by keyword intensity
                if any(c in text for c in ["drained", "rug pull", "critical", "0-day", "exit scam"]):
                    return threat_type, "critical", 0.92
                if any(c in text for c in ["exploit", "phishing", "impersonation", "scam", "vulnerability"]):
                    return threat_type, "high", 0.80
                if any(c in text for c in ["audit", "medium", "risk", "negative"]):
                    return threat_type, "medium", 0.55
                return threat_type, "low", 0.35
    return "reputation", "info", 0.20


# ---------- MCP-Style Tools (the agent's callable toolkit) ----------

# ---- Tool 1: scan_brand_threats ----
def scan_brand_threats(target: str = "OpenAI") -> dict:
    """
    Scan search results for brand threats, impersonation, and phishing targeting a brand.
    """
    query = f'"{target}" phishing OR scam OR fake OR impersonation OR "fake login"'
    raw = _serpapi_search(query)
    results = raw.get("organic_results", [])
    signals = []
    for r in results[:8]:
        t_type, severity, conf = _classify_threat(r.get("snippet", ""), r.get("title", ""))
        if t_type in ("phishing", "impersonation", "reputation"):
            signals.append(ThreatSignal(
                source=r.get("source", "organic"),
                title=r.get("title", ""),
                url=r.get("link", ""),
                snippet=r.get("snippet", ""),
                threat_type=t_type,
                severity=severity,
                confidence=conf,
            ))
    return {
        "tool": "scan_brand_threats",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signals_count": len(signals),
        "signals": [s.model_dump() for s in signals],
        "data_source": "SerpApi (LIVE)" if SERPAPI_KEY else "SerpApi (MOCK — set SERPAPI_API_KEY)",
    }


# ---- Tool 2: scan_security_advisories ----
def scan_security_advisories(technology: str = "FastAPI") -> dict:
    """
    Scan for security advisories and CVEs related to a technology or framework.
    """
    query = f'"{technology}" CVE OR vulnerability OR exploit OR security advisory OR patch'
    raw = _serpapi_search(query)
    results = raw.get("organic_results", [])
    signals = []
    for r in results[:8]:
        t_type, severity, conf = _classify_threat(r.get("snippet", ""), r.get("title", ""))
        if t_type == "vulnerability":
            signals.append(ThreatSignal(
                source=r.get("source", "organic"),
                title=r.get("title", ""),
                url=r.get("link", ""),
                snippet=r.get("snippet", ""),
                threat_type=t_type,
                severity=severity,
                confidence=conf,
            ))
    return {
        "tool": "scan_security_advisories",
        "technology": technology,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signals_count": len(signals),
        "signals": [s.model_dump() for s in signals],
        "data_source": "SerpApi (LIVE)" if SERPAPI_KEY else "SerpApi (MOCK — set SERPAPI_API_KEY)",
    }


# ---- Tool 3: scan_defi_risks ----
def scan_defi_risks(protocol: str = "Uniswap") -> dict:
    """
    Scan for DeFi protocol risk signals — rug pulls, exploits, audit findings.
    """
    query = f'"{protocol}" "rug pull" OR exploit OR drained OR "flash loan" OR audit OR "liquidity removed"'
    raw = _serpapi_search(query)
    results = raw.get("organic_results", [])
    signals = []
    for r in results[:8]:
        t_type, severity, conf = _classify_threat(r.get("snippet", ""), r.get("title", ""))
        if t_type in ("defi_risk", "vulnerability"):
            signals.append(ThreatSignal(
                source=r.get("source", "organic"),
                title=r.get("title", ""),
                url=r.get("link", ""),
                snippet=r.get("snippet", ""),
                threat_type=t_type,
                severity=severity,
                confidence=conf,
            ))
    return {
        "tool": "scan_defi_risks",
        "protocol": protocol,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signals_count": len(signals),
        "signals": [s.model_dump() for s in signals],
        "data_source": "SerpApi (LIVE)" if SERPAPI_KEY else "SerpApi (MOCK — set SERPAPI_API_KEY)",
    }


# ---- Tool 4: generate_threat_report ----
def generate_threat_report(target: str = "OpenAI") -> dict:
    """
    Generate a comprehensive threat intelligence report combining all scan tools.
    """
    brand = scan_brand_threats(target)
    advisories = scan_security_advisories(target)
    defi = scan_defi_risks(target) if any(kw in target.lower() for kw in ["defi", "swap", "fi", "dao", "chain", "protocol"]) else {"signals": []}

    all_signals = brand.get("signals", []) + advisories.get("signals", []) + defi.get("signals", [])

    # Calculate threat score (0–100)
    threat_score = min(100, sum(SEVERITY_WEIGHTS.get(s["severity"], 1) for s in all_signals))

    # Generate recommendations
    recs = []
    critical = [s for s in all_signals if s["severity"] == "critical"]
    high = [s for s in all_signals if s["severity"] == "high"]
    if critical:
        recs.append(f"IMMEDIATE ACTION: {len(critical)} critical threats detected. Initiate incident response for {', '.join(s['threat_type'] for s in critical[:3])}.")
    if high:
        recs.append(f"HIGH PRIORITY: {len(high)} high-severity threats found. Review and triage: {', '.join(s['threat_type'] for s in high[:3])}.")
    phishing_count = sum(1 for s in all_signals if s["threat_type"] == "phishing")
    if phishing_count:
        recs.append(f"Phishing defense: {phishing_count} phishing/impersonation signals detected. Submit takedown requests to affected platforms.")
    vuln_count = sum(1 for s in all_signals if s["threat_type"] == "vulnerability")
    if vuln_count:
        recs.append(f"Patch management: {vuln_count} security advisory signals found. Prioritize patches for affected components.")
    if not recs:
        recs.append("No immediate threats detected. Continue routine monitoring.")

    report = MonitoringReport(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        signals=[ThreatSignal(**s) for s in all_signals],
        threat_score=threat_score,
        summary=f"Detected {len(all_signals)} threat signals for '{target}'. Threat score: {threat_score}/100. "
                f"Breakdown: {len(critical)} critical, {len(high)} high, {len(all_signals) - len(critical) - len(high)} lower severity.",
        recommendations=recs,
    )
    return {
        "tool": "generate_threat_report",
        "report": report.model_dump(),
        "mcp_compatible": True,
        "data_source": "SerpApi (LIVE)" if SERPAPI_KEY else "SerpApi (MOCK — set SERPAPI_API_KEY)",
    }


# ---- Tool 5: list_monitoring_targets ----
def list_monitoring_targets() -> dict:
    """
    List all configured monitoring targets and their current threat scores.
    """
    demo_targets = ["OpenAI", "Uniswap", "FastAPI", "Anthropic", "Chainlink"]
    results = []
    for t in demo_targets:
        report = generate_threat_report(t)
        results.append({
            "target": t,
            "threat_score": report["report"]["threat_score"],
            "signals_count": len(report["report"]["signals"]),
            "last_scan": report["report"]["timestamp"],
        })
    return {
        "tool": "list_monitoring_targets",
        "targets": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------- Agent Definition ----------

class SerpShieldAgent:
    """
    SerpShield Agent — autonomous threat intelligence agent.
    Uses SerpApi for real-time web data and MCP-compatible tool calls.
    """

    name = "SerpShield"
    description = "AI agent for real-time threat intelligence from search data"
    tools = [
        {"name": "scan_brand_threats", "description": "Scan for brand threats, phishing, and impersonation"},
        {"name": "scan_security_advisories", "description": "Scan for CVEs and security advisories for a technology"},
        {"name": "scan_defi_risks", "description": "Scan for DeFi protocol risk signals (rug pulls, exploits)"},
        {"name": "generate_threat_report", "description": "Generate comprehensive threat intelligence report"},
        {"name": "list_monitoring_targets", "description": "List all monitoring targets and their threat scores"},
    ]

    def run_monitoring_cycle(self, target: str = "OpenAI") -> dict:
        """Run a full autonomous monitoring cycle — the 3-minute demo flow."""
        report = generate_threat_report(target)
        return {
            "agent": self.name,
            "action": "monitoring_cycle",
            "target": target,
            "result": report,
            "status": "complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


serp_shield_agent = SerpShieldAgent()
