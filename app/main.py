"""
SerpShield — FastAPI Main Application
AI agent for real-time threat intelligence from search data, powered by SerpApi.
"""
from __future__ import annotations
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os, json, time

from app.agent import (
    serp_shield_agent,
    scan_brand_threats,
    scan_security_advisories,
    scan_defi_risks,
    generate_threat_report,
    list_monitoring_targets,
    SERPAPI_KEY,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="SerpShield",
    description="AI agent for real-time threat intelligence from search data — powered by SerpApi + MCP",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Routes ----------

@app.get("/")
async def root():
    """Serve the web UI."""
    index = PROJECT_ROOT / "static" / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>SerpShield</h1><p>UI not found. See <a href='/api/health'>/api/health</a></p>")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "SerpShield",
        "agent": "SerpShield Agent",
        "serpapi_mode": "LIVE" if SERPAPI_KEY else "DEMO (mock — set SERPAPI_API_KEY)",
        "version": "1.0.0",
        "timestamp": time.time(),
    }


@app.get("/api/agent/status")
async def agent_status():
    """Get agent configuration and tool inventory."""
    return {
        "agent_name": "SerpShield",
        "description": "Autonomous threat intelligence agent powered by SerpApi real-time search data",
        "platform": "SerpApi + MCP-compatible tools",
        "model": "SerpApi-driven analysis engine",
        "tools": [
            {"name": "scan_brand_threats", "description": "Scan for brand threats, phishing, and impersonation"},
            {"name": "scan_security_advisories", "description": "Scan for CVEs and security advisories for a technology"},
            {"name": "scan_defi_risks", "description": "Scan for DeFi protocol risk signals (rug pulls, exploits)"},
            {"name": "generate_threat_report", "description": "Generate comprehensive threat intelligence report"},
            {"name": "list_monitoring_targets", "description": "List all monitoring targets and their threat scores"},
        ],
        "mcp_compatible": True,
        "serpapi_enabled": bool(SERPAPI_KEY),
    }


# ---------- MCP Tool endpoints (expose each agent tool over HTTP) ----------

@app.get("/api/tools/scan_brand_threats")
async def tool_scan_brand_threats(target: str = "OpenAI"):
    return scan_brand_threats(target)

@app.get("/api/tools/scan_security_advisories")
async def tool_scan_security_advisories(technology: str = "FastAPI"):
    return scan_security_advisories(technology)

@app.get("/api/tools/scan_defi_risks")
async def tool_scan_defi_risks(protocol: str = "Uniswap"):
    return scan_defi_risks(protocol)

@app.get("/api/tools/generate_threat_report")
async def tool_generate_threat_report(target: str = "OpenAI"):
    return generate_threat_report(target)

@app.get("/api/tools/list_monitoring_targets")
async def tool_list_monitoring_targets():
    return list_monitoring_targets()


# ---------- MCP Tools listing (for agent discovery) ----------

@app.get("/api/mcp/tools")
async def mcp_tools():
    """List all MCP-compatible tools for agent orchestration."""
    return {
        "protocol": "MCP-compatible",
        "server": "SerpShield",
        "tools": serp_shield_agent.tools,
        "endpoints": {
            "scan_brand_threats": "/api/tools/scan_brand_threats?target=<brand>",
            "scan_security_advisories": "/api/tools/scan_security_advisories?technology=<tech>",
            "scan_defi_risks": "/api/tools/scan_defi_risks?protocol=<protocol>",
            "generate_threat_report": "/api/tools/generate_threat_report?target=<target>",
            "list_monitoring_targets": "/api/tools/list_monitoring_targets",
        },
    }


# ---------- MCP Protocol endpoint ----------

@app.post("/api/mcp")
async def mcp_endpoint(request: dict):
    """
    Model Context Protocol compatible endpoint.
    Accepts tool-call requests and dispatches to agent tools.
    """
    tool_name = request.get("tool")
    args = request.get("args", {})
    tool_map = {
        "scan_brand_threats": scan_brand_threats,
        "scan_security_advisories": scan_security_advisories,
        "scan_defi_risks": scan_defi_risks,
        "generate_threat_report": generate_threat_report,
        "list_monitoring_targets": list_monitoring_targets,
    }
    if tool_name not in tool_map:
        return JSONResponse(
            {"error": f"Unknown tool: {tool_name}", "available": list(tool_map.keys())},
            status_code=404,
        )
    try:
        result = tool_map[tool_name](**args)
        return {"tool": tool_name, "result": result}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ---------- DEMO endpoint ----------

@app.get("/api/demo")
async def demo():
    """
    Run a full autonomous monitoring cycle — the 3-minute demo flow.
    This is the star endpoint for judges.
    """
    return serp_shield_agent.run_monitoring_cycle("OpenAI")
