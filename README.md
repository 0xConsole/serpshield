# 🛡️ SerpShield — AI Threat Intelligence from Real-Time Search Data

> An AI agent that uses **SerpApi** real-time search data to detect brand threats, security vulnerabilities, and DeFi protocol risk signals across the live web — exposed as **MCP-compatible tools** for agent orchestration.

Built for the **DevNetwork [API + Cloud + AI] Hackathon 2026** — **SerpApi "Best AI Use Case" track**.

## Problem

Threat intelligence is reactive and slow. Security teams learn about phishing campaigns, brand impersonation, and DeFi exploits *after* the damage is done — usually from a breach notification or a social media post. By then, the attack has already succeeded.

Meanwhile, the answer is already on Google. Search results contain real-time signals: phishing pages indexed hours ago, vulnerability disclosures trending on forums, rug pull discussions appearing in news. But nobody is systematically converting that search data into structured threat intelligence that an AI agent can act on.

## Solution

SerpShield is an AI agent that queries SerpApi for real-time search results, classifies them into threat signals (phishing, vulnerability, DeFi risk, brand impersonation, reputation), and produces actionable threat intelligence reports — all exposed as MCP-compatible tools that any AI agent can call.

**How it works:**
1. Agent constructs threat-hunting queries (e.g., `"OpenAI" phishing OR scam OR impersonation`)
2. Queries SerpApi for real-time Google search results
3. Classifies each result using threat-type keywords and severity heuristics
4. Aggregates into a threat intelligence report with a 0–100 threat score and recommendations
5. Exposes everything as MCP tools so other agents can call them

## Unique Angle

> Unlike existing SerpApi demos (SEO trackers, price monitors, search aggregators), SerpShield turns search data into **security intelligence** — and exposes every tool as an MCP-compatible endpoint for AI agent orchestration. It's a threat intel SaaS powered by search data, not a search tool.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Web UI (HTML/CSS/JS)               │
│              Dark dashboard — threat scanner         │
└──────────────────┬──────────────────────────────────┘
                   │ fetch() calls
                   ▼
┌─────────────────────────────────────────────────────┐
│              FastAPI Application (app/main.py)        │
│                                                      │
│  /api/health          → service status                │
│  /api/agent/status    → agent config + tool list     │
│  /api/mcp/tools       → MCP tool discovery endpoint   │
│  /api/mcp (POST)      → MCP tool dispatch endpoint    │
│  /api/demo            → full monitoring cycle (demo) │
│  /api/tools/*         → individual tool endpoints     │
└──────────────────┬──────────────────────────────────┘
                   │ calls
                   ▼
┌─────────────────────────────────────────────────────┐
│              SerpShield Agent (app/agent.py)          │
│                                                      │
│  scan_brand_threats()      → phishing/impersonation  │
│  scan_security_advisories() → CVE/vuln detection      │
│  scan_defi_risks()         → rug pull/exploit scan    │
│  generate_threat_report()  → aggregated report        │
│  list_monitoring_targets() → dashboard summary        │
└──────────────────┬──────────────────────────────────┘
                   │ HTTP GET
                   ▼
┌─────────────────────────────────────────────────────┐
│                    SerpApi                            │
│       Real-time Google search results JSON API       │
│       (falls back to realistic mock data in demo)     │
└─────────────────────────────────────────────────────┘
```

Deployed on **Vercel** as a serverless Python function.

## Setup (Under 5 Commands)

```bash
git clone https://github.com/0xConsole/serpshield.git
cd serpshield
pip install -r requirements.txt
export SERPAPI_API_KEY="your_key"   # optional — demo mode works without it
uvicorn api.index:app --reload       # local dev at http://localhost:8000
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| Hosting | Vercel serverless (free tier) |
| Data Source | SerpApi (real-time Google search results) |
| Agent Protocol | MCP-compatible tools (Model Context Protocol) |
| Frontend | Vanilla HTML/CSS/JS — dark threat intel dashboard |
| No paid services | 100% free tier |

## What's Real vs. Mocked

| Component | Status |
|-----------|--------|
| FastAPI backend | ✅ Real — deployed and live |
| SerpApi integration | ✅ Real — live calls when `SERPAPI_API_KEY` is set |
| Threat classification engine | ✅ Real — keyword + severity heuristics |
| MCP-compatible tool endpoints | ✅ Real — `/api/mcp/tools` + `/api/mcp` POST |
| Web dashboard | ✅ Real — interactive threat scanner UI |
| Demo mode (no API key) | ✅ Real — uses realistic mock data so judges can demo without a key |
| Threat score calculation | ✅ Real — weighted severity aggregation |
| Recommendations engine | ✅ Real — rule-based from detected signals |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/health` | GET | Service health + SerpApi mode |
| `/api/agent/status` | GET | Agent configuration + tool inventory |
| `/api/mcp/tools` | GET | MCP tool discovery (for agent orchestration) |
| `/api/mcp` | POST | MCP tool dispatch (`{"tool": "scan_brand_threats", "args": {"target": "OpenAI"}}`) |
| `/api/demo` | GET | Full autonomous monitoring cycle (judge demo flow) |
| `/api/tools/scan_brand_threats` | GET | Scan for brand threats (`?target=OpenAI`) |
| `/api/tools/scan_security_advisories` | GET | Scan for CVEs (`?technology=FastAPI`) |
| `/api/tools/scan_defi_risks` | GET | Scan DeFi risks (`?protocol=Uniswap`) |
| `/api/tools/generate_threat_report` | GET | Full threat report (`?target=OpenAI`) |
| `/api/tools/list_monitoring_targets` | GET | All monitoring targets + scores |

## SerpApi Track Fit

SerpApi's challenge asks for "an innovative AI application using SerpApi APIs to access reliable, structured, real-time web data" that "solves a meaningful real-world problem."

SerpShield delivers:
- **Innovation**: Security/threat intelligence is an unexpected SerpApi use case (judges favor unexpected applications over incremental tweaks)
- **Real-time web data**: Every scan queries live Google results via SerpApi
- **Meaningful problem**: Threat intelligence is a $10B+ market
- **AI agent**: Not just a search tool — an autonomous agent with MCP-compatible tools

## License

Apache 2.0 — See [LICENSE](LICENSE)
