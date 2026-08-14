"""
SerpShield - Vercel Serverless Entry Point
FastAPI app exposed as a Vercel serverless function.
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import os, sys

# Add project root to path so imports work in Vercel
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app as fastapi_app

# Mount static files for the web UI
static_dir = PROJECT_ROOT / "static"
if static_dir.exists():
    fastapi_app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Export for Vercel
app = fastapi_app
