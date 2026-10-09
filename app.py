from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from detector import analyze_message


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="THEREAT AI",
    description="Local AI-powered phishing and scam detection",
    version="2.0"
)


# ============================================================
# REQUEST MODEL
# ============================================================

class MessageRequest(BaseModel):

    message: str


# ============================================================
# HOME PAGE
# ============================================================

@app.get("/")
def home():

    return FileResponse("web.html")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "online",
        "engine": "THEREAT AI",
        "mode": "Local / On-Device",
        "version": "2.0"
    }


# ============================================================
# MESSAGE ANALYSIS API
# ============================================================

@app.post("/analyze")
def analyze(request: MessageRequest):

    result = analyze_message(
        request.message
    )

    return result