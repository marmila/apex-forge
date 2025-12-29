from fastapi import FastAPI, Query
from apex_forge.db import get_pg_cursor
import uvicorn
import logging

logger = logging.getLogger("apexforge.api")

app = FastAPI(title="ApexForge Intelligence API", version="3.0.0")

@app.get("/critical-assets")
async def get_critical_assets(min_score: float = 60.0):
    """Return current high/critical risk assets summary"""
    try:
        with get_pg_cursor() as cur:
            cur.execute("""
                SELECT profile_name, high_critical_count, avg_risk_score, total_count
                FROM intel_stats
                WHERE avg_risk_score >= %s
                ORDER BY high_critical_count DESC
            """, (min_score,))
            rows = cur.fetchall()
            return [{"profile": r[0], "critical_count": r[1], "avg_risk": round(r[2], 2), "total": r[3]} for r in rows]
    except Exception as e:
        logger.error(f"API error: {e}")
        return {"error": str(e)}

@app.get("/health")
async def health():
    return {"status": "healthy", "project": "ApexForge"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)