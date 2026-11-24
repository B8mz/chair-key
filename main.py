from fastapi import FastAPI, HTTPException, Header, Query, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import os
import uvicorn

import config
import database

# Initialize database
database.init_db()

app = FastAPI(
    title="Sibbi Key System API",
    description="Secure HWID-locked Key Management API for Apps and Games",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Models
class VerifyRequest(BaseModel):
    key: str = Field(..., description="The license key to verify")
    hwid: str = Field(..., description="Unique client hardware ID")

class CreateKeyRequest(BaseModel):
    duration_days: float = Field(default=30.0, description="Duration in days (-1 or 0 for Lifetime)")
    note: Optional[str] = Field(default="", description="Customer note or username")
    custom_key: Optional[str] = Field(default=None, description="Optional custom key name")

# Admin Authentication Dependency
def verify_admin(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    token: Optional[str] = Query(None)
):
    provided_token = x_admin_token or token
    if not provided_token or provided_token != config.ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ungueltiger oder fehlender Admin-Token!"
        )
    return True

# Public Endpoints
@app.get("/")
def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Sibbi Key System Server is running. Dashboard not found."}

@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "app": "Sibbi Key System"}

@app.post("/api/v1/verify")
def verify_client_key(req: VerifyRequest):
    result = database.verify_key(req.key, req.hwid)
    return result

# Admin Endpoints
@app.get("/api/v1/admin/keys", dependencies=[Depends(verify_admin)])
def list_keys():
    return {"keys": database.get_all_keys()}

@app.post("/api/v1/admin/keys", dependencies=[Depends(verify_admin)])
def create_new_key(req: CreateKeyRequest):
    new_key = database.create_key(
        duration_days=req.duration_days,
        note=req.note or "",
        custom_key=req.custom_key
    )
    return {"success": True, "key": new_key}

@app.post("/api/v1/admin/keys/{key_str}/reset-hwid", dependencies=[Depends(verify_admin)])
def reset_key_hwid(key_str: str):
    success = database.reset_hwid(key_str)
    if not success:
        raise HTTPException(status_code=404, detail="Key nicht gefunden.")
    return {"success": True, "message": f"HWID fuer Key {key_str} erfolgreich zurueckgesetzt."}

@app.post("/api/v1/admin/keys/{key_str}/ban", dependencies=[Depends(verify_admin)])
def toggle_key_ban(key_str: str):
    new_status = database.toggle_ban(key_str)
    if new_status is None:
        raise HTTPException(status_code=404, detail="Key nicht gefunden.")
    action = "gesperrt" if new_status == 1 else "entsperrt"
    return {"success": True, "is_banned": bool(new_status), "message": f"Key {key_str} wurde {action}."}

@app.delete("/api/v1/admin/keys/{key_str}", dependencies=[Depends(verify_admin)])
def remove_key(key_str: str):
    success = database.delete_key(key_str)
    if not success:
        raise HTTPException(status_code=404, detail="Key nicht gefunden.")
    return {"success": True, "message": f"Key {key_str} wurde geloescht."}

if __name__ == "__main__":
    print(f"[*] Starte Sibbi Key System Server auf {config.HOST}:{config.PORT}...")
    print(f"[*] Admin-Token: {config.ADMIN_TOKEN}")
    print(f"[*] Dashboard: http://localhost:{config.PORT}")
    uvicorn.run("main:app", host=config.HOST, port=config.PORT, reload=True)
