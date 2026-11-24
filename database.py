import sqlite3
import secrets
import string
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from config import DB_PATH

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key_str TEXT PRIMARY KEY,
            duration_seconds INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            expires_at TEXT,
            hwid TEXT,
            is_banned INTEGER NOT NULL DEFAULT 0,
            note TEXT
        )
    """)
    conn.commit()
    conn.close()

def generate_key_string(prefix: str = "SIBBI") -> str:
    chars = string.ascii_uppercase + string.digits
    parts = [prefix]
    for _ in range(3):
        parts.append(''.join(secrets.choice(chars) for _ in range(4)))
    return '-'.join(parts)

def create_key(duration_days: float, note: str = "", custom_key: Optional[str] = None) -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    
    key_str = (custom_key.strip().upper() if custom_key and custom_key.strip() else generate_key_string())
    
    # -1 means Lifetime
    if duration_days < 0 or duration_days == 0:
        duration_seconds = -1
    else:
        duration_seconds = int(duration_days * 86400)
        
    created_at = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
        INSERT INTO keys (key_str, duration_seconds, created_at, activated_at, expires_at, hwid, is_banned, note)
        VALUES (?, ?, ?, NULL, NULL, NULL, 0, ?)
    """, (key_str, duration_seconds, created_at, note))
    
    conn.commit()
    conn.close()
    
    return {
        "key": key_str,
        "duration_days": duration_days,
        "duration_seconds": duration_seconds,
        "created_at": created_at,
        "note": note
    }

def verify_key(key_str: str, client_hwid: str) -> Dict[str, Any]:
    key_str = key_str.strip().upper()
    client_hwid = client_hwid.strip()
    
    if not key_str:
        return {"success": False, "status": "EMPTY_KEY", "message": "Kein Key angegeben."}
    if not client_hwid:
        return {"success": False, "status": "EMPTY_HWID", "message": "Keine HWID uebertragen."}
        
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE key_str = ?", (key_str,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return {"success": False, "status": "INVALID_KEY", "message": "Key existiert nicht oder ist ungueltig."}
        
    if row["is_banned"]:
        conn.close()
        return {"success": False, "status": "BANNED", "message": "Dieser Key wurde gesperrt."}
        
    now = datetime.now(timezone.utc)
    duration_seconds = row["duration_seconds"]
    activated_at = row["activated_at"]
    expires_at = row["expires_at"]
    stored_hwid = row["hwid"]
    
    # First time activation
    if activated_at is None:
        activated_at = now.isoformat()
        stored_hwid = client_hwid
        
        if duration_seconds == -1:
            expires_at = None
        else:
            exp_dt = now + timedelta(seconds=duration_seconds)
            expires_at = exp_dt.isoformat()
            
        cursor.execute("""
            UPDATE keys 
            SET activated_at = ?, expires_at = ?, hwid = ?
            WHERE key_str = ?
        """, (activated_at, expires_at, stored_hwid, key_str))
        conn.commit()
        conn.close()
        
        remaining_secs = -1 if duration_seconds == -1 else duration_seconds
        remaining_days = -1 if duration_seconds == -1 else round(remaining_secs / 86400, 2)
        
        return {
            "success": True,
            "status": "ACTIVATED",
            "message": "Key erfolgreich aktiviert und an diese HWID gebunden!",
            "expires_at": expires_at or "Lifetime",
            "remaining_seconds": remaining_secs,
            "remaining_days": remaining_days,
            "is_lifetime": duration_seconds == -1
        }
        
    # Key was already activated: verify HWID
    if stored_hwid is not None and stored_hwid != client_hwid:
        conn.close()
        return {
            "success": False,
            "status": "HWID_MISMATCH",
            "message": "HWID stimmt nicht ueberein! Der Key ist an einen anderen PC gebunden."
        }
        
    # Check Expiration
    if duration_seconds != -1 and expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if now > exp_dt:
                conn.close()
                return {
                    "success": False,
                    "status": "EXPIRED",
                    "message": "Key ist abgelaufen. Bitte erneuere deine Lizenz."
                }
            remaining_secs = int((exp_dt - now).total_seconds())
            remaining_days = round(remaining_secs / 86400, 2)
        except Exception:
            remaining_secs = 0
            remaining_days = 0
    else:
        remaining_secs = -1
        remaining_days = -1
        
    # If HWID was reset, bind to this new HWID
    if stored_hwid is None:
        cursor.execute("UPDATE keys SET hwid = ? WHERE key_str = ?", (client_hwid, key_str))
        conn.commit()
        
    conn.close()
    
    return {
        "success": True,
        "status": "VALID",
        "message": "Key gueltig und verifiziert.",
        "expires_at": expires_at or "Lifetime",
        "remaining_seconds": remaining_secs,
        "remaining_days": remaining_days,
        "is_lifetime": duration_seconds == -1
    }

def get_all_keys() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    now = datetime.now(timezone.utc)
    keys_list = []
    
    for r in rows:
        d = dict(r)
        # Calculate status
        if d["is_banned"]:
            status = "BANNED"
        elif d["activated_at"] is None:
            status = "UNUSED"
        elif d["duration_seconds"] != -1 and d["expires_at"]:
            try:
                exp_dt = datetime.fromisoformat(d["expires_at"])
                if now > exp_dt:
                    status = "EXPIRED"
                else:
                    status = "ACTIVE"
            except Exception:
                status = "ACTIVE"
        else:
            status = "ACTIVE"
            
        d["computed_status"] = status
        keys_list.append(d)
        
    return keys_list

def reset_hwid(key_str: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE keys SET hwid = NULL WHERE key_str = ?", (key_str.strip().upper(),))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def delete_key(key_str: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keys WHERE key_str = ?", (key_str.strip().upper(),))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def toggle_ban(key_str: str) -> Optional[int]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_banned FROM keys WHERE key_str = ?", (key_str.strip().upper(),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    new_status = 0 if row["is_banned"] else 1
    cursor.execute("UPDATE keys SET is_banned = ? WHERE key_str = ?", (new_status, key_str.strip().upper()))
    conn.commit()
    conn.close()
    return new_status
