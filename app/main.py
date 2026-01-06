from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel

from app.data import USERS, PATIENTS
from app.auth import create_access_token, decode_token
from app.rbac import has_permission
from app.audit import write_audit
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Request


app = FastAPI(title="Epic-like EHR Security Core (RBAC + Audit)")

security = HTTPBearer()

class LoginRequest(BaseModel):
    username: str
    password: str

def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        payload = decode_token(token)
        return {
            "username": payload.get("sub"),
            "role": payload.get("role")
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/login")
def login(body: LoginRequest, request: Request):
    user = USERS.get(body.username)
    success = bool(user and user["password"] == body.password)

    client_ip = request.client.host if request.client else "unknown"

    write_audit({
        "event": "login_attempt",
        "username": body.username,
        "success": success,
        "client_ip": client_ip
    })

    if not success:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": body.username, "role": user["role"]})
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.get("/patients/{patient_id}")
def read_patient(patient_id: str, request: Request, user=Depends(current_user)):
    allowed = has_permission(user["role"], "patient:read")
    exists = patient_id in PATIENTS

    client_ip = request.client.host if request.client else "unknown"

    write_audit({
        "event": "patient_read_attempt",
        "username": user["username"],
        "role": user["role"],
        "patient_id": patient_id,
        "record_exists": exists,
        "allowed": allowed,
        "client_ip": client_ip
    })

    if not allowed:
        raise HTTPException(status_code=403, detail="Access denied (RBAC)")

    if not exists:
        raise HTTPException(status_code=404, detail="Patient record not found")

    return {"patient_id": patient_id, **PATIENTS[patient_id]}

