# server/app.py
"""
Servidor FastAPI standalone de validación de licencias — OMA WMS (P0-1).

Reemplaza el uso del Admin SDK EN EL CLIENTE. El service account vive solo acá,
como secreto del host (variable de entorno FIREBASE_SERVICE_ACCOUNT), nunca en
el .exe ni en el repo. Corre en cualquier host con free tier (Render, Deno
Deploy con python, Fly, Railway, etc.).

Variables de entorno requeridas:
  FIREBASE_SERVICE_ACCOUNT        JSON del service account (una sola línea)
  LICENSE_SIGNING_PRIVATE_KEY     base64 del PEM Ed25519 (de generate_keys.py)
  LICENSE_API_KEY                 clave compartida anti-abuso

Correr local:  uvicorn app:app --port 8080
"""
import os
import json
import base64

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import license_core
import rate_limit

app = FastAPI(title="OMA WMS License API")


def _client_ip(request: Request) -> str:
    # Render (y la mayoría de PaaS) van detrás de proxy: la IP real del cliente
    # está en X-Forwarded-For (primer valor). request.client.host sería el proxy.
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

_sign_key: Ed25519PrivateKey = None
_db = None


def _load_sign_key() -> Ed25519PrivateKey:
    pem = base64.b64decode(os.environ["LICENSE_SIGNING_PRIVATE_KEY"])
    return serialization.load_pem_private_key(pem, password=None)


@app.on_event("startup")
def _startup():
    global _sign_key, _db
    if not firebase_admin._apps:
        sa = json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT"])
        firebase_admin.initialize_app(credentials.Certificate(sa))
    _db = firestore.client()
    _sign_key = _load_sign_key()


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    # GET y HEAD: los monitores de uptime (UptimeRobot, etc.) pinguean con HEAD
    # por defecto. Sin HEAD, un monitor recibe 405 y marca el server como caído.
    return {"ok": True}


@app.post("/license")
async def license_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}

    # P1-4/P1-5: rate limiting antes de tocar Firestore. Protege la cuota del
    # free tier y frena la enumeración de trial keys / creación de trials.
    action = body.get("action", "") if isinstance(body, dict) else ""
    if not rate_limit.check(_client_ip(request), action):
        return JSONResponse(content={"error": "rate_limited"}, status_code=429)

    response_body, status = license_core.handle(
        body=body,
        db=_db,
        sign_key=_sign_key,
        api_key_expected=os.environ.get("LICENSE_API_KEY", ""),
        provided_api_key=request.headers.get("X-Api-Key", ""),
    )
    return JSONResponse(content=response_body, status_code=status)
