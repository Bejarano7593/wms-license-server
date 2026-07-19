# server/app.py
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

app = FastAPI(title="OMA WMS License API")

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
      return {"ok": True}


@app.post("/license")
async def license_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}

    response_body, status = license_core.handle(
        body=body,
        db=_db,
        sign_key=_sign_key,
        api_key_expected=os.environ.get("LICENSE_API_KEY", ""),
        provided_api_key=request.headers.get("X-Api-Key", ""),
    )
    return JSONResponse(content=response_body, status_code=status)
