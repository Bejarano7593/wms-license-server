# server/license_core.py
"""
Núcleo de validación de licencias — independiente del framework web (P0-1).

Contiene la lógica de negocio (paridad con el viejo firebase_service.py), el
dispatch de acciones y la firma Ed25519 de respuestas. NO importa firebase_admin
a nivel de módulo (los writes lo importan lazy), así se puede testear el camino
de lectura + firma sin Firebase.

app.py (FastAPI) es un wrapper fino: carga credenciales/clave y delega en handle().
"""
import os
import json
import base64
import random
import string
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

COLLECTION = "licenses"
DEFAULT_MAX_TRANSFERS = 1


# ── Helpers ─────────────────────────────────────────────────────────────

def normalize_hw(hw_id: str) -> str:
    if not hw_id:
        return ""
    return hw_id.strip().upper().replace(" ", "").replace("-", "")


def _iso(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def sanitize(license_data: dict) -> dict:
    """Solo campos no sensibles hacia el cliente (no cliente_nombre/email)."""
    if not license_data:
        return {}
    campos = (
        "tipo", "estado", "activada", "hardware_id", "fecha_expiracion",
        "fecha_activacion", "max_transferencias", "transferencias_realizadas",
    )
    return {k: _iso(license_data.get(k)) for k in campos if k in license_data}


def canonical(payload: dict) -> bytes:
    """JSON canónico determinístico para firmar/verificar. DEBE coincidir con el
    verificador del cliente."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def signed_body(payload: dict, sign_key: Ed25519PrivateKey) -> dict:
    signature = sign_key.sign(canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


# ── Lógica de validación (pura) ─────────────────────────────────────────

def validate_logic(license_data: dict, hardware_id: str):
    estado = license_data.get("estado", "")
    if estado == "bloqueado":
        return False, "Licencia bloqueada"
    if estado == "expirado":
        return False, "Licencia expirada"

    hw_local = normalize_hw(hardware_id)
    hw_reg = normalize_hw(license_data.get("hardware_id", ""))
    activada = license_data.get("activada", False)

    if activada and hw_reg and hw_local != hw_reg:
        max_trans = license_data.get("max_transferencias", DEFAULT_MAX_TRANSFERS)
        realizadas = license_data.get("transferencias_realizadas", 0)
        if max_trans <= 0:
            return False, "Licencia ya activada en otro equipo. No se permiten transferencias"
        if realizadas >= max_trans:
            return False, f"Licencia ya activada en otro equipo. Transferencias agotadas ({realizadas}/{max_trans})"
        return True, f"Licencia válida. Se usará 1 transferencia ({realizadas + 1}/{max_trans})"

    fecha_exp = license_data.get("fecha_expiracion")
    if fecha_exp and hasattr(fecha_exp, "replace"):
        if datetime.now() > fecha_exp.replace(tzinfo=None):
            return False, "Licencia expirada"

    return True, "Licencia válida"


# ── Operaciones (db = firestore client) ─────────────────────────────────

def _op_check(db, license_key, _hw, _un, _ue):
    doc = db.collection(COLLECTION).document(license_key).get()
    if not doc.exists:
        return {"exists": False, "license": None}
    return {"exists": True, "license": sanitize(doc.to_dict())}


def _op_validate(db, license_key, hardware_id, _un, _ue):
    doc = db.collection(COLLECTION).document(license_key).get()
    if not doc.exists:
        return {"valid": False, "message": "Licencia no encontrada", "license": None}
    data = doc.to_dict()
    valid, msg = validate_logic(data, hardware_id)
    return {"valid": valid, "message": msg, "license": sanitize(data)}


def _op_activate(db, license_key, hardware_id, user_name, user_email):
    from firebase_admin import firestore
    ref = db.collection(COLLECTION).document(license_key)
    doc = ref.get()
    if not doc.exists:
        return {"success": False, "message": "Licencia no encontrada"}
    data = doc.to_dict()
    valid, msg = validate_logic(data, hardware_id)
    if not valid:
        return {"success": False, "message": msg}

    update = {
        "hardware_id": hardware_id,
        "activada": True,
        "fecha_activacion": firestore.SERVER_TIMESTAMP,
        "ultima_sincronizacion": firestore.SERVER_TIMESTAMP,
    }
    hw_anterior = normalize_hw(data.get("hardware_id", ""))
    if hw_anterior and hw_anterior != normalize_hw(hardware_id):
        update["transferencias_realizadas"] = firestore.Increment(1)
    if user_name:
        update["cliente_nombre"] = user_name
    if user_email:
        update["cliente_email"] = user_email

    ref.update(update)
    return {"success": True, "message": "Licencia activada correctamente"}


def _op_register_trial(db, _license_key, hardware_id, user_name, user_email):
    from firebase_admin import firestore
    from firebase_admin.firestore import FieldFilter
    for hw in {hardware_id, normalize_hw(hardware_id)}:
        existing = (
            db.collection(COLLECTION)
            .where(filter=FieldFilter("tipo", "==", "trial"))
            .where(filter=FieldFilter("hardware_id", "==", hw))
            .limit(1)
            .get()
        )
        if len(existing) > 0:
            return {"success": False, "message": "Este equipo ya utilizó el período de prueba", "trial_key": None}

    year = datetime.now().strftime("%Y")
    trial_key = f"OMA-{year}-TRIAL-{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}"
    expiration = datetime.now() + timedelta(days=7)
    db.collection(COLLECTION).document(trial_key).set({
        "tipo": "trial", "hardware_id": hardware_id,
        "cliente_nombre": user_name or "", "cliente_email": user_email or "",
        "estado": "activo", "fecha_creacion": firestore.SERVER_TIMESTAMP,
        "fecha_expiracion": expiration, "fecha_activacion": firestore.SERVER_TIMESTAMP,
        "activada": True, "max_transferencias": 0, "transferencias_realizadas": 0,
        "ultima_sincronizacion": firestore.SERVER_TIMESTAMP,
    })
    return {"success": True, "message": f"Trial activado hasta {expiration.strftime('%Y-%m-%d')}", "trial_key": trial_key}


def _op_sync(db, license_key, _hw, _un, _ue):
    from firebase_admin import firestore
    ref = db.collection(COLLECTION).document(license_key)
    doc = ref.get()
    if not doc.exists:
        return {"success": False, "license": None}
    ref.update({"ultima_sincronizacion": firestore.SERVER_TIMESTAMP})
    return {"success": True, "license": sanitize(doc.to_dict())}


OPERATIONS = {
    "check": _op_check,
    "validate": _op_validate,
    "activate": _op_activate,
    "register_trial": _op_register_trial,
    "sync": _op_sync,
    # "update_status" (bloquear/expirar) NO se expone: es operación de admin.
}


# ── Dispatch + firma ────────────────────────────────────────────────────

def handle(body: dict, db, sign_key: Ed25519PrivateKey,
           api_key_expected: str, provided_api_key: str):
    """Procesa una request. Devuelve (response_body_dict, status_code).
    Todas las respuestas van firmadas."""
    if api_key_expected and provided_api_key != api_key_expected:
        return signed_body({"error": "unauthorized"}, sign_key), 401

    action = (body or {}).get("action", "")
    op = OPERATIONS.get(action)
    if op is None:
        return signed_body({"error": "unknown_action", "action": action}, sign_key), 400

    try:
        result = op(
            db,
            body.get("license_key", ""),
            body.get("hardware_id", ""),
            body.get("user_name"),
            body.get("user_email"),
        )
    except Exception as e:
        return signed_body({"error": "server_error", "detail": str(e)}, sign_key), 500

    result["_ts"] = datetime.utcnow().isoformat() + "Z"
    result["_nonce"] = base64.b64encode(os.urandom(12)).decode("ascii")
    return signed_body(result, sign_key), 200
