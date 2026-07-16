# server/test_license_core.py
"""
Pruebas del núcleo de licencias (server/license_core.py) con un Firestore falso.
No necesita firebase_admin ni fastapi.

Cubre: dispatch, lógica de validación, gate de API key, y que TODA respuesta
va firmada y se verifica con la clave pública (propiedad central de P0-1).

Corre con:  python server/test_license_core.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

import license_core


# ── Firestore falso (solo lo que usan check/validate) ───────────────────

class _FakeDoc:
    def __init__(self, data):
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return self._data


class _FakeDocRef:
    def __init__(self, data):
        self._data = data

    def get(self):
        return _FakeDoc(self._data)


class _FakeCollection:
    def __init__(self, docs):
        self._docs = docs

    def document(self, key):
        return _FakeDocRef(self._docs.get(key))


class _FakeDB:
    def __init__(self, docs):
        self._docs = docs

    def collection(self, _name):
        return _FakeCollection(self._docs)


# ── Utilidades ──────────────────────────────────────────────────────────

_KEY = Ed25519PrivateKey.generate()
_PUB = _KEY.public_key()
_API = "clave-api-secreta"


def _verify(resp_body: dict) -> bool:
    import base64
    payload = resp_body["payload"]
    sig = base64.b64decode(resp_body["signature"])
    try:
        _PUB.verify(sig, license_core.canonical(payload))
        return True
    except InvalidSignature:
        return False


def _call(body, docs=None, api=_API):
    db = _FakeDB(docs or {})
    return license_core.handle(body, db, _KEY, _API, api)


# ── Tests ───────────────────────────────────────────────────────────────

def test_check_existente_firma_ok():
    docs = {"K1": {"estado": "activo", "tipo": "perpetua"}}
    resp, status = _call({"action": "check", "license_key": "K1"}, docs)
    assert status == 200
    assert resp["payload"]["exists"] is True
    assert _verify(resp), "La respuesta debe verificar con la pública"


def test_validate_bloqueada():
    docs = {"K1": {"estado": "bloqueado", "activada": True, "hardware_id": "HW1"}}
    resp, status = _call({"action": "validate", "license_key": "K1", "hardware_id": "HW1"}, docs)
    assert resp["payload"]["valid"] is False
    assert resp["payload"]["message"] == "Licencia bloqueada"
    assert _verify(resp)


def test_validate_ok_mismo_hardware():
    docs = {"K1": {"estado": "activo", "activada": True, "hardware_id": "HW-1"}}
    resp, _ = _call({"action": "validate", "license_key": "K1", "hardware_id": "hw1"}, docs)
    # normaliza HW-1 == hw1 → válida
    assert resp["payload"]["valid"] is True
    assert _verify(resp)


def test_validate_no_encontrada():
    resp, _ = _call({"action": "validate", "license_key": "NOPE", "hardware_id": "X"}, {})
    assert resp["payload"]["valid"] is False
    assert resp["payload"]["message"] == "Licencia no encontrada"


def test_transferencias_agotadas():
    ok, msg = license_core.validate_logic(
        {"estado": "activo", "activada": True, "hardware_id": "HW1",
         "max_transferencias": 1, "transferencias_realizadas": 1}, "HW2"
    )
    assert ok is False and "Transferencias agotadas" in msg


def test_accion_desconocida():
    resp, status = _call({"action": "borrar_todo"}, {})
    assert status == 400
    assert resp["payload"]["error"] == "unknown_action"
    assert _verify(resp), "Hasta los errores van firmados"


def test_api_key_invalida():
    resp, status = _call({"action": "check", "license_key": "K1"}, {"K1": {}}, api="mala")
    assert status == 401
    assert resp["payload"]["error"] == "unauthorized"


def test_no_filtra_datos_sensibles():
    docs = {"K1": {"estado": "activo", "cliente_email": "secreto@x.com", "cliente_nombre": "Juan"}}
    resp, _ = _call({"action": "check", "license_key": "K1"}, docs)
    lic = resp["payload"]["license"]
    assert "cliente_email" not in lic and "cliente_nombre" not in lic


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fallos = 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
        except AssertionError as e:
            fallos += 1
            print(f"[FAIL] {t.__name__}: {e}")
    print(f"\n{len(tests) - fallos}/{len(tests)} pruebas OK")
    sys.exit(1 if fallos else 0)
