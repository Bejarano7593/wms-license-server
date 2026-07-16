# Servidor de licencias standalone — OMA WMS (P0-1)

Valida licencias **fuera del cliente**, manteniendo el plan **Spark** de Firebase.
El service account vive solo acá (variable de entorno del host), nunca en el
`.exe` ni en el repo. Corre en cualquier host con free tier.

## Qué hace

- Expone `POST /license` con las operaciones: `check`, `validate`, `activate`,
  `register_trial`, `sync` (paridad con el viejo `firebase_service.py`).
- Firma cada respuesta con Ed25519. El cliente verifica con la pública embebida
  → nadie puede levantar un servidor falso que diga "válida" siempre.
- Gate de API key compartida anti-abuso.
- `update_status` (bloquear/expirar) NO se expone — es de admin.

## 1. Rotar la service account (PRIMERO)

En Google Cloud Console → IAM → Service Accounts → borrar la key comprometida
(`9ffa6bab...`, proyecto `wms---system`) y **crear una nueva key JSON**. Esa key
nueva va como secreto del host (paso 3), NO al repo ni al cliente.

## 2. Generar el par de firmas

```bash
python functions/generate_keys.py
```
- **Privada** (base64 PEM) → secreto `LICENSE_SIGNING_PRIVATE_KEY`.
- **Pública** → me la pasás para embeberla en el cliente.

## 3. Elegir host y configurar variables de entorno

Opciones con free tier (elegí una; algunas no piden tarjeta):
- **Render** (free web service) — simple, usa el `Procfile`. Se duerme por
  inactividad (cold start ~30s); el cliente ya tiene ventana de gracia offline.
- **Fly.io**, **Railway** — free tier, pueden pedir tarjeta.
- **Deno Deploy / Cloudflare** — sin tarjeta, pero requieren adaptar a JS (no este código).

Variables de entorno a setear en el host (NUNCA en el repo):
```
FIREBASE_SERVICE_ACCOUNT     = <contenido JSON del service account nuevo, en una línea>
LICENSE_SIGNING_PRIVATE_KEY  = <base64 PEM de generate_keys.py>
LICENSE_API_KEY              = <una clave random larga>
```

## 4. Deploy

Con `requirements.txt` + `Procfile`, la mayoría de los hosts detectan Python y
levantan `uvicorn app:app`. Verificá con:
```bash
curl https://<tu-host>/health   # → {"ok": true}
```

## 5. Bloquear Firestore al cliente

En las Firestore Security Rules, denegá acceso directo a `licenses` (el cliente
ya no toca Firestore; solo este servidor, con Admin, que saltea las reglas):
```
match /databases/{db}/documents {
  match /licenses/{doc} { allow read, write: if false; }
}
```

## 6. Reconectar el cliente

Pasame la **URL del host** (`https://<tu-host>/license`) y la **clave pública**.
Reescribo `core/license/firebase_service.py` para llamar por HTTPS y verificar la
firma, y saco `firebase-admin` + `config/firebase_config.enc` del cliente.

> **Orden importa:** no reconectamos el cliente hasta que el servidor esté arriba
> y `/health` responda. Si no, la app se queda sin validar licencias.

## Correr local (para probar antes de deployar)

```bash
cd server
pip install -r requirements.txt
export FIREBASE_SERVICE_ACCOUNT="$(cat serviceAccount.json)"
export LICENSE_SIGNING_PRIVATE_KEY="<base64>"
export LICENSE_API_KEY="test123"
uvicorn app:app --port 8080
```

## Tests

`python server/test_license_core.py` — prueba dispatch, validación, firma y gate
de API key con un Firestore falso (no necesita Firebase ni la red).
