# server/rate_limit.py
"""
Rate limiting in-memory para el servidor de licencias (P1-4, P1-5).

El endpoint /license no tenía ningún límite: martillar register_trial (que
escribe en Firestore) agota la cuota diaria del free tier y tira el servicio
para todos, y permite enumerar trial keys / crear trials infinitos.

Sin dependencias externas ni Redis (el free tier de Render corre una sola
instancia, así que un contador in-memory con ventana deslizante alcanza como
defensa básica). Dos capas:

  PER-IP    frena el abuso desde una IP concreta.
  GLOBAL    backstop por acción sobre TODO el tráfico: protege la cuota de
            Firestore aunque el atacante rote IPs o falsee X-Forwarded-For
            (que el per-IP no puede evitar por sí solo).

register_trial y activate (escrituras) tienen los límites más estrictos.
Limitación conocida: el estado se pierde al reiniciar y no se comparte entre
instancias; si algún día se escala horizontalmente, mover a Redis.
"""
import time
import threading
from collections import defaultdict, deque

# (límite, ventana_segundos) por acción — capa PER-IP.
_PER_IP = {
    "register_trial": (5, 3600),    # un equipo real hace 1 trial
    "activate":       (10, 3600),
    "check":          (60, 60),
    "validate":       (60, 60),
    "sync":           (60, 60),
}
_PER_IP_DEFAULT = (30, 60)

# (límite, ventana_segundos) por acción — capa GLOBAL (todas las IPs juntas).
# Protege la cuota de Firestore del free tier ante rotación de IPs.
_GLOBAL = {
    "register_trial": (100, 3600),
    "activate":       (200, 3600),
    "check":          (1000, 60),
    "validate":       (1000, 60),
    "sync":           (1000, 60),
}
_GLOBAL_DEFAULT = (1000, 60)


class SlidingWindow:
    """Contador de ventana deslizante, seguro para acceso concurrente."""

    def __init__(self, time_fn=time.monotonic):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()
        self._time = time_fn

    def allow(self, key, limit: int, window_s: float) -> bool:
        """Registra un hit y devuelve True si sigue dentro del límite."""
        now = self._time()
        cutoff = now - window_s
        with self._lock:
            dq = self._hits[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit:
                if not dq:
                    self._hits.pop(key, None)
                return False
            dq.append(now)
            return True


_per_ip = SlidingWindow()
_global = SlidingWindow()


def _reset_for_tests():
    """Reinicia el estado in-memory. Solo para tests."""
    global _per_ip, _global
    _per_ip = SlidingWindow()
    _global = SlidingWindow()


def check(ip: str, action: str) -> bool:
    """True si la request se permite; False si excede el límite per-IP o global."""
    p_limit, p_win = _PER_IP.get(action, _PER_IP_DEFAULT)
    g_limit, g_win = _GLOBAL.get(action, _GLOBAL_DEFAULT)
    # Global primero: si el server ya está saturado, no consumimos cupo per-IP.
    if not _global.allow(action, g_limit, g_win):
        return False
    if not _per_ip.allow(f"{ip}|{action}", p_limit, p_win):
        return False
    return True
