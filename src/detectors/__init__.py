"""Motor de detección: reglas deterministas y auditables. Cada detector devuelve objetos Finding."""
from __future__ import annotations

import pandas as pd

from .auth import detect_anomalous_logins, detect_brute_force, detect_escalation, detect_password_spraying
from .base import CATEGORIAS_RETO, ORDEN_SIEM, SEVERIDADES, Finding, accion_para
from .execution import detect_mass_file_access, detect_persistence, detect_suspicious_commands
from .network import detect_exfiltration, detect_lateral_movement, detect_lateral_share_access, detect_web_attack
from .other import detect_other_anomalies

DETECTORES = [
    detect_password_spraying,
    detect_brute_force,
    detect_anomalous_logins,
    detect_escalation,
    detect_suspicious_commands,
    detect_persistence,
    detect_mass_file_access,
    detect_lateral_movement,
    detect_lateral_share_access,
    detect_exfiltration,
    detect_web_attack,
    detect_other_anomalies,
]


def _enriquecer(df: pd.DataFrame, hallazgos: list[Finding]) -> None:
    """Completa cada hallazgo con datos derivados de su propia evidencia (nada se inventa):
    acción SOC, categorías del reto adicionales y comparación contra la severidad del SIEM."""
    for f in hallazgos:
        filas = df[df["Log_ID"].isin(f.evidencia)]
        f.accion = f.accion or accion_para(f.regla)

        etiquetas = []
        if ((filas["Event_ID"] == "4624") & (filas["Result"] == "Success") & filas["Externa"]).any():
            etiquetas.append("Inicios sospechosos")      # la evidencia incluye un acceso exitoso desde IP externa
        if ((filas["Event_ID"] == "4672") & filas["Externa"]).any():
            etiquetas.append("Escalamiento")             # la evidencia incluye privilegios asignados a sesión externa
        f.etiquetas = [e for e in etiquetas if e != f.categoria_reto]

        siem = max(filas["Severity"], key=lambda s: ORDEN_SIEM.get(s, 0)) if len(filas) else "Informational"
        f.metricas["severidad_siem"] = siem
        f.metricas["siem_subestima"] = f.severidad in ("Crítico", "Alto") and ORDEN_SIEM.get(siem, 0) <= ORDEN_SIEM["Warning"]


def run_all(df: pd.DataFrame, errores: list[str] | None = None) -> list[Finding]:
    """Ejecuta todos los detectores, ordena por severidad y hora, y asigna IDs F-01, F-02...

    Si un detector falla, el resto sigue y el error se añade a `errores` (no se oculta).
    """
    todos: list[Finding] = []
    for det in DETECTORES:
        try:
            todos.extend(det(df))
        except Exception as exc:  # noqa: BLE001 - un detector roto no debe tumbar el análisis
            if errores is not None:
                errores.append(f"{det.__name__}: {type(exc).__name__}: {exc}")
            else:
                raise
    todos.sort(key=lambda f: (SEVERIDADES.index(f.severidad), f.inicio))
    for i, f in enumerate(todos, 1):
        f.id = f"F-{i:02d}"
    _enriquecer(df, todos)
    return todos


def conteo_categorias(hallazgos: list[Finding]) -> dict[str, int]:
    """Hallazgos por categoría del reto (un hallazgo cuenta en cada categoría que evidencia). Incluye las vacías."""
    return {c: sum(c in f.categorias_reto for f in hallazgos) for c in CATEGORIAS_RETO}


def explorador(df: pd.DataFrame, hallazgos: list[Finding], incidentes=None) -> pd.DataFrame:
    """Una fila por evento con causa raíz, severidad final y acción SOC (la del hallazgo más grave que lo contiene)."""
    causa: dict[str, tuple] = {}
    for f in hallazgos:                       # ya vienen ordenados de mayor a menor severidad
        for lid in f.evidencia:
            causa.setdefault(lid, (f.id, f.titulo, f.categoria_reto, f.severidad, f.accion))
    out = df[["Log_ID", "Timestamp", "Host", "Source_IP", "User", "Event_ID", "Event_Description",
              "Process_CommandLine", "Severity"]].copy()
    for i, (col, vacio) in enumerate([("Hallazgo", ""), ("Causa raíz", "Operación normal"), ("Categoría", ""),
                                      ("Severidad final", "Normal"), ("Acción SOC", "Sin acción")]):
        out[col] = out["Log_ID"].map(lambda l, i=i, v=vacio: causa.get(l, (v,) * 5)[i])
    out = out.rename(columns={"Severity": "Severidad SIEM"})
    if incidentes:
        inc = {lid: i.id for i in reversed(incidentes) for lid in i.evidencia}
        out.insert(out.columns.get_loc("Hallazgo") + 1, "Incidente", out["Log_ID"].map(inc).fillna(""))
    return out


def eventos_sin_explicar(df: pd.DataFrame, hallazgos: list[Finding]) -> pd.DataFrame:
    """Eventos que el SIEM marcó con alerta (no Informational) y que ningún hallazgo explica. Debería quedar vacío."""
    cubiertos = {lid for f in hallazgos for lid in f.evidencia}
    return df[df["Alerta_SIEM"] & ~df["Log_ID"].isin(cubiertos)]