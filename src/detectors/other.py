"""Otras anomalías: eventos de Windows críticos por sí mismos."""
from __future__ import annotations

import pandas as pd

from .base import Finding, ips_externas, recortar

# Event_ID -> (título, severidad, MITRE, relevancia)
EVENTOS_CRITICOS = {
    "1102": ("Registro de auditoría borrado", "Alto", "T1070.001 Clear Windows Event Logs",
             "Borrar el registro de seguridad oculta rastros de actividad previa."),
    "104": ("Registro de eventos borrado", "Alto", "T1070.001 Clear Windows Event Logs",
            "Borrar registros de eventos oculta rastros de actividad previa."),
    "4719": ("Política de auditoría modificada", "Alto", "T1562.002 Disable Windows Event Logging",
             "Reducir la auditoría limita la visibilidad de lo que ocurra después."),
    "4720": ("Cuenta de usuario creada", "Medio", "T1136.001 Local Account",
             "Crear cuentas es una vía de persistencia; puede ser legítimo si lo hace un administrador autorizado."),
}


def detect_other_anomalies(df: pd.DataFrame) -> list[Finding]:
    hallazgos: list[Finding] = []
    for eid, (titulo, sev, mitre, relevancia) in EVENTOS_CRITICOS.items():
        for (host, user), g in df[df["Event_ID"] == eid].groupby(["Host", "User"]):
            texto = (f"{len(g)} evento(s) {eid} en {host} por {user} entre {g['Timestamp'].min():%H:%M:%S} y "
                     f"{g['Timestamp'].max():%H:%M:%S} ({g.iloc[0]['Log_ID']}): {recortar(g.iloc[0]['Event_Description'])}. "
                     f"Relevancia: {relevancia}")
            hallazgos.append(Finding(
                id="", categoria="Otras anomalías", titulo=f"{titulo} — {user} en {host}", severidad=sev,
                justificacion=texto, evidencia=sorted(g["Log_ID"]), inicio=g["Timestamp"].min(), fin=g["Timestamp"].max(),
                regla=f"OTH-{eid}", mitre=[mitre], hosts=[host], usuarios=[user], ips=ips_externas(g)))
    return hallazgos