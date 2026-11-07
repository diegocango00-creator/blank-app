"""Informe técnico estructurado, construido solo con hallazgos e incidentes (sin IA).
La IA (src/ai.py) redacta a partir de esta misma base y su salida se valida contra los logs."""
from __future__ import annotations

import pandas as pd

from .correlation import Incidente
from .detectors import conteo_categorias, eventos_sin_explicar
from .detectors.base import SEVERIDADES, Finding


def construir_informe(df: pd.DataFrame, hallazgos: list[Finding], incidentes: list[Incidente]) -> dict:
    sev = {s: sum(h.severidad == s for h in hallazgos) for s in SEVERIDADES}
    sev_inc = {s: sum(i.severidad == s for i in incidentes) for s in SEVERIDADES}
    ini, fin = df["Timestamp"].min(), df["Timestamp"].max()
    explicados = {l for h in hallazgos for l in h.evidencia}
    subestimados = [h.id for h in hallazgos if h.metricas.get("siem_subestima")]
    limites = [
        f"El análisis cubre un único periodo continuo ({ini:%Y-%m-%d %H:%M} a {fin:%H:%M}); no hay línea base histórica "
        "para comparar el comportamiento habitual de cuentas y hosts.",
        "Las reglas son deterministas sobre los campos del export; actividad que no deje rastro en esos campos no se detecta.",
    ]
    if any(i.relacionados for i in incidentes):
        limites.append("Hay incidentes con posible relación que los logs no permiten confirmar (ver cada incidente).")
    return {
        "alcance": {"eventos": len(df), "hosts": int(df["Host"].nunique()), "usuarios": int(df["User"].nunique()),
                    "ips_externas": sorted(df.loc[df["Externa"], "Source_IP"].unique()), "inicio": ini, "fin": fin,
                    "eventos_con_hallazgo": len(explicados), "eventos_sin_hallazgo": len(df) - len(explicados)},
        "hallazgos_por_severidad": sev, "incidentes_por_severidad": sev_inc,
        "categorias": conteo_categorias(hallazgos),
        "alertas_siem_sin_explicar": len(eventos_sin_explicar(df, hallazgos)),
        "hallazgos_subestimados_por_siem": subestimados,
        "incidentes": incidentes, "limitaciones": limites,
    }


def a_markdown(inf: dict, narrativa: str | None = None) -> str:
    a = inf["alcance"]
    L = ["# Informe técnico de incidente de seguridad", "",
         "## 1. Alcance",
         f"- Periodo: {a['inicio']:%Y-%m-%d %H:%M:%S} → {a['fin']:%H:%M:%S}",
         f"- {a['eventos']} eventos, {a['hosts']} hosts, {a['usuarios']} cuentas, {len(a['ips_externas'])} IPs externas "
         f"({', '.join(a['ips_externas'])})",
         f"- Eventos respaldados por algún hallazgo: {a['eventos_con_hallazgo']}; sin hallazgo (operación normal): "
         f"{a['eventos_sin_hallazgo']}", "",
         "## 2. Resumen",
         "- Incidentes: " + ", ".join(f"{n} {s}" for s, n in inf["incidentes_por_severidad"].items() if n),
         "- Hallazgos: " + ", ".join(f"{n} {s}" for s, n in inf["hallazgos_por_severidad"].items() if n),
         "- Por categoría: " + "; ".join(f"{c}: {n}" for c, n in inf["categorias"].items()),
         f"- Alertas del SIEM sin explicar por ningún hallazgo: {inf['alertas_siem_sin_explicar']}", ""]
    if narrativa:
        L += ["## 3. Análisis redactado con IA (validado contra los logs)", "", narrativa.strip(), ""]
    L.append(f"## {4 if narrativa else 3}. Incidentes")
    for i in inf["incidentes"]:
        L += ["", f"### {i.id} · {i.severidad} · {i.titulo}", "", i.resumen, "",
              f"**Severidad:** {i.justificacion_severidad}", ""]
        L += [f"> {r}" for r in i.relacionados]
        L += ["", "| Hora | Fase | Hallazgo | Evento |", "|---|---|---|---|"]
        L += [f"| {p.hora:%H:%M:%S} | {p.fase} | {p.hallazgo} | {p.log_id} |" for p in i.pasos]
        L += ["", "**MITRE ATT&CK:** " + (", ".join(i.mitre) or "—"),
              f"**Evidencia:** {len(i.evidencia)} eventos ({i.evidencia[0]} … {i.evidencia[-1]})", "**Acciones recomendadas:**"]
        L += [f"- {x}" for x in i.acciones]
    L += ["", f"## {5 if narrativa else 4}. Limitaciones"] + [f"- {x}" for x in inf["limitaciones"]]
    return "\n".join(L)


_MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"]


def formato_periodo(ini: pd.Timestamp, fin: pd.Timestamp) -> dict:
    """Textos del resumen de actividad: fecha, rango horario y duración (redondeada al minuto)."""
    mins = int(round((fin - ini).total_seconds() / 60))
    fecha = f"{ini.day} de {_MESES[ini.month - 1]} de {ini.year}"
    if ini.date() != fin.date():
        fecha += f" – {fin.day} de {_MESES[fin.month - 1]} de {fin.year}"
    return {"fecha": fecha, "rango": f"{ini:%H:%M} – {fin:%H:%M}", "duracion": f"{mins // 60} h {mins % 60:02d} min"}