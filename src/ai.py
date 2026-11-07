"""Redacción con IA fundamentada. La IA solo recibe hallazgos/incidentes ya calculados y su salida se valida:
cualquier Log_ID o IP que cite y no exista en los logs se reporta (rigor analítico: no inventar hallazgos)."""
from __future__ import annotations

import json
import os
import re

import pandas as pd

MODELO = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")

SISTEMA = """Eres un analista SOC de nivel 2 que redacta la sección de análisis de un informe técnico.
REGLAS ESTRICTAS:
- Usa ÚNICAMENTE los datos del JSON recibido. No agregues eventos, IPs, cuentas, hosts, horas ni cifras que no estén en él.
- Cita siempre los Log_ID (EVT-xxxxx) que sustentan cada afirmación.
- No afirmes que dos incidentes son el mismo actor/campaña si el JSON dice que la relación no está confirmada.
- No atribuyas causas ni intenciones que los datos no muestren; si algo es una hipótesis, dilo como hipótesis.
- Escribe en español, en prosa técnica y concisa, un apartado por incidente (usa su id) y un párrafo final de conclusiones.
- No incluyas recomendaciones nuevas: limítate a las acciones del JSON."""


def contexto_ia(inf: dict) -> str:
    """Hechos que se le entregan a la IA (JSON compacto)."""
    incs = []
    for i in inf["incidentes"]:
        incs.append({"id": i.id, "severidad": i.severidad, "titulo": i.titulo, "resumen": i.resumen,
                     "justificacion_severidad": i.justificacion_severidad, "hosts": i.hosts, "cuentas": i.actores,
                     "ips_externas": i.ips_externas, "mitre": i.mitre, "relaciones_no_confirmadas": i.relacionados,
                     "pasos": [{"hora": f"{p.hora:%H:%M:%S}", "fase": p.fase, "evento": p.log_id, "que": p.titulo} for p in i.pasos],
                     "hallazgos": [{"id": h.id, "regla": h.regla, "titulo": h.titulo, "justificacion": h.justificacion,
                                    "evidencia": h.evidencia[:25]} for h in i.hallazgos],
                     "acciones": i.acciones})
    a = inf["alcance"]
    return json.dumps({"alcance": {k: str(v) for k, v in a.items()}, "limitaciones": inf["limitaciones"],
                       "incidentes": incs}, ensure_ascii=False)


_ID = re.compile(r"EVT-\d{5}")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def validar_narrativa(texto: str, df: pd.DataFrame) -> dict:
    """Devuelve los Log_ID e IPs citados que NO existen en los logs."""
    ids_ok, ips_ok = set(df["Log_ID"]), set(df["Source_IP"]) | set(df["Destination"].astype(str))
    ids_mal = sorted(set(_ID.findall(texto)) - ids_ok)
    ips_mal = sorted(i for i in set(_IP.findall(texto)) if not any(i in d for d in ips_ok))
    return {"ids_inexistentes": ids_mal, "ips_inexistentes": ips_mal, "ok": not ids_mal and not ips_mal,
            "ids_citados": len(set(_ID.findall(texto)))}


def clave_api() -> str | None:
    try:
        import streamlit as st
        if "ANTHROPIC_API_KEY" in st.secrets:
            return st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        pass
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass
    return os.getenv("ANTHROPIC_API_KEY")


def redactar(inf: dict, df: pd.DataFrame, api_key: str | None = None, cliente=None) -> dict:
    """Llama a Claude y valida la respuesta. `cliente` permite inyectar uno falso en pruebas."""
    if cliente is None:
        key = api_key or clave_api()
        if not key:
            raise RuntimeError("Falta ANTHROPIC_API_KEY (en .streamlit/secrets.toml o en el entorno).")
        import anthropic
        cliente = anthropic.Anthropic(api_key=key)
    r = cliente.messages.create(model=MODELO, max_tokens=3000, system=SISTEMA,
                                messages=[{"role": "user", "content": "Datos verificados:\n" + contexto_ia(inf)}])
    texto = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
    return {"texto": texto, "validacion": validar_narrativa(texto, df)}