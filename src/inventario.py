"""Tablas comparativas de hosts, cuentas e IPs externas. Pandas puro: solo cuenta y resume lo que hay en los logs.
Severidad máx. e Incidentes salen de los hallazgos/incidentes que usan cada entidad como evidencia."""
from __future__ import annotations

import pandas as pd

ORDEN = ["Crítico", "Alto", "Medio", "Bajo", "Normal"]


def _hora(t: pd.Timestamp) -> str:
    return f"{t:%H:%M:%S}"


def _enriquecer(df: pd.DataFrame, ex: pd.DataFrame) -> pd.DataFrame:
    cols = ["Log_ID", "Severidad final"] + (["Incidente"] if "Incidente" in ex.columns else [])
    d = df.merge(ex[cols], on="Log_ID", how="left")
    if "Incidente" not in d:
        d["Incidente"] = ""
    d["Incidente"] = d["Incidente"].fillna("")
    d["Severidad final"] = d["Severidad final"].fillna("Normal")
    return d


def _comunes(g: pd.DataFrame) -> dict:
    sev = min(g["Severidad final"], key=ORDEN.index)
    incs = sorted({i for i in g["Incidente"] if i})
    return {"Primer evento": _hora(g["Timestamp"].min()), "Último evento": _hora(g["Timestamp"].max()),
            "Eventos con hallazgo": int((g["Severidad final"] != "Normal").sum()),
            "Incidentes": ", ".join(incs) or "—", "Severidad máx.": sev}


def _ordenar(t: pd.DataFrame) -> pd.DataFrame:
    t["_o"] = t["Severidad máx."].map(ORDEN.index)
    return t.sort_values(["_o", "Eventos"], ascending=[True, False]).drop(columns="_o").reset_index(drop=True)


def _validos(s: pd.Series) -> set:
    return {x for x in s if str(x).strip() not in ("", "-", "nan")}


def tabla_hosts(df: pd.DataFrame, ex: pd.DataFrame) -> pd.DataFrame:
    d = _enriquecer(df, ex)
    filas = []
    for host, g in d.groupby("Host"):
        filas.append({"Host": host, "Eventos": len(g), "Cuentas": len(_validos(g["User"])),
                      "IPs origen": len(_validos(g["Source_IP"])),
                      "IPs externas": len(_validos(g.loc[g["Externa"], "Source_IP"])),
                      "Fallos de login (4625)": int((g["Event_ID"] == "4625").sum()),
                      "Logins exitosos (4624)": int(((g["Event_ID"] == "4624") & (g["Result"] == "Success")).sum()),
                      "Alertas SIEM": int(g["Alerta_SIEM"].sum()), **_comunes(g)})
    return _ordenar(pd.DataFrame(filas))


def tabla_cuentas(df: pd.DataFrame, ex: pd.DataFrame) -> pd.DataFrame:
    d = _enriquecer(df, ex)
    d = d[~d["User"].astype(str).str.strip().isin(["", "-", "nan"])]
    filas = []
    for u, g in d.groupby("User"):
        filas.append({"Cuenta": u, "Eventos": len(g), "Hosts": len(_validos(g["Host"])),
                      "IPs origen": len(_validos(g["Source_IP"])),
                      "IPs externas": len(_validos(g.loc[g["Externa"], "Source_IP"])),
                      "Fallos de login (4625)": int((g["Event_ID"] == "4625").sum()),
                      "Logins exitosos (4624)": int(((g["Event_ID"] == "4624") & (g["Result"] == "Success")).sum()),
                      "Alertas SIEM": int(g["Alerta_SIEM"].sum()), **_comunes(g)})
    return _ordenar(pd.DataFrame(filas))


def tabla_ips_externas(df: pd.DataFrame, ex: pd.DataFrame) -> pd.DataFrame:
    d = _enriquecer(df, ex)
    d = d[d["Externa"]]
    filas = []
    for ip, g in d.groupby("Source_IP"):
        filas.append({"IP externa": ip, "Eventos": len(g), "Cuentas": len(_validos(g["User"])),
                      "Hosts": len(_validos(g["Host"])),
                      "Fallos de login (4625)": int((g["Event_ID"] == "4625").sum()),
                      "Logins exitosos (4624)": int(((g["Event_ID"] == "4624") & (g["Result"] == "Success")).sum()),
                      "Alertas SIEM": int(g["Alerta_SIEM"].sum()), **_comunes(g)})
    return _ordenar(pd.DataFrame(filas))