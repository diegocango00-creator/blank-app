"""Carga y normalización del Excel exportado del SIEM.

Principios:
- No se modifica ni se descarta información original: las columnas del Excel se conservan tal cual
  y la normalización se agrega en columnas nuevas (Host, Interna, Externa, ...).
- Si algo no se puede interpretar, se registra en df.attrs["advertencias"] en vez de ocultarlo.
"""
from __future__ import annotations

import ipaddress
import re
from typing import BinaryIO

import pandas as pd

COLUMNAS_REQUERIDAS = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
    "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity",
]

# Rangos privados RFC 1918. No se usa ipaddress.is_private porque también marca como "privados"
# los rangos de documentación (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), que aquí son atacantes.
REDES_INTERNAS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

HOJA_PREFERIDA = "SIEM Export"


class SiemFormatError(ValueError):
    """El archivo no tiene el formato esperado del export del SIEM."""


def _clasificar_ip(valor) -> tuple[bool, bool]:
    """Devuelve (ip_valida, es_interna)."""
    try:
        ip = ipaddress.ip_address(str(valor).strip())
    except ValueError:
        return False, False
    return True, any(ip in red for red in REDES_INTERNAS)


def _normalizar_host(nombre) -> str:
    """'DC01' y 'DC-01' son el mismo equipo. Solo se inserta guion si no tiene ninguno."""
    n = str(nombre).strip().upper()
    if "-" not in n:
        n = re.sub(r"^([A-Z]+)(\d+)$", r"\1-\2", n)
    return n


def normalizar(df: pd.DataFrame) -> pd.DataFrame:
    """Valida columnas y agrega columnas normalizadas. Devuelve un DataFrame nuevo ordenado por Timestamp."""
    faltan = [c for c in COLUMNAS_REQUERIDAS if c not in df.columns]
    if faltan:
        raise SiemFormatError(f"Faltan columnas requeridas: {', '.join(faltan)}")

    out = df[COLUMNAS_REQUERIDAS].copy()
    advertencias: list[str] = []

    for c in out.columns:
        if c != "Timestamp":
            out[c] = out[c].fillna("").astype(str).str.strip()
    out["Event_ID"] = out["Event_ID"].str.replace(r"\.0$", "", regex=True)  # 4625.0 -> 4625

    out["Timestamp"] = pd.to_datetime(out["Timestamp"], errors="coerce")
    sin_fecha = out["Timestamp"].isna()
    if sin_fecha.any():
        ids = out.loc[sin_fecha, "Log_ID"].tolist()
        advertencias.append(f"{len(ids)} evento(s) sin Timestamp válido fueron excluidos: {', '.join(ids[:10])}")
        out = out[~sin_fecha]

    dup = out["Log_ID"].duplicated(keep=False)
    if dup.any():
        advertencias.append(f"{out.loc[dup, 'Log_ID'].nunique()} Log_ID duplicado(s); se conservan todas las filas")

    out["Host"] = out["Hostname"].map(_normalizar_host)
    alias = out.groupby("Host")["Hostname"].nunique()
    for host in alias[alias > 1].index:
        crudos = sorted(out.loc[out["Host"] == host, "Hostname"].unique())
        advertencias.append(f"Hostname unificado: {' / '.join(crudos)} -> {host}")

    clas = out["Source_IP"].map(_clasificar_ip)
    out["IP_valida"] = clas.str[0].astype(bool)
    out["Interna"] = clas.str[1].astype(bool)
    out["Externa"] = out["IP_valida"] & ~out["Interna"]
    out["Alerta_SIEM"] = out["Severity"].ne("Informational")

    out = out.sort_values(["Timestamp", "Log_ID"], kind="stable").reset_index(drop=True)
    out.attrs["advertencias"] = advertencias
    return out


FORMATOS = ["xlsx", "xlsm", "xls", "ods", "csv", "tsv", "txt", "json", "jsonl"]


def _extension(source, nombre: str | None) -> str:
    ref = nombre or getattr(source, "name", None) or (source if isinstance(source, str) else "")
    return str(ref).rsplit(".", 1)[-1].lower() if "." in str(ref) else ""


def _leer_tabla(source, ext: str) -> pd.DataFrame:
    """Lee el archivo según su formato y devuelve el DataFrame crudo (sin normalizar)."""
    if ext in ("xlsx", "xlsm", "xls", "ods"):
        xls = pd.ExcelFile(source)
        hoja = HOJA_PREFERIDA if HOJA_PREFERIDA in xls.sheet_names else xls.sheet_names[0]
        return xls.parse(hoja)
    if ext in ("json", "jsonl"):
        try:
            return pd.read_json(source, lines=(ext == "jsonl"), dtype=False)
        except ValueError:                      # .json con un objeto por línea, o .jsonl con un arreglo
            if hasattr(source, "seek"):
                source.seek(0)
            return pd.read_json(source, lines=(ext != "jsonl"), dtype=False)
    # csv / tsv / txt: el separador se detecta solo; se prueba UTF-8 y luego Latin-1
    for enc in ("utf-8-sig", "latin-1"):
        if hasattr(source, "seek"):
            source.seek(0)
        try:
            return pd.read_csv(source, sep=None, engine="python", dtype=str, encoding=enc)
        except UnicodeDecodeError:
            continue
    raise SiemFormatError("No se pudo decodificar el archivo de texto (se probó UTF-8 y Latin-1).")


def load_siem(source: str | BinaryIO, nombre: str | None = None) -> pd.DataFrame:
    """Lee el export del SIEM (ruta o archivo subido) en xlsx/xlsm/xls/ods/csv/tsv/txt/json/jsonl y lo normaliza.
    `nombre` permite indicar el formato cuando `source` no trae nombre."""
    ext = _extension(source, nombre)
    intentos = [ext] if ext in FORMATOS else ["xlsx", "csv", "json"]   # sin extensión conocida: se prueba cada lector
    ultimo = None
    for e in intentos:
        try:
            if hasattr(source, "seek"):
                source.seek(0)
            df = _leer_tabla(source, e)
        except SiemFormatError:
            raise
        except Exception as exc:
            ultimo = exc
            continue
        return normalizar(df)
    raise SiemFormatError(f"No se pudo leer el archivo ({', '.join(FORMATOS)} son los formatos admitidos): {ultimo}") from ultimo