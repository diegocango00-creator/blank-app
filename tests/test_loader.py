import io
from pathlib import Path

import pandas as pd
import pytest

from src.loader import SiemFormatError, load_siem, normalizar

EXCEL = Path(__file__).resolve().parents[1] / "data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def fila(i, ts="2026-01-01 10:00:00", ev="4625", user="CORP\\u1", ip="203.0.113.5", host="DC-01"):
    return {"Log_ID": f"EVT-{i:05d}", "Timestamp": ts, "Hostname": host, "Event_ID": ev, "User": user,
            "Source_IP": ip, "Destination": "", "Log_Source": "Security", "Event_Description": "x",
            "Process_CommandLine": "", "Result": "Failure", "Severity": "Warning"}


def test_ip_de_documentacion_cuenta_como_externa():
    # ipaddress.is_private marcaría 203.0.113.x como privada; en estos logs son los atacantes
    df = normalizar(pd.DataFrame([fila(1)]))
    assert bool(df.loc[0, "Externa"]) is True and bool(df.loc[0, "Interna"]) is False


def test_ip_rfc1918_es_interna():
    df = normalizar(pd.DataFrame([fila(1, ip="10.10.1.5"), fila(2, ip="192.168.0.7"), fila(3, ip="172.20.1.1")]))
    assert df["Interna"].all() and not df["Externa"].any()


def test_ip_invalida_no_es_ni_interna_ni_externa():
    df = normalizar(pd.DataFrame([fila(1, ip="-")]))
    assert not df.loc[0, "Interna"] and not df.loc[0, "Externa"] and not df.loc[0, "IP_valida"]


def test_unifica_hostnames():
    df = normalizar(pd.DataFrame([fila(1, host="DC01"), fila(2, host="DC-01")]))
    assert set(df["Host"]) == {"DC-01"}
    assert any("DC01" in a for a in df.attrs["advertencias"])


def test_columnas_faltantes():
    with pytest.raises(SiemFormatError):
        normalizar(pd.DataFrame({"Log_ID": ["a"]}))


def test_timestamp_invalido_se_excluye_y_se_avisa():
    df = normalizar(pd.DataFrame([fila(1), fila(2, ts="no es fecha")]))
    assert len(df) == 1 and any("EVT-00002" in a for a in df.attrs["advertencias"])


@pytest.mark.skipif(not EXCEL.exists(), reason="Excel de datos no disponible")
def test_excel_real_carga():
    df = load_siem(str(EXCEL))
    assert len(df) == 715 and df["Host"].nunique() == 10 and df["Timestamp"].is_monotonic_increasing


class _Archivo(io.BytesIO):
    def __init__(self, datos: bytes, name: str):
        super().__init__(datos)
        self.name = name


def _crudo():
    return pd.read_excel(EXCEL, sheet_name="SIEM Export")


@pytest.mark.skipif(not EXCEL.exists(), reason="Excel de datos no disponible")
@pytest.mark.parametrize("nombre", ["x.csv", "x.tsv", "x.txt", "x.json", "x.jsonl", "x.xlsx"])
def test_mismos_resultados_en_todos_los_formatos(nombre):
    base = _crudo()
    ext = nombre.rsplit(".", 1)[1]
    if ext in ("csv", "txt"):
        datos = base.to_csv(index=False).encode("utf-8")
    elif ext == "tsv":
        datos = base.to_csv(index=False, sep="\t").encode("latin-1", "replace")
    elif ext == "json":
        datos = base.to_json(orient="records", date_format="iso").encode()
    elif ext == "jsonl":
        datos = base.to_json(orient="records", lines=True, date_format="iso").encode()
    else:
        b = io.BytesIO(); base.to_excel(b, index=False, sheet_name="SIEM Export"); datos = b.getvalue()
    df = load_siem(_Archivo(datos, nombre), nombre)
    ref = load_siem(str(EXCEL))
    assert len(df) == len(ref) == 715 and set(df["Log_ID"]) == set(ref["Log_ID"])
    assert df["Host"].nunique() == 10 and int(df["Externa"].sum()) == int(ref["Externa"].sum())


def test_formato_no_valido():
    with pytest.raises(SiemFormatError):
        load_siem(_Archivo(b"\x00\x01\x02 no es una tabla", "x.bin"), "x.bin")