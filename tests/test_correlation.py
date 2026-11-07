from functools import lru_cache
from pathlib import Path

import pytest

from src.correlation import correlacionar
from src.detectors import explorador, run_all
from src.loader import load_siem

EXCEL = Path(__file__).resolve().parents[1] / "data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
pytestmark = pytest.mark.skipif(not EXCEL.exists(), reason="Excel no disponible")


@lru_cache(maxsize=1)
def _real():
    df = load_siem(str(EXCEL))
    h = run_all(df, [])
    return df, h, correlacionar(df, h)


def test_seis_incidentes_cada_hallazgo_una_vez():
    real = _real()
    _, h, inc = real
    ids = [f.id for i in inc for f in i.hallazgos]
    assert len(inc) == 6 and sorted(ids) == sorted(f.id for f in h)
    assert [i.severidad for i in inc].count("Crítico") == 5 and [i.severidad for i in inc].count("Alto") == 1


def test_cadena_admin_en_orden():
    real = _real()
    _, _, inc = real
    adm = next(i for i in inc if "198.51.100.77" in i.ips_externas)
    horas = [p.hora for p in adm.pasos]
    assert horas == sorted(horas)
    fases = [p.fase for p in adm.pasos]
    assert fases.index("Ejecución") < fases.index("Movimiento lateral")


def test_relacion_fs_srv01_es_posible_no_confirmada():
    real = _real()
    _, _, inc = real
    con = [i for i in inc if i.relacionados]
    assert len(con) == 2 and all("no confirmada" in r and "FS-SRV01" in r for i in con for r in i.relacionados)
    assert not any(set(a.evidencia) & set(b.evidencia) for a in con for b in con if a is not b)


def test_cada_incidente_tiene_justificacion_y_evidencia():
    real = _real()
    df, _, inc = real
    for i in inc:
        assert i.justificacion_severidad and i.evidencia and i.acciones
        assert set(p.log_id for p in i.pasos) <= set(i.evidencia)
        assert set(i.evidencia) <= set(df["Log_ID"])


def test_incidentes_no_mezclan_cuentas_ruido():
    real = _real()
    _, _, inc = real
    assert not {a for i in inc for a in i.actores} & {"CORP\\mruiz", "CORP\\svc_backup"}


def test_explorador_incluye_incidente():
    real = _real()
    df, h, inc = real
    ex = explorador(df, h, inc)
    assert len(ex) == len(df) and (ex["Incidente"] != "").sum() == len({l for i in inc for l in i.evidencia})


def test_sin_hallazgos():
    real = _real()
    df, _, _ = real
    assert correlacionar(df, []) == []