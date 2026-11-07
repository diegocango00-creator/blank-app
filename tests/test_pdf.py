import io
from functools import lru_cache
from pathlib import Path

import pytest

from src import pdf_report as P
from src.correlation import correlacionar
from src.detectors import explorador, run_all
from src.loader import load_siem
from src.report import construir_informe

EXCEL = Path(__file__).resolve().parents[1] / "data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
pytestmark = pytest.mark.skipif(not EXCEL.exists(), reason="Excel no disponible")


@lru_cache(maxsize=1)
def _real():
    df = load_siem(str(EXCEL))
    h = run_all(df, [])
    i = correlacionar(df, h)
    return df, h, i, explorador(df, h, i), construir_informe(df, h, i)


def test_pdfs_validos_y_ejecutivo_corto():
    df, h, i, ex, inf = _real()
    tec, eje = P.pdf_tecnico(df, h, i, inf, ex), P.pdf_ejecutivo(df, h, i, inf, ex)
    assert tec.startswith(b"%PDF") and eje.startswith(b"%PDF")
    assert eje.count(b"/Type /Page\n") + eje.count(b"/Type /Page ") + eje.count(b"/Type/Page") <= 3
    assert len(tec) > len(eje)


def test_pdf_tecnico_con_narrativa():
    df, h, i, ex, inf = _real()
    nar = {"texto": "INC-01 (EVT-00123).\n\nConclusión.", "validacion": {"ok": True, "ids_citados": 1, "ids_inexistentes": [], "ips_inexistentes": []}}
    assert P.pdf_tecnico(df, h, i, inf, ex, nar).startswith(b"%PDF")


def test_impactos_salen_de_los_datos():
    _, _, i, _, _ = _real()
    imp = {x.id: P.impactos(x) for x in i}
    assert any("253.3 MB" in t for t in sum(imp.values(), []))
    assert any("copias de seguridad" in t for t in imp["INC-03"])
    assert any("persistencia" in t for t in imp["INC-06"])


def test_texto_seguro_para_helvetica():
    assert P._t("A → B <x> & ñ").startswith("A -&gt; B") or "->" in P._t("A → B")