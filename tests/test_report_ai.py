from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import ai, charts
from src.correlation import correlacionar
from src.detectors import explorador, run_all
from src.loader import load_siem
from src.report import a_markdown, construir_informe, formato_periodo

EXCEL = Path(__file__).resolve().parents[1] / "data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
pytestmark = pytest.mark.skipif(not EXCEL.exists(), reason="Excel no disponible")


@lru_cache(maxsize=1)
def _real():
    df = load_siem(str(EXCEL))
    h = run_all(df, [])
    i = correlacionar(df, h)
    return df, h, i, explorador(df, h, i), construir_informe(df, h, i)


class ClienteFalso:
    def __init__(self, texto):
        self.messages = SimpleNamespace(create=lambda **kw: SimpleNamespace(
            content=[SimpleNamespace(type="text", text=texto)]))


def test_datos_graficos_suman_todos_los_eventos():
    df, _, _, ex, _ = _real()
    assert charts.datos_severidad_eventos(ex)["Eventos"].sum() == len(df)
    assert charts.datos_linea_tiempo(df, ex)["Eventos"].sum() == len(df)
    assert charts.datos_causa_raiz(ex)["Eventos"].sum() == (ex["Hallazgo"] != "").sum()


def test_gantt_un_registro_por_incidente():
    _, _, inc, _, _ = _real()
    d = charts.datos_incidentes(inc)
    assert len(d) == 6 and (d["Fin"] > d["Inicio"]).all()


def test_informe_cifras_coinciden_con_los_datos():
    df, h, inc, _, inf = _real()
    a = inf["alcance"]
    assert a["eventos"] == len(df) == 715
    assert a["eventos_con_hallazgo"] + a["eventos_sin_hallazgo"] == len(df)
    assert sum(inf["hallazgos_por_severidad"].values()) == len(h) == 18
    assert sum(inf["incidentes_por_severidad"].values()) == 6


def test_markdown_cita_solo_ids_existentes():
    df, _, _, _, inf = _real()
    md = a_markdown(inf)
    assert all(i in md for i in ["INC-01", "INC-06", "no confirmada"])
    assert ai.validar_narrativa(md, df)["ok"]


def test_validacion_detecta_ids_e_ips_inventados():
    df, *_ = _real()
    v = ai.validar_narrativa("Ver EVT-99999 y EVT-00123 desde 203.0.113.74 y 8.8.8.8", df)
    assert v["ids_inexistentes"] == ["EVT-99999"] and v["ips_inexistentes"] == ["8.8.8.8"] and not v["ok"]


def test_redactar_con_cliente_falso_valida_salida():
    df, _, _, _, inf = _real()
    buena = ai.redactar(inf, df, cliente=ClienteFalso("INC-01: spraying desde 203.0.113.74 (EVT-00123)."))
    mala = ai.redactar(inf, df, cliente=ClienteFalso("INC-01 involucra EVT-77777."))
    assert buena["validacion"]["ok"] and not mala["validacion"]["ok"]


def test_contexto_ia_solo_contiene_hechos_de_los_logs():
    df, _, _, _, inf = _real()
    ctx = ai.contexto_ia(inf)
    assert ai.validar_narrativa(ctx, df)["ok"] and "relaciones_no_confirmadas" in ctx


def test_sin_clave_error_claro():
    df, _, _, _, inf = _real()
    original = ai.clave_api
    ai.clave_api = lambda: None
    try:
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            ai.redactar(inf, df)
    finally:
        ai.clave_api = original


def test_formato_periodo_real():
    df, *_ = _real()
    p = formato_periodo(df["Timestamp"].min(), df["Timestamp"].max())
    assert p == {"fecha": "23 de octubre de 2026", "rango": "07:46 – 13:44", "duracion": "5 h 58 min"}


def test_tabla_html_escapa_y_colorea():
    import pandas as pd
    from src.tablas import tabla_html
    t = tabla_html(pd.DataFrame({"Severidad": ["Crítico"], "X": ["<script>CORP\\admin"]}), sev_col="Severidad")
    assert "&lt;script&gt;" in t and "<script>" not in t and "#ff6b6b" in t


def test_explorador_con_estilo():
    from src.tablas import styler_explorador
    _, _, _, ex, _ = _real()
    html = styler_explorador(ex.head(5)).to_html()
    assert "background-color: #0a1224" in html and "EVT-" in html


def test_inventario_cuadra_con_los_datos():
    from src.inventario import tabla_cuentas, tabla_hosts, tabla_ips_externas
    df, _, _, ex, _ = _real()
    h, c, ips = tabla_hosts(df, ex), tabla_cuentas(df, ex), tabla_ips_externas(df, ex)
    assert len(h) == df["Host"].nunique() and h["Eventos"].sum() == len(df)
    assert len(ips) == df.loc[df["Externa"], "Source_IP"].nunique() == 3
    assert ips["Eventos"].sum() == df["Externa"].sum()
    assert c["Eventos"].sum() == (~df["User"].isin(["-", ""])).sum()
    fila = ips.set_index("IP externa").loc["203.0.113.74"]
    assert fila["Fallos de login (4625)"] == 33 and fila["Cuentas"] == 8 and fila["Incidentes"] == "INC-01"
    norm = c.set_index("Cuenta").loc["CORP\\mruiz"]
    assert norm["Severidad máx."] == "Normal" and norm["Incidentes"] == "—"


def test_tabla_html_recorta_con_tooltip():
    import pandas as pd
    from src.tablas import tabla_html
    t = tabla_html(pd.DataFrame({"x": ["a" * 100]}), max_chars=20)
    assert "…" in t and 'title="' + "a" * 100 in t