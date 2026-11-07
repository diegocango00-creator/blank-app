"""Gráficos del dashboard. Las funciones `datos_*` son pandas puro (se pueden probar); las `fig_*` solo dibujan."""
from __future__ import annotations

import pandas as pd

from .detectors.base import SEVERIDADES

COLOR_SEV = {"Crítico": "#ef4444", "Alto": "#f97316", "Medio": "#eab308", "Bajo": "#22c55e", "Normal": "#4a6fa5"}
_FONDO = "rgba(0,0,0,0)"


# ---------- datos ----------
def datos_severidad_eventos(ex: pd.DataFrame) -> pd.DataFrame:
    """Eventos por severidad final (explorador)."""
    orden = [*SEVERIDADES, "Normal"]
    c = ex["Severidad final"].value_counts().reindex(orden, fill_value=0)
    return c.rename_axis("Severidad").reset_index(name="Eventos")


def datos_causa_raiz(ex: pd.DataFrame) -> pd.DataFrame:
    """Eventos por causa raíz (solo los explicados por un hallazgo)."""
    d = ex[ex["Hallazgo"] != ""]
    return (d.groupby(["Categoría", "Severidad final"]).size().reset_index(name="Eventos")
            .sort_values("Eventos", ascending=True))


def datos_linea_tiempo(df: pd.DataFrame, ex: pd.DataFrame, minutos: int = 10) -> pd.DataFrame:
    """Eventos por ventana de tiempo, separando normales de los que pertenecen a un hallazgo."""
    t = pd.DataFrame({"Hora": df["Timestamp"].dt.floor(f"{minutos}min"),
                      "Tipo": ex["Hallazgo"].ne("").map({True: "Asociado a hallazgo", False: "Operación normal"})})
    return t.groupby(["Hora", "Tipo"]).size().reset_index(name="Eventos")


def datos_incidentes(incidentes) -> pd.DataFrame:
    return pd.DataFrame([{"Incidente": i.id, "Inicio": i.inicio, "Fin": max(i.fin, i.inicio + pd.Timedelta(minutes=1)),
                          "Severidad": i.severidad, "Etiqueta": i.id, "Resumen": i.titulo} for i in incidentes])


# ---------- figuras ----------
TEXTO = "#f1f5ff"
EJE = dict(tickfont=dict(color="#dbe4f5", size=13), title_font=dict(color=TEXTO, size=14),
           gridcolor="rgba(90,160,255,.20)", linecolor="rgba(90,160,255,.55)", zerolinecolor="rgba(90,160,255,.35)")


def _estilo(fig, alto=320):
    """Estilo explícito (se usa con theme=None en st.plotly_chart): texto claro, rejilla azul tenue, tooltip oscuro."""
    fig.update_layout(height=alto, paper_bgcolor=_FONDO, plot_bgcolor=_FONDO,
                      font=dict(family="Barlow Condensed, Arial Narrow, sans-serif", size=14, color=TEXTO),
                      title=dict(font=dict(size=19, color="#ffffff")),
                      legend=dict(font=dict(color=TEXTO, size=13), title_text=""),
                      hoverlabel=dict(bgcolor="#0a1224", bordercolor="#2f6bff", font=dict(color="#ffffff", size=13)),
                      autosize=True, margin=dict(l=20, r=20, t=55, b=20))
    fig.update_xaxes(automargin=True, **EJE)
    fig.update_yaxes(automargin=True, **EJE)
    return fig


def fig_donut_severidad(ex: pd.DataFrame):
    import plotly.express as px
    d = datos_severidad_eventos(ex)
    fig = px.pie(d, names="Severidad", values="Eventos", hole=0.6, color="Severidad", color_discrete_map=COLOR_SEV,
                 title="Eventos por severidad final")
    fig.update_traces(sort=False, textinfo="value", textposition="inside",
                      textfont=dict(color=TEXTO, size=14), marker=dict(line=dict(color="#04070f", width=2)))
    fig = _estilo(fig)
    fig.update_layout(legend=dict(orientation="h", yanchor="top", y=-0.02, xanchor="center", x=0.5), margin=dict(b=55))
    return fig


def fig_causa_raiz(ex: pd.DataFrame):
    import plotly.express as px
    d = datos_causa_raiz(ex)
    fig = px.bar(d, x="Eventos", y="Categoría", color="Severidad final", orientation="h",
                 color_discrete_map=COLOR_SEV, title="Causa raíz: eventos explicados por categoría")
    return _estilo(fig)


def fig_linea_tiempo(df: pd.DataFrame, ex: pd.DataFrame):
    import plotly.express as px
    fig = px.bar(datos_linea_tiempo(df, ex), x="Hora", y="Eventos", color="Tipo",
                 color_discrete_map={"Asociado a hallazgo": "#ef4444", "Operación normal": "#4a6fa5"},
                 title="Actividad en el tiempo (ventanas de 10 min)")
    return _estilo(fig)


def fig_gantt_incidentes(incidentes):
    import plotly.express as px
    d = datos_incidentes(incidentes)
    fig = px.timeline(d, x_start="Inicio", x_end="Fin", y="Etiqueta", color="Severidad", color_discrete_map=COLOR_SEV,
                      hover_data={"Resumen": True, "Etiqueta": False}, title="Incidentes en el tiempo")
    fig.update_yaxes(autorange="reversed", title="")
    return _estilo(fig, 60 + 45 * max(len(d), 1))