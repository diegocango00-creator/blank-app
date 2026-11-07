"""Tablas con buen contraste sobre el tema oscuro. Pandas puro (sin Streamlit) para poder probarlas."""
from __future__ import annotations

from html import escape

import pandas as pd

# colores de texto (más claros que los de relleno para que contrasten sobre fondo oscuro)
TXT_SEV = {"Crítico": "#ff6b6b", "Alto": "#ffa94d", "Medio": "#ffd43b", "Bajo": "#4ade80", "Normal": "#9fb0cc"}


def _celda(v, fecha: bool = False) -> str:
    if isinstance(v, pd.Timestamp):
        return v.strftime("%Y-%m-%d %H:%M:%S" if fecha else "%H:%M:%S")
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    return str(v)


def tabla_html(df: pd.DataFrame, sev_col: str | None = None, max_alto: int = 340, max_chars: int | None = None,
               fecha: bool = False) -> str:
    """Tabla HTML escapada, con cabecera fija y desplazamiento vertical. `max_chars` recorta textos largos
    (el texto completo queda en el tooltip); `fecha` muestra fecha y hora en los Timestamp."""
    cab = "".join(f"<th>{escape(str(c))}</th>" for c in df.columns)
    filas = []
    for _, r in df.iterrows():
        tds = []
        for c in df.columns:
            crudo = _celda(r[c], fecha)
            largo = max_chars is not None and len(crudo) > max_chars
            txt = escape(crudo[:max_chars].rstrip() + "…" if largo else crudo)
            if c == sev_col and r[c] in TXT_SEV:
                txt = f'<b style="color:{TXT_SEV[r[c]]}">{txt}</b>'
            corto = ' class="corto"' if len(crudo) <= 26 else ""   # IDs, horas e IPs no se parten
            tip = f' title="{escape(crudo, quote=True)}"' if largo else ""
            tds.append(f"<td{corto}{tip}>{txt}</td>")
        filas.append("<tr>" + "".join(tds) + "</tr>")
    return (f'<div class="scroll-soc" style="max-height:{max_alto}px"><table class="tabla-soc">'
            f"<thead><tr>{cab}</tr></thead><tbody>{''.join(filas)}</tbody></table></div>")


def styler_explorador(ex: pd.DataFrame):
    """Estilo para st.dataframe: texto claro sobre fondo azul noche y severidad final coloreada."""
    def col(v):
        return f"color:{TXT_SEV.get(v, '#f1f5ff')};font-weight:700"
    s = ex.style.set_properties(**{"color": "#f1f5ff", "background-color": "#0a1224"})
    cols = [c for c in ("Severidad final", "Severidad SIEM") if c in ex.columns]
    # el SIEM usa Critical/Warning/Informational: solo se colorea la severidad final (la nuestra)
    s = s.map(col, subset=["Severidad final"]) if "Severidad final" in cols else s
    if "Timestamp" in ex.columns:
        s = s.format({"Timestamp": "{:%Y-%m-%d %H:%M:%S}"})
    return s