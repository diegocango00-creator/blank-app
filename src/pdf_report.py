"""PDF con reportlab: informe técnico (Tier-1/2) e informe ejecutivo (C-Level).
Todo el contenido sale de hallazgos/incidentes; la narrativa de IA, si se incluye, va en una sección aparte."""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .detectors.base import SEVERIDADES

COL = {"Crítico": "#dc2626", "Alto": "#ea580c", "Medio": "#ca8a04", "Bajo": "#16a34a", "Normal": "#64748b"}
AZUL, GRIS = colors.HexColor("#0f172a"), colors.HexColor("#475569")
_REEMPLAZOS = {"→": "->", "↔": "<->", "≥": ">=", "≤": "<=", "…": "...", "—": "-", "–": "-", "✨": "", "⚠️": "", "“": '"', "”": '"'}


def _t(x) -> str:
    """Texto seguro para Helvetica (WinAnsi) y para el marcado de Paragraph."""
    s = str(x)
    for a, b in _REEMPLAZOS.items():
        s = s.replace(a, b)
    return escape(s.encode("cp1252", "replace").decode("cp1252"))


def _estilos():
    b = getSampleStyleSheet()
    return {
        "t": ParagraphStyle("t", parent=b["Title"], fontSize=22, textColor=AZUL, alignment=TA_LEFT, spaceAfter=4),
        "sub": ParagraphStyle("sub", parent=b["Normal"], fontSize=10, textColor=GRIS, spaceAfter=10),
        "h1": ParagraphStyle("h1", parent=b["Heading1"], fontSize=15, textColor=AZUL, spaceBefore=10, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=b["Heading2"], fontSize=12, textColor=AZUL, spaceBefore=8, spaceAfter=4),
        "p": ParagraphStyle("p", parent=b["Normal"], fontSize=9.5, leading=13, spaceAfter=4),
        "s": ParagraphStyle("s", parent=b["Normal"], fontSize=7.5, leading=9.5),
        "b": ParagraphStyle("b", parent=b["Normal"], fontSize=9.5, leading=13, leftIndent=12, bulletIndent=2, spaceAfter=2),
        "nota": ParagraphStyle("nota", parent=b["Normal"], fontSize=8.5, leading=11, textColor=GRIS),
    }


def _tabla(filas, anchos, cab=True, tam=8, sev_col=None):
    S = ParagraphStyle("c", fontSize=tam, leading=tam + 2)
    datos = []
    for i, f in enumerate(filas):
        fila = []
        for j, c in enumerate(f):
            if cab and i == 0:
                fila.append(Paragraph(f'<font color="white"><b>{_t(c)}</b></font>', S))
            elif sev_col == j and c in COL:
                fila.append(Paragraph(f'<font color="{COL[c]}"><b>{_t(c)}</b></font>', S))
            else:
                fila.append(Paragraph(_t(c), S))
        datos.append(fila)
    t = Table(datos, colWidths=anchos, repeatRows=1 if cab else 0)
    est = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]
    if cab:
        est.append(("BACKGROUND", (0, 0), (-1, 0), AZUL))
    t.setStyle(TableStyle(est))
    return t


def _pie(c, d):
    c.saveState()
    c.setFont("Helvetica", 7.5)
    c.setFillColor(GRIS)
    c.drawString(1.8 * cm, 1.1 * cm, "SOC Log-to-Inform - generado solo a partir de los registros del SIEM")
    c.drawRightString(A4[0] - 1.8 * cm, 1.1 * cm, f"Pagina {d.page}")
    c.restoreState()


def _doc(titulo):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm, topMargin=1.6 * cm,
                            bottomMargin=1.8 * cm, title=titulo, author="SOC Log-to-Inform")
    return buf, doc


# ---------- gráficos (matplotlib) ----------
def _png(fig, w_cm, h_cm):
    import matplotlib.pyplot as plt
    b = io.BytesIO()
    fig.savefig(b, format="png", dpi=170, bbox_inches="tight")
    plt.close(fig)
    b.seek(0)
    return Image(b, width=w_cm * cm, height=h_cm * cm)


def _graf_resumen(ex, incidentes):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.2), gridspec_kw={"width_ratios": [1, 1.5]})
    c = ex["Severidad final"].value_counts().reindex([*SEVERIDADES, "Normal"], fill_value=0)
    c = c[c > 0]
    ax[0].pie(c.values, labels=[f"{k} ({v})" for k, v in c.items()], colors=[COL[k] for k in c.index],
              wedgeprops=dict(width=0.45), textprops=dict(fontsize=8), startangle=90)
    ax[0].set_title("Eventos por severidad final", fontsize=9)
    for k, inc in enumerate(incidentes):
        ini = inc.inicio.hour + inc.inicio.minute / 60
        dur = max((inc.fin - inc.inicio).total_seconds() / 3600, 0.05)
        ax[1].barh(k, dur, left=ini, color=COL[inc.severidad])
        ax[1].text(ini + dur + 0.04, k, inc.id, va="center", fontsize=7.5)
    ax[1].set_yticks([]); ax[1].invert_yaxis()
    ax[1].set_xlabel("Hora del día", fontsize=8); ax[1].tick_params(labelsize=8)
    ax[1].set_title("Incidentes en el tiempo", fontsize=9)
    for s in ("top", "right", "left"):
        ax[1].spines[s].set_visible(False)
    return _png(fig, 17, 6)


# ---------- contenido derivado de los datos ----------
def impactos(inc) -> list[str]:
    """Impacto observable, en lenguaje claro, solo desde métricas de los hallazgos."""
    out = []
    for f in inc.hallazgos:
        m = f.metricas
        if f.regla == "EXF-01":
            out.append(f"Salida de {m.get('mb')} MB hacia {f.ips[0] if f.ips else 'un destino externo'} (posible fuga de datos).")
        elif f.regla == "DATA-01":
            out.append(f"Acceso a {m.get('archivos', 'varios')} archivos de un recurso compartido.")
        elif f.regla == "CMD-02":
            out.append("Eliminación de copias de seguridad/sombra (dificulta la recuperación).")
        elif f.regla == "PERS-01":
            out.append("Mecanismo de persistencia: el atacante podría volver a entrar.")
        elif f.regla in ("AUTH-01", "AUTH-02"):
            out.append("Intentos masivos de contraseña" + (" con acceso exitoso posterior." if "Inicios sospechosos" in f.etiquetas or inc.ips_externas else "."))
        elif f.regla in ("LAT-01", "LAT-02"):
            out.append("Desplazamiento hacia otros equipos de la red.")
        elif f.regla == "WEB-01":
            out.append("Ataque contra el servidor web expuesto.")
    return list(dict.fromkeys(out))


def _portada(E, titulo, sub, inf, incidentes):
    a = inf["alcance"]
    cab = [Paragraph(_t(titulo), E["t"]),
           Paragraph(_t(f"{sub} - Periodo analizado: {a['inicio']:%Y-%m-%d %H:%M} a {a['fin']:%H:%M}"), E["sub"])]
    kp = [["Eventos", "Hosts", "Cuentas", "IPs externas", "Incidentes", "Críticos"],
          [a["eventos"], a["hosts"], a["usuarios"], len(a["ips_externas"]), len(incidentes),
           inf["incidentes_por_severidad"].get("Crítico", 0)]]
    t = Table([[Paragraph(f"<b>{_t(x)}</b>", ParagraphStyle("k", fontSize=14 if i else 8, alignment=1,
                                                              textColor=AZUL if i else GRIS, leading=18)) for x in r]
               for i, r in enumerate(kp)], colWidths=[2.85 * cm] * 6)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                           ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1"))]))
    return cab + [t, Spacer(1, 8)]


def _limites(E, inf):
    return [Paragraph("Limitaciones", E["h1"])] + [Paragraph(_t(x), E["b"], bulletText="-") for x in inf["limitaciones"]]


# ---------- informe técnico ----------
def pdf_tecnico(df: pd.DataFrame, hallazgos, incidentes, inf: dict, ex: pd.DataFrame, narrativa: dict | None = None) -> bytes:
    E = _estilos()
    buf, doc = _doc("Informe técnico de incidente de seguridad")
    h = _portada(E, "Informe técnico de incidente de seguridad", "Audiencia: SOC Tier-1/Tier-2", inf, incidentes)
    h += [_graf_resumen(ex, incidentes), Paragraph("Resumen", E["h1"]),
          Paragraph(_t("Incidentes: " + ", ".join(f"{n} {s}" for s, n in inf["incidentes_por_severidad"].items() if n)
                       + ". Hallazgos: " + ", ".join(f"{n} {s}" for s, n in inf["hallazgos_por_severidad"].items() if n) + "."), E["p"]),
          Paragraph(_t("Por categoría: " + "; ".join(f"{c}: {n}" for c, n in inf["categorias"].items()) + "."), E["p"]),
          Paragraph(_t(f"Eventos respaldados por algún hallazgo: {inf['alcance']['eventos_con_hallazgo']} de "
                       f"{inf['alcance']['eventos']}. Alertas del SIEM sin explicar: {inf['alertas_siem_sin_explicar']}. "
                       f"Hallazgos cuya severidad el SIEM subestimó: {len(inf['hallazgos_subestimados_por_siem'])}."), E["p"])]
    tabla = [["ID", "Severidad", "Resumen", "Inicio-Fin"]] + [[i.id, i.severidad, i.titulo, f"{i.inicio:%H:%M}-{i.fin:%H:%M}"] for i in incidentes]
    h += [Spacer(1, 4), _tabla(tabla, [1.5 * cm, 2 * cm, 11.2 * cm, 2.5 * cm], sev_col=1, tam=8.5)]
    if narrativa:
        v = narrativa["validacion"]
        h += [PageBreak(), Paragraph("Análisis redactado con IA", E["h1"]),
              Paragraph(_t("Validación contra los logs: " + ("todos los Log_ID e IPs citados existen." if v["ok"] else
                           f"ATENCIÓN, citó datos inexistentes: {v['ids_inexistentes'] + v['ips_inexistentes']}")), E["nota"])]
        h += [Paragraph(_t(p), E["p"]) for p in narrativa["texto"].strip().split("\n\n")]
    for inc in incidentes:
        bloque = [PageBreak(), Paragraph(_t(f"{inc.id} - {inc.severidad}"), E["h1"]), Paragraph(_t(inc.titulo), E["h2"]),
                  Paragraph(_t(inc.resumen), E["p"]), Paragraph(_t(inc.justificacion_severidad), E["p"])]
        bloque += [Paragraph(_t(r), E["nota"]) for r in inc.relacionados]
        bloque += [Paragraph("Cadena de ataque", E["h2"]),
                   _tabla([["Hora", "Fase", "Hallazgo", "Evento", "Severidad"]] +
                          [[f"{p.hora:%H:%M:%S}", p.fase, p.hallazgo, p.log_id, p.severidad] for p in inc.pasos],
                          [2 * cm, 5.5 * cm, 2 * cm, 2.5 * cm, 2.5 * cm], sev_col=4),
                   Paragraph("Hallazgos", E["h2"])]
        for f in inc.hallazgos:
            bloque += [Paragraph(_t(f"{f.id} [{f.severidad}] {f.titulo}"), E["p"]),
                       Paragraph(_t(f"{f.justificacion} | Regla {f.regla} | MITRE: {', '.join(f.mitre) or '-'} | "
                                    f"Evidencia: {len(f.evidencia)} eventos"), E["nota"])]
        bloque += [Paragraph("Acciones recomendadas", E["h2"])] + [Paragraph(_t(a), E["b"], bulletText="-") for a in inc.acciones]
        ev = inc.evidencia_df(df)
        filas = [["Log_ID", "Hora", "Host", "Evento", "Cuenta", "IP origen", "Descripción / comando"]]
        for _, r in ev.iterrows():
            filas.append([r["Log_ID"], f"{r['Timestamp']:%H:%M:%S}", r["Host"], r["Event_ID"], r["User"], r["Source_IP"],
                          (str(r["Process_CommandLine"]) if str(r["Process_CommandLine"]).strip() not in ("", "nan", "-")
                           else str(r["Event_Description"]))[:90]])
        bloque += [Paragraph(f"Evidencia ({len(ev)} eventos)", E["h2"]),
                   _tabla(filas, [1.9 * cm, 1.5 * cm, 1.8 * cm, 1.2 * cm, 2.4 * cm, 2.3 * cm, 6.1 * cm], tam=6.5)]
        h += bloque
    h += [PageBreak()] + _limites(E, inf)
    doc.build(h, onFirstPage=_pie, onLaterPages=_pie)
    return buf.getvalue()


# ---------- informe ejecutivo ----------
def pdf_ejecutivo(df: pd.DataFrame, hallazgos, incidentes, inf: dict, ex: pd.DataFrame) -> bytes:
    E = _estilos()
    buf, doc = _doc("Informe ejecutivo de incidente de seguridad")
    n_crit = inf["incidentes_por_severidad"].get("Crítico", 0)
    a = inf["alcance"]
    h = _portada(E, "Informe ejecutivo de seguridad", "Audiencia: dirección", inf, incidentes)
    h += [Paragraph("Situación", E["h1"]),
          Paragraph(_t(f"El análisis de {a['eventos']} registros del SIEM ({a['inicio']:%Y-%m-%d}, {a['inicio']:%H:%M} a {a['fin']:%H:%M}) "
                       f"identificó {len(incidentes)} incidentes de seguridad, {n_crit} de ellos de severidad Crítica. "
                       f"{len(a['ips_externas'])} direcciones externas aparecen asociadas a la actividad maliciosa. "
                       f"Cada conclusión está respaldada por eventos concretos del registro."), E["p"]),
          _graf_resumen(ex, incidentes), Paragraph("Qué ocurrió", E["h1"])]
    for inc in incidentes:
        imp = impactos(inc)
        h.append(KeepTogether([
            Paragraph(f'<font color="{COL[inc.severidad]}"><b>{_t(inc.id)} - {_t(inc.severidad)}</b></font> '
                      f'({inc.inicio:%H:%M}-{inc.fin:%H:%M}, {_t(", ".join(inc.hosts))})', E["p"]),
            Paragraph(_t(inc.titulo), E["b"], bulletText="-"),
            *[Paragraph(_t(x), E["b"], bulletText="-") for x in imp],
            *[Paragraph(_t(r), E["nota"]) for r in inc.relacionados]]))
    h.append(Paragraph("Acciones prioritarias", E["h1"]))
    prio = [["Prioridad", "Incidente", "Acción"]]
    vistos = set()
    for k, inc in enumerate(incidentes):
        for a_ in inc.acciones[:2]:
            if a_ not in vistos:
                vistos.add(a_)
                prio.append(["Inmediata" if inc.severidad == "Crítico" else "Corto plazo", inc.id, a_])
    h.append(_tabla(prio, [2.3 * cm, 1.7 * cm, 13.2 * cm], tam=8))
    h += [Spacer(1, 6)] + _limites(E, inf)
    doc.build(h, onFirstPage=_pie, onLaterPages=_pie)
    return buf.getvalue()