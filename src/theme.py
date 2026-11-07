"""Tema visual de la app: fondo azul noche, azul eléctrico, tipografía condensada en mayúsculas y líneas finas.
Solo estilo: no cambia ningún dato ni cálculo."""
from __future__ import annotations

import random

import streamlit as st

AZUL = "#2f6bff"
AZUL_CLARO = "#5aa0ff"
FUENTE = "'Barlow Condensed', 'Oswald', 'Arial Narrow', sans-serif"
TEXTO = "'Inter', 'Segoe UI', Roboto, Arial, sans-serif"

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap');
:root {{ --azul:{AZUL}; --azul2:{AZUL_CLARO}; --linea:rgba(90,160,255,.22); }}
html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {{ font-family:{TEXTO}; color:#f1f5ff; }}
[data-testid="stApp"] {{
  background: radial-gradient(1100px 600px at 78% 12%, rgba(47,107,255,.16), transparent 60%),
              radial-gradient(700px 500px at 5% 95%, rgba(47,107,255,.10), transparent 60%), #04070f;
}}
[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 1.2rem; max-width: 1280px; }}
/* texto de lectura: sans legible, sin tracking, alto contraste (IDs como EVT-00123 deben distinguirse) */
p, li, label, [data-testid="stMarkdownContainer"] {{ font-family:{TEXTO}; letter-spacing:0; color:#f1f5ff; }}
p, li {{ font-size:.97rem; line-height:1.55; }}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p, small {{ color:#c3cee4 !important; font-size:.88rem; }}
code {{ font-family:'JetBrains Mono','Fira Code',Consolas,monospace; color:#9fd0ff; background:rgba(47,107,255,.16); padding:.05em .35em; }}
strong, b {{ color:#ffffff; }}
h1, h2, h3, h4 {{ font-family:{FUENTE}; text-transform:uppercase; letter-spacing:.07em; font-weight:600; color:#ffffff; }}
h2 {{ border-left:4px solid var(--azul); padding-left:.6rem; }}

/* HERO */
.hero {{ position:relative; padding:1.2rem 0 1.6rem; margin-bottom:.5rem; border-bottom:1px solid var(--linea); overflow:hidden; }}
.hero-red {{ position:absolute; right:-40px; top:-30px; width:62%; height:130%; opacity:.9; pointer-events:none; }}
.hero-kicker {{ color:var(--azul2); font-weight:700; letter-spacing:.28em; font-size:1.15rem; }}
.hero h1 {{ margin:0; padding:0; border:0; font-size:clamp(2.6rem,6.2vw,5.4rem); line-height:.95; margin-top:.5rem; font-weight:500;
  letter-spacing:.03em; color:#e8ecf4; }}
.hero h1 .raya {{ display:inline-block; width:.55em; height:.09em; background:var(--azul); vertical-align:middle; margin-left:.25em; }}
.hero h1 .hueco {{ color:transparent; -webkit-text-stroke:2px #e8ecf4; }}
.hero-lateral {{ z-index:2; position:absolute; right:1rem; top:2.2rem; width:min(300px,26%); text-align:left; font-weight:600;
  letter-spacing:.14em; font-size:1.05rem; line-height:1.5; color:#e8ecf4; text-transform:uppercase; }}
.hero-lateral .marca {{ background:var(--azul); padding:.05rem .5rem; display:inline-block; margin:.1rem 0; }}
.hero-lateral .fina {{ height:1px; background:linear-gradient(90deg,var(--azul),transparent); margin:1rem 0; }}
.hero-resumen {{ margin-top:1.3rem; max-width:430px; border-left:3px solid var(--azul); padding-left:1rem; }}
.hero-resumen .tit {{ color:var(--azul2); font-weight:700; letter-spacing:.24em; font-size:.95rem; text-transform:uppercase; font-family:{FUENTE}; }}
.hero-resumen .fecha {{ color:#ffffff; font-size:1.25rem; font-family:{FUENTE}; font-weight:500; letter-spacing:.06em; margin:.2rem 0 .6rem; }}
.hero-resumen .dur {{ display:flex; justify-content:space-between; gap:1.5rem; border-top:1px solid var(--linea); padding-top:.5rem;
  color:#c3cee4; font-family:{FUENTE}; letter-spacing:.1em; text-transform:uppercase; font-size:1rem; }}
.hero-resumen .dur b {{ text-transform:none; color:#ffffff; font-weight:600; font-size:1.15rem; letter-spacing:.05em; }}
.hero-vacio {{ margin-top:1.2rem; color:#c3cee4; letter-spacing:.2em; text-transform:uppercase; font-weight:600; font-family:{FUENTE}; }}
.punto {{ position:absolute; right:.4rem; top:.4rem; width:18px; height:18px; border-radius:50%; background:var(--azul);
  box-shadow:0 0 18px var(--azul); }}

/* KPI */
[data-testid="stMetric"] {{ background:linear-gradient(180deg,rgba(47,107,255,.10),rgba(10,18,36,.7)); border:1px solid var(--linea);
  border-top:2px solid var(--azul); padding:.7rem .9rem; border-radius:2px; }}
[data-testid="stMetricLabel"] p {{ text-transform:uppercase; letter-spacing:.16em; color:#c3cee4; font-size:1rem; font-family:{FUENTE}; }}
[data-testid="stMetricValue"] {{ font-family:{FUENTE}; color:#fff; font-weight:500; font-size:2.4rem; letter-spacing:.03em; }}

/* PESTAÑAS */
.stTabs [data-baseweb="tab-list"] {{ gap:.2rem; border-bottom:1px solid var(--linea); }}
.stTabs [data-baseweb="tab"] {{ font-family:{FUENTE}; text-transform:uppercase; letter-spacing:.18em; font-weight:600; height:2.8rem; }}
.stTabs [data-baseweb="tab"] p {{ font-size:1rem; }}
.stTabs [aria-selected="true"] {{ color:#fff; }}
.stTabs [data-baseweb="tab-highlight"] {{ background:var(--azul); height:3px; }}

/* EXPANDERS, BOTONES, ALERTAS, TABLAS */
[data-testid="stExpander"] {{ border:1px solid var(--linea); border-left:3px solid var(--azul); border-radius:2px;
  background:rgba(10,18,36,.55); }}
[data-testid="stExpander"] summary p {{ font-family:{TEXTO}; font-weight:600; letter-spacing:0; font-size:.98rem; color:#fff; }}
.stButton button, [data-testid="stDownloadButton"] button {{ background:transparent; color:#e8ecf4; border:1px solid var(--azul);
  border-radius:0; text-transform:uppercase; letter-spacing:.2em; font-weight:600; font-family:{FUENTE}; }}
.stButton button:hover, [data-testid="stDownloadButton"] button:hover {{ background:var(--azul); color:#fff; border-color:var(--azul); }}
[data-testid="stAlert"] {{ border-radius:2px; border:1px solid var(--linea); background:rgba(47,107,255,.08); }}
[data-testid="stFileUploaderDropzone"] {{ border:1px dashed var(--azul); background:rgba(47,107,255,.06); border-radius:2px; }}
[data-testid="stDataFrame"] {{ border:1px solid var(--linea); }}
hr {{ border-color:var(--linea); }}

/* CARGA DE ARCHIVO: botón translúcido azul en lugar del blanco por defecto */
[data-testid="stFileUploaderDropzone"] button {{ background:rgba(47,107,255,.14) !important; color:#fff !important; border:1px solid var(--azul) !important;
  border-radius:0; text-transform:uppercase; letter-spacing:.18em; font-family:{FUENTE}; font-weight:600; box-shadow:0 0 12px rgba(47,107,255,.3); }}
[data-testid="stFileUploaderDropzone"] button:hover {{ background:var(--azul) !important; box-shadow:0 0 20px rgba(47,107,255,.8); }}
[data-testid="stFileUploaderDropzone"] button p, [data-testid="stFileUploaderDropzone"] button span, [data-testid="stFileUploaderDropzone"] button svg {{ color:#fff !important; fill:#fff; }}
[data-testid="stFileUploaderDropzoneInstructions"] span, [data-testid="stFileUploaderDropzoneInstructions"] small, [data-testid="stFileUploaderDropzone"] small {{ color:#c3cee4 !important; }}
[data-testid="stFileUploaderFile"], [data-testid="stFileUploaderFile"] * {{ color:#f1f5ff !important; }}

/* TABLAS PROPIAS (contraste sobre el tema) */
.scroll-soc {{ overflow:auto; border:1px solid rgba(90,160,255,.4); border-radius:2px; background:#070d1b; margin:.3rem 0 .8rem; }}
.tabla-soc, [data-testid="stMarkdownContainer"] table {{ width:100%; border-collapse:collapse; font-family:{TEXTO}; font-size:.84rem; color:#f1f5ff; }}
.tabla-soc th, [data-testid="stMarkdownContainer"] th {{ position:sticky; top:0; background:#12307a !important; color:#fff !important; text-transform:uppercase;
  letter-spacing:.08em; font-family:{FUENTE}; font-size:.9rem; text-align:left; padding:.45rem .6rem; border-bottom:2px solid var(--azul); white-space:nowrap; }}
.tabla-soc td, [data-testid="stMarkdownContainer"] td {{ padding:.4rem .6rem; border-bottom:1px solid rgba(90,160,255,.18); vertical-align:top;
  color:#f1f5ff !important; overflow-wrap:anywhere; }}
.tabla-soc td.corto {{ white-space:nowrap; overflow-wrap:normal; }}
.tabla-soc tbody tr:nth-child(even) td, [data-testid="stMarkdownContainer"] tbody tr:nth-child(even) td {{ background:rgba(47,107,255,.08); }}
.tabla-soc tbody tr:hover td {{ background:rgba(47,107,255,.22); }}

/* GRÁFICOS: cada uno en su propio marco, ajustado al ancho de su columna */
[data-testid="stPlotlyChart"] {{ box-sizing:border-box; width:100% !important; overflow:hidden; max-width:100%; border:1px solid rgba(90,160,255,.45); background:rgba(10,18,36,.6); padding:.5rem .5rem 0; border-radius:2px; }}
[data-testid="stPlotlyChart"] > div, [data-testid="stPlotlyChart"] .js-plotly-plot, [data-testid="stPlotlyChart"] .plotly {{ width:100% !important; max-width:100%; }}

/* TARJETAS CLICABLES: el botón de Streamlit se superpone invisible sobre la tarjeta */
[class*="st-key-card_"] {{ position:relative; }}
[class*="st-key-card_"] [data-testid="stVerticalBlock"] {{ gap:0; }}
[class*="st-key-card_"] [data-testid="stElementContainer"]:has(button) {{ position:absolute; inset:0; z-index:5; width:100% !important; margin:0; }}
[class*="st-key-card_"] [data-testid="stButton"], [class*="st-key-card_"] button {{ width:100%; height:100%; opacity:0; cursor:pointer; }}
[class*="st-key-card_"]:hover .sev {{ transform:translateY(-2px); filter:brightness(1.3); }}
.sev {{ transition:transform .15s, filter .15s; }}
.sev .h {{ font-family:{FUENTE}; font-size:.85rem; letter-spacing:.14em; color:#fff; opacity:.85; text-transform:uppercase; margin-top:.2rem; }}

/* BOTONES DE INFORME EN EL HERO (bajo el bloque lateral) */
.st-key-hero_wrap {{ position:relative; }}
.st-key-hero_botones {{ position:absolute; right:1rem; top:11.5rem; width:min(300px,26%); z-index:6; gap:.6rem; }}
.st-key-hero_botones button {{ width:100%; min-height:2.9rem; border-radius:0; border:1px solid var(--azul);
  background:linear-gradient(135deg,rgba(47,107,255,.45),rgba(47,107,255,.10)); color:#fff; text-transform:uppercase; letter-spacing:.2em;
  font-family:{FUENTE}; font-weight:600; font-size:1.05rem; box-shadow:0 0 14px rgba(47,107,255,.35), inset 0 0 12px rgba(90,160,255,.12);
  transition:box-shadow .15s, background .15s, transform .15s; }}
.st-key-hero_botones button:hover {{ background:var(--azul); box-shadow:0 0 22px rgba(47,107,255,.85); transform:translateY(-2px); color:#fff; border-color:var(--azul2); }}
.st-key-hero_botones button p {{ font-family:{FUENTE}; letter-spacing:.2em; font-size:1.05rem; }}
@media (max-width:1000px) {{ .st-key-hero_botones {{ position:static; width:100%; margin:.8rem 0; }} }}

/* TARJETA KPI (misma apariencia para todas; algunas son enlace o abren una ventana) */
.kpi {{ display:block; text-decoration:none !important; background:linear-gradient(180deg,rgba(47,107,255,.10),rgba(10,18,36,.7));
  border:1px solid var(--linea); border-top:2px solid var(--azul); padding:.7rem .9rem; border-radius:2px; transition:filter .15s, transform .15s; }}
a.kpi:hover, [class*="st-key-card_"]:hover .kpi {{ filter:brightness(1.3); transform:translateY(-2px); }}
.kpi .l, .kpi .n {{ display:block; }}
a.kpi, a.kpi:visited, a.kpi:hover {{ color:inherit !important; }}
.kpi .l {{ font-family:{FUENTE}; text-transform:uppercase; letter-spacing:.16em; color:#c3cee4; font-size:1rem; }}
.kpi .n {{ font-family:{FUENTE}; color:#fff; font-size:2.4rem; font-weight:500; line-height:1.15; letter-spacing:.03em; }}
html {{ scroll-behavior:smooth; }}
[data-testid="stMain"], section.main {{ scroll-behavior:smooth; }}

/* VENTANA EMERGENTE: fondo del tema en todas las capas del diálogo */
div[role="dialog"], div[role="dialog"] > div, div[role="dialog"] > div > div, div[data-baseweb="modal"] > div > div,
[data-testid="stDialog"] div[role="dialog"], [data-testid="stModal"] div[role="dialog"] {{ background-color:#070d1b !important; color:#f1f5ff !important; }}
div[role="dialog"] {{ border:1px solid rgba(90,160,255,.45); border-top:3px solid var(--azul); }}
div[role="dialog"] header, div[role="dialog"] [data-testid="stDialogHeader"] {{ background:#070d1b !important; }}
div[role="dialog"] h1, div[role="dialog"] h2, div[role="dialog"] h3 {{ color:#fff !important; }}
div[role="dialog"] button[aria-label="Close"], div[role="dialog"] button[aria-label="Close"] svg {{ color:#fff !important; fill:#fff !important; }}
[data-testid="stDialog"] > div, [data-testid="stModal"] > div {{ background-color:rgba(2,4,10,.95) !important; }}
[class*="st-key-incbtn_"] button, [class*="st-key-hallbtn_"] button {{ justify-content:flex-start; text-align:left; border:1px solid rgba(90,160,255,.4); border-left:4px solid var(--rgbsolid, var(--azul));
  background:rgba(47,107,255,.08); text-transform:none; letter-spacing:.02em; font-family:{TEXTO}; font-weight:600; border-radius:2px; }}
[class*="st-key-incbtn_"] button:hover, [class*="st-key-hallbtn_"] button:hover {{ background:rgba(47,107,255,.25); }}


/* TARJETAS DE SEVERIDAD: color sublimado (degradado tenue), no relleno sólido */
.sev {{ border:1px solid rgba(var(--rgb),.45); border-radius:2px; padding:.8rem 1rem;
  background:linear-gradient(135deg, rgba(var(--rgb),.30) 0%, rgba(var(--rgb),.10) 55%, rgba(10,18,36,.55) 100%);
  box-shadow:inset 0 0 28px rgba(var(--rgb),.10); }}
.sev .n {{ font-family:{FUENTE}; font-size:2.6rem; font-weight:500; color:#fff; line-height:1.05; }}
.sev .l {{ font-family:{FUENTE}; letter-spacing:.18em; text-transform:uppercase; font-size:1rem; color:#f1f5ff; font-weight:600; }}
.sev .s {{ font-family:{FUENTE}; letter-spacing:.12em; font-size:.85rem; color:#c3cee4; text-transform:uppercase; }}

</style>
"""


def _red_svg(semilla: int = 7, n: int = 46) -> str:
    """Red decorativa de nodos conectados (fondo del hero)."""
    r = random.Random(semilla)
    pts = [(r.uniform(40, 760), r.uniform(20, 380)) for _ in range(n)]
    lin, nod = [], []
    for i, (x, y) in enumerate(pts):
        cerca = sorted(range(n), key=lambda j: (pts[j][0] - x) ** 2 + (pts[j][1] - y) ** 2)[1:3]
        for j in cerca:
            cx, cy = (x + pts[j][0]) / 2 + r.uniform(-25, 25), (y + pts[j][1]) / 2 + r.uniform(-25, 25)
            lin.append(f'<path d="M{x:.0f},{y:.0f} Q{cx:.0f},{cy:.0f} {pts[j][0]:.0f},{pts[j][1]:.0f}" />')
        nod.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r.choice([1.5, 2, 3])}" />')
    return ('<svg class="hero-red" viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMaxYMid slice">'
            f'<g fill="none" stroke="{AZUL_CLARO}" stroke-opacity=".5" stroke-width="1">{"".join(lin)}</g>'
            f'<g fill="{AZUL_CLARO}" fill-opacity=".85">{"".join(nod)}</g></svg>')


CSS_RESPONSIVO = "<style>@media (max-width:1000px){.hero-lateral{display:none}}</style>"


def aplicar_tema() -> None:
    st.markdown(CSS + CSS_RESPONSIVO, unsafe_allow_html=True)


RGB_SEV = {"Crítico": "239,68,68", "Alto": "249,115,22", "Medio": "234,179,8", "Bajo": "34,197,94"}


def tarjeta_severidad(nombre: str, n: int, subtitulo: str = "Incidentes") -> None:
    """Recuadro con el color de la severidad sublimado en degradado (sin icono). Va dentro de un contenedor card_*
    con un botón superpuesto que lo vuelve clicable."""
    pista = '<div class="h">Ver incidentes</div>' if n else ""
    st.markdown(f'<div class="sev" style="--rgb:{RGB_SEV[nombre]}"><div class="s">{subtitulo}</div>'
                f'<div class="l">{nombre}</div><div class="n">{n}</div>{pista}</div>', unsafe_allow_html=True)


def tarjeta_kpi(etiqueta: str, valor, destino: str | None = None) -> None:
    """Tarjeta KPI. Con `destino` ('#ancla') es un enlace que baja a esa sección; sin él puede llevar un botón superpuesto."""
    inner = f'<span class="l">{etiqueta}</span><span class="n">{valor}</span>'
    if destino:
        st.markdown(f'<a class="kpi" href="{destino}" target="_self">{inner}</a>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="kpi">{inner}</div>', unsafe_allow_html=True)


def ancla(id_: str) -> None:
    st.markdown(f'<div id="{id_}" style="position:relative;top:-70px"></div>', unsafe_allow_html=True)


def separador() -> None:
    st.markdown('<div style="height:2px;margin:1.5rem 0;background:linear-gradient(90deg,transparent,#2f6bff 15%,#5aa0ff 50%,#2f6bff 85%,transparent)"></div>',
                unsafe_allow_html=True)


def estilo_dialogo_hallazgos(hallazgos) -> None:
    """Borde izquierdo de cada botón de hallazgo con el color de su severidad."""
    reglas = "".join(f'.st-key-hallbtn_{h.id} button{{border-left-color:rgb({RGB_SEV[h.severidad]}) !important;}}' for h in hallazgos)
    st.markdown(f"<style>{reglas}</style>", unsafe_allow_html=True)


def estilo_dialogo(nombre: str) -> None:
    """Color de la severidad en el borde de los botones de incidente dentro del diálogo."""
    st.markdown(f'<style>[class*="st-key-incbtn_"]{{--rgbsolid:rgb({RGB_SEV[nombre]});}}</style>', unsafe_allow_html=True)


def hero(periodo: dict | None = None) -> None:
    """`periodo` = report.formato_periodo(...). Sin datos aún, muestra la invitación a cargar el Excel."""
    if periodo:
        pie = (f'<div class="hero-resumen"><div class="tit">Resumen de actividad</div>'
               f'<div class="fecha">{periodo["fecha"]} · {periodo["rango"]}</div>'
               f'<div class="dur"><span><svg class="ico" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#5aa0ff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px;margin-right:.45rem;filter:drop-shadow(0 0 4px rgba(47,107,255,.9))"><circle cx="12" cy="13" r="8"/><path d="M12 9v4l2.5 2.5"/><path d="M9.5 2.5h5"/><path d="M12 2.5V5"/></svg>Duración del análisis</span><b>{periodo["duracion"]}</b></div></div>')
    else:
        pie = '<div class="hero-vacio">Carga el export del SIEM para comenzar</div>'
    st.markdown(f"""
<div class="hero">{_red_svg()}<span class="punto"></span>
  <div class="hero-kicker">SOC - SIEMInsight</div>
  <h1>ANÁLISIS DE<span class="raya"></span><br>INCIDENTES <span class="hueco">SIEM</span></h1>
  <div class="hero-lateral">Bootcamp analista SOC<br><span class="marca">NIVEL 2</span><br>reto final</div>
  {pie}
</div>""", unsafe_allow_html=True)