import streamlit as st

from src import ai, charts, inventario, pdf_report, tablas, theme
from src.correlation import correlacionar
from src.detectors import conteo_categorias, explorador, run_all
from src.report import a_markdown, construir_informe, formato_periodo
from src.loader import FORMATOS, SiemFormatError, load_siem

st.set_page_config(page_title="SOC - SIEMInsight", page_icon="🛡️", layout="wide")
theme.aplicar_tema()
HERO = st.empty()
with HERO.container():
    theme.hero()

ICONO = {"Crítico": "🔴", "Alto": "🟠", "Medio": "🟡", "Bajo": "🟢", "Normal": "⚪"}

archivo = st.file_uploader("Archivo del SIEM", type=FORMATOS, label_visibility="collapsed")
if not archivo:
    st.info("Sube el export del SIEM para comenzar. Formatos admitidos: " + ", ".join(f".{f}" for f in FORMATOS) + ".")
    st.stop()

try:
    df = load_siem(archivo, archivo.name)
except SiemFormatError as e:
    st.error(str(e))
    st.stop()

for aviso in df.attrs.get("advertencias", []):
    st.caption(f"ℹ️ {aviso}")

errores: list[str] = []
hallazgos = run_all(df, errores)
for e in errores:
    st.warning(f"Un detector falló y se omitió: {e}")

incidentes = correlacionar(df, hallazgos)
with HERO.container():
    with st.container(key="hero_wrap"):
        theme.hero(formato_periodo(df["Timestamp"].min(), df["Timestamp"].max()))
        with st.container(key="hero_botones"):   # CSS los coloca bajo "Bootcamp analista SOC · Nivel 2 · Reto final"
            ver_tec = st.button("Informe técnico", key="btn_inf_tec", icon=":material/description:", use_container_width=True)
            ver_eje = st.button("Informe ejecutivo", key="btn_inf_eje", icon=":material/summarize:", use_container_width=True)

ex = explorador(df, hallazgos, incidentes)
informe = construir_informe(df, hallazgos, incidentes)


PLURAL = {"Crítico": "Críticos", "Alto": "Altos", "Medio": "Medios", "Bajo": "Bajos"}
st.session_state.setdefault("inc_abierto", None)
st.session_state.setdefault("hall_abierto", None)


def _alternar(clave: str, valor: str) -> None:
    """Acordeón: abrir uno cierra el anterior; pulsar el abierto lo cierra."""
    st.session_state[clave] = None if st.session_state[clave] == valor else valor


def _detalle_incidente(inc) -> None:
    st.write(inc.resumen)
    st.markdown(f"**Por qué {inc.severidad}:** {inc.justificacion_severidad}")
    for r in inc.relacionados:
        st.warning(r)
    st.markdown("**Cadena de ataque**")
    st.markdown(tablas.tabla_html(inc.pasos_df(), sev_col="Severidad", max_alto=300), unsafe_allow_html=True)
    if inc.vinculos:
        with st.expander("Vínculos entre hallazgos"):
            st.write("\n".join(f"- {v}" for v in inc.vinculos))
    st.markdown("**Acciones SOC recomendadas**\n" + "\n".join(f"- {a}" for a in inc.acciones))
    st.markdown(f"**MITRE ATT&CK:** {', '.join(inc.mitre) or '—'}")
    st.markdown(f"**Evidencia ({len(inc.evidencia)} eventos)**")
    st.markdown(tablas.tabla_html(inc.evidencia_df(df), max_alto=320), unsafe_allow_html=True)


def _detalle_hallazgo(h) -> None:
    st.write(h.justificacion)
    st.markdown(f"**Categorías:** {', '.join(h.categorias_reto)}  \n"
                f"**MITRE ATT&CK:** {', '.join(h.mitre) or '—'}  \n"
                f"**Ventana:** {h.inicio:%H:%M:%S} → {h.fin:%H:%M:%S}  \n"
                f"**Hosts:** {', '.join(h.hosts)}  \n"
                f"**Incidente:** {h.metricas.get('incidente', '—')}")
    if h.metricas.get("siem_subestima"):
        st.caption(f"El SIEM clasificó la evidencia como máximo «{h.metricas['severidad_siem']}»; "
                   f"la clasificación final es {h.severidad}.")
    st.info(f"**Acción SOC recomendada:** {h.accion}")
    st.markdown(f"**Evidencia ({len(h.evidencia)} eventos)**")
    st.markdown(tablas.tabla_html(h.evidencia_df(df), max_alto=320), unsafe_allow_html=True)


def abrir_incidentes(nombre: str) -> None:
    @st.dialog(f"Incidentes {PLURAL[nombre]}", width="large")
    def _dialogo():
        theme.estilo_dialogo(nombre)
        lista = [i for i in incidentes if i.severidad == nombre]
        st.caption(f"{len(lista)} incidente(s). Pulsa uno para ver su detalle; al abrir otro, el anterior se cierra.")
        for inc in lista:
            abierto = st.session_state.inc_abierto == inc.id
            st.button(f"{'▾' if abierto else '▸'}  {inc.id} · {inc.titulo}  ({inc.inicio:%H:%M}–{inc.fin:%H:%M})",
                      key=f"incbtn_{inc.id}", use_container_width=True, on_click=_alternar, args=("inc_abierto", inc.id))
            if abierto:
                _detalle_incidente(inc)
    _dialogo()


def abrir_hallazgos() -> None:
    @st.dialog("Hallazgos", width="large")
    def _dialogo():
        theme.estilo_dialogo_hallazgos(hallazgos)
        cats = conteo_categorias(hallazgos)
        st.caption("Por categoría: " + " · ".join(f"{c}: {n}" for c, n in cats.items())
                   + ". Pulsa un hallazgo para ver su detalle; al abrir otro, el anterior se cierra.")
        if not hallazgos:
            st.success("Los detectores activos no encontraron actividad sospechosa.")
        for h in hallazgos:
            abierto = st.session_state.hall_abierto == h.id
            st.button(f"{'▾' if abierto else '▸'}  {h.id} · {h.severidad} · {h.titulo}", key=f"hallbtn_{h.id}",
                      use_container_width=True, on_click=_alternar, args=("hall_abierto", h.id))
            if abierto:
                _detalle_hallazgo(h)
    _dialogo()


def abrir_tabla(titulo: str, tabla, nota: str, sev_col: str = "Severidad máx.") -> None:
    @st.dialog(titulo, width="large")
    def _dialogo():
        st.caption(nota)
        st.markdown(tablas.tabla_html(tabla, sev_col=sev_col, max_alto=520), unsafe_allow_html=True)
    _dialogo()


NOTA_INV = ("Conteos tomados directamente de los registros. «Incidentes» y «Severidad máx.» indican en qué incidentes "
            "aparece como evidencia, ya sea como autor o como objetivo (p. ej. cuentas atacadas por password spraying).")


def _pdf(tipo: str, nar) -> bytes:
    """PDF generado una vez por archivo/narrativa (se guarda en sesión)."""
    clave = (archivo.name, archivo.size, tipo, nar["texto"] if nar else None)
    cache = st.session_state.setdefault("pdfs", {})
    if clave not in cache:
        cache.clear()
        cache[clave] = (pdf_report.pdf_tecnico(df, hallazgos, incidentes, informe, ex, nar) if tipo == "tecnico"
                        else pdf_report.pdf_ejecutivo(df, hallazgos, incidentes, informe, ex))
    return cache[clave]


def _paginas_png(pdf: bytes) -> list[bytes]:
    """Páginas del PDF como PNG (Chrome bloquea los PDF incrustados con data:, así que se muestran como imágenes)."""
    try:
        import pymupdf as fitz
    except ImportError:
        import fitz
    clave = hash(pdf)
    cache = st.session_state.setdefault("png_pdf", {})
    if clave not in cache:
        cache.clear()
        doc = fitz.open(stream=pdf, filetype="pdf")
        cache[clave] = [pag.get_pixmap(dpi=110).tobytes("png") for pag in doc]
    return cache[clave]


def _vista_pdf(pdf: bytes) -> None:
    try:
        paginas = _paginas_png(pdf)
    except Exception as e:   # sin PyMuPDF o PDF ilegible: la descarga sigue funcionando
        st.warning(f"No se pudo generar la vista previa ({type(e).__name__}). Usa el botón de descarga.")
        return
    st.caption(f"Vista previa · {len(paginas)} página(s). Desplázate para ver todo el informe.")
    with st.container(height=640, border=True):
        for n, img in enumerate(paginas, 1):
            st.image(img, caption=f"Página {n}", use_container_width=True)


def abrir_informe(tipo: str) -> None:
    titulo = "Informe técnico" if tipo == "tecnico" else "Informe ejecutivo"

    @st.dialog(titulo, width="large")
    def _dialogo():
        st.session_state.setdefault("narrativa", None)
        if tipo == "tecnico":
            st.caption("La estructura sale solo de hallazgos e incidentes. La IA añade la redacción y su salida se valida contra los logs.")
            if st.button("✨ Redactar análisis con IA", key="btn_ia"):
                try:
                    with st.spinner("Redactando..."):
                        st.session_state.narrativa = ai.redactar(informe, df)
                except Exception as e:  # sin clave, sin red, etc.: el informe sin IA sigue disponible
                    st.error(f"No se pudo usar la IA: {e}")
            nar = st.session_state.narrativa
            if nar:
                v = nar["validacion"]
                if v["ok"]:
                    st.success(f"Validación: los {v['ids_citados']} Log_ID y las IPs citadas existen en los logs.")
                else:
                    st.error(f"La IA citó datos que NO existen en los logs: {v['ids_inexistentes'] + v['ips_inexistentes']}. "
                             "No uses esta narrativa sin revisarla.")
        else:
            st.caption("Resumen para dirección: situación, qué ocurrió, acciones prioritarias y limitaciones.")
            nar = None
        pdf = _pdf(tipo, nar)
        nombre = "informe_tecnico" if tipo == "tecnico" else "informe_ejecutivo"
        c1, c2 = st.columns(2)
        c1.download_button("⬇️ Descargar PDF", pdf, file_name=f"{nombre}.pdf", mime="application/pdf", key=f"dl_{tipo}")
        if tipo == "tecnico":
            c2.download_button("⬇️ Descargar Markdown", a_markdown(informe, nar["texto"] if nar else None),
                               file_name=f"{nombre}.md", mime="text/markdown", key="dl_md")
        _vista_pdf(pdf)
    _dialogo()


n_ips = df.loc[df["Externa"], "Source_IP"].nunique()
por_abrir = "inf_tec" if ver_tec else "inf_eje" if ver_eje else None
k = st.columns(5)
with k[0]:
    theme.tarjeta_kpi("Eventos", len(df), destino="#explorador")   # baja al explorador
for col, clave, etiqueta, valor in [(k[1], "hosts", "Hosts", df["Host"].nunique()),
                                    (k[2], "cuentas", "Cuentas", df["User"].nunique()),
                                    (k[3], "ips", "IPs externas", n_ips),
                                    (k[4], "hallazgos", "Hallazgos", len(hallazgos))]:
    with col, st.container(key=f"card_kpi_{clave}"):
        theme.tarjeta_kpi(etiqueta, valor)
        if st.button(f"Ver {etiqueta}", key=f"btn_kpi_{clave}", use_container_width=True):
            por_abrir = clave
st.write("")
for col, nombre in zip(st.columns(4), ["Crítico", "Alto", "Medio", "Bajo"]):
    n = sum(i.severidad == nombre for i in incidentes)
    with col, st.container(key=f"card_{nombre.lower().replace('í', 'i')}"):
        theme.tarjeta_severidad(nombre, n)
        if st.button("Ver incidentes", key=f"btn_{nombre}", disabled=n == 0, use_container_width=True):
            por_abrir = nombre
if por_abrir in PLURAL:
    st.session_state.inc_abierto = None
    abrir_incidentes(por_abrir)
elif por_abrir in ("inf_tec", "inf_eje"):
    abrir_informe("tecnico" if por_abrir == "inf_tec" else "ejecutivo")
elif por_abrir == "hallazgos":
    st.session_state.hall_abierto = None
    abrir_hallazgos()
elif por_abrir == "hosts":
    abrir_tabla("Hosts", inventario.tabla_hosts(df, ex), NOTA_INV)
elif por_abrir == "cuentas":
    abrir_tabla("Cuentas", inventario.tabla_cuentas(df, ex), NOTA_INV)
elif por_abrir == "ips":
    abrir_tabla("IPs externas", inventario.tabla_ips_externas(df, ex), NOTA_INV)
theme.separador()
g1, g2 = st.columns(2)
g1.plotly_chart(charts.fig_donut_severidad(ex), use_container_width=True, theme=None)
g2.plotly_chart(charts.fig_causa_raiz(ex), use_container_width=True, theme=None)
theme.separador()
st.plotly_chart(charts.fig_linea_tiempo(df, ex), use_container_width=True, theme=None)
theme.separador()
if incidentes:
    st.plotly_chart(charts.fig_gantt_incidentes(incidentes), use_container_width=True, theme=None)
    theme.separador()
sub = len(informe["hallazgos_subestimados_por_siem"])
st.info(f"El SIEM subestimó la severidad de {sub} de {len(hallazgos)} hallazgos; "
        f"alertas del SIEM sin explicar por ningún hallazgo: {informe['alertas_siem_sin_explicar']}.")

# ---- explorador de eventos (destino del recuadro "Eventos") ----
theme.ancla("explorador")
st.subheader("Explorador de eventos")

@st.fragment  # filtrar/buscar/paginar solo recalcula esta sección, no todo el dashboard
def explorador_ui():
    f1, f2, f3 = st.columns([3, 1, 1])
    texto = f1.text_input("Buscar (IP, usuario, host, causa...)")
    filtro = f2.selectbox("Severidad final", ["Todas", "Crítico", "Alto", "Medio", "Bajo", "Normal"])
    ex_f = ex
    if filtro != "Todas":
        ex_f = ex_f[ex_f["Severidad final"] == filtro]
    if texto:
        ex_f = ex_f[ex_f.astype(str).apply(lambda c: c.str.contains(texto, case=False, regex=False)).any(axis=1)]
    por_pag = 100
    paginas = max(1, -(-len(ex_f) // por_pag))
    pag = f3.number_input("Página", min_value=1, max_value=paginas, value=1, step=1, key=f"pag_{filtro}_{texto}")
    ini = (pag - 1) * por_pag
    st.caption(f"{len(ex_f)} de {len(ex)} eventos · mostrando {ini + 1 if len(ex_f) else 0}–{min(ini + por_pag, len(ex_f))} "
               f"(página {pag} de {paginas}). Pasa el cursor sobre un texto recortado para ver el contenido completo.")
    st.markdown(tablas.tabla_html(ex_f.iloc[ini:ini + por_pag], sev_col="Severidad final", max_alto=560,
                                  max_chars=70, fecha=df["Timestamp"].dt.date.nunique() > 1),
                unsafe_allow_html=True)

explorador_ui()