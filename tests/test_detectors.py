"""Pruebas del motor de detección: casos sintéticos (positivos y negativos) + regresión sobre el Excel real."""
from collections import Counter
from pathlib import Path

import pandas as pd

import src.detectors as motor
from src.detectors import (detect_anomalous_logins, detect_brute_force, detect_escalation, detect_exfiltration,
                           detect_lateral_movement, detect_mass_file_access, detect_other_anomalies,
                           detect_persistence, detect_suspicious_commands, detect_web_attack, run_all)
from src.detectors import (CATEGORIAS_RETO, conteo_categorias, detect_lateral_share_access, eventos_sin_explicar,
                           explorador)
from src.loader import load_siem, normalizar

EXCEL = Path(__file__).resolve().parents[1] / "data" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
T0 = pd.Timestamp("2026-01-05 10:00:00")  # lunes


def mk(specs):
    """specs: lista de dicts con t (segundos desde T0) y campos opcionales."""
    filas = []
    for i, s in enumerate(specs, 1):
        filas.append({
            "Log_ID": f"EVT-{i:05d}", "Timestamp": T0 + pd.Timedelta(seconds=s.get("t", 0)),
            "Hostname": s.get("host", "WS-01"), "Event_ID": s.get("ev", "4688"), "User": s.get("user", "CORP\\u1"),
            "Source_IP": s.get("ip", "10.10.1.5"), "Destination": s.get("dest", ""),
            "Log_Source": s.get("src", "Security"), "Event_Description": s.get("desc", "x"),
            "Process_CommandLine": s.get("cmd", ""), "Result": s.get("result", "Success"), "Severity": "Informational"})
    return normalizar(pd.DataFrame(filas))


def una(hallazgos, regla=None):
    h = [f for f in hallazgos if regla is None or f.regla == regla]
    assert len(h) == 1, f"se esperaba 1 hallazgo ({regla}) y hubo {len(h)}"
    return h[0]


EXT = "203.0.113.9"


def fallos(n, user="CORP\\admin", ip=EXT, paso=15):
    return [dict(t=i * paso, ev="4625", user=user, ip=ip, result="Failure", host="SRV-01") for i in range(n)]


# ------------------------------- fuerza bruta -------------------------------
def test_fuerza_bruta_externa_sin_exito_es_medio():
    assert una(detect_brute_force(mk(fallos(4)))).severidad == "Medio"


def test_fuerza_bruta_con_exito_es_critico():
    ok = [dict(t=300, ev="4624", user="CORP\\admin", ip=EXT, host="SRV-01", desc="ok (LogonType=10; RDP)")]
    h = una(detect_brute_force(mk(fallos(4) + ok)))
    assert h.severidad == "Crítico" and "LogonType=10" in h.justificacion


def test_fuerza_bruta_interna_necesita_umbral_mayor():
    assert detect_brute_force(mk(fallos(5, ip="10.10.1.9"))) == []
    assert una(detect_brute_force(mk(fallos(8, ip="10.10.1.9")))).severidad == "Medio"


def test_fuerza_bruta_no_duplica_spraying():
    spray = [dict(t=i * 10, ev="4625", user=f"CORP\\u{i % 6}", ip=EXT, result="Failure") for i in range(12)]
    assert detect_brute_force(mk(spray)) == []


# ------------------------------- logins anómalos -------------------------------
def test_login_externo_aislado_es_alto():
    h = una(detect_anomalous_logins(mk([dict(ev="4624", ip=EXT)])), "AUTH-03")
    assert h.severidad == "Alto"


def test_login_externo_ya_explicado_por_fuerza_bruta_no_se_duplica():
    ok = [dict(t=300, ev="4624", user="CORP\\admin", ip=EXT, host="SRV-01")]
    assert detect_anomalous_logins(mk(fallos(4) + ok)) == []


def test_login_fuera_de_horario():
    h = una(detect_anomalous_logins(mk([dict(t=12 * 3600, ev="4624")])), "AUTH-04")  # 22:00
    assert h.severidad == "Medio" and "supuesto" in h.justificacion
    assert detect_anomalous_logins(mk([dict(t=0, ev="4624")])) == []                 # 10:00 lunes


# ------------------------------- escalamiento -------------------------------
def test_4672_externo_es_alto_e_interno_se_ignora():
    assert una(detect_escalation(mk([dict(ev="4672", ip=EXT)])), "PRIV-01").severidad == "Alto"
    assert detect_escalation(mk([dict(ev="4672", ip="10.10.1.7")])) == []


def test_alta_en_grupo_privilegiado():
    assert una(detect_escalation(mk([dict(ev="4732", desc="member added")])), "PRIV-02").severidad == "Alto"


# ------------------------------- comandos y procesos -------------------------------
def test_comandos_benignos_no_generan_hallazgos():
    legit = [dict(cmd=c, t=i) for i, c in enumerate(["explorer.exe", "svchost.exe", "notepad.exe", "taskhostw.exe"])]
    assert detect_suspicious_commands(mk(legit)) == []


def test_powershell_codificado_y_shadow_copies():
    h = detect_suspicious_commands(mk([
        dict(cmd="powershell.exe -NoProfile -EncodedCommand AAAA", t=0),
        dict(cmd="vssadmin.exe delete shadows /all /quiet", t=60, host="WS-02")]))
    por = {f.regla: f for f in h}
    assert por["CMD-04"].severidad == "Alto" and por["CMD-02"].severidad == "Crítico"


def test_powershell_con_parametro_e_no_codificado_no_coincide():
    assert detect_suspicious_commands(mk([dict(cmd="powershell.exe -ExecutionPolicy Bypass -File a.ps1")])) == []


def test_shell_bajo_worker_de_iis_es_critico():
    h = una(detect_suspicious_commands(mk([dict(cmd="cmd.exe /c whoami", user="IIS APPPOOL\\DefaultAppPool")])))
    assert h.regla == "CMD-03" and h.severidad == "Crítico"


def test_archivado_staging_alto_y_generico_medio():
    h = {f.regla: f for f in detect_suspicious_commands(mk([
        dict(cmd=r"7z.exe a C:\Users\Public\x.7z C:\datos", t=0),
        dict(cmd=r"7z.exe a D:\backup\x.7z C:\datos", t=10, host="WS-02")]))}
    assert h["CMD-07"].severidad == "Alto" and h["CMD-09"].severidad == "Medio"


def test_ejecucion_periodica_desde_ruta_no_estandar():
    h = una(detect_suspicious_commands(mk([dict(cmd=r"C:\ProgramData\x.exe", t=i * 360) for i in range(4)])))
    assert h.regla == "CMD-08" and "360" in h.justificacion


def test_conexion_saliente_de_powershell_a_ip_externa():
    ok = dict(ev="5156", src="Firewall", desc="Allowed outbound connection to 203.0.113.88:443 (process=powershell.exe)")
    interna = dict(ev="5156", src="Firewall", desc="Allowed outbound connection to 10.1.1.1:443 (process=powershell.exe)")
    h = una(detect_suspicious_commands(mk([ok, interna])), "CMD-06")
    assert h.metricas["destinos"] == ["203.0.113.88"]


# ------------------------------- persistencia -------------------------------
def test_persistencia_ruta_no_estandar_alto_y_estandar_medio():
    alto = una(detect_persistence(mk([dict(ev="7045", cmd=r"ServiceName=Evil; ImagePath=C:\ProgramData\e.exe")])))
    medio = una(detect_persistence(mk([dict(ev="7045", cmd=r"ServiceName=Ok; ImagePath=C:\Windows\System32\ok.exe")])))
    assert alto.severidad == "Alto" and medio.severidad == "Medio"


# ------------------------------- acceso masivo -------------------------------
def test_acceso_masivo_a_archivos():
    def accesos(n):
        return [dict(t=i * 10, ev="4663", cmd=rf"File access: Fin\FY\doc_{i}.xlsx", dest=r"\\FS\Fin") for i in range(n)]
    assert una(detect_mass_file_access(mk(accesos(12)))).severidad == "Alto"
    assert detect_mass_file_access(mk(accesos(5))) == []


# ------------------------------- movimiento lateral -------------------------------
def salto(origen="APP-01", destino="FS-01", t=600, user="CORP\\admin", ev="4624", result="Success"):
    return dict(t=t, ev=ev, host=destino, user=user, result=result, desc=f"logon (LogonType=3; source={origen})")


def test_lateral_con_login_externo_previo_es_critico_y_lista_actividad_posterior():
    h = una(detect_lateral_movement(mk([
        dict(t=0, ev="4624", host="APP-01", user="CORP\\admin", ip=EXT),
        salto(),
        dict(t=660, ev="5140", host="FS-01", user="CORP\\admin", desc="Network share accessed: \\\\FS-01\\Finance")])))
    assert h.severidad == "Crítico" and "Finance" in h.justificacion and len(h.evidencia) == 3


def test_lateral_sin_contexto_es_alto_y_solo_fallos_es_medio():
    assert una(detect_lateral_movement(mk([salto()]))).severidad == "Alto"
    assert una(detect_lateral_movement(mk([salto(ev="4625", result="Failure")]))).severidad == "Medio"


def test_logon_de_red_al_mismo_host_no_es_lateral():
    assert detect_lateral_movement(mk([salto(origen="FS-01", destino="FS-01")])) == []


def test_lateral_normaliza_nombres_de_host():
    assert detect_lateral_movement(mk([salto(origen="DC01", destino="DC-01")])) == []


# ------------------------------- exfiltración -------------------------------
def posts(n, mb, t0=100):
    return [dict(t=t0 + i * 15, ev="PROXY_ACCESS", src="Proxy", user="CORP\\r", host="WS-9", dest="198.51.100.8:443",
                 cmd=f"bytes_out={int(mb * 1e6)} uri=/u/{i}") for i in range(n)]


def test_exfiltracion_alto_y_critico_con_archivado_previo():
    assert una(detect_exfiltration(mk(posts(10, 8)))).severidad == "Alto"
    arch = dict(t=0, ev="4688", user="CORP\\r", host="WS-9", cmd=r"7z.exe a C:\Users\Public\a.7z C:\x")
    h = una(detect_exfiltration(mk([arch] + posts(10, 8))))
    assert h.severidad == "Crítico" and "no prueba del contenido" in h.justificacion


def test_trafico_saliente_pequeno_no_es_exfiltracion():
    assert detect_exfiltration(mk(posts(5, 1))) == []


# ------------------------------- ataque web -------------------------------
def web(uri, t, code="200"):
    return dict(t=t, ev="HTTP_ACCESS", src="IIS", host="WEB-9", user="-", ip=EXT, cmd=uri, result=code)


def test_webshell_seguida_de_proceso_del_worker_es_critico():
    h = una(detect_web_attack(mk([
        web("/uploads/s.aspx?cmd=whoami", 0), web("/uploads/s.aspx?cmd=id", 10),
        dict(t=60, ev="4688", host="WEB-9", user="IIS APPPOOL\\Pool", ip=EXT, cmd="cmd.exe /c whoami")])))
    assert h.severidad == "Crítico" and "T1505.003 Web Shell" in h.mitre


def test_sqli_alto_y_trafico_normal_sin_hallazgo():
    assert una(detect_web_attack(mk([web("/item?id=1' OR 1=1--", 0)]))).severidad == "Alto"
    assert detect_web_attack(mk([web("/index.html", 0), web("/about", 20), web("/css/a.css", 40)])) == []


# ------------------------------- otras y orquestación -------------------------------
def test_borrado_de_logs():
    assert una(detect_other_anomalies(mk([dict(ev="1102", desc="The audit log was cleared")]))).severidad == "Alto"


def test_run_all_asigna_ids_ordena_y_no_oculta_errores_de_detectores():
    df = mk(fallos(4) + [dict(t=300, ev="4624", user="CORP\\admin", ip=EXT, host="SRV-01")])
    hs = run_all(df)
    assert [h.id for h in hs] == [f"F-{i:02d}" for i in range(1, len(hs) + 1)]
    assert hs[0].severidad == "Crítico"

    def roto(_df):
        raise RuntimeError("boom")
    original = motor.DETECTORES[:]
    motor.DETECTORES.append(roto)
    try:
        errores: list[str] = []
        assert run_all(df, errores)                      # los demás detectores siguen funcionando
        assert any("boom" in e and "roto" in e for e in errores)
    finally:
        motor.DETECTORES[:] = original


# ------------------------------- regresión con el Excel real -------------------------------
def test_excel_real_18_hallazgos_sin_falsos_positivos_de_ruido():
    if not EXCEL.exists():
        return
    df = load_siem(str(EXCEL))
    errores: list[str] = []
    hs = run_all(df, errores)
    assert errores == []
    assert Counter(h.regla for h in hs) == Counter({
        "AUTH-01": 1, "AUTH-02": 1, "LAT-01": 1, "LAT-02": 2, "EXF-01": 1, "WEB-01": 1, "DATA-01": 1, "PERS-01": 1,
        "CMD-02": 1, "CMD-03": 1, "CMD-04": 2, "CMD-06": 1, "CMD-07": 2, "CMD-08": 1, "CMD-10": 1})
    # el ruido de fondo (cuentas/hosts que solo generan actividad normal) no debe aparecer en ningún hallazgo
    usuarios = {u for h in hs for u in h.usuarios}
    # (dtorres sí aparece: es una de las 8 cuentas atacadas por el spraying, por eso ya no está en esta lista)
    assert not usuarios & {"CORP\\mruiz", "CORP\\svc_backup"}
    assert "WS-022" not in {x for h in hs for x in h.hosts}
    # cifras clave verificadas contra los datos
    por = {h.regla: h for h in hs}
    assert por["EXF-01"].metricas["bytes"] == 253_305_558 and por["EXF-01"].severidad == "Crítico"
    assert por["DATA-01"].metricas["archivos"] == 16
    assert por["LAT-01"].severidad == "Crítico" and "EVT-00188" in por["LAT-01"].evidencia
    assert por["CMD-06"].metricas["destinos"] == ["203.0.113.88"]
    assert "360" in por["CMD-08"].justificacion
    # toda la evidencia existe realmente en el Excel
    assert {i for h in hs for i in h.evidencia} <= set(df["Log_ID"])


# ------------------------------- movimiento lateral por acceso a recursos compartidos (LAT-02) -------------------------------
PS_COD = "powershell.exe -NoProfile -EncodedCommand AAAA"


def share(t=420, host="FS-01", user="CORP\\bk", dest=r"\\FS-01\Finance", desc="A network share object was checked"):
    return dict(t=t, ev="5145", host=host, user=user, ip="10.10.1.44", dest=dest, desc=desc)


def cmd_alto(t=0, host="WS-01", user="CORP\\bk"):
    return dict(t=t, ev="4688", host=host, user=user, cmd=PS_COD)


def test_lat02_share_tras_comando_de_alto_riesgo_es_alto():
    h = una(detect_lateral_share_access(mk([cmd_alto(), share()])))
    assert h.regla == "LAT-02" and h.severidad == "Alto" and len(h.evidencia) == 2
    assert "Finance" in h.justificacion and "después de" in h.justificacion


def test_lat02_share_poco_antes_del_comando_tambien_cuenta():
    h = una(detect_lateral_share_access(mk([share(t=0), cmd_alto(t=120)])))
    assert "antes de" in h.justificacion


def test_lat02_login_externo_previo_es_critico():
    h = una(detect_lateral_share_access(mk([dict(t=0, ev="4624", host="WS-01", user="CORP\\bk", ip=EXT), share()])))
    assert h.severidad == "Crítico"


def test_lat02_casos_negativos():
    assert detect_lateral_share_access(mk([share()])) == []                                    # sin ancla
    assert detect_lateral_share_access(mk([cmd_alto(), share(dest="", desc="A network share object was accessed")])) == []  # share genérico
    assert detect_lateral_share_access(mk([cmd_alto(host="FS-01"), share()])) == []             # mismo host
    assert detect_lateral_share_access(mk([cmd_alto(user="CORP\\otro"), share()])) == []        # otra cuenta
    assert detect_lateral_share_access(mk([cmd_alto(t=0), share(t=3000)])) == []                # fuera de ventana


def test_lat02_no_repite_lo_que_ya_explica_lat01():
    evs = [dict(t=0, ev="4624", host="APP-01", user="CORP\\admin", ip=EXT), salto(),
           dict(t=660, ev="5140", host="FS-01", user="CORP\\admin", desc="Network share accessed: \\\\FS-01\\Finance")]
    assert len(detect_lateral_movement(mk(evs))) == 1
    assert detect_lateral_share_access(mk(evs)) == []


# ------------------------------- vistas derivadas y Excel real -------------------------------
def test_excel_real_categorias_del_reto_etiquetas_y_acciones():
    if not EXCEL.exists():
        return
    df = load_siem(str(EXCEL))
    hs = run_all(df, [])
    cuenta = conteo_categorias(hs)
    assert list(cuenta) == CATEGORIAS_RETO and all(v >= 1 for v in cuenta.values())
    por = {h.regla: h for h in hs}
    # spraying y fuerza bruta contienen un logon externo exitoso y un 4672 externo: también cuentan en esas categorías
    assert set(por["AUTH-01"].etiquetas) == {"Inicios sospechosos", "Escalamiento"}
    assert set(por["AUTH-02"].etiquetas) == {"Inicios sospechosos", "Escalamiento"}
    assert all(h.accion for h in hs)
    assert por["EXF-01"].metricas["siem_subestima"] is True and por["AUTH-02"].metricas["siem_subestima"] is False


def test_excel_real_ninguna_alerta_sin_explicar_y_solo_informational_esperados():
    if not EXCEL.exists():
        return
    df = load_siem(str(EXCEL))
    hs = run_all(df, [])
    assert eventos_sin_explicar(df, hs).empty
    evidencia = {i for h in hs for i in h.evidencia}
    informational = evidencia - set(df.loc[df["Alerta_SIEM"], "Log_ID"])
    assert informational == {"EVT-00123", "EVT-00126", "EVT-00315", "EVT-00419", "EVT-00428",
                             "EVT-00528", "EVT-00542", "EVT-00548", "EVT-00559", "EVT-00564"}


def test_explorador_una_fila_por_evento():
    if not EXCEL.exists():
        return
    df = load_siem(str(EXCEL))
    hs = run_all(df, [])
    ex = explorador(df, hs)
    assert len(ex) == len(df) and ex["Log_ID"].is_unique
    assert (ex.loc[ex["Severidad final"] == "Normal", "Hallazgo"] == "").all()
    assert ex.loc[ex["Log_ID"] == "EVT-00419", "Severidad final"].iloc[0] == "Alto"
    assert ex.loc[ex["Log_ID"] == "EVT-00123", "Hallazgo"].iloc[0] == por_regla(hs, "AUTH-01").id


def por_regla(hs, regla):
    return next(h for h in hs if h.regla == regla)