"""Ejecución: comandos y procesos sospechosos, persistencia y acceso masivo a archivos."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta

import pandas as pd

from .base import Finding, fmt_duracion, ips_externas, periodicidad, rafagas, recortar

# Eventos donde la línea de comandos / descripción describe una ejecución o conexión de proceso.
# (4698/7045 los cubre detect_persistence; las peticiones HTTP las cubre detect_web_attack.)
EVENTOS_EJECUCION = {"4688", "4104", "4103", "1", "5156"}

_ARCHIVADO = r"(?:\b(?:7z|7za|rar)(?:\.exe)?\s+a\b|\btar(?:\.exe)?\s.*-\w*c|Compress-Archive)"
_DIR_STAGING = r"\\(?:Users\\Public|Temp|ProgramData|PerfLogs)\\"
_RUTA_NO_ESTANDAR = (r"(?:^|[\s\"'])[a-z]:\\(?:ProgramData|Users\\Public|Windows\\Temp|Temp|PerfLogs)\\"
                     r"[^\s\"']+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js)\b")
ARCHIVADO_RE = re.compile(_ARCHIVADO, re.I)
_IP_DESTINO = re.compile(r"outbound connection to (\d{1,3}(?:\.\d{1,3}){3})", re.I)


@dataclass(frozen=True)
class Regla:
    id: str
    nombre: str
    patron: re.Pattern
    severidad: str
    mitre: tuple[str, ...]
    relevancia: str
    usuario: re.Pattern | None = None  # si se define, el User del evento también debe coincidir


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.I)


# El ORDEN importa: cada evento se asigna a la primera regla que coincide.
REGLAS_CMD: list[Regla] = [
    Regla("CMD-01", "Volcado de credenciales", _r(
        r"mimikatz|sekurlsa|procdump.*lsass|comsvcs\.dll.*minidump|ntdsutil|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)"),
        "Crítico", ("T1003 OS Credential Dumping",),
        "Estas herramientas se usan para extraer credenciales de la memoria o del registro."),
    Regla("CMD-02", "Inhibición de recuperación (borrado de copias de sombra)", _r(
        r"vssadmin(?:\.exe)?\s+delete\s+shadows|wbadmin\s+delete|wmic\s+shadowcopy\s+delete|"
        r"bcdedit.*(?:recoveryenabled\s+no|ignoreallfailures)"),
        "Crítico", ("T1490 Inhibit System Recovery",),
        "Eliminar copias de sombra impide restaurar archivos y es un paso típico previo a ransomware o sabotaje."),
    Regla("CMD-03", "Comando ejecutado por el proceso de servidor web", _r(
        r"\b(?:cmd(?:\.exe)?\s+/c|powershell|whoami|net1?(?:\.exe)?\s|certutil|bitsadmin)"),
        "Crítico", ("T1505.003 Web Shell", "T1059.003 Windows Command Shell"),
        "Un worker de IIS no ejecuta shells de forma legítima: es el comportamiento característico de una webshell.",
        usuario=_r(r"APPPOOL|\bw3wp\b")),
    Regla("CMD-04", "PowerShell con comando codificado", _r(
        r"powershell(?:\.exe)?\b.*\s-(?:e|ec|enc|encodedcommand)(?:\s|$)"),
        "Alto", ("T1059.001 PowerShell", "T1027 Obfuscated Files or Information"),
        "La codificación en Base64 oculta el contenido del script y es común en malware y post-explotación."),
    Regla("CMD-05", "Descarga de ficheros / ejecución remota de código", _r(
        r"certutil.*-urlcache|bitsadmin.*(?:/transfer|/download)|Invoke-WebRequest|Invoke-Expression|\bIEX\b|"
        r"DownloadString|DownloadFile|Net\.WebClient"),
        "Alto", ("T1105 Ingress Tool Transfer", "T1059.001 PowerShell"),
        "Permite traer herramientas o código desde Internet al equipo."),
    Regla("CMD-06", "Conexión saliente iniciada por un intérprete de comandos", _r(
        r"outbound connection to (?!(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\s*"
        r"\(process=(?:powershell|cmd|rundll32|mshta|wscript|cscript|regsvr32|certutil)"),
        "Alto", ("T1071 Application Layer Protocol",),
        "Un intérprete que abre conexiones a Internet es compatible con comando y control o con descarga de herramientas."),
    Regla("CMD-07", "Archivado de datos en directorio de staging", _r(rf"^(?=.*{_ARCHIVADO})(?=.*{_DIR_STAGING})"),
        "Alto", ("T1560.001 Archive via Utility", "T1074 Data Staged"),
        "Comprimir datos en directorios compartidos o temporales es una preparación habitual antes de exfiltrar."),
    Regla("CMD-08", "Ejecución desde ruta no estándar", _r(_RUTA_NO_ESTANDAR),
        "Alto", ("T1036 Masquerading", "T1204 User Execution"),
        "Los programas legítimos no suelen ejecutarse desde ProgramData, Temp o Users\\Public."),
    Regla("CMD-09", "Archivado de datos", _r(_ARCHIVADO),
        "Medio", ("T1560.001 Archive via Utility",),
        "La compresión de datos puede preceder a una exfiltración; por sí sola también puede ser legítima."),
    Regla("CMD-10", "Reconocimiento del sistema o de la red", _r(
        r"\b(?:whoami|ipconfig|systeminfo|nltest|quser|qwinsta|tasklist)\b|"
        r"\bnet1?(?:\.exe)?\s+(?:view|user|group|localgroup|accounts|share|use)\b|"
        r"Get-LocalGroupMember|Get-SmbShare|Get-ADUser|Get-ADGroupMember|Get-NetTCPConnection"),
        "Medio", ("T1087 Account Discovery", "T1135 Network Share Discovery", "T1033 System Owner/User Discovery"),
        "Enumerar cuentas, recursos compartidos o la identidad actual es la fase de reconocimiento posterior al acceso."),
]


def clasificar_comandos(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve los eventos de ejecución que coinciden con alguna regla, con columnas Regla_ID y Regla."""
    d = df[df["Event_ID"].isin(EVENTOS_EJECUCION)].copy()
    if d.empty:
        return d.assign(Regla_ID=pd.Series(dtype=str), Regla=pd.Series(dtype=object))
    texto = d["Event_Description"] + " " + d["Process_CommandLine"]
    asignada: list[Regla | None] = []
    for t, u in zip(texto, d["User"]):
        asignada.append(next((r for r in REGLAS_CMD if r.patron.search(t) and (r.usuario is None or r.usuario.search(u))), None))
    d["Regla"] = asignada
    d = d[d["Regla"].notna()].copy()
    d["Regla_ID"] = d["Regla"].map(lambda r: r.id)
    return d


def detect_suspicious_commands(df: pd.DataFrame, max_gap: timedelta = timedelta(minutes=15)) -> list[Finding]:
    """Un hallazgo por (regla, host, usuario) y ráfaga temporal."""
    hits = clasificar_comandos(df)
    hallazgos: list[Finding] = []
    for (rid, host, user), g in hits.groupby(["Regla_ID", "Host", "User"]):
        regla: Regla = g["Regla"].iloc[0]
        for b in rafagas(g, max_gap):
            # En 4104 (script block) y 5156 (conexión) lo informativo está en la descripción, no en la línea de comandos.
            cmds = list(dict.fromkeys(
                recortar(d if (e in ("4104", "5156") or not c) else c, 100)
                for e, c, d in zip(b["Event_ID"], b["Process_CommandLine"], b["Event_Description"])))
            destinos = sorted(set(_IP_DESTINO.findall(" ".join(b["Event_Description"])))) if regla.id == "CMD-06" else []
            texto = (
                f"{len(b)} evento(s) de «{regla.nombre}» de {user} en {host} entre {b['Timestamp'].min():%H:%M:%S} y "
                f"{b['Timestamp'].max():%H:%M:%S} ({b.iloc[0]['Log_ID']}"
                f"{' … ' + b.iloc[-1]['Log_ID'] if len(b) > 1 else ''}). Comando(s) observado(s): "
                + "; ".join(f"`{c}`" for c in cmds[:3]) + ("…" if len(cmds) > 3 else "") + "."
            )
            per = periodicidad(b["Timestamp"])
            if per:
                texto += " " + per
            texto += f" Relevancia: {regla.relevancia}"
            hallazgos.append(Finding(
                id="", categoria="Comandos y procesos sospechosos", titulo=f"{regla.nombre} — {user} en {host}",
                severidad=regla.severidad, justificacion=texto, evidencia=sorted(b["Log_ID"]),
                inicio=b["Timestamp"].min(), fin=b["Timestamp"].max(), regla=regla.id, mitre=list(regla.mitre),
                hosts=[host], usuarios=[user], ips=sorted(set(ips_externas(b)) | set(destinos)),
                metricas={"eventos": len(b), **({"destinos": destinos} if destinos else {})}))
    return hallazgos


# --------------------------------------------------------------------------------------------------
_TASK =re.compile(r"TaskName=([^;]+)")
_ACTION = re.compile(r"Action=(.+)$")
_SVC = re.compile(r"ServiceName=([^;]+)")
_IMG = re.compile(r"ImagePath=(.+)$")
_ACCION_SOSPECHOSA = re.compile(r"powershell|cmd(?:\.exe)?\s|wscript|cscript|mshta|rundll32|" + _RUTA_NO_ESTANDAR, re.I)


def detect_persistence(df: pd.DataFrame, max_gap: timedelta = timedelta(minutes=30)) -> list[Finding]:
    """Tareas programadas (4698) y servicios nuevos (7045). Severidad Alta si la acción es un
    intérprete de comandos o apunta a una ruta no estándar; Media en otro caso."""
    p = df[df["Event_ID"].isin(["4698", "7045"])]
    hallazgos: list[Finding] = []
    for (host, user), g in p.groupby(["Host", "User"]):
        for b in rafagas(g, max_gap):
            partes, sospechoso = [], False
            for _, e in b.iterrows():
                cmd = e["Process_CommandLine"]
                if e["Event_ID"] == "4698":
                    nom = (_TASK.search(cmd) or [None, "?"])[1].strip()
                    acc = (_ACTION.search(cmd) or [None, "?"])[1].strip()
                    partes.append(f"tarea programada «{nom}» con acción `{recortar(acc, 90)}` ({e['Log_ID']}, {e['Timestamp']:%H:%M:%S})")
                else:
                    nom = (_SVC.search(cmd) or [None, "?"])[1].strip()
                    acc = (_IMG.search(cmd) or [None, "?"])[1].strip()
                    partes.append(f"servicio «{nom}» con ejecutable `{recortar(acc, 90)}` ({e['Log_ID']}, {e['Timestamp']:%H:%M:%S})")
                sospechoso |= bool(_ACCION_SOSPECHOSA.search(" " + acc))
            sev = "Alto" if sospechoso else "Medio"
            texto = (f"{user} creó en {host}: " + "; ".join(partes) + ". "
                     + ("La acción es un intérprete de comandos o apunta a una ruta no estándar (ProgramData/Temp/Public). "
                        if sospechoso else "No se identificó una ruta o intérprete sospechoso en la acción. ")
                     + "Crear tareas o servicios permite que el código se ejecute de forma persistente y repetida.")
            tipos = set(b["Event_ID"])
            hallazgos.append(Finding(
                id="", categoria="Persistencia", titulo=f"Persistencia creada por {user} en {host}", severidad=sev,
                justificacion=texto, evidencia=sorted(b["Log_ID"]), inicio=b["Timestamp"].min(), fin=b["Timestamp"].max(),
                regla="PERS-01", mitre=(["T1053.005 Scheduled Task"] if "4698" in tipos else [])
                + (["T1543.003 Windows Service"] if "7045" in tipos else []),
                hosts=[host], usuarios=[user], ips=ips_externas(b), metricas={"eventos": len(b)}))
    return hallazgos


# --------------------------------------------------------------------------------------------------
_RUTA_ARCHIVO = re.compile(r"(?:file access|file share access):\s*([^|]+?)\s*(?:\||$)", re.I)


def detect_mass_file_access(
    df: pd.DataFrame, min_files: int = 10, max_gap: timedelta = timedelta(seconds=120),
) -> list[Finding]:
    """Una cuenta que accede a >= min_files archivos distintos en una misma ráfaga (recolección de datos)."""
    a = df[df["Event_ID"].isin(["4663", "5145"])].copy()
    a["Ruta"] = (a["Event_Description"] + " | " + a["Process_CommandLine"]).str.extract(_RUTA_ARCHIVO)[0]
    a = a[a["Ruta"].notna()]
    hallazgos: list[Finding] = []
    for (user, host), g in a.groupby(["User", "Host"]):
        for b in rafagas(g, max_gap):
            rutas = b["Ruta"].nunique()
            if rutas < min_files:
                continue
            dur = b["Timestamp"].max() - b["Timestamp"].min()
            carpeta = b["Ruta"].str.rsplit("\\", n=1).str[0].value_counts()
            destinos = sorted({d for d in b["Destination"] if d})
            texto = (
                f"{user} accedió a {rutas} archivos distintos en {host} en {fmt_duracion(dur)} "
                f"({b['Timestamp'].min():%H:%M:%S}–{b['Timestamp'].max():%H:%M:%S}), un acceso cada "
                f"≈{dur.total_seconds() / max(len(b) - 1, 1):.0f} s, principalmente en «{carpeta.index[0]}» "
                f"({carpeta.iloc[0]} archivos){' sobre ' + ', '.join(destinos) if destinos else ''} "
                f"({b.iloc[0]['Log_ID']} … {b.iloc[-1]['Log_ID']}). Un acceso secuencial y rápido a muchos "
                "documentos es compatible con recolección automatizada de datos."
            )
            hallazgos.append(Finding(
                id="", categoria="Acceso masivo a datos", titulo=f"Acceso masivo a archivos — {user} en {host}",
                severidad="Alto", justificacion=texto, evidencia=sorted(b["Log_ID"]), inicio=b["Timestamp"].min(),
                fin=b["Timestamp"].max(), regla="DATA-01", mitre=["T1039 Data from Network Shared Drive"],
                hosts=[host], usuarios=[user], ips=ips_externas(b), metricas={"archivos": rutas, "duracion_s": int(dur.total_seconds())}))
    return hallazgos