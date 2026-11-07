"""Tipos y utilidades compartidas por los detectores.

Regla de oro: toda cifra o hecho que aparezca en una justificación se calcula a partir de los datos.
Las frases de "relevancia" son conocimiento de dominio (por qué importa un patrón) y se separan
explícitamente de los hechos observados.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

import pandas as pd

from ..loader import _normalizar_host as normalizar_host  # noqa: F401  (reexportado para los detectores)

SEVERIDADES = ["Crítico", "Alto", "Medio", "Bajo"]  # de mayor a menor

# Las seis categorías del enunciado y cómo se agrupan las categorías internas de los detectores
CATEGORIAS_RETO = ["Fuerza bruta", "Inicios sospechosos", "Escalamiento", "Comandos y procesos",
                   "Movimiento lateral", "Otras anomalías"]
MAPA_CATEGORIA = {
    "Fuerza bruta": "Fuerza bruta",
    "Inicio de sesión anómalo": "Inicios sospechosos",
    "Escalamiento de privilegios": "Escalamiento",
    "Comandos y procesos sospechosos": "Comandos y procesos",
    "Movimiento lateral": "Movimiento lateral",
}  # cualquier otra (Exfiltración, Persistencia, Ataque web, Acceso masivo...) cuenta como "Otras anomalías"

# Severidad que asigna el SIEM, de menor a mayor
ORDEN_SIEM = {"Informational": 0, "Low": 1, "Warning": 2, "Medium": 3, "High": 4, "Critical": 5}

# Acción SOC recomendada por regla. Es guía de respuesta, no una afirmación sobre los logs.
_ACCION_REGLA = {
    "AUTH-01": "Bloquear la IP origen en el perímetro, restablecer las contraseñas de las cuentas atacadas (primero las que "
               "tuvieron acceso exitoso), revisar su actividad posterior y exigir MFA.",
    "AUTH-02": "Bloquear la IP origen, restablecer la contraseña de la cuenta objetivo, no exponer RDP a internet "
               "(VPN/MFA) y revisar las sesiones activas de la cuenta.",
    "AUTH-03": "Confirmar con el titular si el acceso fue legítimo; si no, deshabilitar la cuenta, cerrar sesiones y "
               "restablecer credenciales.",
    "AUTH-04": "Confirmar con el titular o su responsable si el acceso fuera de horario fue legítimo.",
    "PRIV-01": "Revisar los privilegios de la cuenta y de la sesión que los obtuvo; revocar los que no correspondan.",
    "PRIV-02": "Verificar que el alta en el grupo privilegiado fue autorizada; si no, revertirla y revisar la cuenta.",
    "LAT-01": "Restringir el tráfico SMB/RDP entre servidores, revisar la cuenta usada y la actividad en el host destino.",
    "LAT-02": "Revisar qué recursos se accedieron desde el equipo de origen, restringir el acceso a los shares y validar la cuenta.",
    "DATA-01": "Verificar si el acceso masivo es una tarea autorizada; si no, suspender la cuenta y determinar qué archivos "
               "fueron leídos o copiados.",
    "EXF-01": "Bloquear el destino en el proxy, aislar el equipo de origen, identificar qué se comprimió y evaluar la "
              "notificación de la fuga de datos.",
    "PERS-01": "Preservar evidencia y luego eliminar la tarea/servicio y el binario; buscar otros mecanismos de "
               "persistencia y revisar la cuenta que los creó.",
    "WEB-01": "Retirar el archivo subido, bloquear la IP origen en el WAF o perímetro, revisar permisos del application "
              "pool y buscar archivos similares en la carpeta de subidas.",
}
_ACCION_PREFIJO = {
    "CMD": "Obtener el comando completo (decodificar si es base64), revisar el proceso padre y la cuenta, y aislar el equipo "
           "si se confirma actividad maliciosa.",
    "OTH": "Revisar el evento con el responsable del sistema y confirmar si fue una acción autorizada.",
}


def accion_para(regla: str) -> str:
    return _ACCION_REGLA.get(regla) or _ACCION_PREFIJO.get(regla.split("-")[0], "")


LOGON_TYPE_RE = re.compile(r"LogonType=(\d+)")
SOURCE_RE = re.compile(r"source=([^;)\s]+)")


@dataclass
class Finding:
    id: str
    categoria: str
    titulo: str
    severidad: str
    justificacion: str
    evidencia: list[str]                      # Log_ID que respaldan el hallazgo
    inicio: pd.Timestamp
    fin: pd.Timestamp
    regla: str = ""                           # identificador de la regla que lo generó
    mitre: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    usuarios: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    metricas: dict = field(default_factory=dict)
    accion: str = ""                          # acción SOC recomendada (guía general de respuesta, no un hecho del log)
    etiquetas: list[str] = field(default_factory=list)  # otras categorías del reto que este hallazgo también evidencia

    @property
    def categoria_reto(self) -> str:
        """Una de las seis categorías que pide el reto."""
        return MAPA_CATEGORIA.get(self.categoria, "Otras anomalías")

    @property
    def categorias_reto(self) -> list[str]:
        return [self.categoria_reto, *[e for e in self.etiquetas if e != self.categoria_reto]]

    def evidencia_df(self, df: pd.DataFrame) -> pd.DataFrame:
        cols = ["Log_ID", "Timestamp", "Host", "Event_ID", "User", "Source_IP", "Destination",
                "Event_Description", "Process_CommandLine", "Result", "Severity"]
        return df[df["Log_ID"].isin(self.evidencia)][cols].sort_values("Timestamp")


def fmt_duracion(td: pd.Timedelta) -> str:
    s = int(td.total_seconds())
    m, s = divmod(s, 60)
    return f"{m} min {s:02d} s" if m else f"{s} s"


def recortar(texto: str, n: int = 110) -> str:
    texto = " ".join(str(texto).split())
    return texto if len(texto) <= n else texto[: n - 1] + "…"


def rafagas(g: pd.DataFrame, max_gap: timedelta) -> list[pd.DataFrame]:
    """Parte un DataFrame en ráfagas: eventos consecutivos separados por <= max_gap."""
    g = g.sort_values("Timestamp")
    grupo = (g["Timestamp"].diff() > max_gap).cumsum()
    return [b for _, b in g.groupby(grupo)]


def periodicidad(ts: pd.Series, tolerancia: float = 0.15) -> str | None:
    """Si >=3 eventos se repiten a intervalos casi constantes, lo describe (patrón de tarea automatizada)."""
    ts = ts.sort_values()
    if len(ts) < 3:
        return None
    d = ts.diff().dropna().dt.total_seconds()
    media = d.mean()
    if media > 0 and d.std(ddof=0) / media <= tolerancia:
        return f"Se repite cada ≈{media:.0f} s (intervalo regular), compatible con ejecución automatizada."
    return None


def seguimiento_exito(df: pd.DataFrame, ip: str, usuarios: set[str], desde: pd.Timestamp, hasta: pd.Timestamp):
    """Inicios de sesión exitosos (4624) de las cuentas atacadas desde la misma IP, y sus 4672 posteriores."""
    mismos = df[(df["Source_IP"] == ip) & (df["Timestamp"] >= desde) & (df["Timestamp"] <= hasta)]
    exitos = mismos[(mismos["Event_ID"] == "4624") & mismos["User"].isin(usuarios) & (mismos["Result"] == "Success")]
    privilegios = mismos[(mismos["Event_ID"] == "4672") & mismos["User"].isin(set(exitos["User"]))]
    return exitos, privilegios


def texto_seguimiento(exitos: pd.DataFrame, privilegios: pd.DataFrame) -> str:
    if exitos.empty:
        return " No se observó inicio de sesión exitoso posterior de las cuentas atacadas desde esa IP."
    e = exitos.iloc[0]
    lt = LOGON_TYPE_RE.search(e["Event_Description"])
    tipo = f" (LogonType={lt.group(1)})" if lt else ""
    t = (f" Después, la cuenta {e['User']} inició sesión con éxito (4624){tipo} desde la misma IP a las "
         f"{e['Timestamp']:%H:%M:%S} en {e['Host']} ({e['Log_ID']}), cuenta que estaba entre las atacadas: "
         "es compatible con una credencial válida comprometida.")
    if not privilegios.empty:
        p = privilegios.iloc[0]
        t += (f" Se registró además asignación de privilegios especiales (4672) para esa cuenta desde la misma IP "
              f"a las {p['Timestamp']:%H:%M:%S} en {p['Host']} ({p['Log_ID']}).")
    return t


def ips_externas(d: pd.DataFrame) -> list[str]:
    return sorted(d.loc[d["Externa"], "Source_IP"].unique())