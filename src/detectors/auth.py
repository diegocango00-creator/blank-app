"""Autenticación: password spraying, fuerza bruta, inicios de sesión anómalos y escalamiento."""
from __future__ import annotations

from datetime import timedelta

import pandas as pd

from .base import (LOGON_TYPE_RE, Finding, fmt_duracion, ips_externas, rafagas, recortar, seguimiento_exito,
                   texto_seguimiento)

SPRAY_MIN_FALLOS = 10
SPRAY_MIN_CUENTAS = 5


def _es_spraying(n: int, cuentas: int, min_failures: int, min_accounts: int) -> bool:
    return n >= min_failures and cuentas >= min_accounts


# --------------------------------------------------------------------------------------------------
def detect_password_spraying(
    df: pd.DataFrame,
    min_failures: int = SPRAY_MIN_FALLOS,
    min_accounts: int = SPRAY_MIN_CUENTAS,
    max_gap: timedelta = timedelta(minutes=5),
    follow_window: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    """Una IP externa con muchos fallos 4625 contra muchas cuentas distintas en una misma ráfaga.

    Si una cuenta atacada inicia sesión con éxito desde la misma IP (durante la ráfaga o hasta
    follow_window después), el hallazgo sube a Crítico: posible credencial válida comprometida.
    """
    fallos = df[(df["Event_ID"] == "4625") & df["Externa"]]
    hallazgos: list[Finding] = []
    for ip, g in fallos.groupby("Source_IP"):
        for b in rafagas(g, max_gap):
            n, cuentas = len(b), b["User"].nunique()
            if not _es_spraying(n, cuentas, min_failures, min_accounts):
                continue
            inicio, fin = b["Timestamp"].min(), b["Timestamp"].max()
            atacadas = set(b["User"])
            exitos, priv = seguimiento_exito(df, ip, atacadas, inicio, fin + follow_window)

            dur = fin - inicio
            ritmo = n / max(dur.total_seconds() / 60, 1 / 60)
            hosts = sorted(b["Host"].unique())
            texto = (
                f"La IP externa {ip} generó {n} fallos de autenticación (4625) contra {cuentas} cuentas distintas "
                f"en {fmt_duracion(dur)} (de {inicio:%H:%M:%S} a {fin:%H:%M:%S}), unos {ritmo:.1f} por minuto "
                f"y ≈{n / cuentas:.1f} intentos por cuenta, sobre {', '.join(hosts)}. "
                "Pocos intentos repartidos entre muchas cuentas es el patrón de password spraying."
                + texto_seguimiento(exitos, priv)
            )
            evidencia = sorted(set(b["Log_ID"]) | set(exitos["Log_ID"]) | set(priv["Log_ID"]))
            hallazgos.append(Finding(
                id="", categoria="Fuerza bruta", titulo=f"Password spraying desde {ip}",
                severidad="Crítico" if len(exitos) else "Alto", justificacion=texto, evidencia=evidencia,
                inicio=inicio, fin=max([fin, *exitos["Timestamp"], *priv["Timestamp"]]), regla="AUTH-01",
                mitre=["T1110.003 Password Spraying"] + (["T1078 Valid Accounts"] if len(exitos) else []),
                hosts=sorted(set(hosts) | set(exitos["Host"]) | set(priv["Host"])), usuarios=sorted(atacadas), ips=[ip],
                metricas={"fallos": n, "cuentas_atacadas": cuentas, "duracion_s": int(dur.total_seconds()),
                          "cuentas_con_exito": sorted(set(exitos["User"]))},
            ))
    return hallazgos


# --------------------------------------------------------------------------------------------------
def detect_brute_force(
    df: pd.DataFrame,
    min_failures_ext: int = 3,
    min_failures_int: int = 8,
    spray_failures: int = SPRAY_MIN_FALLOS,
    spray_accounts: int = SPRAY_MIN_CUENTAS,
    max_gap: timedelta = timedelta(minutes=5),
    follow_window: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    """Ráfagas de fallos 4625 desde una misma IP que NO son spraying (pocas cuentas, muchos intentos).

    Umbral más bajo para IP externa que interna: los fallos internos ocasionales son ruido normal.
    Una sesión exitosa posterior de la cuenta atacada desde la misma IP eleva la severidad.
    """
    fallos = df[(df["Event_ID"] == "4625") & df["IP_valida"]]
    hallazgos: list[Finding] = []
    for ip, g in fallos.groupby("Source_IP"):
        externa = bool(g["Externa"].iloc[0])
        umbral = min_failures_ext if externa else min_failures_int
        for b in rafagas(g, max_gap):
            n, cuentas = len(b), b["User"].nunique()
            if n < umbral or _es_spraying(n, cuentas, spray_failures, spray_accounts):
                continue
            inicio, fin = b["Timestamp"].min(), b["Timestamp"].max()
            atacadas = set(b["User"])
            exitos, priv = seguimiento_exito(df, ip, atacadas, inicio, fin + follow_window)

            if len(exitos):
                sev = "Crítico" if externa else "Alto"
            else:
                sev = "Alto" if (externa and n >= spray_failures) else "Medio"

            top = b["User"].value_counts()
            objetivo = ", ".join(f"{u} ({c})" for u, c in top.head(3).items())
            tipos = sorted({m.group(1) for d in b["Event_Description"] if (m := LOGON_TYPE_RE.search(d))})
            tipo_txt = f" Tipo de inicio de sesión registrado: LogonType={', '.join(tipos)}." if tipos else ""
            hosts = sorted(b["Host"].unique())
            texto = (
                f"La IP {'externa' if externa else 'interna'} {ip} generó {n} fallos de autenticación (4625) contra "
                f"{cuentas} cuenta(s) [{objetivo}] en {fmt_duracion(fin - inicio)} (de {inicio:%H:%M:%S} a "
                f"{fin:%H:%M:%S}) sobre {', '.join(hosts)}.{tipo_txt}" + texto_seguimiento(exitos, priv)
            )
            evidencia = sorted(set(b["Log_ID"]) | set(exitos["Log_ID"]) | set(priv["Log_ID"]))
            hallazgos.append(Finding(
                id="", categoria="Fuerza bruta",
                titulo=f"Fuerza bruta desde {'IP externa' if externa else 'IP interna'} {ip}", severidad=sev,
                justificacion=texto, evidencia=evidencia, inicio=inicio,
                fin=max([fin, *exitos["Timestamp"], *priv["Timestamp"]]), regla="AUTH-02",
                mitre=["T1110.001 Password Guessing" if cuentas == 1 else "T1110 Brute Force"]
                + (["T1078 Valid Accounts"] if len(exitos) else []),
                hosts=sorted(set(hosts) | set(exitos["Host"]) | set(priv["Host"])), usuarios=sorted(atacadas), ips=[ip],
                metricas={"fallos": n, "cuentas_atacadas": cuentas, "con_exito": bool(len(exitos))},
            ))
    return hallazgos


# --------------------------------------------------------------------------------------------------
def _cubiertos(df: pd.DataFrame) -> set[str]:
    """Log_ID ya explicados por spraying/fuerza bruta (para no duplicar hallazgos)."""
    ids: set[str] = set()
    for f in detect_password_spraying(df) + detect_brute_force(df):
        ids |= set(f.evidencia)
    return ids


def detect_anomalous_logins(
    df: pd.DataFrame,
    horario: tuple[int, int] = (7, 19),
    fines_de_semana_fuera: bool = True,
) -> list[Finding]:
    """Inicios de sesión exitosos con origen externo o fuera del horario laboral configurado.

    Solo informa lo que NO esté ya explicado por un hallazgo de spraying/fuerza bruta.
    El horario laboral es un SUPUESTO configurable (los logs no traen línea base histórica).
    """
    cubiertos = _cubiertos(df)
    ok = df[(df["Event_ID"] == "4624") & (df["Result"] == "Success") & ~df["Log_ID"].isin(cubiertos)]
    hallazgos: list[Finding] = []

    externos = ok[ok["Externa"]]
    for (ip, user), g in externos.groupby(["Source_IP", "User"]):
        hosts = sorted(g["Host"].unique())
        texto = (
            f"La cuenta {user} inició sesión con éxito (4624) {len(g)} vez/veces desde la IP externa {ip} en "
            f"{', '.join(hosts)} (primer evento {g.iloc[0]['Log_ID']} a las {g['Timestamp'].min():%H:%M:%S}). "
            "No está precedido por una ráfaga de fallos detectada, por lo que el origen externo es la única señal."
        )
        hallazgos.append(Finding(
            id="", categoria="Inicio de sesión anómalo", titulo=f"Inicio de sesión exitoso desde IP externa {ip}",
            severidad="Alto", justificacion=texto, evidencia=sorted(g["Log_ID"]), inicio=g["Timestamp"].min(),
            fin=g["Timestamp"].max(), regla="AUTH-03", mitre=["T1078 Valid Accounts"], hosts=hosts, usuarios=[user],
            ips=[ip], metricas={"inicios": len(g)}))

    h0, h1 = horario
    hora_ok = ok["Timestamp"].dt.hour.between(h0, h1 - 1)
    finde = ok["Timestamp"].dt.weekday >= 5 if fines_de_semana_fuera else pd.Series(False, index=ok.index)
    fuera = ok[(~hora_ok | finde) & ~ok["Externa"]]
    for user, g in fuera.groupby("User"):
        hosts = sorted(g["Host"].unique())
        texto = (
            f"La cuenta {user} registra {len(g)} inicio(s) de sesión exitoso(s) (4624) fuera del horario laboral "
            f"configurado ({h0:02d}:00–{h1:02d}:00{', lun–vie' if fines_de_semana_fuera else ''}), entre "
            f"{g['Timestamp'].min():%Y-%m-%d %H:%M:%S} y {g['Timestamp'].max():%Y-%m-%d %H:%M:%S} en {', '.join(hosts)}. "
            "El horario es un supuesto: debe validarse contra el horario real de la organización."
        )
        hallazgos.append(Finding(
            id="", categoria="Inicio de sesión anómalo", titulo=f"Inicios de sesión fuera de horario: {user}",
            severidad="Medio", justificacion=texto, evidencia=sorted(g["Log_ID"]), inicio=g["Timestamp"].min(),
            fin=g["Timestamp"].max(), regla="AUTH-04", mitre=["T1078 Valid Accounts"], hosts=hosts, usuarios=[user],
            ips=ips_externas(g), metricas={"inicios": len(g), "horario": f"{h0}-{h1}"}))
    return hallazgos


# --------------------------------------------------------------------------------------------------
GRUPOS_PRIVILEGIADOS = {"4728", "4732", "4756"}  # miembro agregado a grupo global / local / universal


def detect_escalation(df: pd.DataFrame) -> list[Finding]:
    """Elevación de privilegios: 4672 en sesiones de origen externo y altas en grupos privilegiados.

    Los 4672 que ya forman parte de un hallazgo de spraying/fuerza bruta no se repiten aquí
    (van dentro de su evidencia). Los 4672 de origen interno son habituales y no se marcan.
    """
    cubiertos = _cubiertos(df)
    hallazgos: list[Finding] = []

    p = df[(df["Event_ID"] == "4672") & df["Externa"] & ~df["Log_ID"].isin(cubiertos)]
    for (ip, user, host), g in p.groupby(["Source_IP", "User", "Host"]):
        texto = (
            f"Se asignaron privilegios especiales (4672) a {user} en {host} en una sesión originada en la IP externa "
            f"{ip} ({g.iloc[0]['Log_ID']}, {g['Timestamp'].min():%H:%M:%S}). Los 4672 de origen interno son "
            "habituales en este conjunto; el origen externo es lo que lo hace anómalo."
        )
        hallazgos.append(Finding(
            id="", categoria="Escalamiento de privilegios", titulo=f"Privilegios especiales desde IP externa ({user})",
            severidad="Alto", justificacion=texto, evidencia=sorted(g["Log_ID"]), inicio=g["Timestamp"].min(),
            fin=g["Timestamp"].max(), regla="PRIV-01", mitre=["T1078 Valid Accounts", "T1068 Exploitation for Privilege Escalation"],
            hosts=[host], usuarios=[user], ips=[ip]))

    for _, e in df[df["Event_ID"].isin(GRUPOS_PRIVILEGIADOS)].iterrows():
        texto = (f"Evento {e['Event_ID']} en {e['Host']}: {recortar(e['Event_Description'])} "
                 f"(ejecutado por {e['User']}, {e['Log_ID']}, {e['Timestamp']:%H:%M:%S}). "
                 "Agregar miembros a grupos privilegiados es una vía de persistencia y escalamiento.")
        hallazgos.append(Finding(
            id="", categoria="Escalamiento de privilegios", titulo=f"Alta en grupo privilegiado en {e['Host']}",
            severidad="Alto", justificacion=texto, evidencia=[e["Log_ID"]], inicio=e["Timestamp"], fin=e["Timestamp"],
            regla="PRIV-02", mitre=["T1098 Account Manipulation"], hosts=[e["Host"]], usuarios=[e["User"]],
            ips=ips_externas(df[df["Log_ID"] == e["Log_ID"]])))
    return hallazgos