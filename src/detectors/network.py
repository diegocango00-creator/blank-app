"""Red: movimiento lateral, exfiltración y ataques web."""
from __future__ import annotations

import re
from datetime import timedelta

import pandas as pd

from .base import (LOGON_TYPE_RE, SOURCE_RE, Finding, fmt_duracion, ips_externas, normalizar_host, rafagas,
                   recortar)
from .execution import ARCHIVADO_RE, clasificar_comandos


# --------------------------------------------------------------------------------------------------
def detect_lateral_movement(
    df: pd.DataFrame,
    ventana_contexto: timedelta = timedelta(minutes=60),
    ventana_post: timedelta = timedelta(minutes=30),
    gap: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    """Inicios de sesión de red (LogonType 3) o RDP (10) en un host cuyo origen declarado (source=HOST)
    es OTRO host del entorno.

    Crítico si la misma cuenta, en el host de origen y en la hora previa, tuvo un inicio de sesión desde IP
    externa o ejecutó comandos de severidad Alta/Crítica. Alto si solo hay el salto. Medio si todos los
    intentos fallaron. Se incluye la actividad posterior de la cuenta en el host destino.
    """
    d = df[df["Event_ID"].isin(["4624", "4625"])].copy()
    d["_lt"] = d["Event_Description"].str.extract(LOGON_TYPE_RE)[0]
    d["_src"] = d["Event_Description"].str.extract(SOURCE_RE)[0].map(lambda x: normalizar_host(x) if isinstance(x, str) else None)
    cand = d[d["_lt"].isin(["3", "10"]) & d["_src"].notna() & (d["_src"] != d["Host"])]
    if cand.empty:
        return []
    duros = clasificar_comandos(df)
    # .astype(bool): con `duros` vacío, .map() devuelve dtype object y pandas lo trataría como selección de columnas
    duros = duros[duros["Regla"].map(lambda r: r.severidad in ("Crítico", "Alto")).astype(bool)]

    hallazgos: list[Finding] = []
    for (user, origen, destino), g in cand.groupby(["User", "_src", "Host"]):
        for b in rafagas(g, gap):
            exitos = b[(b["Event_ID"] == "4624") & (b["Result"] == "Success")]
            fallos = b[b["Event_ID"] == "4625"]
            ids = set(b["Log_ID"])
            if exitos.empty:
                texto = (f"{user} intentó {len(fallos)} vez/veces iniciar sesión en {destino} con origen declarado {origen} "
                         f"(LogonType={b.iloc[0]['_lt']}), sin éxito ({b.iloc[0]['Log_ID']}). Es un intento de salto entre "
                         "sistemas fallido; por sí solo no confirma movimiento lateral.")
                sev, fin, mitre = "Medio", b["Timestamp"].max(), ["T1021 Remote Services"]
            else:
                t0 = exitos["Timestamp"].min()
                previo = df[(df["Host"] == origen) & (df["User"] == user) & (df["Timestamp"] >= t0 - ventana_contexto)
                            & (df["Timestamp"] <= t0)]
                ext = previo[(previo["Event_ID"] == "4624") & (previo["Result"] == "Success") & previo["Externa"]]
                cmds = duros[(duros["Host"] == origen) & (duros["User"] == user) & (duros["Timestamp"] >= t0 - ventana_contexto)
                             & (duros["Timestamp"] <= t0)]
                post = df[(df["User"] == user) & (df["Host"] == destino) & (df["Timestamp"] >= t0)
                          & (df["Timestamp"] <= t0 + ventana_post) & ~df["Event_ID"].isin(["4624", "4625", "4634"])
                          & ~df["Log_ID"].isin(ids)].sort_values("Timestamp")
                ids |= set(ext["Log_ID"]) | set(cmds["Log_ID"]) | set(post["Log_ID"])

                texto = (f"{user} inició sesión en {destino} con éxito (4624, LogonType={exitos.iloc[0]['_lt']}) a las "
                         f"{t0:%H:%M:%S} con origen declarado {origen} ({exitos.iloc[0]['Log_ID']})"
                         + (f", tras {len(fallos)} intento(s) fallido(s) ({fallos.iloc[0]['Log_ID']})" if len(fallos) else "") + ".")
                if len(ext):
                    texto += (f" Esa misma cuenta había iniciado sesión en {origen} desde la IP externa {ext.iloc[0]['Source_IP']} a las "
                              f"{ext.iloc[0]['Timestamp']:%H:%M:%S} ({ext.iloc[0]['Log_ID']}), {fmt_duracion(t0 - ext.iloc[0]['Timestamp'])} antes del salto.")
                if len(cmds):
                    texto += (f" En {origen} había ejecutado {len(cmds)} comando(s) de severidad Alta/Crítica antes del salto "
                              f"(p. ej. {cmds.iloc[0]['Log_ID']}: «{cmds.iloc[0]['Regla'].nombre}»).")
                if len(post):
                    texto += (" Tras el acceso, la cuenta realizó en " + destino + ": "
                              + "; ".join(f"{recortar(e['Event_Description'], 70)} ({e['Log_ID']}, {e['Timestamp']:%H:%M:%S})"
                                          for _, e in post.head(4).iterrows()) + ".")
                texto += (" Un salto entre sistemas con una cuenta ya vista en actividad sospechosa en el host de origen "
                          "es compatible con movimiento lateral.") if (len(ext) or len(cmds)) else (
                          " Un inicio de sesión de red entre equipos es habitual en un dominio; se marca por el contexto "
                          "descrito.")
                sev = "Crítico" if (len(ext) or len(cmds)) else "Alto"
                fin = max([b["Timestamp"].max(), *post["Timestamp"]])
                mitre = ["T1021 Remote Services", "T1078 Valid Accounts"]

            alld = df[df["Log_ID"].isin(ids)]
            hallazgos.append(Finding(
                id="", categoria="Movimiento lateral", titulo=f"Movimiento lateral {origen} → {destino} ({user})",
                severidad=sev, justificacion=texto, evidencia=sorted(ids), inicio=alld["Timestamp"].min(), fin=fin,
                regla="LAT-01", mitre=mitre, hosts=sorted({origen, destino}), usuarios=[user], ips=ips_externas(alld),
                metricas={"origen": origen, "destino": destino, "exitos": len(exitos), "fallos": len(fallos),
                          "t_paso": b["Timestamp"].min()}))   # momento del salto en sí (inicio incluye el contexto previo)
    return hallazgos


# --------------------------------------------------------------------------------------------------
_RECURSO_RE = re.compile(r"share\s+access(?:ed)?:\s*\S+|\\\\[^\\\s]+\\[^\\\s]+", re.I)


def detect_lateral_share_access(
    df: pd.DataFrame,
    antes: timedelta = timedelta(minutes=10),
    despues: timedelta = timedelta(minutes=30),
) -> list[Finding]:
    """Acceso a un recurso compartido con ruta explícita (5140/5145) en OTRO host, por una cuenta que en ese
    entorno mostró actividad sospechosa: un inicio de sesión desde IP externa o un comando de severidad
    Alta/Crítica, hasta `antes` después o `despues` antes del acceso.

    Complementa LAT-01 (que exige LogonType 3/10 con `source=`): aquí el salto se infiere por el acceso a un
    recurso con ruta identificada (UNC o "share access: ..."). Los eventos 5140/5145 genéricos, sin ruta, son
    ruido normal en este conjunto y no se consideran. No repite lo que ya explica LAT-01.
    """
    texto = df["Event_Description"] + " " + df["Destination"] + " " + df["Process_CommandLine"]
    cand = df[df["Event_ID"].isin(["5140", "5145"]) & texto.str.contains(_RECURSO_RE) & ~df["Externa"]]
    cand = cand[~cand["Log_ID"].isin({i for f in detect_lateral_movement(df) for i in f.evidencia})]
    if cand.empty:
        return []

    duros = clasificar_comandos(df)
    duros = duros[duros["Regla"].map(lambda r: r.severidad in ("Crítico", "Alto")).astype(bool)]
    anclas = [dict(User=r.User, Host=r.Host, Timestamp=r.Timestamp, Log_ID=r.Log_ID, Source_IP=r.Source_IP,
                   externa=False, desc=f"ejecutar «{r.Regla.nombre}»") for r in duros.itertuples()]
    ext = df[(df["Event_ID"] == "4624") & (df["Result"] == "Success") & df["Externa"]]
    anclas += [dict(User=r.User, Host=r.Host, Timestamp=r.Timestamp, Log_ID=r.Log_ID, Source_IP=r.Source_IP,
                    externa=True, desc=f"iniciar sesión desde la IP externa {r.Source_IP}") for r in ext.itertuples()]
    if not anclas:
        return []
    anclas = pd.DataFrame(anclas)

    grupos: dict[tuple[str, str, str], list[tuple[int, pd.Series]]] = {}
    for idx, ev in cand.iterrows():
        a = anclas[(anclas["User"] == ev["User"]) & (anclas["Host"] != ev["Host"])]
        delta = ev["Timestamp"] - a["Timestamp"]
        a = a[(delta >= -antes) & (delta <= despues)]
        if a.empty:
            continue
        a = a.assign(_ni=~a["externa"], _d=(ev["Timestamp"] - a["Timestamp"]).abs()).sort_values(["_ni", "_d"])
        anc = a.iloc[0]
        grupos.setdefault((ev["User"], ev["Host"], anc["Host"]), []).append((idx, anc))

    hallazgos: list[Finding] = []
    for (user, destino, origen), items in grupos.items():
        g = cand.loc[[i for i, _ in items]].sort_values("Timestamp")
        anc = items[0][1]
        t0 = g["Timestamp"].min()
        dt = t0 - anc["Timestamp"]
        rel = f"{fmt_duracion(abs(dt))} {'después de' if dt >= pd.Timedelta(0) else 'antes de'}"
        lista = "; ".join(f"{recortar(e['Destination'] or e['Event_Description'], 60)} ({e['Log_ID']}, {e['Timestamp']:%H:%M:%S})"
                          for _, e in g.head(4).iterrows())
        texto = (f"{user} accedió en {destino} a recursos compartidos con ruta explícita: {lista}, {rel} {anc['desc']} en "
                 f"{origen} ({anc['Log_ID']}, {anc['Timestamp']:%H:%M:%S}), con origen de red {', '.join(sorted(g['Source_IP'].unique()))}. "
                 "Acceder a un servidor de archivos desde otro equipo es habitual en un dominio; se marca porque la misma "
                 "cuenta venía de actividad sospechosa en el equipo de origen, lo que es compatible con movimiento lateral "
                 "y recolección de datos.")
        ids = sorted(set(g["Log_ID"]) | {anc["Log_ID"]})
        alld = df[df["Log_ID"].isin(ids)]
        hallazgos.append(Finding(
            id="", categoria="Movimiento lateral", titulo=f"Acceso a recursos compartidos {origen} → {destino} ({user})",
            severidad="Crítico" if anc["externa"] else "Alto", justificacion=texto, evidencia=ids,
            inicio=alld["Timestamp"].min(), fin=alld["Timestamp"].max(), regla="LAT-02",
            mitre=["T1021.002 SMB/Windows Admin Shares", "T1039 Data from Network Shared Drive"],
            hosts=sorted({origen, destino}), usuarios=[user], ips=ips_externas(alld),
            metricas={"origen": origen, "destino": destino, "accesos": len(g), "ancla": anc["Log_ID"],
                      "t_paso": g["Timestamp"].min()}))
    return hallazgos


# --------------------------------------------------------------------------------------------------
_BYTES = re.compile(r"bytes_out=(\d+)")


def detect_exfiltration(
    df: pd.DataFrame, min_total_mb: float = 50.0, gap: timedelta = timedelta(minutes=2),
    ventana_archivado: timedelta = timedelta(minutes=60),
) -> list[Finding]:
    """Volumen saliente grande hacia un mismo destino por proxy (suma de bytes_out) desde un mismo usuario/host.

    Crítico si el mismo usuario, en el mismo equipo y en la hora previa, comprimió datos (7z/rar/tar/Compress-Archive).
    """
    p = df[(df["Event_ID"] == "PROXY_ACCESS") | (df["Log_Source"] == "Proxy")].copy()
    p["_bytes"] = pd.to_numeric(p["Process_CommandLine"].str.extract(_BYTES)[0], errors="coerce")
    p = p[p["_bytes"].notna()]
    hallazgos: list[Finding] = []
    for (user, host, dest), g in p.groupby(["User", "Host", "Destination"]):
        for b in rafagas(g, gap):
            total = b["_bytes"].sum()
            if total / 1e6 < min_total_mb:
                continue
            ini, fin = b["Timestamp"].min(), b["Timestamp"].max()
            arch = df[(df["Host"] == host) & (df["User"] == user) & (df["Event_ID"] == "4688")
                      & (df["Timestamp"] >= ini - ventana_archivado) & (df["Timestamp"] <= ini)
                      & (df["Process_CommandLine"] + " " + df["Event_Description"]).map(lambda t: bool(ARCHIVADO_RE.search(t)))]
            dur = max((fin - ini).total_seconds(), 1)
            texto = (
                f"{user} envió {len(b)} peticiones por proxy a {dest} en {fmt_duracion(fin - ini)} ({ini:%H:%M:%S}–{fin:%H:%M:%S}) "
                f"desde {host}, con un total de {total / 1e6:.1f} MB ({int(total):,} bytes) salientes (≈{total / 1e6 / dur * 60:.1f} MB/min; "
                f"{b.iloc[0]['Log_ID']} … {b.iloc[-1]['Log_ID']})."
            )
            if len(arch):
                a = arch.iloc[0]
                texto += (f" Minutos antes ({fmt_duracion(ini - a['Timestamp'])}), el mismo usuario ejecutó en el mismo equipo "
                          f"`{recortar(a['Process_CommandLine'], 90)}` ({a['Log_ID']}, {a['Timestamp']:%H:%M:%S}): compresión previa "
                          "seguida de subida masiva es compatible con exfiltración.")
            texto += " Los logs no muestran el contenido transferido: el volumen y la secuencia son indicios, no prueba del contenido."
            hallazgos.append(Finding(
                id="", categoria="Exfiltración", titulo=f"Posible exfiltración desde {host} hacia {dest}",
                severidad="Crítico" if len(arch) else "Alto", justificacion=texto,
                evidencia=sorted(set(b["Log_ID"]) | set(arch["Log_ID"])), inicio=min(ini, *arch["Timestamp"]) if len(arch) else ini,
                fin=fin, regla="EXF-01", mitre=["T1048 Exfiltration Over Alternative Protocol", "T1560 Archive Collected Data"]
                if len(arch) else ["T1048 Exfiltration Over Alternative Protocol"], hosts=[host], usuarios=[user],
                ips=[dest.split(":")[0]], metricas={"peticiones": len(b), "bytes": int(total), "mb": round(total / 1e6, 1),
                                                    "t_paso": ini}))   # primera subida (inicio incluye la compresión previa)
    return hallazgos


# --------------------------------------------------------------------------------------------------
_WEBSHELL = re.compile(r"\.(?:aspx?|php|jsp|ashx)\?.*\b(?:cmd|exec|command)=", re.I)
_TRAVERSAL = re.compile(r"\.\./|%2e%2e", re.I)
_SQLI = re.compile(r"(?:'|%27)\s*(?:or|union)\b|union\s+select|sleep\(|information_schema", re.I)
_LOGIN = re.compile(r"/(?:login|signin|auth|wp-login)", re.I)


def detect_web_attack(
    df: pd.DataFrame, min_requests: int = 15, min_login: int = 5, gap: timedelta = timedelta(minutes=2),
    ventana_post: timedelta = timedelta(minutes=15),
) -> list[Finding]:
    """Ráfagas de peticiones HTTP de una IP con indicadores de ataque: parámetro de comando en un script
    subido (webshell), traversal, inyección SQL, intentos repetidos de login o volumen alto.

    Crítico si, tras peticiones de webshell, el worker del servidor web crea un proceso en el mismo host.
    """
    w = df[(df["Log_Source"] == "IIS") | (df["Event_ID"] == "HTTP_ACCESS")]
    hallazgos: list[Finding] = []
    for (ip, host), g in w.groupby(["Source_IP", "Host"]):
        for b in rafagas(g, gap):
            uri = b["Process_CommandLine"]
            shell = b[uri.str.contains(_WEBSHELL)]
            trav = int(uri.str.contains(_TRAVERSAL).sum())
            sqli = int(uri.str.contains(_SQLI).sum())
            login = int(uri.str.contains(_LOGIN).sum())
            indicadores = []
            if len(shell):
                indicadores.append(f"{len(shell)} petición(es) con parámetro de comando a un script ({recortar(shell.iloc[0]['Process_CommandLine'], 60)})")
            if trav: indicadores.append(f"{trav} con path traversal")
            if sqli: indicadores.append(f"{sqli} con patrones de inyección SQL")
            if login >= min_login: indicadores.append(f"{login} intentos sobre rutas de login")
            if len(b) >= min_requests and not indicadores:
                indicadores.append(f"volumen alto de peticiones ({len(b)})")
            if not indicadores:
                continue

            ini, fin = b["Timestamp"].min(), b["Timestamp"].max()
            post = pd.DataFrame()
            if len(shell):
                post = df[(df["Host"] == host) & (df["Event_ID"] == "4688") & (df["Timestamp"] >= shell["Timestamp"].min())
                          & (df["Timestamp"] <= fin + ventana_post)
                          & (df["User"].str.contains("APPPOOL|w3wp", case=False) | (df["Source_IP"] == ip))]
            codigos = b["Result"].value_counts().to_dict()
            rutas = b["Process_CommandLine"].str.split("?").str[0].value_counts()
            texto = (
                f"La IP {ip} envió {len(b)} peticiones HTTP a {host} en {fmt_duracion(fin - ini)} ({ini:%H:%M:%S}–{fin:%H:%M:%S}; "
                f"{b.iloc[0]['Log_ID']} … {b.iloc[-1]['Log_ID']}). Indicadores: " + "; ".join(indicadores) + ". "
                f"Rutas más solicitadas: " + ", ".join(f"{r} ({c})" for r, c in rutas.head(4).items()) + ". "
                f"Códigos de respuesta: " + ", ".join(f"{k}×{v}" for k, v in sorted(codigos.items())) + "."
            )
            if len(shell):
                texto += (f" La primera petición con parámetro de comando respondió {shell.iloc[0]['Result']} "
                          f"({shell.iloc[0]['Log_ID']}).")
            if len(post):
                p0 = post.iloc[0]
                texto += (f" Después, {p0['User']} creó un proceso en {host} (4688, {p0['Log_ID']}, {p0['Timestamp']:%H:%M:%S}): "
                          f"`{recortar(p0['Process_CommandLine'], 80)}`. Que el worker del servidor web lance un shell tras esas "
                          "peticiones es compatible con la ejecución de una webshell.")
            sev = "Crítico" if len(post) else ("Alto" if (len(shell) or sqli or trav or login >= min_login) else "Medio")
            hallazgos.append(Finding(
                id="", categoria="Ataque web", titulo=f"Ataque web contra {host} desde {ip}", severidad=sev,
                justificacion=texto, evidencia=sorted(set(b["Log_ID"]) | set(post["Log_ID"] if len(post) else [])),
                inicio=ini, fin=max([fin, *(post["Timestamp"] if len(post) else [])]), regla="WEB-01",
                mitre=(["T1190 Exploit Public-Facing Application"] + (["T1505.003 Web Shell"] if len(shell) else [])
                       + (["T1110 Brute Force"] if login >= min_login else [])),
                hosts=[host], usuarios=sorted(set(post["User"]) if len(post) else []), ips=[ip],
                metricas={"peticiones": len(b), "codigos": codigos, "login": login, "webshell": len(shell)}))
    return hallazgos