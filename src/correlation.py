"""Correlación: agrupa los hallazgos en incidentes y reconstruye la cadena de ataque.

Misma regla de oro que los detectores: todo lo que se afirma sale de los datos o de la evidencia.
  * Dos hallazgos se agrupan solo si hay un vínculo explícito y reproducible (se guarda el motivo):
      - comparten eventos de evidencia, o
      - comparten una IP externa de origen, o
      - comparten una cuenta que actúa (eventos que no son fallos de autenticación) con <= 30 min de separación.
  * Dos incidentes distintos que tocan el mismo host con poca diferencia de tiempo NO se fusionan: se anotan como
    "posible relación (no confirmada)".
  * La fase de ATT&CK de cada hallazgo es conocimiento de dominio (qué táctica representa esa técnica), no un hecho
    de los logs; los momentos y eventos de cada paso sí salen de la evidencia.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta

import pandas as pd

from .detectors.base import SEVERIDADES, Finding

GAP_ACTOR = timedelta(minutes=30)
ADMIN_RE = re.compile(r"(?i)(^|\\)(admin(istrat\w+)?|root)$")

# Táctica de ATT&CK que representa cada regla (en orden de aparición dentro del hallazgo)
FASES_REGLA = {
    "AUTH-01": ["Acceso a credenciales"], "AUTH-02": ["Acceso a credenciales"],
    "AUTH-03": ["Acceso inicial"], "AUTH-04": ["Acceso inicial"],
    "PRIV-01": ["Escalamiento de privilegios"], "PRIV-02": ["Escalamiento de privilegios"],
    "CMD-01": ["Acceso a credenciales"], "CMD-02": ["Impacto"], "CMD-03": ["Ejecución"], "CMD-04": ["Ejecución"],
    "CMD-05": ["Comando y control"], "CMD-06": ["Comando y control"], "CMD-07": ["Recolección"],
    "CMD-08": ["Ejecución"], "CMD-09": ["Recolección"], "CMD-10": ["Descubrimiento"],
    "LAT-01": ["Movimiento lateral"], "LAT-02": ["Movimiento lateral"],
    "DATA-01": ["Recolección"], "EXF-01": ["Exfiltración"], "PERS-01": ["Persistencia"], "WEB-01": ["Acceso inicial"],
}
# Si la evidencia de un hallazgo incluye un acceso exitoso o privilegios desde IP externa, suma esas fases
FASES_ETIQUETA = {"Inicios sospechosos": "Acceso inicial", "Escalamiento": "Escalamiento de privilegios"}


@dataclass
class Paso:
    hora: pd.Timestamp
    fase: str
    hallazgo: str          # id del hallazgo (F-xx)
    titulo: str
    severidad: str
    log_id: str            # evento concreto que respalda el paso


@dataclass
class Incidente:
    id: str
    titulo: str
    severidad: str
    justificacion_severidad: str
    resumen: str
    hallazgos: list[Finding]
    pasos: list[Paso]
    evidencia: list[str]
    inicio: pd.Timestamp
    fin: pd.Timestamp
    hosts: list[str] = field(default_factory=list)
    actores: list[str] = field(default_factory=list)
    ips_externas: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    categorias: list[str] = field(default_factory=list)
    acciones: list[str] = field(default_factory=list)
    vinculos: list[str] = field(default_factory=list)       # por qué se agruparon los hallazgos
    relacionados: list[str] = field(default_factory=list)   # posibles relaciones con otros incidentes (no confirmadas)
    factores: list[str] = field(default_factory=list)
    fases: list[str] = field(default_factory=list)

    def pasos_df(self) -> pd.DataFrame:
        return pd.DataFrame([{"Hora": p.hora.strftime("%H:%M:%S"), "Fase": p.fase, "Hallazgo": p.hallazgo,
                              "Qué ocurrió": p.titulo, "Severidad": p.severidad, "Evento": p.log_id}
                             for p in self.pasos])

    def evidencia_df(self, df: pd.DataFrame) -> pd.DataFrame:
        cols = ["Log_ID", "Timestamp", "Host", "Event_ID", "User", "Source_IP", "Destination",
                "Event_Description", "Process_CommandLine", "Result", "Severity"]
        return df[df["Log_ID"].isin(self.evidencia)][cols].sort_values("Timestamp")


# --------------------------------------------------------------------------------------------------
def fases_de(f: Finding) -> list[str]:
    base = FASES_REGLA.get(f.regla) or ["Otras"]
    extra = [FASES_ETIQUETA[e] for e in f.etiquetas if e in FASES_ETIQUETA]
    return list(dict.fromkeys([*base, *extra]))


def _filas(df: pd.DataFrame, f: Finding) -> pd.DataFrame:
    return df[df["Log_ID"].isin(f.evidencia)]


def _actores(rows: pd.DataFrame) -> set[str]:
    """Cuentas que ACTÚAN en la evidencia: se excluyen los fallos de autenticación (la cuenta solo es víctima)."""
    return set(rows.loc[(rows["Event_ID"] != "4625") & ~rows["User"].isin(["-", ""]), "User"])


def _ips_externas(rows: pd.DataFrame) -> set[str]:
    return set(rows.loc[rows["Externa"], "Source_IP"])


def _separacion(a: Finding, b: Finding) -> timedelta:
    sep = max(a.inicio, b.inicio) - min(a.fin, b.fin)
    return max(sep, timedelta(0))


def _pasos(df: pd.DataFrame, f: Finding) -> list[Paso]:
    rows = _filas(df, f).sort_values("Timestamp")
    pasos = []
    for fase in fases_de(f):
        r = None
        if fase == "Acceso inicial" and "Inicios sospechosos" in f.etiquetas:
            r = rows[(rows["Event_ID"] == "4624") & (rows["Result"] == "Success") & rows["Externa"]]
        elif fase == "Escalamiento de privilegios" and "Escalamiento" in f.etiquetas:
            r = rows[(rows["Event_ID"] == "4672") & rows["Externa"]]
        if r is not None and len(r):
            hora, lid = r["Timestamp"].min(), r.iloc[0]["Log_ID"]
        else:
            hora = f.metricas.get("t_paso", f.inicio)
            en_hora = rows[rows["Timestamp"] >= hora]
            lid = (en_hora if len(en_hora) else rows).iloc[0]["Log_ID"]
        pasos.append(Paso(hora, fase, f.id, f.titulo, f.severidad, lid))
    return pasos


# --------------------------------------------------------------------------------------------------
def correlacionar(df: pd.DataFrame, hallazgos: list[Finding], gap_actor: timedelta = GAP_ACTOR) -> list[Incidente]:
    """Agrupa los hallazgos en incidentes. Devuelve los incidentes ordenados por severidad y hora (INC-01, INC-02...)
    y anota en cada hallazgo `metricas["incidente"]`."""
    n = len(hallazgos)
    if n == 0:
        return []
    ents = [{"ids": set(f.evidencia), "ips": _ips_externas(_filas(df, f)), "actores": _actores(_filas(df, f))}
            for f in hallazgos]

    padre = list(range(n))

    def raiz(i: int) -> int:
        while padre[i] != i:
            padre[i] = padre[padre[i]]
            i = padre[i]
        return i

    motivos: dict[tuple[int, int], list[str]] = {}
    for i in range(n):
        for j in range(i + 1, n):
            m = []
            comunes = ents[i]["ids"] & ents[j]["ids"]
            if comunes:
                m.append(f"comparten {len(comunes)} evento(s) de evidencia (p. ej. {sorted(comunes)[0]})")
            ips = ents[i]["ips"] & ents[j]["ips"]
            if ips:
                m.append(f"misma IP externa {', '.join(sorted(ips))}")
            cuentas = ents[i]["actores"] & ents[j]["actores"]
            sep = _separacion(hallazgos[i], hallazgos[j])
            if cuentas and sep <= gap_actor:
                m.append(f"misma cuenta {', '.join(sorted(cuentas))} con {int(sep.total_seconds() // 60)} min de separación")
            if m:
                motivos[(i, j)] = m
                padre[raiz(i)] = raiz(j)

    grupos: dict[int, list[int]] = {}
    for i in range(n):
        grupos.setdefault(raiz(i), []).append(i)

    incidentes = [_construir(df, [hallazgos[i] for i in idx], [ents[i] for i in idx],
                             [f"{hallazgos[i].id} ↔ {hallazgos[j].id}: {'; '.join(m)}"
                              for (i, j), m in motivos.items() if i in idx and j in idx])
                  for idx in grupos.values()]
    incidentes.sort(key=lambda x: (SEVERIDADES.index(x.severidad), x.inicio))
    for k, inc in enumerate(incidentes, 1):
        inc.id = f"INC-{k:02d}"
        for f in inc.hallazgos:
            f.metricas["incidente"] = inc.id
    _anotar_relaciones(incidentes)
    return incidentes


def _construir(df: pd.DataFrame, hs: list[Finding], ents: list[dict], vinculos: list[str]) -> Incidente:
    hs = sorted(hs, key=lambda f: f.inicio)
    evidencia = sorted({i for f in hs for i in f.evidencia})
    rows = df[df["Log_ID"].isin(evidencia)]

    # cadena de ataque: pasos en orden de ocurrencia, sin repetir (fase, evento)
    pasos: list[Paso] = []
    vistos = set()
    for p in sorted((p for f in hs for p in _pasos(df, f)), key=lambda p: p.hora):
        if (p.fase, p.log_id) not in vistos:
            vistos.add((p.fase, p.log_id))
            pasos.append(p)
    fases = list(dict.fromkeys(p.fase for p in pasos))

    actores_cnt = Counter(rows.loc[(rows["Event_ID"] != "4625") & ~rows["User"].isin(["-", ""]), "User"])
    actores = [u for u, _ in actores_cnt.most_common()]
    ips = sorted(_ips_externas(rows))
    hosts = sorted({h for f in hs for h in f.hosts})
    inicio, fin = min(f.inicio for f in hs), max(f.fin for f in hs)

    # severidad: la del hallazgo más grave; se eleva Alto -> Crítico si la cadena cubre >= 3 fases
    mejor = min(SEVERIDADES.index(f.severidad) for f in hs)
    severidad = SEVERIDADES[mejor]
    elevado = False
    if severidad == "Alto" and len(fases) >= 3:
        severidad, elevado = "Crítico", True

    factores = _factores(df, hs, rows, fases, actores, ips)
    justificacion = f"Clasificado {severidad}: " + "; ".join(factores) + "."
    if elevado:
        justificacion += (f" Se elevó de Alto a Crítico porque la cadena observada abarca {len(fases)} fases "
                          "(regla: Alto con >= 3 fases => Crítico).")

    if len(hs) == 1:
        titulo = hs[0].titulo
    else:
        cadena = " → ".join(fases[:5]) + (" → …" if len(fases) > 5 else "")
        sujeto = actores[0] if actores else (f"IP {ips[0]}" if ips else hosts[0])
        titulo = f"{sujeto}{f' (origen {ips[0]})' if ips else ''}: {cadena}"

    secuencia = "; ".join(f"{p.hora:%H:%M:%S} {p.fase} ({p.hallazgo}, {p.log_id})" for p in pasos)
    resumen = (f"Entre {inicio:%H:%M:%S} y {fin:%H:%M:%S} del {inicio:%Y-%m-%d} se observó actividad en "
               f"{', '.join(hosts)} vinculada a {', '.join(actores) if actores else 'origen sin cuenta identificada'}"
               f"{f', con origen externo {chr(44).join(ips)}' if ips else ''}. Secuencia observada: {secuencia}.")

    acciones = list(dict.fromkeys(f.accion for f in sorted(hs, key=lambda f: SEVERIDADES.index(f.severidad)) if f.accion))
    return Incidente(
        id="", titulo=titulo, severidad=severidad, justificacion_severidad=justificacion, resumen=resumen,
        hallazgos=hs, pasos=pasos, evidencia=evidencia, inicio=inicio, fin=fin, hosts=hosts, actores=actores,
        ips_externas=ips, mitre=list(dict.fromkeys(m for f in hs for m in f.mitre)),
        categorias=[c for c in dict.fromkeys(c for f in hs for c in f.categorias_reto)],
        acciones=acciones, vinculos=vinculos, factores=factores, fases=fases)


def _factores(df, hs, rows, fases, actores, ips) -> list[str]:
    out = []
    criticos = [f for f in hs if f.severidad == "Crítico"]
    if criticos:
        out.append(f"incluye {len(criticos)} hallazgo(s) Crítico(s): " + ", ".join(f"{f.id} ({f.titulo[:60]})" for f in criticos[:3])
                   + ("…" if len(criticos) > 3 else ""))
    else:
        out.append(f"su hallazgo más grave es {hs[0].id if len(hs) == 1 else min(hs, key=lambda f: SEVERIDADES.index(f.severidad)).id} "
                   f"({min(hs, key=lambda f: SEVERIDADES.index(f.severidad)).severidad})")
    if len(fases) >= 2:
        out.append(f"cadena observada de {len(fases)} fases: {' → '.join(fases)}")
    if ips:
        ok = rows[(rows["Event_ID"] == "4624") & (rows["Result"] == "Success") & rows["Externa"]]
        out.append(f"origen externo {', '.join(ips)}" + (f", con {len(ok)} acceso(s) exitoso(s) desde fuera" if len(ok) else ""))
    admin = [a for a in actores if ADMIN_RE.search(a)]
    if admin:
        out.append(f"involucra una cuenta administrativa ({', '.join(admin)})")
    for f in hs:
        if f.regla == "EXF-01":
            out.append(f"salida de {f.metricas.get('mb')} MB hacia {f.ips[0] if f.ips else 'un destino externo'}")
        elif f.regla == "DATA-01":
            out.append(f"acceso a {f.metricas.get('archivos')} archivos de un recurso compartido")
        elif f.regla == "CMD-02":
            out.append("eliminación de copias de seguridad/sombra")
        elif f.regla == "PERS-01":
            out.append("mecanismo de persistencia creado")
    subestima = [f for f in hs if f.metricas.get("siem_subestima")]
    if subestima:
        peor = max(subestima, key=lambda f: -SEVERIDADES.index(f.severidad))
        out.append(f"el SIEM clasificó parte de la evidencia como máximo «{peor.metricas.get('severidad_siem')}» "
                   "(subestimada respecto de la clasificación final)")
    return out


def _anotar_relaciones(incidentes: list[Incidente], gap: timedelta = GAP_ACTOR) -> None:
    for a in incidentes:
        for b in incidentes:
            if a is b or a.id > b.id:
                continue
            hosts = sorted(set(a.hosts) & set(b.hosts))
            sep = max(max(a.inicio, b.inicio) - min(a.fin, b.fin), timedelta(0))
            if hosts and sep <= gap and not (set(a.actores) & set(b.actores)):
                for x, y in ((a, b), (b, a)):
                    x.relacionados.append(
                        f"Posible relación (no confirmada) con {y.id}: ambos afectan a {', '.join(hosts)} con "
                        f"{int(sep.total_seconds() // 60)} min de diferencia; usan cuentas distintas "
                        f"({', '.join(x.actores[:2]) or '—'} / {', '.join(y.actores[:2]) or '—'}) y los logs no prueban que sea el mismo actor.")