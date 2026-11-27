"""Consulta copias locales de listas de phishing y actualízalas por separado."""
import csv
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from http.client import HTTPException
from io import StringIO
import os
from pathlib import Path
import sqlite3
from time import monotonic
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from analyzers.url_analyzer import ResultadoURL, analizar_url
from dominios import normalizar_dominio


@dataclass(frozen=True)
class Fuente:
    nombre: str
    regla: Literal["url_exacta", "dominio_y_subdominios"]
    descarga: str


PHISHTANK = Fuente("PhishTank", "url_exacta", "https://data.phishtank.com/data/online-valid.csv")
CERT_POLSKA = Fuente("CERT Polska", "dominio_y_subdominios", "https://hole.cert.pl/domains/v2/domains.txt")
FUENTES = (PHISHTANK, CERT_POLSKA)
VIGENCIA = timedelta(hours=24)
MAX_DESCARGA = 32 * 1024 * 1024


@dataclass(frozen=True)
class EvidenciaReputacion:
    fuente: Fuente
    estado: Literal["observado", "ausente", "desconocido", "error"]
    fecha_consulta: datetime = field(compare=False)
    fecha_lista: datetime | None = None
    fecha_indicador: datetime | None = None
    vigente: bool = False
    explicacion: str = ""


@dataclass(frozen=True)
class ResultadoReputacion:
    evidencias: tuple[EvidenciaReputacion, ...]

    @property
    def puntos_sugeridos(self) -> int:
        return 70 if any(e.estado == "observado" and e.vigente for e in self.evidencias) else 0


@dataclass(frozen=True)
class Actualizacion:
    fuente: Fuente
    cantidad: int | None = None
    error: str | None = None


def _ahora():
    return datetime.now(timezone.utc)


def _base_local():
    local = os.environ.get("LOCALAPPDATA")
    carpeta = Path(local) / "QuimeraLink" if local else Path.home() / ".quimeralink"
    return carpeta / "reputacion.sqlite3"


def _huella(clave):
    return sha256(clave.encode("utf-8")).hexdigest()


def _candidatos(url, fuente):
    if fuente == PHISHTANK:
        return (_huella(url.clave_reputacion),) if url.clave_reputacion else ()
    if url.es_ip_literal:
        return ()
    etiquetas = url.dominio.split(".")
    return tuple(".".join(etiquetas[i:]) for i in range(len(etiquetas) - 1))


def _consultar(conexion, url, fuente, ahora):
    candidatos = _candidatos(url, fuente)
    if not candidatos:
        mensaje = ("La URL contiene credenciales incrustadas." if fuente == PHISHTANK else
                   "La lista cubre nombres de dominio.")
        return EvidenciaReputacion(fuente, "desconocido", ahora, explicacion=mensaje)
    parametros = ",".join("?" for _ in candidatos)
    fila = conexion.execute(f"""
        SELECT l.fecha_lista, i.valor, i.fecha_indicador FROM listas AS l
        LEFT JOIN indicadores AS i ON i.fuente = l.fuente AND i.valor IN ({parametros})
        WHERE l.fuente = ? ORDER BY length(i.valor) DESC LIMIT 1
    """, (*candidatos, fuente.nombre)).fetchone()
    if fila is None:
        return _sin_lista(fuente, ahora)
    fecha_lista, valor, fecha_indicador = fila
    fecha_lista = _fecha_iso(fecha_lista)
    fecha_indicador = _fecha_iso(fecha_indicador) if fecha_indicador else None
    vigente = timedelta(0) <= ahora - fecha_lista <= VIGENCIA
    if valor is not None:
        if fuente == PHISHTANK:
            mensaje = "Coincidencia exacta de URL."
        elif valor == url.dominio:
            mensaje = f"Coincidencia con el dominio listado {valor}."
        else:
            mensaje = f"El destino es un subdominio de {valor}, que figura en la lista."
        if not vigente:
            mensaje += " La coincidencia procede de una copia desactualizada."
        return EvidenciaReputacion(fuente, "observado", ahora, fecha_lista, fecha_indicador, vigente, mensaje)
    if not vigente:
        return EvidenciaReputacion(fuente, "desconocido", ahora, fecha_lista,
                                   explicacion="La copia local está desactualizada.")
    return EvidenciaReputacion(fuente, "ausente", ahora, fecha_lista, vigente=True,
                               explicacion="Sin coincidencia en la copia local.")


def _sin_lista(fuente, ahora):
    return EvidenciaReputacion(fuente, "desconocido", ahora, explicacion="No hay copia local. Actualiza las listas.")


def analizar_reputacion(url: ResultadoURL | str) -> ResultadoReputacion:
    if isinstance(url, str):
        url = analizar_url(url)
    ahora = _ahora()
    ruta = _base_local()
    try:
        ruta.stat()
    except FileNotFoundError:
        return ResultadoReputacion(tuple(_sin_lista(fuente, ahora) for fuente in FUENTES))
    except OSError:
        return _error_local(ahora)
    try:
        with closing(sqlite3.connect(ruta.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2)) as conexion:
            conexion.execute("BEGIN")  # Ambas fuentes se leen de la misma instantánea.
            evidencias = []
            for fuente in FUENTES:
                try:
                    evidencias.append(_consultar(conexion, url, fuente, ahora))
                except (sqlite3.Error, ValueError, TypeError):
                    evidencias.append(_error_fuente(fuente, ahora))
            return ResultadoReputacion(tuple(evidencias))
    except (OSError, sqlite3.Error):
        return _error_local(ahora)


def _error_local(ahora):
    return ResultadoReputacion(tuple(_error_fuente(fuente, ahora) for fuente in FUENTES))


def _error_fuente(fuente, ahora):
    return EvidenciaReputacion(fuente, "error", ahora, explicacion="No se pudo leer la copia local.")


def _fecha_iso(texto):
    if not isinstance(texto, str):
        raise ValueError("La fecha de la fuente debe ser texto.")
    fecha = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    if fecha.tzinfo is None:
        raise ValueError("La fecha de la fuente requiere zona horaria.")
    return fecha.astimezone(timezone.utc)


class _RedireccionLista(HTTPRedirectHandler):
    max_redirections = 1

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destino = urlsplit(newurl)
        if (req.full_url == PHISHTANK.descarga and destino.scheme == "https"
                and destino.netloc == "cdn.phishtank.com" and destino.path == "/datadumps/verified_online.csv"
                and not destino.fragment):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        return None


def _descargar(fuente):
    solicitud = Request(fuente.descarga, headers={
        "User-Agent": "phishtank/QuimeraLink" if fuente == PHISHTANK else "QuimeraLink",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
    })
    limite = monotonic() + 30
    with build_opener(_RedireccionLista()).open(solicitud, timeout=8) as respuesta:
        if respuesta.status != 200:
            raise ValueError("Respuesta de lista incompleta.")
        descarga = _ahora()
        modificado = respuesta.headers.get("Last-Modified")
        fecha_lista = parsedate_to_datetime(modificado) if modificado else descarga
        if fecha_lista.tzinfo is None:
            fecha_lista = fecha_lista.replace(tzinfo=timezone.utc)
        fecha_lista = fecha_lista.astimezone(timezone.utc)
        fecha_lista = min(fecha_lista, descarga)
        longitud = respuesta.headers.get("Content-Length")
        tamano = int(longitud) if longitud is not None else None
        if ((tamano is not None and not 0 < tamano <= MAX_DESCARGA)
                or respuesta.headers.get("Content-Encoding", "identity").lower() != "identity"):
            raise ValueError("Tamaño o codificación de lista no admitidos.")
        datos = bytearray()
        while monotonic() < limite:
            bloque = respuesta.read1(min(65536, MAX_DESCARGA + 1 - len(datos)))
            if not bloque:
                if tamano is not None and len(datos) != tamano:
                    raise ValueError("Descarga incompleta.")
                return datos.decode("utf-8-sig"), fecha_lista, descarga
            datos.extend(bloque)
            if len(datos) > MAX_DESCARGA:
                raise ValueError("La lista excede el tamaño admitido.")
        raise TimeoutError


def _indicadores(fuente, texto):
    if fuente == CERT_POLSKA:
        for linea in StringIO(texto):
            if not linea.strip():
                continue
            dominio, _ = normalizar_dominio(linea.strip())
            if "." not in dominio:
                raise ValueError("La lista contiene una entrada fuera de formato.")
            yield dominio, None
        return
    filas = csv.DictReader(StringIO(texto, newline=""), strict=True)
    necesarios = {"url", "verification_time", "verified", "online"}
    if not necesarios.issubset(filas.fieldnames or ()):
        raise ValueError("Faltan columnas de PhishTank.")
    for fila in filas:
        if None in fila or any(fila[campo] is None for campo in necesarios):
            raise ValueError("Fila de PhishTank incompleta.")
        if fila["verified"] != "yes" or fila["online"] != "yes":
            continue
        # El analizador local solo cubre las URLs HTTP y HTTPS que admite la aplicación.
        if not fila["url"].lower().startswith(("http://", "https://")):
            continue
        try:
            clave = analizar_url(fila["url"]).clave_reputacion
        except ValueError:
            continue
        if clave:
            fecha = _fecha_iso(fila["verification_time"]).isoformat() if fila["verification_time"] else None
            yield _huella(clave), fecha


def _guardar(fuente, texto, fecha_lista, descarga):
    indicadores = {}
    for valor, fecha in _indicadores(fuente, texto):
        anterior = indicadores.get(valor)
        if anterior is None or (fecha is not None and fecha > anterior):
            indicadores[valor] = fecha
    if not indicadores:
        raise ValueError("La lista no contiene indicadores admitidos.")
    ruta = _base_local()
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(ruta)) as conexion, conexion:
        conexion.execute("BEGIN IMMEDIATE")
        conexion.execute("CREATE TABLE IF NOT EXISTS listas (fuente TEXT PRIMARY KEY, fecha_lista TEXT, descarga TEXT)")
        conexion.execute("""
            CREATE TABLE IF NOT EXISTS indicadores (
                fuente TEXT, valor TEXT, fecha_indicador TEXT, PRIMARY KEY (fuente, valor)
            ) WITHOUT ROWID
        """)
        anterior = conexion.execute("SELECT fecha_lista, descarga FROM listas WHERE fuente = ?",
                                    (fuente.nombre,)).fetchone()
        version = (fecha_lista.isoformat(), descarga.isoformat())
        if anterior is not None and anterior >= version:
            return conexion.execute("SELECT count(*) FROM indicadores WHERE fuente = ?", (fuente.nombre,)).fetchone()[0]
        conexion.execute("DELETE FROM indicadores WHERE fuente = ?", (fuente.nombre,))
        conexion.executemany("INSERT INTO indicadores VALUES (?, ?, ?)",
                              ((fuente.nombre, valor, fecha) for valor, fecha in indicadores.items()))
        conexion.execute("INSERT OR REPLACE INTO listas VALUES (?, ?, ?)", (fuente.nombre, *version))
    return len(indicadores)


def actualizar_listas(fuentes=FUENTES) -> tuple[Actualizacion, ...]:
    """Descarga las listas completas. La operación no recibe enlaces del usuario."""
    resultados = []
    for fuente in fuentes:
        try:
            cantidad = _guardar(fuente, *_descargar(fuente))
        except HTTPError as exc:
            codigo = exc.code
            exc.close()
            mensaje = "La fuente alcanzó su límite de solicitudes." if codigo == 429 else f"La fuente respondió con HTTP {codigo}."
        except (URLError, TimeoutError, ConnectionError, HTTPException):
            mensaje = "No se pudo descargar la lista. Comprueba la conexión."
        except (ValueError, csv.Error):
            mensaje = "La lista descargada no se pudo validar."
        except (OSError, sqlite3.Error):
            mensaje = "No se pudo completar la descarga o guardar la copia local."
        else:
            resultados.append(Actualizacion(fuente, cantidad))
            continue
        resultados.append(Actualizacion(fuente, error=mensaje))
    return tuple(resultados)


def lineas_actualizacion(resultados):
    lineas = []
    for resultado in resultados:
        mensaje = resultado.error or f"{resultado.cantidad} indicadores disponibles en la copia local."
        lineas.append(f"{resultado.fuente.nombre} · {mensaje}")
    return tuple(lineas)


def lineas_reputacion(resultado: ResultadoReputacion, *, solo_coincidencias=False) -> tuple[str, ...]:
    lineas = []
    for evidencia in resultado.evidencias:
        if solo_coincidencias and evidencia.estado != "observado":
            continue
        linea = f"{evidencia.fuente.nombre} · {evidencia.explicacion}"
        if evidencia.fecha_lista:
            linea += f" Lista del {evidencia.fecha_lista:%Y-%m-%d %H:%M UTC}."
        if evidencia.fecha_indicador:
            linea += f" Verificación del {evidencia.fecha_indicador:%Y-%m-%d %H:%M UTC}."
        lineas.append(linea)
    if not solo_coincidencias and resultado.evidencias:
        fecha = resultado.evidencias[0].fecha_consulta
        lineas.extend((f"Consulta local del {fecha:%Y-%m-%d %H:%M UTC}.",
                       "La ausencia en estas listas no confirma la legitimidad del enlace."))
    return tuple(lineas)
