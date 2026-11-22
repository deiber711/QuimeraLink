"""Comparación local de nombres y dominios con un catálogo revisado."""
from dataclasses import dataclass
from functools import cache
import json
from operator import eq
import re
from typing import Literal
from unicodedata import normalize

from analyzers.url_analyzer import ResultadoURL, analizar_url
from dominios import DATOS, esqueleto_visual


SUSTITUCIONES_VISUALES = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
REGIONES = frozenset({"colombia", "latam"})
CONTEXTO = frozenset({
    "acceso", "actualizacion", "actualizar", "auth", "autenticacion", "bono", "bonos", "cobro", "comparendo", "comparendos",
    "cuenta", "cuentas", "envio", "envios", "factura", "facturacion", "giro", "giros", "guia", "inicio", "login",
    "multa", "multas", "oferta", "ofertas", "pago", "pagos", "payment", "premio", "premios", "rastreo", "recarga", "recargas",
    "secure", "seguridad",
    "sesion", "signin", "soporte",
    "support", "tracking", "tramite", "validacion", "validar", "verifica", "verificacion", "verificar", "verify",
})
SOLICITUD = frozenset({"digita", "escribe", "ingresa", "ingresar", "introduce", "numero", "linea", "inicia"})
PUNTOS_SUPLANTACION = 35


@dataclass(frozen=True)
class CoincidenciaMarca:
    nombre: str
    tipo: Literal["dominio", "autenticacion", "infraestructura"]


@dataclass(frozen=True)
class ResultadoMarca:
    estado: Literal["ausente", "observado"]
    puntos_sugeridos: int
    marca: str | None
    explicacion: str
    coincidencias: tuple[CoincidenciaMarca, ...] = ()
    senales: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Nombre:
    texto: str
    esqueleto: str
    visual: str


@dataclass(frozen=True)
class _Marca:
    nombre: str
    distintivos: tuple[_Nombre, ...]
    contextuales: tuple[_Nombre, ...]
    dominios: frozenset[str]
    hosts: frozenset[str]
    autenticacion: frozenset[str]


def normalizar_visual(texto: str) -> str:
    """Normaliza leetspeak y homoglifos. El 1 representa i o l en la comparación."""
    caracteres = (c if c.isascii() else esqueleto_visual(c) for c in texto.casefold())
    return "".join(caracteres).casefold().translate(SUSTITUCIONES_VISUALES).replace("rn", "m")


def _nombre(texto: str) -> _Nombre:
    return _Nombre(texto, esqueleto_visual(texto), normalizar_visual(texto))


@cache
def _catalogo():
    with (DATOS / "marcas.json").open(encoding="utf-8") as archivo:
        datos = json.load(archivo)
    marcas = tuple(
        _Marca(ficha["nombre"],
               tuple(_nombre(alias) for alias in ficha.get("distintivos", ())),
               tuple(_nombre(alias) for alias in ficha.get("contextuales", ())),
               frozenset(ficha.get("dominios", ())), frozenset(ficha.get("hosts", ())),
               frozenset(ficha.get("autenticacion", ())))
        for ficha in datos["marcas"]
    )
    plataformas = tuple((ficha["sufijo"], ficha["proveedor"]) for ficha in datos["plataformas_autenticacion"])
    return marcas, plataformas


def _igual_visual(letra: str, referencia: str) -> bool:
    return letra == referencia or (letra == "1" and referencia in "il")


def _dentro_de_ediciones(nombre: str, alias: str, limite: int, *, iguales=eq, transposiciones=False) -> bool:
    if abs(len(nombre) - len(alias)) > limite:
        return False
    # Levenshtein por defecto. La regla complementaria admite transposiciones.
    anterior = list(range(len(alias) + 1))
    anteanterior = anterior
    for i, letra in enumerate(nombre, start=1):
        fila = [i]
        for j, referencia in enumerate(alias, start=1):
            coste = min(anterior[j] + 1, fila[j - 1] + 1, anterior[j - 1] + (not iguales(letra, referencia)))
            if (transposiciones and i > 1 and j > 1
                and iguales(letra, alias[j - 2]) and iguales(nombre[i - 2], referencia)):
                coste = min(coste, anteanterior[j - 2] + 1)
            fila.append(coste)
        if min(fila) > limite:
            return False
        anteanterior, anterior = anterior, fila
    return anterior[-1] <= limite


def _nombres_con_contexto(etiquetas):
    nombres = set()
    for etiqueta in etiquetas:
        partes = etiqueta.split("-")
        if CONTEXTO.intersection(partes):
            nombres.add("".join(parte for parte in partes if parte not in CONTEXTO))
        compacto = "".join(partes)
        for palabra in CONTEXTO:
            if compacto.startswith(palabra):
                nombres.add(compacto.removeprefix(palabra))
            if compacto.endswith(palabra):
                nombres.add(compacto.removesuffix(palabra))
    for anterior, siguiente in zip(etiquetas, etiquetas[1:]):
        if anterior in CONTEXTO:
            nombres.add(siguiente.replace("-", ""))
        if siguiente in CONTEXTO:
            nombres.add(anterior.replace("-", ""))
    nombres.discard("")
    return nombres


def _es_equivalente(nombre: _Nombre, alias: _Nombre) -> bool:
    return (nombre.texto == alias.texto or nombre.esqueleto == alias.esqueleto
            or (len(nombre.visual) == len(alias.visual)
                and all(map(_igual_visual, nombre.visual, alias.visual))))


def _es_similar(nombre: _Nombre, alias: _Nombre, *, con_contexto: bool, es_principal: bool) -> bool:
    if len(alias.texto) < 5:
        return False
    # La etiqueta completa y el contexto permiten conservar variantes con varios cambios.
    limite = 2 if (len(alias.texto) >= 8 and con_contexto) or (len(alias.texto) >= 10 and es_principal) else 1
    comparaciones = [(nombre.texto, alias.texto, eq)]
    if nombre.visual != nombre.texto or alias.visual != alias.texto or "1" in nombre.visual:
        comparaciones.append((nombre.visual, alias.visual, _igual_visual))
    return any(
        # Similitud de Levenshtein de al menos 0,85.
        _dentro_de_ediciones(n, a, 15 * max(len(n), len(a)) // 100, iguales=iguales)
        or _dentro_de_ediciones(n, a, limite, iguales=iguales, transposiciones=True)
        for n, a, iguales in comparaciones
    )


def _palabras_en_etiquetas(etiquetas):
    palabras = set()
    for etiqueta in etiquetas:
        partes = etiqueta.split("-")
        for inicio in range(len(partes)):
            palabra = ""
            for parte in partes[inicio:]:
                palabra += parte
                palabras.add(palabra)
    palabras.discard("")
    return palabras


def _plataformas_del_host(host, plataformas):
    return [(sufijo, proveedor) for sufijo, proveedor in plataformas if host.endswith("." + sufijo)]


def _es_dominio_de_marca(marca, host, registrable, compartidas):
    return host in marca.hosts or (not compartidas and registrable in marca.dominios)


def _coincidencias_oficiales(marcas, host, registrable, compartidas):
    for marca in marcas:
        if host in marca.autenticacion:
            yield CoincidenciaMarca(marca.nombre, "autenticacion")
        elif _es_dominio_de_marca(marca, host, registrable, compartidas):
            yield CoincidenciaMarca(marca.nombre, "dominio")


def _evaluar(host: str, registrable: str | None, etiquetas: tuple[str, ...]) -> ResultadoMarca:
    marcas, plataformas = _catalogo()
    compartidas = _plataformas_del_host(host, plataformas)
    oficiales = tuple(_coincidencias_oficiales(marcas, host, registrable, compartidas))
    if oficiales:
        marca = oficiales[0].nombre
        return ResultadoMarca(
            "ausente", 0, marca, f"El destino coincide con una referencia oficial de {marca}.", oficiales
        )

    if compartidas:
        # El contexto de una instancia compartida se busca antes del sufijo del proveedor.
        corte = max(sufijo.count(".") + 1 for sufijo, _ in compartidas)
    else:
        corte = registrable.count(".") if registrable else len(etiquetas)
    nombres = etiquetas[:-corte] if corte else ()
    contexto = _nombres_con_contexto(nombres)
    contexto_edicion = set(contexto)
    distintivos = set(contexto)
    candidatos_edicion = set(contexto)
    principal = ""
    if nombres and not compartidas:
        principal = nombres[-1].replace("-", "")
        partes = nombres[-1].split("-")
        sin_region = "".join(p for p in partes if p not in REGIONES)
        if sin_region and sin_region != principal:
            contexto_edicion.add(sin_region)
            candidatos_edicion.add(sin_region)
        distintivos.update(_palabras_en_etiquetas(nombres))
        for etiqueta in nombres:
            candidatos_edicion.add(etiqueta.replace("-", ""))
            candidatos_edicion.update(etiqueta.split("-"))
    candidatos_edicion.discard("")

    coincidencias = tuple(CoincidenciaMarca(proveedor, "infraestructura")
                          for proveedor in dict.fromkeys(proveedor for _, proveedor in compartidas))
    formas = {texto: _nombre(texto) for texto in distintivos | contexto | candidatos_edicion}
    host_delimitado = "." + host
    hallazgos = []
    for marca in marcas:
        if any(f".{dominio}." in host_delimitado for dominio in marca.dominios | marca.hosts | marca.autenticacion):
            explicacion = f"El host incluye una dirección de {marca.nombre} dentro de otro dominio."
            hallazgos.append((0, marca.nombre, explicacion))
        elif (any(_es_equivalente(formas[n], alias) for n in distintivos for alias in marca.distintivos)
              or any(_es_equivalente(formas[n], alias) for n in contexto for alias in marca.contextuales)):
            explicacion = f"La dirección usa un nombre de {marca.nombre} fuera de sus dominios de referencia."
            hallazgos.append((1, marca.nombre, explicacion))
        elif any(_es_similar(formas[n], alias, con_contexto=n in contexto_edicion, es_principal=n == principal)
                 for n in candidatos_edicion for alias in marca.distintivos):
            explicacion = f"El host se parece a un nombre de {marca.nombre} y está fuera de sus dominios de referencia."
            hallazgos.append((2, marca.nombre, explicacion))

    if hallazgos:
        hallazgos.sort(key=lambda hallazgo: hallazgo[0])
        _, marca, explicacion = hallazgos[0]
        return ResultadoMarca("observado", PUNTOS_SUPLANTACION, marca, explicacion, coincidencias,
                              tuple(senal for _, _, senal in hallazgos))
    return ResultadoMarca("ausente", 0, None, "No se observó suplantación de las marcas del catálogo.", coincidencias)


def analizar_marca(url: str | ResultadoURL) -> ResultadoMarca:
    """Evalúa indicios de suplantación y devuelve el hallazgo con su puntuación sugerida."""
    resultado = analizar_url(url) if isinstance(url, str) else url
    if resultado.es_ip_literal:
        return ResultadoMarca("ausente", 0, None, "El destino es una IP literal y carece de nombre de dominio.")
    return _evaluar(resultado.dominio, resultado.dominio_registrable, resultado.etiquetas_unicode)


def evaluar_marcas(host: str, registrable: str | None, etiquetas: tuple[str, ...]):
    resultado = _evaluar(host, registrable, etiquetas)
    return resultado.coincidencias, resultado.senales


def _nombres_en_texto(texto, contexto=None):
    ascii_ = normalize("NFKD", texto.casefold()).encode("ascii", "ignore").decode("ascii")
    palabras = re.findall(r"[a-z0-9]+", ascii_)
    nombres = set()
    for inicio in range(len(palabras)):
        if contexto and contexto.isdisjoint(palabras[max(0, inicio - 5):inicio + 7]):
            continue
        nombre = ""
        for palabra in palabras[inicio:inicio + 6]:
            nombre += palabra
            nombres.add(nombre)
    return nombres


def senales_marcas_en_pagina(host, registrable, titulo, texto):
    """Contrasta el nombre mostrado con el dominio de una página que solicita datos."""
    en_titulo = _nombres_en_texto(titulo or "")
    distintivos = en_titulo | _nombres_en_texto(texto, SOLICITUD)
    con_contexto = _nombres_en_texto(titulo or "", CONTEXTO)
    marcas, plataformas = _catalogo()
    compartidas = _plataformas_del_host(host, plataformas)
    for marca in marcas:
        if host in marca.autenticacion or _es_dominio_de_marca(marca, host, registrable, compartidas):
            continue
        if (any(alias.texto in distintivos for alias in marca.distintivos)
            or any(alias.texto in con_contexto for alias in marca.contextuales)):
            yield f"El HTML menciona a {marca.nombre} y solicita datos desde un dominio ajeno a su catálogo."


def lineas_catalogo(coincidencias: tuple[CoincidenciaMarca, ...]):
    etiquetas = {
        "dominio": "Dominio en el catálogo",
        "autenticacion": "Host de autenticación en el catálogo",
        "infraestructura": "Infraestructura de autenticación compartida",
    }
    return tuple(f"{etiquetas[c.tipo]} · {c.nombre}" for c in coincidencias)
