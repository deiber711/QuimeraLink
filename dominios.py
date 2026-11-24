"""Normalización IDNA, sufijos públicos y caracteres visualmente confusos."""
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path
import re
from unicodedata import name, normalize

import idna
from requests import Session
from requests_file import FileAdapter
from tldextract import TLDExtract


DATOS = Path(__file__).with_name("datos_dominios")
ETIQUETA = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ESCRITURAS = {"LATIN", "CYRILLIC", "GREEK"}


def normalizar_dominio(texto: str) -> tuple[str, tuple[str, ...]]:
    """Devuelve el nombre ASCII y sus etiquetas decodificadas."""
    etiquetas_ascii = []
    etiquetas_unicode = []
    for etiqueta in idna.uts46_remap(texto).removesuffix(".").split("."):
        if etiqueta.isascii():
            etiqueta_ascii = etiqueta
            etiqueta_unicode = idna.ulabel(etiqueta) if etiqueta.startswith("xn--") else etiqueta
        else:
            etiqueta_ascii = idna.alabel(etiqueta).decode("ascii")
            etiqueta_unicode = etiqueta
        if not ETIQUETA.fullmatch(etiqueta_ascii):
            raise ValueError("Etiqueta de dominio inválida.")
        etiquetas_ascii.append(etiqueta_ascii)
        etiquetas_unicode.append(etiqueta_unicode)
    host = ".".join(etiquetas_ascii)
    if len(host) > 253:
        raise ValueError("Nombre de dominio demasiado largo.")
    return host, tuple(etiquetas_unicode)


@dataclass(frozen=True)
class PartesDominio:
    subdominio: str
    etiqueta_principal: str | None
    sufijo: str

    @property
    def registrable(self) -> str | None:
        if self.etiqueta_principal and self.sufijo:
            return f"{self.etiqueta_principal}.{self.sufijo}"
        return None


@cache
def _extractor():
    extractor = TLDExtract(
        suffix_list_urls=((DATOS / "public_suffix_list.dat").resolve().as_uri(),),
        fallback_to_snapshot=False,
        include_psl_private_domains=True,
        cache_dir=None,
    )
    with Session() as sesion:
        sesion.mount("file://", FileAdapter())
        sesion.hooks["response"].append(_leer_y_cerrar_psl)
        extractor("com", session=sesion)
    return extractor


def _leer_y_cerrar_psl(respuesta, **_):
    # El archivo se cierra tras cargar su contenido en la caché local.
    with respuesta:
        _ = respuesta.content
    return respuesta


@lru_cache(maxsize=2048)
def separar_dominio(host: str, *, incluir_privados: bool = True) -> PartesDominio:
    """Separa un host DNS normalizado con la PSL local y la regla implícita *."""
    partes = _extractor()(host, include_psl_private_domains=incluir_privados)
    if partes.suffix or not partes.subdomain:
        return PartesDominio(partes.subdomain, partes.domain or None, partes.suffix)
    prefijo, sufijo = host.rsplit(".", 1)
    subdominio, _, etiqueta = prefijo.rpartition(".")
    return PartesDominio(subdominio, etiqueta, sufijo)


def dominio_registrable(host: str) -> str | None:
    return separar_dominio(host).registrable


@cache
def _tabla_confusables():
    tabla = {}
    with (DATOS / "confusables.txt").open(encoding="utf-8-sig") as archivo:
        for linea in archivo:
            regla = linea.partition("#")[0].strip()
            if regla:
                origen, destino, _ = regla.split(";")
                tabla[int(origen, 16)] = "".join(chr(int(codigo, 16)) for codigo in destino.split())
    return tabla


def esqueleto_visual(etiqueta: str) -> str:
    return normalize("NFD", normalize("NFD", etiqueta).translate(_tabla_confusables()))


def tiene_formas_de_compatibilidad(host: str) -> bool:
    # IDNA reconoce las variantes de punto como separadores de etiquetas.
    return any(not c.isascii() and c not in "。．｡" and normalize("NFKC", c).isascii() for c in host)


def tiene_caracteres_confusos(etiqueta: str) -> bool:
    if etiqueta.isascii():
        return False
    if esqueleto_visual(etiqueta).isascii():
        return True
    escrituras = {name(c, "").partition(" ")[0] for c in etiqueta if c.isalpha()}
    return len(escrituras & ESCRITURAS) > 1
