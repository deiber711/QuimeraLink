"""Extrae el destino real y las señales técnicas de una URL sin visitarla."""
from collections.abc import Collection
from dataclasses import dataclass, field
from ipaddress import IPv6Address, ip_address
import re
import unicodedata
from urllib.parse import unquote, urlsplit, urlunsplit

from dominios import (
    PartesDominio,
    dominio_registrable,
    normalizar_dominio,
    separar_dominio,
    tiene_caracteres_confusos,
    tiene_formas_de_compatibilidad,
)


@dataclass(frozen=True)
class ResultadoURL:
    dominio: str
    dominio_registrable: str | None
    subdominio: str
    etiqueta_principal: str | None
    sufijo: str
    dominio_unicode: str | None
    etiquetas_unicode: tuple[str, ...]
    es_ip_literal: bool
    usa_punycode: bool
    tiene_credenciales: bool
    es_acortador: bool
    senales: tuple[str, ...]
    url_captura: str | None
    clave_reputacion: str | None = field(default=None, repr=False, compare=False)


ESQUEMA = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE | re.ASCII)
AUTORIDAD_IPV6 = re.compile(r"\[[0-9a-fA-F:.]+\](?::[0-9]*)?")
RUTA_HOST = re.compile(r"^/(https?://|/)?([a-z0-9.-]+)(?=[:/]|$)", re.IGNORECASE | re.ASCII)
SUFIJOS_COMUNES = {"com", "edu", "gov", "net", "org"}
ACORTADORES_CONOCIDOS = frozenset({"bit.ly", "t.co", "tinyurl.com"})


def _ip_literal(host):
    try:
        return ip_address(host)
    except ValueError:
        return None


def _parece_dominio_publico(registrable):
    if registrable is None:
        return False
    sufijo = registrable.partition(".")[2]
    return sufijo in SUFIJOS_COMUNES or "." in sufijo


def _senales_direccion(host, registrable, ruta):
    if registrable and host != registrable:
        subdominio = host.removesuffix("." + registrable)
        while "." in subdominio:
            candidato = dominio_registrable(subdominio)
            if candidato != registrable and _parece_dominio_publico(candidato):
                yield "El subdominio contiene un nombre que parece un dominio independiente."
                break
            subdominio = subdominio.rsplit(".", 1)[0]

    coincidencia = RUTA_HOST.match(unquote(ruta))
    if coincidencia and "." in coincidencia[2].removesuffix("."):
        try:
            host_ruta, _ = normalizar_dominio(coincidencia[2])
        except ValueError:
            return
        if _ip_literal(host_ruta):
            return
        registrable_ruta = dominio_registrable(host_ruta)
        if registrable_ruta and registrable_ruta != registrable and (
            coincidencia[1] or _parece_dominio_publico(registrable_ruta)
        ):
            yield "La ruta del enlace parece comenzar con otro dominio. Comprueba el destino mostrado."


def analizar_url(texto: str, *, acortadores_conocidos: Collection[str] = ACORTADORES_CONOCIDOS) -> ResultadoURL:
    texto = texto.strip()
    invalido = "Pega una dirección web válida que empiece por https:// o http://."
    if not texto or len(texto) > 8192 or "\\" in texto or any(
        c.isspace() or unicodedata.category(c).startswith("C") for c in texto
    ):
        raise ValueError(invalido)
    if not ESQUEMA.match(texto):
        texto = "https://" + texto
    try:
        partes = urlsplit(texto)
        puerto = partes.port
        bruto = partes.hostname or ""
        if partes.scheme not in ("http", "https") or not bruto:
            raise ValueError
        autoridad = partes.netloc.rsplit("@", 1)[-1]
        if autoridad.startswith("["):
            if not AUTORIDAD_IPV6.fullmatch(autoridad):
                raise ValueError
            ip = IPv6Address(bruto)
            host, etiquetas = str(ip), ()
            entrada_host = bruto
        else:
            bruto = autoridad.partition(":")[0]
            entrada_host = unquote(bruto, errors="strict")
            host, etiquetas = normalizar_dominio(entrada_host)
            ip = _ip_literal(host)
    except ValueError:
        raise ValueError(invalido) from None
    if ip is None:
        ultima = host.rsplit(".", 1)[-1]
        if ultima.isdigit() or re.fullmatch(r"0x[0-9a-f]*", ultima):
            raise ValueError("El destino usa un formato IPv4 no estándar o termina en un número.")
        if len(etiquetas) < 2:
            raise ValueError(invalido)

    dominio = separar_dominio(host) if ip is None else PartesDominio("", None, "")
    registrable = dominio.registrable
    nombre_unicode = ".".join(etiquetas) if any(not e.isascii() for e in etiquetas) else None
    tiene_credenciales = partes.username is not None
    es_acortador = host in acortadores_conocidos or registrable in acortadores_conocidos
    senales = []
    if partes.scheme == "http":
        senales.append("La conexión HTTP deja los datos enviados sin cifrar.")
    if tiene_credenciales:
        senales.append("El texto anterior a @ puede ocultar el destino real del enlace.")
    if ip:
        senales.append("El destino usa una dirección IP literal que dificulta reconocer al propietario.")
    if es_acortador:
        senales.append("El enlace está acortado y oculta su destino final.")
    if "%" in bruto:
        senales.append("El nombre del destino incluye caracteres codificados con %.")
    if tiene_formas_de_compatibilidad(entrada_host) or any(tiene_caracteres_confusos(e) for e in etiquetas):
        senales.append("El dominio contiene caracteres Unicode que pueden confundirse con los de otro nombre.")
    senales.extend(_senales_direccion(host, registrable, partes.path))
    autoridad = f"[{host}]" if ip and ip.version == 6 else host
    clave_reputacion = None
    if not tiene_credenciales:
        autoridad_reputacion = autoridad
        if puerto is not None and puerto != (443 if partes.scheme == "https" else 80):
            autoridad_reputacion += f":{puerto}"
        clave_reputacion = f"{partes.scheme}://{autoridad_reputacion}{partes.path or '/'}"
        sin_fragmento, separador, fragmento = texto.partition("#")
        if "?" in sin_fragmento:
            clave_reputacion += "?" + partes.query
        clave_reputacion += separador + fragmento
    if puerto is not None:
        autoridad += f":{puerto}"
    url = urlunsplit((partes.scheme, autoridad, partes.path, partes.query, partes.fragment))
    capturable = not tiene_credenciales and puerto in (None, 80, 443) and (not ip or ip.is_global)
    return ResultadoURL(
        dominio=host,
        dominio_registrable=registrable,
        subdominio=dominio.subdominio,
        etiqueta_principal=dominio.etiqueta_principal,
        sufijo=dominio.sufijo,
        dominio_unicode=nombre_unicode,
        etiquetas_unicode=etiquetas,
        es_ip_literal=ip is not None,
        usa_punycode=nombre_unicode is not None,
        tiene_credenciales=tiene_credenciales,
        es_acortador=es_acortador,
        senales=tuple(senales),
        url_captura=url if capturable else None,
        clave_reputacion=clave_reputacion,
    )
