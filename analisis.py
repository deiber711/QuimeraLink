"""Análisis local de direcciones. Independiente de la interfaz y del navegador."""
from dataclasses import dataclass
from ipaddress import ip_address
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class Resultado:
    dominio: str
    senales: tuple[str, ...]
    url_captura: str | None


MARCAS = {"paypal": ("paypal.com",), "bancolombia": ("bancolombia.com", "bancolombia.com.co")}
ETIQUETA = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def analizar(texto: str) -> Resultado:
    texto = texto.strip()
    invalido = "Pega una dirección web válida que empiece por https:// o http://."
    if not texto or len(texto) > 8192 or "\\" in texto or any(
        c.isspace() or unicodedata.category(c).startswith("C") for c in texto
    ):
        raise ValueError(invalido)
    if "://" not in texto:
        texto = "https://" + texto
    try:
        partes = urlsplit(texto)
        host = (partes.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        puerto = partes.port
    except (UnicodeError, ValueError):
        raise ValueError(invalido) from None
    if partes.scheme not in ("http", "https") or not host or len(host) > 253:
        raise ValueError(invalido)
    try:
        ip = ip_address(host)
    except ValueError:
        ip = None
    etiquetas = host.split(".")
    if ip is None and (len(etiquetas) < 2 or not all(map(ETIQUETA.fullmatch, etiquetas))
                       or etiquetas[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", etiquetas[-1])):
        raise ValueError(invalido)
    senales = []
    if partes.scheme == "http":
        senales.append("La conexión HTTP deja los datos enviados sin cifrar.")
    if partes.username is not None:
        senales.append("El texto anterior a @ puede ocultar el destino real del enlace.")
    if ip:
        senales.append("El destino usa una dirección numérica que dificulta reconocer al propietario.")
    if any(e.startswith("xn--") for e in etiquetas):
        senales.append("El dominio contiene caracteres internacionales. Comprueba su escritura.")
    for marca, oficiales in MARCAS.items():
        if any(host == d or host.endswith("." + d) for d in oficiales):
            continue
        for e in etiquetas:
            similar = len(e) == len(marca) and sum(a != b for a, b in zip(e, marca)) == 1
            if marca in e or similar:
                senales.append(f"Una parte del dominio se parece a {marca}. Verifica la dirección en su app oficial.")
                break
    autoridad = f"[{host}]" if ip and ip.version == 6 else host
    if puerto is not None:
        autoridad += f":{puerto}"
    url = urlunsplit((partes.scheme, autoridad, partes.path, partes.query, partes.fragment))
    capturable = partes.username is None and puerto in (None, 80, 443) and (not ip or ip.is_global)
    return Resultado(host, tuple(senales), url if capturable else None)
