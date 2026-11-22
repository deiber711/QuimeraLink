"""Combina los analizadores locales para los clientes existentes del programa."""
from dataclasses import dataclass

from analyzers.brand_analyzer import CoincidenciaMarca, ResultadoMarca, analizar_marca
from analyzers.url_analyzer import analizar_url


@dataclass(frozen=True)
class Resultado:
    dominio: str
    senales: tuple[str, ...]
    url_captura: str | None
    dominio_registrable: str | None = None
    dominio_unicode: str | None = None
    coincidencias_marca: tuple[CoincidenciaMarca, ...] = ()
    analisis_marca: ResultadoMarca | None = None


def analizar(texto: str) -> Resultado:
    url = analizar_url(texto)
    marca = analizar_marca(url)
    return Resultado(
        dominio=url.dominio,
        senales=url.senales + marca.senales,
        url_captura=url.url_captura,
        dominio_registrable=url.dominio_registrable,
        dominio_unicode=url.dominio_unicode,
        coincidencias_marca=marca.coincidencias,
        analisis_marca=marca,
    )
