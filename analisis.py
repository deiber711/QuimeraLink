"""Combina los analizadores locales para escritorio y consola."""
from dataclasses import dataclass

from analyzers.brand_analyzer import CoincidenciaMarca, ResultadoMarca, analizar_marca
from analyzers.rdap_dns import ResultadoDominio, analizar_dns_rdap
from analyzers.reputation import ResultadoReputacion, analizar_reputacion
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
    reputacion: ResultadoReputacion = ResultadoReputacion(())
    dns_rdap: ResultadoDominio | None = None


def analizar(texto: str, *, consultar_dominio: bool = False) -> Resultado:
    url = analizar_url(texto)
    marca = analizar_marca(url)
    reputacion = analizar_reputacion(url)
    return Resultado(
        dominio=url.dominio,
        senales=url.senales + marca.senales,
        url_captura=url.url_captura,
        dominio_registrable=url.dominio_registrable,
        dominio_unicode=url.dominio_unicode,
        coincidencias_marca=marca.coincidencias,
        analisis_marca=marca,
        reputacion=reputacion,
        dns_rdap=analizar_dns_rdap(url) if consultar_dominio else None,
    )
