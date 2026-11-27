"""Flujo del análisis profundo. La captura se solicita aparte y no interviene en los puntos."""
from dataclasses import dataclass, replace
from threading import Lock
from time import monotonic

from analisis import Resultado, analizar
from analyzers.rdap_dns import analizar_dns_rdap
from analyzers.reputation import Actualizacion, actualizar_listas, analizar_reputacion
from informe import generar_informe
from inspeccion import Inspeccion, inspeccionar


@dataclass(frozen=True)
class Revision:
    resultado: Resultado
    inspeccion: Inspeccion
    informe: dict
    actualizaciones: tuple[Actualizacion, ...]


_ultimo_intento = {}
_turno_listas = Lock()


def _renovar(reputacion):
    # Un proveedor caído no debe recibir otra descarga por cada enlace de la sesión.
    with _turno_listas:
        ahora = monotonic()
        faltantes = [e.fuente for e in reputacion.evidencias if not e.vigente
                     and ahora - _ultimo_intento.get(e.fuente, float("-inf")) >= 900]
        if not faltantes:
            return ()
        for fuente in faltantes:
            _ultimo_intento[fuente] = ahora
        return actualizar_listas(faltantes)


def analizar_completo(enlace, progreso=lambda mensaje: None):
    progreso("Revisando la dirección y las marcas que menciona…")
    resultado = analizar(enlace, verificar_dns=True)
    progreso("Comprobando las listas de sitios denunciados…")
    cambios = _renovar(resultado.reputacion)
    if any(not fuente.error for fuente in cambios):
        resultado = replace(resultado, reputacion=analizar_reputacion(enlace))
    progreso("Consultando el registro y la antigüedad del sitio…")
    resultado = replace(resultado, dns_rdap=analizar_dns_rdap(enlace))
    progreso("Revisando la página y los datos que solicita…")
    inspeccion = inspeccionar(enlace)
    return Revision(resultado, inspeccion, generar_informe(resultado, inspeccion), cambios)
