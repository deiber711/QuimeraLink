from __future__ import annotations

import argparse
import sys
from uuid import uuid4

from analisis import analizar
from analyzers.brand_analyzer import lineas_catalogo
from analyzers.rdap_dns import lineas_dns_rdap
from analyzers.reputation import actualizar_listas, lineas_actualizacion, lineas_reputacion
from captura import tomar_captura
from inspeccion import describir, inspeccionar


def main() -> int:
    parser = argparse.ArgumentParser(description="Analiza enlaces localmente, inspecciona la página o solicita una captura.")
    parser.add_argument("url", nargs="?")
    parser.add_argument("salida", nargs="?", help="Ruta PNG para solicitar una captura")
    parser.add_argument("--captura", action="store_true", help="Visitar el sitio y guardar una imagen")
    parser.add_argument("--full", action="store_true", help="Solicitar una captura de página completa")
    parser.add_argument("--inspeccionar", action="store_true", help="Visitar el sitio y examinar su respuesta y el HTML")
    parser.add_argument("--dns-rdap", action="store_true", help="Consultar el host en Google Public DNS y el dominio en su registro RDAP")
    parser.add_argument("--actualizar-reputacion", action="store_true", help="Descargar las listas de reputación sin analizar un enlace")
    args = parser.parse_args()
    if args.actualizar_reputacion:
        if args.url or args.salida or args.inspeccionar or args.captura or args.full or args.dns_rdap:
            parser.error("--actualizar-reputacion se usa sin URL ni opciones web")
        actualizaciones = actualizar_listas()
        print("\n".join(lineas_actualizacion(actualizaciones)))
        return int(any(r.error for r in actualizaciones))
    if not args.url:
        if args.inspeccionar:
            parser.error("--inspeccionar requiere una URL")
        if args.dns_rdap:
            parser.error("--dns-rdap requiere una URL")
        from escritorio import abrir
        abrir()
        return 0
    try:
        resultado = analizar(args.url, consultar_dominio=args.dns_rdap)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    print("Destino:", resultado.dominio)
    if resultado.dominio_registrable:
        print("Dominio registrable:", resultado.dominio_registrable)
    if resultado.dominio_unicode:
        print("Nombre internacional (Unicode):", resultado.dominio_unicode)
    for linea in lineas_catalogo(resultado.coincidencias_marca):
        print(linea)
    for senal in resultado.senales:
        print("-", senal)
    print("\nReputación")
    for linea in lineas_reputacion(resultado.reputacion):
        print(linea)
    if resultado.dns_rdap:
        print("\n" + "\n".join(lineas_dns_rdap(resultado.dns_rdap)))
    if resultado.reputacion.puntos_sugeridos:
        print("Alto riesgo por reputación. Evita ingresar datos y verifica el enlace por un canal oficial.")
    elif resultado.senales:
        print("Verifica el sitio antes de ingresar datos personales.")
    else:
        print("Autenticidad sin confirmar.")
    codigo = 0
    if args.inspeccionar:
        inspeccion = inspeccionar(args.url)
        print("\n" + describir(inspeccion))
        codigo = int(inspeccion.limitacion is not None)
    if args.captura or args.salida or args.full:
        try:
            tomar_captura(args.url, args.salida or f"captura-{uuid4().hex[:12]}.png", full_page=args.full)
        except Exception:
            print("No se pudo obtener la captura.", file=sys.stderr)
            return 1
        print("Captura guardada.")
    return codigo


if __name__ == "__main__":
    raise SystemExit(main())
