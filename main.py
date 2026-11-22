from __future__ import annotations

import argparse
import sys
from uuid import uuid4

from analisis import analizar
from analyzers.brand_analyzer import lineas_catalogo
from captura import tomar_captura
from inspeccion import describir, inspeccionar


def main() -> int:
    parser = argparse.ArgumentParser(description="Analiza enlaces localmente, inspecciona la página o solicita una captura.")
    parser.add_argument("url", nargs="?")
    parser.add_argument("salida", nargs="?", help="Ruta PNG para solicitar una captura")
    parser.add_argument("--captura", action="store_true", help="Visitar el sitio y guardar una imagen")
    parser.add_argument("--full", action="store_true", help="Solicitar una captura de página completa")
    parser.add_argument("--inspeccionar", action="store_true", help="Visitar el sitio y examinar su respuesta y el HTML")
    args = parser.parse_args()
    if not args.url:
        if args.inspeccionar:
            parser.error("--inspeccionar requiere una URL")
        from escritorio import abrir
        abrir()
        return 0
    try:
        resultado = analizar(args.url)
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
    print("Verifica el sitio antes de ingresar datos personales." if resultado.senales else
          "Autenticidad sin confirmar. El análisis local solo revisó la dirección.")
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
