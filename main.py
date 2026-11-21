from __future__ import annotations

import argparse
import sys
from uuid import uuid4

from analisis import analizar
from captura import tomar_captura


def main() -> int:
    parser = argparse.ArgumentParser(description="Analiza enlaces localmente o solicita una captura.")
    parser.add_argument("url", nargs="?")
    parser.add_argument("salida", nargs="?", help="Ruta PNG para solicitar una captura")
    parser.add_argument("--captura", action="store_true", help="Visitar el sitio y guardar una imagen")
    parser.add_argument("--full", action="store_true", help="Solicitar una captura de página completa")
    args = parser.parse_args()
    if not args.url:
        from escritorio import abrir
        abrir()
        return 0
    try:
        resultado = analizar(args.url)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    print("Destino:", resultado.dominio)
    for senal in resultado.senales:
        print("-", senal)
    print("Verifica el sitio antes de ingresar datos personales." if resultado.senales else
          "Sin señales evidentes. La autenticidad sigue sin confirmarse.")
    if args.captura or args.salida or args.full:
        try:
            tomar_captura(args.url, args.salida or f"captura-{uuid4().hex[:12]}.png", full_page=args.full)
        except Exception:
            print("No se pudo obtener la captura.", file=sys.stderr)
            return 1
        print("Captura guardada.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
