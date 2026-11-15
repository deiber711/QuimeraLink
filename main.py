
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Error as PlaywrightError, sync_playwright

# Selectores habituales de botones "aceptar cookies". Se prueban en orden
# hasta que uno funcione; si ninguno existe, se ignora sin fallar.
COOKIE_SELECTORS = [
    "#onetrust-accept-btn-handler",
    "button:has-text('Aceptar todas')",
    "button:has-text('Aceptar todo')",
    "button:has-text('Aceptar')",
    "button:has-text('Acepto')",
    "button:has-text('Entendido')",
]

# Botones "X" de modales típicos (ubicación, newsletter, promociones) que
# aparecen encima del contenido y estropean la captura.
POPUP_SELECTORS = [
    "#testId-modal-close",
    "[aria-label='Cerrar']",
    "[aria-label='Close']",
    "button[class*='modal-close']",
]

# Desactiva animaciones y transiciones para que la captura sea reproducible.
CSS_SIN_ANIMACIONES = """
*, *::before, *::after {
    animation: none !important;
    transition: none !important;
}
"""


def tomar_captura(
    url: str,
    archivo_salida: str | Path = "captura.png",
    *,
    full_page: bool = False,
    ancho: int = 1440,
    alto: int = 900,
    timeout_ms: int = 30_000,
    espera_ms: int = 1_500,
) -> Path:
    """Abre `url` en Chromium headless y guarda una captura en `archivo_salida`.

    Devuelve la ruta absoluta del archivo generado.
    """
    destino = Path(archivo_salida).resolve()
    destino.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                viewport={"width": ancho, "height": alto},
                device_scale_factor=1,  # Zoom 100%
                locale="es-CO",
                timezone_id="America/Bogota",
                color_scheme="light",
            )
            page = context.new_page()
            page.set_default_timeout(timeout_ms)

            print(f"Cargando {url} ...")
            # "domcontentloaded" no se cuelga en sitios que hacen peticiones
            # constantes (analytics, chat, precios en vivo).
            respuesta = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            if respuesta is not None and respuesta.status >= 400:
                print(
                    f"Aviso: la página respondió HTTP {respuesta.status}",
                    file=sys.stderr,
                )

            # Espera "best effort" a que la red se calme. Si el sitio nunca
            # llega a networkidle, seguimos con la captura en vez de fallar.
            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except PlaywrightError:
                print("Aviso: la red no se calmó, continúo con la captura")

            # Espera a que las fuentes estén listas (evita texto con fuente fallback).
            try:
                page.evaluate("document.fonts.ready")
            except PlaywrightError:
                pass

            # Quita animaciones y banners de cookies que tapan el contenido.
            try:
                page.add_style_tag(content=CSS_SIN_ANIMACIONES)
            except PlaywrightError:
                pass
            _cerrar_banner_cookies(page)

            # Algunos modales solo aparecen después de aceptar las cookies.
            page.wait_for_timeout(500)
            _cerrar_popups(page)

            # Pausa extra por si hay contenido tardío.
            page.wait_for_timeout(espera_ms)

            page.screenshot(path=destino, full_page=full_page)
            print(f"¡Listo! Guardada en {destino}")
            return destino
        finally:
            browser.close()


def _cerrar_banner_cookies(page) -> None:
    """Intenta cerrar el banner de cookies probando los selectores conocidos."""
    for selector in COOKIE_SELECTORS:
        try:
            page.locator(selector).first.click(timeout=1_500)
            print(f"Banner de cookies cerrado ({selector})")
            return
        except PlaywrightError:
            continue


def _cerrar_popups(page) -> None:
    """Cierra modales (ubicación, newsletter...) probando botones de cierre."""
    for selector in POPUP_SELECTORS:
        try:
            boton = page.locator(selector).first
            if boton.is_visible():
                boton.click(timeout=1_500)
                print(f"Modal cerrado ({selector})")
        except PlaywrightError:
            continue


def _nombre_por_defecto(url: str) -> str:
    host = urlparse(url).netloc.replace("www.", "") or "captura"
    return f"{re.sub(r'[^\w.-]', '_', host)}.png"


def _normalizar_url(texto: str) -> str:
    """Limpia la entrada y añade https:// si el usuario escribe solo el dominio."""
    url = texto.strip().strip("\"'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"
    return url


def _pausa_final() -> None:
    """Evita que la ventana se cierre sola al ejecutar con doble clic."""
    try:
        input("Pulsa Enter para cerrar esta ventana...")
    except (EOFError, KeyboardInterrupt):
        pass


def modo_interactivo(full_page: bool = False) -> int:
    """Pregunta la URL por consola y toma la captura (repite hasta dejarla vacía)."""
    print("=== Web Site Screenshot By Deiber ===")
    print("Escribe la URL del sitio y pulsa Enter. Déjalo vacío para salir.\n")

    while True:
        try:
            entrada = input("Ingrese la URL del sitio que desea capturar: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not entrada:
            print("¡Hasta luego!")
            return 0

        url = _normalizar_url(entrada)
        if not urlparse(url).netloc:
            print("Esa URL no parece válida. Ejemplo: falabella.com.co\n")
            continue

        salida = _nombre_por_defecto(url)
        try:
            tomar_captura(url, salida, full_page=full_page)
        except PlaywrightError as exc:
            print(f"No se pudo capturar {url}: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            print("Captura cancelada.")

        print()  # Línea en blanco antes de la siguiente pregunta.


def main() -> int:
    # Evita que los acentos se vean como caracteres raros en consolas Windows.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(
        description="Toma una captura de pantalla de una página web.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="URL de la página a capturar (si se omite, se pregunta por consola)",
    )
    parser.add_argument(
        "salida",
        nargs="?",
        default=None,
        help="Archivo de salida (por defecto: <dominio>.png)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Capturar la página completa, no solo la ventana visible",
    )
    args = parser.parse_args()

    # Sin URL en los argumentos -> modo interactivo (doble clic o "python main.py").
    if args.url is None:
        codigo = modo_interactivo(full_page=args.full)
        _pausa_final()
        return codigo

    salida = args.salida or _nombre_por_defecto(args.url)

    try:
        tomar_captura(args.url, salida, full_page=args.full)
    except PlaywrightError as exc:
        print(f"Error de Playwright: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
