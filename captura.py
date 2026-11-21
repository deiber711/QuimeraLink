"""Captura pasiva de recursos públicos para la vista previa."""
import http.client
import socket
import ssl
import sys
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from analisis import analizar


def imagen(url, *, full_page=False, ancho=1200, alto=800, timeout_ms=45000, espera_ms=1200):
    from playwright.sync_api import sync_playwright

    url = analizar(url).url_captura
    if not url:
        raise ValueError("La vista previa requiere una dirección pública sin credenciales.")
    @lru_cache(maxsize=128)
    def resolver(host, puerto):
        direcciones = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
        ips = [ip_address(d[4][0]) for d in direcciones]
        if not ips or any(not ip.is_global or ip.is_multicast for ip in ips):
            raise ValueError("La vista previa solo admite destinos públicos.")
        return str(next((ip for ip in ips if ip.version == 4), ips[0]))

    origen = urlsplit(url)
    resolver(origen.hostname, origen.port or (443 if origen.scheme == "https" else 80))
    tls = ssl.create_default_context()
    presupuesto = 48 * 1024 * 1024

    def recurso(route):
        nonlocal presupuesto
        peticion = route.request
        u = urlsplit(peticion.url)
        if (u.scheme not in ("http", "https") or u.username is not None or u.port not in (None, 80, 443)
                or peticion.method != "GET" or peticion.resource_type in ("media", "websocket") or presupuesto <= 0):
            return route.abort()
        puerto = u.port or (443 if u.scheme == "https" else 80)
        conexion = http.client.HTTPConnection(u.hostname, puerto, timeout=5)
        try:
            # Conectar a la IP ya validada y verificar TLS con el nombre original.
            destino = resolver(u.hostname, puerto)
            conexion.sock = socket.create_connection((destino, puerto), timeout=5)
            if u.scheme == "https":
                conexion.sock = tls.wrap_socket(conexion.sock, server_hostname=u.hostname)
            conexion.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""))
            respuesta = conexion.getresponse()
            if not 200 <= respuesta.status < 300:
                return route.abort()
            contenido = respuesta.read(min(presupuesto, 8 * 1024 * 1024) + 1)
            presupuesto -= len(contenido)
            if presupuesto < 0 or len(contenido) > 8 * 1024 * 1024:
                return route.abort()
            cabeceras = {k: v for k, v in respuesta.getheaders() if k.lower() in (
                "content-type", "content-encoding", "access-control-allow-origin", "content-security-policy"
            )}
            route.fulfill(status=200, headers=cabeceras, body=contenido)
        except (OSError, http.client.HTTPException, ValueError):
            route.abort()
        finally:
            conexion.close()

    with sync_playwright() as p:
        opciones = {}
        if getattr(sys, "frozen", False):
            opciones["executable_path"] = str(next((Path(sys._MEIPASS) / "chromium").rglob("chrome-headless-shell.exe")))
        with p.chromium.launch(chromium_sandbox=True, **opciones) as navegador:
            contexto = navegador.new_context(java_script_enabled=True, accept_downloads=False,
                service_workers="block", offline=True, viewport={"width": ancho, "height": alto})
            contexto.route("**/*", recurso)
            contexto.route_web_socket("**/*", lambda ws: ws.close())
            pagina = contexto.new_page()
            pagina.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            from playwright.sync_api import TimeoutError as TiempoAgotado
            try:
                pagina.wait_for_load_state("load", timeout=10000)
            except TiempoAgotado:
                pass
            if espera_ms:
                pagina.wait_for_timeout(espera_ms)
            return pagina.screenshot(full_page=full_page, animations="disabled", timeout=timeout_ms)


def tomar_captura(url, archivo_salida="captura.png", **opciones):
    datos = imagen(url, **opciones)
    destino = Path(archivo_salida).resolve()
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_bytes(datos)
    return destino
