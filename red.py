"""Resolución de destinos para las operaciones web opcionales."""
from contextlib import closing, contextmanager, suppress
import http.client
from ipaddress import ip_address
from queue import Empty, Queue
import socket
from threading import BoundedSemaphore, Thread, Timer
from time import monotonic
from urllib.parse import urlsplit, urlunsplit


class DestinoNoPublico(ValueError):
    pass


_consultas_dns = BoundedSemaphore(4)


def _es_publica(ip):
    if ip.version == 6:
        if ip.scope_id or ip.is_site_local:
            return False
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def resolver_publico(host, puerto, *, timeout=None):
    def resolver():
        direcciones = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
        ips = [ip_address(datos[4][0]) for datos in direcciones]
        if not ips or any(not _es_publica(ip) for ip in ips):
            raise DestinoNoPublico("Solo se admiten destinos públicos.")
        return str(next((ip for ip in ips if ip.version == 4), ips[0]))

    if timeout is None:
        return resolver()
    if not _consultas_dns.acquire(blocking=False):
        raise TimeoutError("Hay consultas DNS pendientes.")
    resultados = Queue(maxsize=1)

    def consultar():
        try:
            resultados.put(resolver())
        except (OSError, ValueError) as exc:
            resultados.put(exc)
        finally:
            _consultas_dns.release()

    # El resolvedor del sistema puede seguir ocupado tras el plazo de la inspección.
    try:
        Thread(target=consultar, daemon=True).start()
    except RuntimeError:
        _consultas_dns.release()
        raise
    try:
        resultado = resultados.get(timeout=timeout)
    except Empty:
        raise TimeoutError("Tiempo de resolución agotado.") from None
    if isinstance(resultado, Exception):
        raise resultado
    return resultado


def plazo_restante(limite):
    tiempo = limite - monotonic()
    if tiempo <= 0:
        raise TimeoutError
    return tiempo


def _interrumpir(canal):
    with suppress(OSError):
        canal.shutdown(socket.SHUT_RDWR)


@contextmanager
def solicitar_publico(url, tls, limite, *, aceptar, resolver=resolver_publico, al_conectar=None):
    partes = urlsplit(url)
    puerto = partes.port or (443 if partes.scheme == 'https' else 80)
    ip = resolver(partes.hostname, puerto, timeout=min(5, plazo_restante(limite)))
    familia = socket.AF_INET6 if ':' in ip else socket.AF_INET
    with socket.socket(familia, socket.SOCK_STREAM) as tcp:
        # La conexión usa la IP validada y TLS verifica el nombre de la URL.
        tcp.settimeout(min(5, plazo_restante(limite)))
        tcp.connect((ip, puerto))
        if al_conectar is not None:
            al_conectar(partes.hostname)
        tcp.settimeout(min(5, plazo_restante(limite)))
        canal = tls.wrap_socket(tcp, server_hostname=partes.hostname) if partes.scheme == 'https' else tcp
        with closing(canal), closing(http.client.HTTPConnection(partes.hostname, puerto)) as conexion:
            conexion.sock = canal
            canal.settimeout(min(5, plazo_restante(limite)))
            alarma = Timer(plazo_restante(limite), _interrumpir, args=(canal,))
            alarma.daemon = True
            alarma.start()
            try:
                ruta = urlunsplit(('', '', partes.path or '/', partes.query, ''))
                conexion.request('GET', ruta, headers={'Accept': aceptar})
                with closing(conexion.getresponse()) as respuesta:
                    yield respuesta
            finally:
                alarma.cancel()
