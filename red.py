"""Resolución de destinos para las operaciones web opcionales."""
from ipaddress import ip_address
from queue import Empty, Queue
import socket
from threading import BoundedSemaphore, Thread


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
