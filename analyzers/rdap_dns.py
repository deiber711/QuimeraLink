"""Consulta el DNS público y el registro del dominio sin abrir el enlace."""
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from http.client import HTTPException
from ipaddress import ip_address
import json
import socket
import ssl
from time import monotonic
from typing import Literal
from unicodedata import category
from urllib.parse import urlencode, urljoin, urlsplit

from analyzers.url_analyzer import ResultadoURL, analizar_url
from dominios import DATOS, normalizar_dominio, separar_dominio
from red import DestinoNoPublico, estado_error_dns, plazo_restante, resolver_publico, solicitar_publico


DNS = 'https://dns.google/resolve'
# El propio operador publica este servicio de .co aunque el directorio de IANA no lo incluya.
RDAP_CO = 'https://rdap.registry.co/co/'
SUFIJOS_LOCALES = frozenset({'alt', 'arpa', 'example', 'internal', 'invalid', 'local', 'localhost', 'onion', 'test'})
MAX_JSON = 1024 * 1024
ERRORES_RED = (OSError, HTTPException, DestinoNoPublico)
REDIRECCIONES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class ResultadoDNS:
    host: str
    estado: Literal['resuelve', 'sin_direccion', 'nxdomain', 'desconocido', 'error']
    explicacion: str


@dataclass(frozen=True)
class ResultadoRDAP:
    dominio: str | None
    estado: Literal['observado', 'ausente', 'desconocido', 'error']
    explicacion: str = ''
    servidor: str | None = None
    registro: datetime | None = None
    vencimiento: datetime | None = None
    ultimo_cambio: datetime | None = None
    antiguedad_dias: int | None = None
    registrador: str | None = None
    estados_registro: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResultadoDominio:
    fecha_consulta: datetime
    dns: ResultadoDNS
    rdap: ResultadoRDAP
    registro_de_plataforma: bool = False


def analizar_dns_sistema(url: ResultadoURL) -> ResultadoDNS | None:
    host = url.dominio
    if url.es_ip_literal or '.' not in host or host.rsplit('.', 1)[-1] in SUFIJOS_LOCALES:
        return None
    try:
        resolver_publico(host + '.', 443, timeout=4)
    except socket.gaierror as exc:
        estado = estado_error_dns(exc)
        detalle = {
            'nxdomain': 'El DNS del sistema no encontró el nombre solicitado.',
            'sin_direccion': 'El DNS del sistema no encontró una dirección para el nombre solicitado.',
            'error': 'El DNS del sistema no pudo completar la consulta.',
        }
        return ResultadoDNS(host, estado, detalle[estado])
    except DestinoNoPublico:
        return ResultadoDNS(host, 'desconocido', 'El DNS del sistema no devolvió un destino web público.')
    except TimeoutError:
        return ResultadoDNS(host, 'error', 'La consulta al DNS del sistema agotó el tiempo de espera.')
    except OSError:
        return ResultadoDNS(host, 'error', 'Falló la consulta al DNS del sistema.')
    return ResultadoDNS(host, 'resuelve', 'El DNS del sistema encontró una dirección pública.')


def _filas(datos, campo):
    filas = datos.get(campo)
    return (fila for fila in filas if isinstance(fila, dict)) if isinstance(filas, list) else ()


def _nombre_dns(valor):
    return valor.removesuffix('.').lower() if isinstance(valor, str) else ''


def _pedir_json(url, tls, limite, tipo):
    with solicitar_publico(url, tls, limite, aceptar=tipo) as respuesta:
        if respuesta.status in REDIRECCIONES:
            return respuesta.status, respuesta.getheader('Location')
        if respuesta.status != 200:
            return respuesta.status, {}
        longitud = respuesta.length
        if ((longitud is not None and not 0 < longitud <= MAX_JSON)
                or respuesta.getheader('Content-Encoding', 'identity').lower() != 'identity'):
            raise ValueError('Tamaño o codificación de respuesta no admitidos.')
        cuerpo = respuesta.read(MAX_JSON + 1)
        plazo_restante(limite)
        if len(cuerpo) > MAX_JSON or (longitud is not None and len(cuerpo) != longitud):
            raise ValueError('Respuesta incompleta o demasiado grande.')
        datos = json.loads(cuerpo)
        if not isinstance(datos, dict):
            raise ValueError('Se esperaba un objeto JSON.')
        return 200, datos


def _respuesta_dns(datos, host, tipo):
    preguntas = tuple(_filas(datos, 'Question'))
    if (len(preguntas) != 1 or _nombre_dns(preguntas[0].get('name')) != host
            or preguntas[0].get('type') != tipo or datos.get('TC')):
        raise ValueError('La respuesta DNS está truncada o corresponde a otra pregunta.')
    codigo = datos.get('Status')
    if type(codigo) is not int or codigo not in (0, 3):
        return 'error'
    respuestas = tuple(_filas(datos, 'Answer'))
    alias = {_nombre_dns(fila.get('name')): _nombre_dns(fila.get('data'))
             for fila in respuestas if fila.get('type') == 5}
    nombre = host
    visitados = set()
    while nombre in alias and nombre not in visitados:
        visitados.add(nombre)
        nombre = alias[nombre]
    if not nombre or nombre in visitados:
        return 'alias'
    if codigo == 3:
        return 'alias' if visitados else 'nxdomain'
    for fila in respuestas:
        if fila.get('type') == tipo and _nombre_dns(fila.get('name')) == nombre:
            valor = fila.get('data')
            if not isinstance(valor, str):
                raise ValueError('Registro DNS de dirección inválido.')
            direccion = ip_address(valor)
            if direccion.version == (4 if tipo == 1 else 6):
                return 'direccion'
    if visitados:
        return 'alias'
    for fila in _filas(datos, 'Authority'):
        zona = _nombre_dns(fila.get('name'))
        if fila.get('type') == 6 and (zona == host or (zona and host.endswith('.' + zona))):
            return 'nodata'
    return 'indeterminado'


def _consultar_dns(host, tls):
    limite = monotonic() + 7
    estados = []
    error = 'El resolvedor no pudo completar la consulta.'
    for tipo, etiqueta in ((1, 'IPv4 (A)'), (28, 'IPv6 (AAAA)')):
        consulta = urlencode({'name': host + '.', 'type': tipo, 'edns_client_subnet': '0.0.0.0/0'})
        try:
            codigo, datos = _pedir_json(f'{DNS}?{consulta}', tls, limite, 'application/dns-json')
            if codigo == 429:
                error = 'El resolvedor alcanzó su límite de consultas (HTTP 429).'
                estados.append('error')
                break
            estado = _respuesta_dns(datos, host, tipo) if codigo == 200 else 'error'
        except ERRORES_RED:
            estado = 'error'
        except (ValueError, RecursionError):
            error = 'El resolvedor devolvió una respuesta no válida para este host.'
            estado = 'error'
        if estado == 'direccion':
            return ResultadoDNS(host, 'resuelve', f'El host resuelve a una dirección {etiqueta}.')
        if estado == 'nxdomain' and not {'nodata', 'alias'}.intersection(estados):
            return ResultadoDNS(host, 'nxdomain', 'El resolvedor indicó que el host no existe en DNS (NXDOMAIN).')
        estados.append(estado)
    if 'alias' in estados:
        return ResultadoDNS(host, 'sin_direccion', 'El host existe como alias DNS. Sus direcciones no se pudieron confirmar.')
    if estados == ['nodata', 'nodata']:
        return ResultadoDNS(host, 'sin_direccion', 'El host existe en DNS y la respuesta no contiene registros A ni AAAA.')
    if 'nodata' in estados:
        return ResultadoDNS(host, 'desconocido', 'El DNS devolvió información parcial sobre las direcciones del host.')
    if 'error' in estados:
        return ResultadoDNS(host, 'error', error)
    return ResultadoDNS(host, 'desconocido', 'El resolvedor no confirmó la existencia del host.')


@cache
def _directorio_rdap():
    contenido = json.loads((DATOS / 'rdap_dns.json').read_bytes())
    return {sufijo: tuple(bases) for sufijos, bases in contenido['services'] for sufijo in sufijos}


def _bases_rdap(dominio):
    directorio = _directorio_rdap()
    sufijo = dominio
    while sufijo:
        if sufijo in directorio:
            return tuple(base for base in directorio[sufijo] if _base_https(base))
        if sufijo == 'co':
            return (RDAP_CO,)
        sufijo = sufijo.partition('.')[2]
    return ()


def _base_https(base):
    partes = urlsplit(base)
    return (partes.scheme == 'https' and partes.hostname and partes.username is None
            and partes.port in (None, 443) and not partes.query and not partes.fragment)


def _fecha(valor):
    if isinstance(valor, str):
        try:
            fecha = datetime.fromisoformat(valor.removesuffix('Z') + '+00:00' if valor.endswith('Z') else valor)
            if fecha.tzinfo is not None:
                return fecha.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            pass
    return None


def _texto_publico(valor):
    if isinstance(valor, str):
        limpio = ''.join(' ' if caracter.isspace() else caracter for caracter in valor[:250]
                         if caracter.isspace() or not category(caracter).startswith('C'))
        return ' '.join(limpio.split())[:120]
    return ''


def _registrador(datos):
    for entidad in _filas(datos, 'entities'):
        roles = entidad.get('roles')
        if not isinstance(roles, list) or 'registrar' not in roles:
            continue
        ficha = entidad.get('vcardArray')
        if isinstance(ficha, list) and len(ficha) == 2 and isinstance(ficha[1], list):
            for campo in ficha[1]:
                if isinstance(campo, list) and len(campo) == 4 and campo[0] == 'fn':
                    if nombre := _texto_publico(campo[3]):
                        return nombre
        for identificador in _filas(entidad, 'publicIds'):
            if identificador.get('type') == 'IANA Registrar ID' and (valor := _texto_publico(identificador.get('identifier'))):
                return f'IANA {valor}'
    return None


def _registro_rdap(dominio, servidor, datos, ahora):
    if datos.get('objectClassName') != 'domain':
        raise ValueError('El servicio no devolvió un registro de dominio.')
    nombre = datos.get('ldhName') or datos.get('unicodeName')
    if not isinstance(nombre, str) or normalizar_dominio(nombre)[0] != dominio:
        raise ValueError('El registro corresponde a otro dominio.')
    fechas = {}
    for evento in _filas(datos, 'events'):
        accion = evento.get('eventAction')
        if accion in ('registration', 'expiration', 'last changed') and (fecha := _fecha(evento.get('eventDate'))):
            if accion == 'expiration' or fecha <= ahora:
                fechas[accion] = max(fecha, fechas.get(accion, fecha))
    registro = fechas.get('registration')
    estados = datos.get('status')
    estados = tuple(dict.fromkeys(filter(None, map(_texto_publico, estados[:25])))) if isinstance(estados, list) else ()
    return ResultadoRDAP(dominio, 'observado', servidor=servidor, registro=registro,
                         vencimiento=fechas.get('expiration'), ultimo_cambio=fechas.get('last changed'),
                         antiguedad_dias=(ahora - registro).days if registro else None,
                         registrador=_registrador(datos), estados_registro=estados)


def _pedir_rdap(url, dominio, tls, limite):
    origen = urlsplit(url)
    visitados = {url}
    for intento in range(3):
        codigo, datos = _pedir_json(url, tls, limite, 'application/rdap+json, application/json')
        if (codigo not in REDIRECCIONES or intento == 2 or not isinstance(datos, str)
                or any(not '!' <= c <= '~' for c in datos)):
            return codigo, datos
        destino = urljoin(url, datos)
        partes = urlsplit(destino)
        # El registro puede cambiar la ruta para una categoría territorial como .com.co.
        if (partes.scheme != 'https' or partes.netloc != origen.netloc or partes.query or partes.fragment
                or not partes.path.endswith(f'/domain/{dominio}') or destino in visitados):
            return codigo, datos
        visitados.add(destino)
        url = destino


def _consultar_rdap(dominio, tls, ahora):
    if not dominio:
        return ResultadoRDAP(None, 'desconocido', 'El host no tiene un dominio registrable para consultar.')
    try:
        bases = _bases_rdap(dominio)
    except (OSError, ValueError, KeyError, TypeError):
        return ResultadoRDAP(dominio, 'error', 'No se pudo leer el directorio local de servicios RDAP.')
    if not bases:
        return ResultadoRDAP(dominio, 'desconocido', 'No hay un servicio RDAP HTTPS disponible en el directorio local.')

    limite = monotonic() + 8
    for base in bases:
        servidor = urlsplit(base).hostname
        try:
            codigo, datos = _pedir_rdap(f'{base.rstrip("/")}/domain/{dominio}', dominio, tls, limite)
            if codigo == 200:
                return _registro_rdap(dominio, servidor, datos, ahora)
        except ERRORES_RED:
            mensaje = 'No se pudo completar la conexión con el registro.'
        except (ValueError, RecursionError):
            mensaje = 'El servicio devolvió una respuesta inválida para este dominio.'
        else:
            if codigo == 404:
                return ResultadoRDAP(dominio, 'ausente', 'El servicio no devolvió un registro (HTTP 404).', servidor)
            if codigo in (401, 403, 451):
                return ResultadoRDAP(dominio, 'desconocido', f'El servicio restringió el acceso (HTTP {codigo}).', servidor)
            if codigo == 429:
                return ResultadoRDAP(dominio, 'error', 'El servicio alcanzó su límite de consultas (HTTP 429).', servidor)
            mensaje = (f'El servicio devolvió una redirección (HTTP {codigo}).' if 300 <= codigo < 400 else
                       f'El servicio no completó la consulta (HTTP {codigo}).')
    return ResultadoRDAP(dominio, 'error', mensaje, servidor)


def analizar_dns_rdap(url: ResultadoURL | str) -> ResultadoDominio:
    if isinstance(url, str):
        url = analizar_url(url)
    ahora = datetime.now(timezone.utc)
    host = url.dominio
    if url.es_ip_literal or host.rsplit('.', 1)[-1] in SUFIJOS_LOCALES:
        motivo = 'La consulta externa requiere un nombre de dominio público.'
        return ResultadoDominio(ahora, ResultadoDNS(host, 'desconocido', motivo),
                                ResultadoRDAP(None, 'desconocido', motivo))
    registrable = separar_dominio(host, incluir_privados=False).registrable
    plataforma = bool(url.dominio_registrable and registrable and registrable != url.dominio_registrable)
    try:
        tls = ssl.create_default_context()
    except OSError:
        motivo = 'No se pudo iniciar la validación de certificados TLS.'
        return ResultadoDominio(ahora, ResultadoDNS(host, 'error', motivo),
                                ResultadoRDAP(registrable, 'error', motivo), plataforma)
    return ResultadoDominio(ahora, _consultar_dns(host, tls), _consultar_rdap(registrable, tls, ahora), plataforma)


def lineas_dns_rdap(resultado: ResultadoDominio) -> tuple[str, ...]:
    dns, rdap = resultado.dns, resultado.rdap
    dominio = f' · {rdap.dominio}' if rdap.dominio else ''
    servidor = f' · {rdap.servidor}' if rdap.servidor else ''
    lineas = [f'DNS · {dns.host} · Google Public DNS', dns.explicacion, '', f'RDAP{dominio}{servidor}']
    if rdap.explicacion:
        lineas.append(rdap.explicacion)
    if rdap.estado == 'observado':
        if resultado.registro_de_plataforma:
            lineas.append('Las fechas corresponden al dominio de la plataforma. La antigüedad de la cuenta o del subdominio queda sin verificar.')
        if rdap.registro:
            lineas.append(f'Registro · {rdap.registro:%Y-%m-%d %H:%M UTC} · {rdap.antiguedad_dias} días')
        else:
            lineas.append('El servicio no publicó una fecha de registro utilizable.')
        if rdap.vencimiento:
            lineas.append(f'Vencimiento · {rdap.vencimiento:%Y-%m-%d %H:%M UTC}')
        if rdap.ultimo_cambio:
            lineas.append(f'Último cambio · {rdap.ultimo_cambio:%Y-%m-%d %H:%M UTC}')
        if rdap.registrador:
            lineas.append(f'Registrador · {rdap.registrador}')
        if rdap.estados_registro:
            lineas.append('Estados del registro · ' + ', '.join(rdap.estados_registro))
    lineas.append(f'Consulta · {resultado.fecha_consulta:%Y-%m-%d %H:%M UTC}')
    return tuple(lineas)
