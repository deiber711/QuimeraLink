"""Inspección opcional de respuestas HTTP y del HTML recibido."""
from collections import Counter
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
import http.client
from ipaddress import ip_address
import socket
import ssl
from threading import Timer
from time import monotonic
import unicodedata
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from analisis import analizar
from analyzers.brand_analyzer import senales_marcas_en_pagina
from dominios import dominio_registrable
from red import DestinoNoPublico, resolver_publico


MAX_REDIRECCIONES = 5
MAX_HTML = 2 * 1024 * 1024
MAX_TEXTO_MARCAS = 24_000
PLAZO = 15
REDIRECCIONES = {301, 302, 303, 307, 308}
ERRORES_RED = (OSError, http.client.HTTPException, DestinoNoPublico)
CAMPOS_PERSONALES = {'tel', 'current-password', 'new-password', 'one-time-code', 'cc-number', 'cc-csc'}


@dataclass(frozen=True)
class PasoHTTP:
    origen: str
    estado: int | None
    origen_redireccion: str | None = None


@dataclass(frozen=True)
class Formulario:
    origen: str | None
    tiene_password: bool


@dataclass(frozen=True)
class Inspeccion:
    pasos: tuple[PasoHTTP, ...]
    titulo: str | None
    formularios: tuple[Formulario, ...] | None
    limitacion: str | None
    senales_contenido: tuple[str, ...] = ()


class _Pagina(HTMLParser):
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, 'title', 'textarea',
                              'xmp', 'iframe', 'noembed', 'noframes', 'noscript')

    def __init__(self):
        super().__init__()
        self.base = None
        self.titulo = None
        self.formularios = []
        self._en_titulo = False
        self._plantillas = 0
        self._formulario = None
        self._con_password = set()
        self._ids_con_password = set()
        self._texto = []
        self._presupuesto_texto = MAX_TEXTO_MARCAS
        self._en_etiqueta = False
        self._etiqueta_personal = False
        self._campo_editable = False
        self._campo_personal = False

    def handle_starttag(self, tag, attrs):
        if tag == 'template':
            self._plantillas += 1
        if self._plantillas:
            return
        atributos = dict(reversed(attrs))  # El primer atributo con un nombre prevalece.
        if tag == 'base' and self.base is None and 'href' in atributos:
            self.base = atributos['href'] or ''
        elif tag == 'title' and self.titulo is None:
            self.titulo = ''
            self._en_titulo = True
        elif tag == 'form' and self._formulario is None:
            self._formulario = len(self.formularios)
            self.formularios.append(atributos)
        elif tag == 'label':
            self._en_etiqueta = True
        elif tag == 'input':
            tipo = (atributos.get('type') or 'text').lower()
            if tipo == 'password':
                if 'form' in atributos:
                    self._ids_con_password.add(atributos['form'])
                elif self._formulario is not None:
                    self._con_password.add(self._formulario)
            if tipo in {'text', 'number', 'tel', 'password'} and not {'disabled', 'readonly', 'hidden'} & atributos.keys():
                self._campo_editable = True
                autocompletar = (atributos.get('autocomplete') or '').lower().split()
                if tipo in {'tel', 'password'} or CAMPOS_PERSONALES.intersection(autocompletar):
                    self._campo_personal = True

    def handle_endtag(self, tag):
        if tag == 'template' and self._plantillas:
            self._plantillas -= 1
        elif not self._plantillas:
            if tag == 'form':
                self._formulario = None
            elif tag == 'title':
                self._en_titulo = False
            elif tag == 'label':
                self._en_etiqueta = False

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._plantillas:
            return
        if self._en_titulo:
            self.titulo = (self.titulo + unescape(data))[:512]
        elif self.cdata_elem is None:
            if self._en_etiqueta and any(palabra in data.casefold() for palabra in (
                'celular', 'teléfono', 'telefono', 'contraseña', 'número de línea', 'número de tarjeta'
            )):
                self._etiqueta_personal = True
            if self._presupuesto_texto and data.strip():
                fragmento = data[:self._presupuesto_texto]
                self._texto.append(fragmento)
                self._presupuesto_texto -= len(fragmento)

    def senales_contenido(self, host, titulo):
        if self._campo_personal or (self._campo_editable and self._etiqueta_personal):
            return tuple(senales_marcas_en_pagina(host, _registrable(host), titulo, ' '.join(self._texto)))
        return ()

    def destinos(self, url):
        base = _referencia(url, self.base) if self.base else url
        destinos = []
        ids = set()
        for indice, atributos in enumerate(self.formularios):
            identificador = atributos.get('id')
            asociado = bool(identificador and identificador not in ids and identificador in self._ids_con_password)
            if identificador:
                ids.add(identificador)
            accion = (atributos.get('action') or '').strip()
            destino = _referencia(base or url, accion) if accion else url
            origen = None if (atributos.get('method') or '').lower() == 'dialog' else _origen(destino)
            destinos.append(Formulario(origen, asociado or indice in self._con_password))
        return tuple(destinos)


def _referencia(base, referencia):
    if len(referencia) > 8192:
        return ''
    try:
        return urljoin(base, referencia.strip())
    except ValueError:
        return ''


def _origen(url, *, host=None):
    try:
        partes = urlsplit(url)
        if partes.scheme not in ('http', 'https') or not partes.hostname:
            return None
        if host is None:
            host = partes.hostname.rstrip('.').encode('idna').decode('ascii')
        if not host or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-:' for c in host):
            return None
        autoridad = f'[{host}]' if ':' in host else host
        puerto = partes.port
        if puerto is not None and puerto != (443 if partes.scheme == 'https' else 80):
            autoridad += f':{puerto}'
        return f'{partes.scheme}://{autoridad}'
    except (ValueError, UnicodeError):
        return None


def _url_http(resultado):
    if resultado.url_captura is None:
        raise DestinoNoPublico('La dirección requiere un destino público sin credenciales y un puerto web.')
    partes = urlsplit(resultado.url_captura)
    origen = _origen(resultado.url_captura)
    if origen is None:
        raise DestinoNoPublico('La dirección no tiene un origen HTTP o HTTPS válido.')
    ruta = quote(partes.path or '/', safe="/%:@!$&'()*+,;=-._~")
    consulta = quote(partes.query, safe="/%?:@!$&'()*+,;=-._~")
    return origen + urlunsplit(('', '', ruta, consulta, ''))


def _restante(limite):
    tiempo = limite - monotonic()
    if tiempo <= 0:
        raise TimeoutError
    return tiempo


def _interrumpir(canal):
    with suppress(OSError):
        canal.shutdown(socket.SHUT_RDWR)


@contextmanager
def _solicitar(url, tls, limite):
    partes = urlsplit(url)
    puerto = partes.port or (443 if partes.scheme == 'https' else 80)
    ip = resolver_publico(partes.hostname, puerto, timeout=min(5, _restante(limite)))
    familia = socket.AF_INET6 if ':' in ip else socket.AF_INET
    with socket.socket(familia, socket.SOCK_STREAM) as tcp:
        # La conexión usa la IP validada y TLS verifica el nombre de la URL.
        tcp.settimeout(min(5, _restante(limite)))
        tcp.connect((ip, puerto))
        tcp.settimeout(min(5, _restante(limite)))
        canal = tls.wrap_socket(tcp, server_hostname=partes.hostname) if partes.scheme == 'https' else tcp
        with closing(canal), closing(http.client.HTTPConnection(partes.hostname, puerto)) as conexion:
            conexion.sock = canal
            canal.settimeout(min(5, _restante(limite)))
            # El plazo total también se aplica a respuestas que llegan byte a byte.
            alarma = Timer(_restante(limite), _interrumpir, args=(canal,))
            alarma.daemon = True
            alarma.start()
            try:
                ruta = urlunsplit(('', '', partes.path, partes.query, ''))
                conexion.request('GET', ruta, headers={'Accept': 'text/html, application/xhtml+xml'})
                with closing(conexion.getresponse()) as respuesta:
                    yield respuesta
            finally:
                alarma.cancel()


def _motivo_red(exc, limite):
    if isinstance(exc, DestinoNoPublico):
        return 'Se bloqueó el acceso a un destino que no es público.'
    if isinstance(exc, TimeoutError) or monotonic() >= limite:
        return 'Se agotó el tiempo de inspección.'
    if isinstance(exc, ssl.SSLError):
        return 'Falló la conexión TLS con el sitio.'
    if isinstance(exc, socket.gaierror):
        return 'No se pudo resolver el dominio.'
    return 'Se interrumpió la comunicación con el sitio.'


def _leer_html(respuesta, url, limite):
    if respuesta.headers.get_content_type() not in ('text/html', 'application/xhtml+xml'):
        return None, None, 'La respuesta no contiene HTML.', ()
    codificacion = respuesta.getheader('Content-Encoding', 'identity').strip().lower()
    if codificacion not in ('', 'identity'):
        return None, None, 'El sitio devolvió HTML con una codificación de contenido no admitida.', ()

    contenido = bytearray()
    limitacion = None
    try:
        while len(contenido) <= MAX_HTML:
            _restante(limite)
            bloque = respuesta.read1(min(65536, MAX_HTML + 1 - len(contenido)))
            if not bloque:
                _restante(limite)
                if respuesta.length:
                    limitacion = 'El sitio cerró la conexión antes de completar el HTML.'
                break
            contenido.extend(bloque)
        if len(contenido) > MAX_HTML:
            del contenido[MAX_HTML:]
            limitacion = 'El HTML superó el límite de 2 MiB. Se inspeccionó el inicio de la página.'
    except ERRORES_RED as exc:
        limitacion = _motivo_red(exc, limite)
    if not contenido:
        return None, None, limitacion or 'El sitio devolvió un documento HTML vacío.', ()

    charset = respuesta.headers.get_content_charset() or 'utf-8-sig'
    try:
        html = contenido.decode(charset, errors='replace')
    except (LookupError, UnicodeError):
        html = contenido.decode('utf-8-sig', errors='replace')
    pagina = _Pagina()
    try:
        pagina.feed(html)
        pagina.close()
    except ValueError:
        limitacion = limitacion or 'Una parte del HTML no se pudo interpretar.'
    # El título del sitio se muestra como texto, sin controles ni marcas invisibles.
    titulo = ''.join(' ' if c.isspace() else c for c in (pagina.titulo or '')
                     if c.isspace() or not unicodedata.category(c).startswith('C'))
    titulo = ' '.join(titulo.split())[:160] or None
    return titulo, pagina.destinos(url), limitacion, pagina.senales_contenido(urlsplit(url).hostname, titulo)


def inspeccionar(url: str) -> Inspeccion:
    """Recoge evidencia de una URL por GET y sigue hasta cinco redirecciones públicas."""
    try:
        destino = _url_http(analizar(url))
    except ValueError:
        return Inspeccion((), None, None, 'La inspección requiere una dirección web pública sin credenciales.')

    limite = monotonic() + PLAZO
    try:
        tls = ssl.create_default_context()
    except OSError:
        return Inspeccion((), None, None, 'No se pudo inicializar la validación de certificados TLS.')
    pasos = []
    visitados = set()
    titulo = formularios = limitacion = None
    senales_contenido = ()
    while destino not in visitados:
        visitados.add(destino)
        origen_actual = _origen(destino)
        pasos.append(PasoHTTP(origen_actual, None))
        try:
            with _solicitar(destino, tls, limite) as respuesta:
                pasos[-1] = PasoHTTP(origen_actual, respuesta.status)
                if respuesta.status not in REDIRECCIONES:
                    if 200 <= respuesta.status < 300:
                        titulo, formularios, limitacion, senales_contenido = _leer_html(respuesta, destino, limite)
                    else:
                        limitacion = 'El servidor devolvió una respuesta HTTP sin una página disponible para inspección.'
                    break
                ubicaciones = respuesta.headers.get_all('Location', [])
                if len(ubicaciones) != 1 or not ubicaciones[0].strip():
                    limitacion = 'La redirección no indicó un destino único.'
                    break
                siguiente = _referencia(destino, ubicaciones[0])
                try:
                    analisis_siguiente = analizar(siguiente)
                except ValueError:
                    limitacion = 'La redirección indicó un destino HTTP o HTTPS inválido.'
                    break
                origen_siguiente = _origen(siguiente, host=analisis_siguiente.dominio)
                if origen_siguiente is None:
                    limitacion = 'La redirección indicó un destino HTTP o HTTPS inválido.'
                    break
                pasos[-1] = PasoHTTP(origen_actual, respuesta.status, origen_siguiente)
                if len(pasos) > MAX_REDIRECCIONES:
                    limitacion = 'Se alcanzó el límite de cinco redirecciones.'
                    break
                try:
                    destino = _url_http(analisis_siguiente)
                except ValueError:
                    limitacion = 'Se bloqueó una redirección hacia una dirección no admitida.'
                    break
        except ERRORES_RED as exc:
            limitacion = _motivo_red(exc, limite)
            break
    else:
        limitacion = 'Se detectó un ciclo de redirecciones.'
    return Inspeccion(tuple(pasos), titulo, formularios, limitacion, senales_contenido)


def _registrable(host):
    try:
        ip_address(host)
    except ValueError:
        return dominio_registrable(host)
    return None


def _senales_redirecciones(pasos):
    for indice, paso in enumerate(pasos):
        destino = paso.origen_redireccion
        if destino is None and indice + 1 < len(pasos):
            destino = pasos[indice + 1].origen
        if destino is None:
            continue
        anterior, siguiente = urlsplit(paso.origen), urlsplit(destino)
        if anterior.hostname != siguiente.hostname:
            origen_registrable = _registrable(anterior.hostname)
            destino_registrable = _registrable(siguiente.hostname)
            if origen_registrable and destino_registrable:
                if origen_registrable != destino_registrable:
                    yield f'Una redirección cambia de dominio registrable · {origen_registrable} → {destino_registrable}'
            else:
                yield f'Una redirección cambia de host · {anterior.hostname} → {siguiente.hostname}'
        if anterior.scheme == 'https' and siguiente.scheme == 'http':
            yield f'Una redirección pasa de HTTPS a HTTP · {paso.origen} → {destino}'


def describir(resultado: Inspeccion) -> str:
    lineas = []
    if resultado.pasos:
        lineas.append('Recorrido de la solicitud')
    for paso in resultado.pasos:
        estado = f'HTTP {paso.estado}' if paso.estado is not None else 'Sin respuesta HTTP'
        lineas.append(f'• {paso.origen} · {estado}')
    if resultado.pasos and resultado.pasos[-1].origen_redireccion:
        lineas.append(f'Destino anunciado por la última redirección · {resultado.pasos[-1].origen_redireccion}')

    respuestas = [paso for paso in resultado.pasos if paso.estado is not None]
    if respuestas:
        ultimo = respuestas[-1]
        if ultimo.estado in REDIRECCIONES:
            lineas.append(f'Último origen que respondió · {ultimo.origen}')
        else:
            lineas.append(f'Destino final · {ultimo.origen}')
            registrable = _registrable(urlsplit(ultimo.origen).hostname)
            if registrable:
                lineas.append(f'Dominio registrable final · {registrable}')
    senales = [*_senales_redirecciones(resultado.pasos), *resultado.senales_contenido]

    if resultado.formularios is not None and respuestas:
        lineas.extend(('', f'Título · {resultado.titulo or "Sin título en el HTML inspeccionado"}'))
        cantidad = sum(formulario.tiene_password for formulario in resultado.formularios)
        lineas.append(f'Formularios en el HTML inspeccionado · {len(resultado.formularios)} ({cantidad} con contraseña)')
        grupos = Counter(resultado.formularios)
        orden = sorted(grupos, key=lambda f: (f.tiene_password and f.origen not in (None, ultimo.origen),
                                               f.tiene_password, grupos[f]), reverse=True)
        principales = orden[:8]
        for formulario in principales:
            etiqueta = 'con contraseña' if formulario.tiene_password else 'sin contraseña'
            destino = formulario.origen or 'sin destino HTTP o HTTPS'
            lineas.append(f'• {grupos[formulario]} {etiqueta} · {destino}')
        restantes = len(resultado.formularios) - sum(grupos[f] for f in principales)
        if restantes:
            lineas.append(f'• {restantes} formularios más')
        destinos = {f.origen for f in grupos if f.tiene_password and f.origen}
        if destinos.difference({ultimo.origen}):
            senales.append('Un formulario de contraseña apunta a otro origen.')
        if any(origen.startswith('http://') for origen in destinos):
            senales.append('Un formulario de contraseña apunta a una dirección HTTP.')

    if senales:
        lineas.extend(('', 'Señales observadas', *(f'• {senal}' for senal in dict.fromkeys(senales))))
    if resultado.limitacion:
        lineas.extend(('', f'Inspección incompleta · {resultado.limitacion}'))
    lineas.extend(('', 'La autenticidad del sitio sigue sin confirmarse.'))
    return '\n'.join(lineas).strip()
