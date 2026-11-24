"""Inspección opcional de respuestas HTTP y del HTML recibido."""
from collections import Counter
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
import http.client
from ipaddress import ip_address
import socket
import ssl
from time import monotonic
import unicodedata
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from analisis import analizar
from analyzers.brand_analyzer import cliente_de_proveedor, es_opcion_de_proveedor, senales_marcas_en_pagina
from analyzers.html_analyzer import Formulario, FormulariosHTML
from analyzers.reputation import ResultadoReputacion, lineas_reputacion
from dominios import dominio_registrable, normalizar_dominio
from red import DestinoNoPublico, plazo_restante as _restante, resolver_publico, solicitar_publico


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
    senales_marca_destino: tuple[str, ...] = ()
    senales_reputacion_destino: tuple[str, ...] = ()
    puntos_marca_destino: int = 0
    reputacion_destino: ResultadoReputacion | None = None


@dataclass(frozen=True)
class Inspeccion:
    pasos: tuple[PasoHTTP, ...]
    titulo: str | None
    formularios: tuple[Formulario, ...] | None
    limitacion: str | None
    senales_contenido: tuple[str, ...] = ()
    dominios_contactados: tuple[str, ...] = ()


class _Pagina(HTMLParser):
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, 'title', 'textarea',
                              'xmp', 'iframe', 'noembed', 'noframes', 'noscript')

    def __init__(self):
        super().__init__()
        self.base = None
        self.titulo = None
        self.formularios = FormulariosHTML()
        self._en_titulo = False
        self._plantillas = 0
        self._texto = []
        self._enlace = None
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
        self.formularios.inicio(tag, atributos)
        if tag == 'a':
            self._enlace = (len(self._texto), atributos.get('href') or '')
        elif tag == 'base' and self.base is None and 'href' in atributos:
            self.base = atributos['href'] or ''
        elif tag == 'title' and self.titulo is None:
            self.titulo = ''
            self._en_titulo = True
        elif tag == 'label':
            self._en_etiqueta = True
        elif tag == 'input':
            tipo = (atributos.get('type') or 'text').lower()
            if tipo in {'text', 'number', 'tel', 'password'} and not {'disabled', 'readonly', 'hidden'} & atributos.keys():
                self._campo_editable = True
                autocompletar = (atributos.get('autocomplete') or '').lower().split()
                if tipo in {'tel', 'password'} or CAMPOS_PERSONALES.intersection(autocompletar):
                    self._campo_personal = True

    def handle_endtag(self, tag):
        if tag == 'template' and self._plantillas:
            self._plantillas -= 1
        elif not self._plantillas:
            self.formularios.fin(tag)
            if tag == 'title':
                self._en_titulo = False
            elif tag == 'label':
                self._en_etiqueta = False
            elif tag == 'a' and self._enlace is not None:
                inicio, href = self._enlace
                self._enlace = None
                if self._presupuesto_texto and es_opcion_de_proveedor(' '.join(self._texto[inicio:]), href):
                    del self._texto[inicio:]

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._plantillas:
            return
        if self._en_titulo:
            self.titulo = (self.titulo + unescape(data))[:512]
        elif self.cdata_elem is None:
            self.formularios.datos(data)
            if self._en_etiqueta and any(palabra in data.casefold() for palabra in (
                'celular', 'teléfono', 'telefono', 'contraseña', 'número de línea', 'número de tarjeta'
            )):
                self._etiqueta_personal = True
            if self._presupuesto_texto and data.strip():
                fragmento = data[:self._presupuesto_texto]
                self._texto.append(fragmento)
                self._presupuesto_texto -= len(fragmento)

    def senales_contenido(self, url, titulo):
        if self._campo_personal or (self._campo_editable and self._etiqueta_personal):
            partes = urlsplit(url)
            return tuple(senales_marcas_en_pagina(
                partes.hostname, _registrable(partes.hostname), titulo, ' '.join(self._texto),
                https_estandar=partes.scheme == 'https' and partes.port in (None, 443),
            ))
        return ()

    def destinos(self, url):
        base = _referencia_formulario(url, self.base) if self.base else url
        return self.formularios.resultados(url, base, _referencia_formulario, _origen)


def _referencia_formulario(base, referencia):
    # Las barras invertidas y autoridades ambiguas se interpretan de forma distinta en navegadores.
    if chr(92) in referencia or referencia.startswith('///') or any(ord(c) < 32 for c in referencia):
        return ''
    try:
        partes = urlsplit(referencia)
        if partes.scheme in ('http', 'https') and not partes.netloc:
            return ''
    except ValueError:
        return ''
    return _referencia(base, referencia)


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
            host = (ip_address(partes.hostname).compressed if ':' in partes.hostname
                    else normalizar_dominio(partes.hostname)[0])
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


def _solicitar(url, tls, limite, al_conectar):
    return solicitar_publico(url, tls, limite, aceptar='text/html, application/xhtml+xml',
                             resolver=resolver_publico, al_conectar=al_conectar)


def _error_certificado(exc):
    codigo = getattr(exc, 'verify_code', None)
    motivos = {
        9: 'certificado aún fuera de vigencia',
        10: 'certificado vencido',
        18: 'certificado autofirmado sin confianza local',
        19: 'cadena con certificado autofirmado sin confianza local',
        20: 'no se pudo verificar el emisor',
        21: 'no se pudo verificar la firma con la cadena disponible',
        23: 'certificado revocado',
        62: 'el nombre del dominio no coincide con el certificado',
        64: 'la dirección IP no coincide con el certificado',
    }
    return motivos.get(codigo, f'error de verificación {codigo}' if codigo is not None
                       else 'falló la verificación del certificado')


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
    except (ValueError, AssertionError):
        limitacion = limitacion or 'Una parte del HTML no se pudo interpretar.'
    # El título del sitio se muestra como texto, sin controles ni marcas invisibles.
    titulo = ''.join(' ' if c.isspace() else c for c in (pagina.titulo or '')
                     if c.isspace() or not unicodedata.category(c).startswith('C'))
    titulo = ' '.join(titulo.split())[:160] or None
    return titulo, pagina.destinos(url), limitacion, pagina.senales_contenido(url, titulo)


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
    contactados = {}
    visitados = set()
    titulo = formularios = limitacion = None
    senales_contenido = ()
    while destino not in visitados:
        visitados.add(destino)
        origen_actual = _origen(destino)
        pasos.append(PasoHTTP(origen_actual, None))
        try:
            with _solicitar(destino, tls, limite, contactados.setdefault) as respuesta:
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
                pasos[-1] = PasoHTTP(origen_actual, respuesta.status, origen_siguiente,
                                     analisis_siguiente.analisis_marca.senales,
                                     lineas_reputacion(analisis_siguiente.reputacion, solo_coincidencias=True),
                                     analisis_siguiente.analisis_marca.puntos_sugeridos,
                                     analisis_siguiente.reputacion)
                if len(pasos) > MAX_REDIRECCIONES:
                    limitacion = 'Se alcanzó el límite de cinco redirecciones.'
                    break
                try:
                    destino = _url_http(analisis_siguiente)
                except ValueError:
                    limitacion = 'Se bloqueó una redirección hacia una dirección no admitida.'
                    break
        except ssl.SSLCertVerificationError as exc:
            limitacion = f'Certificado TLS rechazado en {origen_actual} · {_error_certificado(exc)}.'
            break
        except ERRORES_RED as exc:
            limitacion = _motivo_red(exc, limite)
            break
    else:
        limitacion = 'Se detectó un ciclo de redirecciones.'
    return Inspeccion(tuple(pasos), titulo, formularios, limitacion, senales_contenido, tuple(contactados))


def _registrable(host):
    try:
        ip_address(host)
    except ValueError:
        return dominio_registrable(host)
    return None


def senales_redirecciones(pasos):
    for indice, paso in enumerate(pasos):
        destino = paso.origen_redireccion
        if destino is None and indice + 1 < len(pasos):
            destino = pasos[indice + 1].origen
        if destino is None:
            continue
        anterior, siguiente = urlsplit(paso.origen), urlsplit(destino)
        for senal in (*paso.senales_marca_destino, *paso.senales_reputacion_destino):
            yield f'Destino anunciado · {siguiente.hostname} · {senal}'
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
        if paso.origen_redireccion:
            lineas.append(f'  → {paso.origen_redireccion} (destino anunciado)')
    if resultado.pasos:
        dominios = ', '.join(resultado.dominios_contactados) or 'ninguno'
        lineas.append(f'Dominios contactados durante la inspección · {dominios}')
    for anterior, siguiente in zip(resultado.pasos, resultado.pasos[1:]):
        origen, destino = urlsplit(anterior.origen), urlsplit(siguiente.origen)
        if (anterior.origen_redireccion == siguiente.origen and siguiente.estado is not None
                and origen.scheme == destino.scheme == 'https' and origen.port is None and destino.port is None):
            cliente = cliente_de_proveedor(origen.hostname, _registrable(origen.hostname), destino.hostname)
            if cliente:
                lineas.append(f'{cliente} tiene registrado a {destino.hostname} como proveedor de acceso.')
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
    senales = [*senales_redirecciones(resultado.pasos), *resultado.senales_contenido]

    if resultado.formularios is not None and respuestas:
        lineas.extend(('', f'Título · {resultado.titulo or "Sin título en el HTML inspeccionado"}'))
        cantidad = sum(formulario.tiene_password for formulario in resultado.formularios)
        financieros = sum(f.datos_financieros for f in resultado.formularios)
        lineas.append(f'Formularios en el HTML inspeccionado · {len(resultado.formularios)} '
                      f'({cantidad} con contraseña, {financieros} con datos financieros)')
        grupos = Counter(resultado.formularios)

        def receptores(f):
            return (f.origen, *f.destinos_botones)

        def prioridad(f):
            sensible = f.tiene_password or f.datos_financieros
            riesgo = any(o and (o != ultimo.origen or o.startswith('http://')) for o in receptores(f))
            return sensible and riesgo, sensible, grupos[f]

        principales = sorted(grupos, key=prioridad, reverse=True)[:8]
        for formulario in principales:
            campos = []
            if formulario.tiene_password:
                campos.append('contraseña')
            if formulario.datos_financieros:
                campos.append('datos financieros')
            etiqueta = 'con ' + ' y '.join(campos) if campos else 'sin campos sensibles detectados'
            destino = formulario.origen or 'sin destino HTTP o HTTPS identificable'
            lineas.append(f'• {grupos[formulario]} {etiqueta} · {destino}')
            for opcion in formulario.destinos_botones[:8]:
                lineas.append(f'  Destino por botón · {opcion or "sin destino HTTP o HTTPS identificable"}')
            if len(formulario.destinos_botones) > 8:
                lineas.append(f'  Otros destinos por botón · {len(formulario.destinos_botones) - 8}')
        restantes = len(resultado.formularios) - sum(grupos[f] for f in principales)
        if restantes:
            lineas.append(f'• {restantes} formularios más')
        for atributo, nombre in (('tiene_password', 'contraseña'), ('datos_financieros', 'datos financieros')):
            destinos = {o for f in grupos if getattr(f, atributo) for o in receptores(f) if o}
            if destinos.difference({ultimo.origen}):
                senales.append(f'Un formulario de {nombre} apunta a otro origen.')
            if any(o.startswith('http://') for o in destinos):
                senales.append(f'Un formulario de {nombre} apunta a una dirección HTTP.')

    if senales:
        lineas.extend(('', 'Señales observadas', *(f'• {senal}' for senal in dict.fromkeys(senales))))
    if resultado.limitacion:
        lineas.extend(('', f'Inspección incompleta · {resultado.limitacion}'))
    lineas.extend(('', 'HTTPS cifra la conexión. La autenticidad del sitio sigue sin confirmarse.'))
    return '\n'.join(lineas).strip()
