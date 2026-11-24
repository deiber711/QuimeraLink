from datetime import datetime, timezone
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

from analisis import analizar
from analyzers import rdap_dns as modulo
from main import main


HOST = 'acceso.example.com'
AHORA = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)


def dns(host=HOST, tipo=1, *, codigo=0, respuestas=(), soa=False):
    return {'Status': codigo, 'Question': [{'name': host + '.', 'type': tipo}], 'Answer': list(respuestas),
            'Authority': [{'name': 'example.com.', 'type': 6}] if soa else []}


def registro(dominio='example.com', **datos):
    return {'objectClassName': 'domain', 'ldhName': dominio, **datos}


def simular(monkeypatch, respuesta_dns, respuesta_rdap):
    llamadas = []

    def consultar(url, *_):
        llamadas.append(url)
        partes = urlsplit(url)
        if partes.hostname == 'dns.google':
            parametros = parse_qs(partes.query)
            assert parametros['edns_client_subnet'] == ['0.0.0.0/0']
            return respuesta_dns(parametros['name'][0].removesuffix('.'), int(parametros['type'][0]))
        assert partes.path.split('/')[-2] == 'domain' and not partes.query
        return respuesta_rdap(partes.path.split('/')[-1])

    monkeypatch.setattr(modulo, '_pedir_json', consultar)
    return llamadas


def test_analisis_local_preserva_privacidad(monkeypatch):
    def sin_red(*_):
        pytest.fail('El análisis local abrió una conexión.')

    monkeypatch.setattr(modulo, 'solicitar_publico', sin_red)
    assert analizar('https://example.com/?token=privado').dns_rdap is None
    for url in ('https://192.0.2.1', 'https://[::1]', 'equipo.local', 'cuenta.internal', 'app.home.arpa'):
        resultado = modulo.analizar_dns_rdap(url)
        assert resultado.dns.estado == resultado.rdap.estado == 'desconocido'


def test_consulta_ipv6_subdominio_y_registro_redactado(monkeypatch, capsys):
    def resolver(host, tipo):
        if tipo == 1:
            return 200, dns(host, tipo, soa=True)
        return 200, dns(host, tipo, respuestas=({'name': host + '.', 'type': 28, 'data': '2001:db8::1'},))

    llamadas = simular(monkeypatch, resolver, lambda dominio: (200, registro(dominio)))
    url = f'https://usuario:clave@{HOST}:8443/ruta-privada?token=secreto#fragmento'
    monkeypatch.setattr(sys, 'argv', ['main.py', url, '--dns-rdap'])
    assert main() == 0
    salida = capsys.readouterr().out
    assert 'IPv6 (AAAA)' in salida
    assert 'no publicó una fecha' in salida
    assert 'Reputación' in salida and 'Autenticidad' not in salida
    assert llamadas[-1] == 'https://rdap.verisign.com/com/v1/domain/example.com'
    for dato in ('usuario', 'clave', '8443', 'ruta-privada', 'secreto', 'fragmento'):
        assert all(dato not in llamada for llamada in llamadas)
        assert dato not in salida


def test_eventos_publicos_y_antiguedad():
    datos = registro(
        'EXAMPLE.COM',
        events=[{'eventAction': 'registration', 'eventDate': '2026-11-20T07:00:00-05:00'},
                {'eventAction': 'registration', 'eventDate': '2030-01-01T00:00:00Z'},
                {'eventAction': 'last changed', 'eventDate': '2026-11-23T03:00:00Z'},
                {'eventAction': 'expiration', 'eventDate': '2027-11-20T12:00:00Z'}],
        status=['active', 'active'],
        entities=[{'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Persona privada']]]},
                  {'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Operador\nPúblico'],
                                                                   ['email', {}, 'text', 'excluido@example.com']]]}],
    )
    resultado = modulo._registro_rdap('example.com', 'rdap.example.com', datos, AHORA)
    assert resultado.registro == datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    assert resultado.antiguedad_dias == 4
    assert resultado.ultimo_cambio.day == 23 and resultado.vencimiento.year == 2027
    assert resultado.registrador == 'Operador Público' and resultado.estados_registro == ('active',)
    assert 'Persona privada' not in repr(resultado) and 'excluido' not in repr(resultado)
    sin_fecha = modulo._registro_rdap('example.com', 'rdap.example.com', registro(status=['active']), AHORA)
    assert sin_fecha.registro is None and sin_fecha.antiguedad_dias is None


@pytest.mark.parametrize(('respuesta_dns', 'estado'), [
    (lambda host, tipo: dns(host, tipo, codigo=3), 'nxdomain'),
    (lambda host, tipo: dns(host, tipo, soa=True), 'sin_direccion'),
    (lambda host, tipo: dns(host, tipo, codigo=3, respuestas=(
        {'name': host + '.', 'type': 5, 'data': 'destino-ausente.example.com.'},)), 'sin_direccion'),
    (lambda host, tipo: dns(host, tipo, codigo=2), 'error'),
    (lambda host, tipo: dns(host, tipo), 'desconocido'),
    (lambda host, tipo: dns('otro.example.com', tipo), 'error'),
])
def test_diferencia_respuestas_dns_y_conserva_rdap(monkeypatch, respuesta_dns, estado):
    simular(monkeypatch, lambda host, tipo: (200, respuesta_dns(host, tipo)),
            lambda dominio: (200, registro(dominio)))
    resultado = modulo.analizar_dns_rdap(HOST)
    assert resultado.dns.estado == estado and resultado.rdap.estado == 'observado'


@pytest.mark.parametrize(('codigo', 'estado'), [(404, 'ausente'), (403, 'desconocido'), (429, 'error'), (302, 'error')])
def test_rdap_sin_registro_y_fallos_conservan_dns(monkeypatch, codigo, estado):
    respuesta = lambda host, tipo: (200, dns(host, tipo, respuestas=(
        {'name': host + '.', 'type': 1, 'data': '192.0.2.1'},)))
    llamadas = simular(monkeypatch, respuesta, lambda _: (codigo, {}))
    resultado = modulo.analizar_dns_rdap(HOST)
    assert resultado.dns.estado == 'resuelve' and resultado.rdap.estado == estado
    assert len(llamadas) == 2


def test_plataforma_propia_co_e_idna(monkeypatch):
    llamadas = simular(monkeypatch, lambda host, tipo: (200, dns(host, tipo, codigo=3)),
                       lambda dominio: (200, registro(dominio)))
    plataforma = modulo.analizar_dns_rdap('micuenta.pages.dev')
    assert plataforma.registro_de_plataforma and plataforma.rdap.dominio == 'pages.dev'
    assert 'plataforma' in '\n'.join(modulo.lineas_dns_rdap(plataforma))
    resultado = modulo.analizar_dns_rdap('www.café.com.co')
    assert resultado.rdap.dominio == 'xn--caf-dma.com.co'
    assert llamadas[-1] == 'https://rdap.registry.co/co/domain/xn--caf-dma.com.co'


def test_sufijo_maximo_servicio_https_y_registro_ajeno(monkeypatch):
    directorio = {'co': ('https://rdap.registry.co/co/',), 'com': ('https://servidor.example/',),
                  'ejemplo.com': ('https://otro.example/rdap/',), 'nohttps': ('http://sin-tls.example/',)}
    monkeypatch.setattr(modulo, '_directorio_rdap', lambda: directorio)
    assert modulo._bases_rdap('ejemplo.com') == ('https://otro.example/rdap/',)
    assert modulo._bases_rdap('miejemplo.com') == ('https://servidor.example/',)
    llamadas = simular(monkeypatch, lambda host, tipo: (200, dns(host, tipo, codigo=3)),
                       lambda _: (200, registro('dominio-ajeno.com')))
    resultado = modulo.analizar_dns_rdap('web.ejemplo.com')
    assert resultado.rdap.estado == 'error'
    resultado = modulo.analizar_dns_rdap('dominio.nohttps')
    assert resultado.rdap.estado == 'desconocido'
    assert urlsplit(llamadas[-1]).hostname == 'dns.google'


@pytest.mark.parametrize(('destino', 'estado'), [
    ('https://rdap.registry.co/com.co/domain/entidad.com.co', 'observado'),
    ('https://rdap.registry.co/com.co/domain/otra.com.co', 'error'),
    ('https://entidad.com.co/domain/entidad.com.co', 'error'),
])
def test_redireccion_rdap_limitada_al_servidor_y_dominio(monkeypatch, destino, estado):
    llamadas = []

    def pedir(url, *_):
        llamadas.append(url)
        if '/co/domain/' in url:
            return 302, destino
        return 200, registro('entidad.com.co')

    monkeypatch.setattr(modulo, '_pedir_json', pedir)
    resultado = modulo._consultar_rdap('entidad.com.co', None, AHORA)
    assert resultado.estado == estado
    assert llamadas[1:] == ([destino] if estado == 'observado' else [])
