from contextlib import contextmanager, redirect_stdout
from http.client import HTTPResponse
from io import BytesIO, StringIO
import socket
import ssl
from threading import Event
import unittest
from unittest.mock import MagicMock, Mock, patch

from inspeccion import Formulario, describir, inspeccionar
from main import main


def respuesta(estado=200, cabeceras=(), cuerpo=b''):
    datos = f'HTTP/1.1 {estado} Test\r\n'.encode('ascii')
    datos += b''.join(f'{k}: {v}\r\n'.encode('ascii') for k, v in cabeceras) + b'\r\n' + cuerpo
    resultado = HTTPResponse(Mock(makefile=Mock(return_value=BytesIO(datos))))
    resultado.begin()
    return resultado


def html(cuerpo, *, longitud=None):
    return respuesta(cabeceras=(('Content-Type', 'text/html; charset=utf-8'),
                                ('Content-Length', len(cuerpo) if longitud is None else longitud)),
                     cuerpo=cuerpo)


def redireccion(destino):
    return respuesta(302, (('Location', destino),))


@contextmanager
def simular(*respuestas):
    @contextmanager
    def solicitar(*_):
        resultado = next(secuencia)
        if isinstance(resultado, Exception):
            raise resultado
        with resultado:
            yield resultado

    secuencia = iter(respuestas)
    with patch('inspeccion._solicitar', side_effect=solicitar) as mock:
        yield mock


class InspeccionTests(unittest.TestCase):
    def test_datos_financieros_y_destinos_por_boton_sin_contactarlos(self):
        pagina = b'''
            <base href="https://pagos.example/">
            <input form="pago" autocomplete="section-order billing cc-number" value="privado">
            <form id="pago" action="cobrar?token=oculto">
              <input autocomplete="current-password">
              <button formaction="">Continuar</button>
              <button disabled formaction="//inactivo.example">Otro</button>
            </form>
            <input type="image" form="pago" formaction="http://procesador.example:8080/reserva">
        '''
        with simular(html(pagina)) as pedir:
            resultado = inspeccionar('https://tienda.example/')
        pedir.assert_called_once()
        self.assertEqual(resultado.formularios, (Formulario('https://pagos.example', True, True,
                         ('https://tienda.example', 'http://procesador.example:8080')),))
        informe = describir(resultado)
        self.assertIn('datos financieros apunta a una dirección HTTP', informe)
        for privado in ('token', 'oculto', 'privado', 'reserva', 'inactivo'):
            self.assertNotIn(privado, informe)

    def test_etiquetas_asociadas_y_formularios_sin_senales(self):
        pagina = '''
            <form id="p"><input id="campo"></form>
            <label for="campo">Número de <b>tarjeta</b></label>
            <form><label>IBAN <input name="campo"></label></form>
            <form><input name="accountNumber"></form>
            <form><input type="hidden" name="cvv"><input disabled type="password">
              <label for="ausente">Contraseña</label><input placeholder="Correo"></form>
        '''
        with simular(html(pagina.encode())):
            resultado = inspeccionar('https://tienda.example/')
        self.assertEqual([f.datos_financieros for f in resultado.formularios], [True, True, True, False])
        self.assertFalse(any(f.tiene_password for f in resultado.formularios))
        self.assertNotIn('Señales observadas', describir(resultado))

    def test_relacion_documentada_distingue_proveedor_y_cliente(self):
        titulo = b'<title>Social Security Administration</title><input type="password">'
        for origen, destino, relacion, alerta in (
            ('https://www.ssa.gov', 'https://secure.login.gov', True, False),
            ('https://otro.example', 'https://secure.login.gov', False, False),
            ('https://www.ssa.gov', 'https://otro.secure.login.gov', False, True),
            ('https://www.ssa.gov', 'https://secure.login.gov.example', False, True),
            ('https://www.ssa.gov', 'http://secure.login.gov', False, True),
            ('https://www.ssa.gov', 'https://secure.login.gov:80', False, True),
        ):
            with self.subTest(origen=origen, destino=destino), simular(redireccion(destino), html(titulo)):
                resultado = inspeccionar(origen)
                informe = describir(resultado)
                self.assertEqual('tiene registrado' in informe, relacion)
                self.assertEqual(bool(resultado.senales_contenido), alerta)
                self.assertIn('Destino final', informe)
                if destino.startswith('http:'):
                    self.assertIn('de HTTPS a HTTP', informe)

    def test_proveedor_conocido_no_exime_la_cadena_ni_el_formulario(self):
        with simular(redireccion('https://accounts.google.com'), html(
            b'<title>Inicia sesion en OpenAI</title><form action="https://otro.example">'
            b'<input type="password"></form>'
        )):
            resultado = inspeccionar('https://auth.openai.com')
        self.assertFalse(resultado.senales_contenido)
        self.assertIn('OpenAI tiene registrado a accounts.google.com', describir(resultado))
        self.assertIn('contraseña apunta a otro origen', describir(resultado))

        with simular(redireccion('https://accounts.google.com'), redireccion('https://nequi-premios.example'),
                     html(b'<title>Inicio</title>')):
            informe = describir(inspeccionar('https://auth.openai.com'))
        self.assertIn('Destino anunciado · nequi-premios.example', informe)
        self.assertIn('Nequi', informe)

    def test_mencion_editorial_y_opcion_de_acceso_no_suplantan_al_proveedor(self):
        enlace = b'<a href="https://accounts.google.com/o/oauth2/v2/auth">Continuar con <b>Google</b></a>'
        pagina = b'<title>Noticias de Bancolombia</title><p>Ingresa tu clave</p><input type="password">'
        with simular(html(pagina + enlace)):
            self.assertFalse(inspeccionar('https://revista.example').senales_contenido)
        for contenido in (pagina + enlace + b'<p>Ingresa tu clave de Google</p>',
                          pagina + enlace.replace(b'accounts.google.com/', b'accounts.google.com.example/')):
            with self.subTest(contenido=contenido), simular(html(contenido)):
                self.assertTrue(any('Google' in s for s in inspeccionar('https://revista.example').senales_contenido))

    def test_el_nombre_del_tenant_no_establece_una_relacion_documentada(self):
        pagina = b'<title>Acceso a Bancolombia</title><input type="password">'
        with simular(html(pagina)):
            self.assertTrue(inspeccionar('https://bancolombia.okta.com').senales_contenido)

    def test_contrasta_marca_y_solicitud_de_datos_con_el_dominio(self):
        factura = b'''<title>Consulta tu factura</title>
            <p>Ingresa tu n&uacute;mero de l&iacute;nea Movistar</p>
            <label for="numero">N&uacute;mero de celular</label>
            <input id="numero" type="number" value="dato-de-prueba">
        '''
        with simular(html(factura)) as pedir:
            resultado = inspeccionar('https://facturas.example')
        pedir.assert_called_once()
        self.assertIn('Movistar y solicita datos', describir(resultado))
        self.assertNotIn('dato-de-prueba', describir(resultado))

        with simular(html(factura)):
            resultado = inspeccionar('https://www.movistar.co')
        self.assertFalse(resultado.senales_contenido)

    def test_mencion_de_marca_sin_solicitud_visible_no_genera_alerta(self):
        casos = (
            b'<title>Movistar</title><input type="search">',
            b'<title>Movistar</title><input type="password" disabled>',
            b'<script>Ingresa tu numero Movistar</script><input type="tel">',
            b'<template><label>Celular</label><input type="tel"></template><p>Ingresa tu numero Movistar</p>',
        )
        for pagina in casos:
            with self.subTest(pagina=pagina), simular(html(pagina)):
                self.assertFalse(inspeccionar('https://noticias.example').senales_contenido)

    def test_recorrido_y_formularios_sin_exponer_rutas(self):
        pagina = b'''<title>
            P&aacute;gina &amp; acceso &#27; &#8238;</title>
            <base href="https://cuentas.example/privada?clave=oculta">
            <input form="autenticar" type="password" value="secreto">
            <form id="autenticar" action="recibir"></form>
            <form><input type="password"></form>
            <form action="mailto:datos@example.org"></form>
            <form action="http://formularios.example/"><input type="password"></form>
            <template><form action="https://plantilla.example/"></form></template>
            <textarea><form action="https://texto.example/"></form></textarea>
        '''
        with simular(redireccion('/sesion'), redireccion('https://otro.example/inicio'), html(pagina)) as pedir:
            resultado = inspeccionar('https://sitio.example/ruta-privada?token=prueba#local')

        self.assertEqual([llamada.args[0] for llamada in pedir.call_args_list], [
            'https://sitio.example/ruta-privada?token=prueba', 'https://sitio.example/sesion',
            'https://otro.example/inicio'])
        self.assertEqual(resultado.titulo, 'Página & acceso')
        self.assertEqual(resultado.formularios, (Formulario('https://cuentas.example', True),
                                                  Formulario('https://otro.example', True),
                                                  Formulario(None, False),
                                                  Formulario('http://formularios.example', True)))
        self.assertIsNone(resultado.limitacion)
        informe = describir(resultado)
        for evidencia in ('HTTP 302', 'Destino final · https://otro.example', 'Dominio registrable final · otro.example',
                          'cambia de dominio registrable · sitio.example → otro.example', 'otro origen', 'dirección HTTP'):
            self.assertIn(evidencia, informe)
        for oculto in ('token', 'privada', 'secreto', 'clave', '\x1b', '\u202e'):
            self.assertNotIn(oculto, informe)

    def test_distingue_subdominios_y_cambios_de_dominio_registrable(self):
        with simular(redireccion('https://login.entidad.com.co'), redireccion('http://cuentas.entidad.com.co'),
                     redireccion('https://panel.usuario.github.io'), redireccion('https://otro.github.io'),
                     html(b'<title>Fin</title>')):
            informe = describir(inspeccionar('https://www.entidad.com.co'))

        recorrido = [linea for linea in informe.splitlines() if linea.startswith('• http')]
        self.assertEqual(recorrido, [
            '• https://www.entidad.com.co · HTTP 302',
            '• https://login.entidad.com.co · HTTP 302',
            '• http://cuentas.entidad.com.co · HTTP 302',
            '• https://panel.usuario.github.io · HTTP 302',
            '• https://otro.github.io · HTTP 200',
        ])
        self.assertEqual(informe.count('cambia de dominio registrable'), 2)
        self.assertIn('entidad.com.co → usuario.github.io', informe)
        self.assertIn('usuario.github.io → otro.github.io', informe)
        self.assertEqual(informe.count('pasa de HTTPS a HTTP'), 1)
        self.assertIn('https://login.entidad.com.co → http://cuentas.entidad.com.co', informe)
        self.assertIn('Destino final · https://otro.github.io', informe)
        self.assertIn('Dominio registrable final · otro.github.io', informe)

    def test_normaliza_el_dominio_internacional_anunciado(self):
        with simular(redireccion('https://login.fa%C3%9F.de'), html(b'<title>Fin</title>')):
            informe = describir(inspeccionar('https://www.faß.de'))

        self.assertIn('Destino final · https://login.xn--fa-hia.de', informe)
        self.assertIn('Dominio registrable final · xn--fa-hia.de', informe)
        self.assertNotIn('Señales observadas', informe)

    def test_detecta_ciclos_y_permite_hasta_cinco_redirecciones(self):
        with simular(redireccion('/segundo'), redireccion('https://sitio.example:443/#ancla')) as pedir:
            resultado = inspeccionar('https://sitio.example')
        self.assertEqual(pedir.call_count, 2)
        self.assertIn('ciclo', resultado.limitacion)

        for pagina_final in (True, False):
            final = html(b'<title>Fin</title>') if pagina_final else redireccion('http://otro.example/6')
            with simular(*(redireccion(f'/{i}') for i in range(1, 6)), final) as pedir:
                resultado = inspeccionar('https://sitio.example')
            self.assertEqual(pedir.call_count, 6)
            self.assertEqual(resultado.limitacion is None, pagina_final)
            if not pagina_final:
                informe = describir(resultado)
                self.assertIn('Destino anunciado por la última redirección · http://otro.example', informe)
                self.assertIn('pasa de HTTPS a HTTP', informe)

    def test_preserva_status_si_no_hay_html_o_el_cuerpo_queda_incompleto(self):
        with simular(respuesta(cabeceras=(('Content-Type', 'application/json'),))):
            resultado = inspeccionar('https://sitio.example')
        self.assertEqual(resultado.pasos[-1].estado, 200)
        self.assertIsNone(resultado.formularios)
        self.assertIn('no contiene HTML', resultado.limitacion)

        cuerpo = b'<title>Inicio</title>' + b'x' * 100
        with patch('inspeccion.MAX_HTML', 24), simular(html(cuerpo)):
            resultado = inspeccionar('https://sitio.example')
        self.assertEqual(resultado.titulo, 'Inicio')
        self.assertIn('límite', resultado.limitacion)

        with simular(html(cuerpo, longitud=len(cuerpo) + 100)):
            resultado = inspeccionar('https://sitio.example')
        self.assertEqual(resultado.titulo, 'Inicio')
        self.assertIn('antes de completar', resultado.limitacion)

    def test_conserva_el_recorrido_tras_error_de_red_o_destino_invalido(self):
        with simular(redireccion('http://otro.example'), TimeoutError()) as pedir:
            resultado = inspeccionar('https://sitio.example')
        self.assertEqual(pedir.call_count, 2)
        self.assertEqual([paso.estado for paso in resultado.pasos], [302, None])
        self.assertIn('tiempo', resultado.limitacion)
        informe = describir(resultado)
        self.assertIn('pasa de HTTPS a HTTP', informe)
        self.assertIn('Último origen que respondió · https://sitio.example', informe)
        self.assertNotIn('Destino final', informe)

        for destino in ('http://127.0.0.1/', 'http://user@host.example/', 'ftp://host.example/'):
            with self.subTest(destino=destino), simular(redireccion(destino)) as pedir:
                resultado = inspeccionar('https://sitio.example')
                self.assertIsNotNone(resultado.limitacion)
                self.assertEqual(pedir.call_count, 1)

    def test_muestra_el_salto_bloqueado_sin_exponer_credenciales_ni_ruta(self):
        with simular(redireccion('http://usuario:secreto@otro.example/privada?token=oculto')) as pedir:
            informe = describir(inspeccionar('https://sitio.example'))

        pedir.assert_called_once()
        self.assertIn('Destino anunciado por la última redirección · http://otro.example', informe)
        self.assertIn('pasa de HTTPS a HTTP', informe)
        self.assertIn('cambia de dominio registrable · sitio.example → otro.example', informe)
        self.assertNotIn('Destino final', informe)
        for oculto in ('usuario', 'secreto', 'privada', 'token', 'oculto'):
            self.assertNotIn(oculto, informe)

    def test_dns_bloquea_redireccion_si_el_destino_tambien_resuelve_a_una_ip_privada(self):
        conexion_inicial = MagicMock()
        conexion_inicial.makefile.return_value = BytesIO(b'HTTP/1.1 302 Found\r\n'
                                                        b'Location: http://otro.example\r\nContent-Length: 0\r\n\r\n')
        publica = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 80))
        privada = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::ffff:127.0.0.1', 80, 0, 0))
        with (patch('socket.getaddrinfo', side_effect=[[publica], [publica, privada]]) as resolver,
              patch('socket.socket', return_value=conexion_inicial) as conectar):
            conexion_inicial.__enter__.return_value = conexion_inicial
            resultado = inspeccionar('http://sitio.example/ruta')

        self.assertEqual([llamada.args[0] for llamada in resolver.call_args_list], ['sitio.example', 'otro.example'])
        conectar.assert_called_once()
        conexion_inicial.connect.assert_called_once_with(('93.184.215.14', 80))
        self.assertIn(b'GET /ruta HTTP/1.1', conexion_inicial.sendall.call_args.args[0])
        self.assertEqual([paso.estado for paso in resultado.pasos], [302, None])
        self.assertIn('destino que no es público', resultado.limitacion)

    def test_tls_verifica_el_nombre_original_y_reporta_certificado_rechazado(self):
        conexion = MagicMock()
        conexion.__enter__.return_value = conexion
        tls = Mock(wrap_socket=Mock(side_effect=ssl.SSLCertVerificationError()))
        with (patch('inspeccion.ssl.create_default_context', return_value=tls),
              patch('inspeccion.resolver_publico', return_value='93.184.215.14'),
              patch('socket.socket', return_value=conexion)):
            resultado = inspeccionar('https://sitio.example')

        tls.wrap_socket.assert_called_once_with(conexion, server_hostname='sitio.example')
        conexion.connect.assert_called_once_with(('93.184.215.14', 443))
        conexion.sendall.assert_not_called()
        self.assertIn('TLS', resultado.limitacion)

    def test_retorna_al_superar_el_plazo_dns(self):
        termino = Event()
        liberar_dns = Event()

        def resolver(*_, **__):
            liberar_dns.wait(5)
            termino.set()
            raise socket.gaierror

        tls = ssl.create_default_context()
        try:
            with (patch('inspeccion.PLAZO', 0.1), patch('inspeccion.ssl.create_default_context', return_value=tls),
                  patch('socket.getaddrinfo', side_effect=resolver), patch('socket.socket') as conectar):
                resultado = inspeccionar('https://sitio.example')
                self.assertFalse(termino.is_set())
                conectar.assert_not_called()
        finally:
            liberar_dns.set()
        self.assertIn('tiempo', resultado.limitacion)

    def test_cli_solo_accede_a_la_red_con_opcion_explicita(self):
        url = 'http://sitio.example'
        salida = StringIO()
        with (patch('sys.argv', ['main.py', url]), patch('main.inspeccionar') as pedir, redirect_stdout(salida)):
            self.assertEqual(main(), 0)
            pedir.assert_not_called()
        with (patch('sys.argv', ['main.py', url, '--inspeccionar']), redirect_stdout(salida),
              simular(respuesta(403))):
            self.assertEqual(main(), 1)
        self.assertIn('HTTP 403', salida.getvalue())


if __name__ == '__main__':
    unittest.main()
