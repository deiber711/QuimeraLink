import json
import socket
from urllib.parse import urlsplit

import pytest

from analisis import analizar
from analyzers import brand_analyzer
from analyzers.brand_analyzer import analizar_marca, normalizar_visual
from analyzers.url_analyzer import analizar_url
from dominios import DATOS


@pytest.mark.parametrize(
    ("direccion", "marca"),
    [
        ("nequi.com.co", "Nequi"),
        ("recarga.nequi.com.co", "Nequi"),
        ("sucursalvirtual.bancolombia.com", "Bancolombia"),
        ("pse.com.co", "PSE"),
        ("registro.pse.com.co", "PSE"),
        ("login.microsoftonline.com", "Microsoft"),
    ],
)
def test_referencia_oficial_ausente(direccion, marca):
    resultado = analizar_marca(direccion)

    assert resultado.estado == "ausente"
    assert resultado.puntos_sugeridos == 0
    assert resultado.marca == marca
    assert resultado.senales == ()


@pytest.mark.parametrize(
    ("direccion", "marca"),
    [
        ("nequi-premios.example", "Nequi"),
        ("bancolombia.verificacion-datos.com", "Bancolombia"),
        ("banc0lom1bia.com", "Bancolombia"),
        ("servientega.com", "Servientrega"),
        ("servientrega.verificacion.example", "Servientrega"),
        ("movt4r-colombia.cc", "Movistar"),
        ("www.vancolmbia.com/personas", "Bancolombia"),
        ("a11express.example", "AliExpress"),
        ("airnb.example", "Airbnb"),
        ("bancolornbia.example", "Bancolombia"),
        ("p\u0430yp\u0430l.example", "PayPal"),
        ("mov1star.pagos.example", "Movistar"),
        ("falabella-ofertas.example", "Falabella"),
    ],
)
def test_suplantacion_observada(direccion, marca):
    resultado = analizar_marca(analizar_url(direccion))

    assert resultado.estado == "observado"
    assert resultado.puntos_sugeridos == 35
    assert resultado.marca == marca
    assert marca in resultado.explicacion
    assert not resultado.coincidencias


@pytest.mark.parametrize(
    "direccion",
    [
        "visa.example",
        "claro.foro.example",
        "visa-colombia.example",
        "portal.example/paypal?empresa=nequi",
        "nequi.okta.com",
    ],
)
def test_palabra_ambigua_o_mencion_fuera_del_host(direccion):
    resultado = analizar_marca(direccion)

    assert resultado.estado == "ausente"
    assert resultado.puntos_sugeridos == 0
    assert resultado.marca is None


def test_acortador_y_credenciales_son_senales_tecnicas():
    corto = analizar_url("bit.ly/3xyz")
    assert corto.es_acortador
    assert any("oculta su destino final" in senal for senal in corto.senales)
    assert not analizar_url("bit.ly.example/3xyz").es_acortador
    assert analizar_marca(corto).estado == "ausente"

    resultado = analizar("http://usuario:secreto@pse.com.co/")
    assert resultado.dominio == "pse.com.co"
    assert resultado.analisis_marca.estado == "ausente"
    assert resultado.analisis_marca.puntos_sugeridos == 0
    assert resultado.url_captura is None
    assert any("@" in senal for senal in resultado.senales)
    assert "secreto" not in repr(resultado)
    assert normalizar_visual("p@yp4l") == "paypal"


def test_extraccion_y_deteccion_sin_dns(monkeypatch):
    def sin_red(*args, **kwargs):
        pytest.fail("El análisis local intentó conectarse")

    monkeypatch.setattr(socket, "getaddrinfo", sin_red)
    monkeypatch.setattr(socket.socket, "connect", sin_red)

    dominio = analizar_url("https://app.tienda.com.co/privado")
    assert (dominio.subdominio, dominio.etiqueta_principal, dominio.sufijo) == ("app", "tienda", "com.co")
    assert dominio.dominio_registrable == "tienda.com.co"
    assert analizar_url("blog.usuario.github.io").dominio_registrable == "usuario.github.io"
    assert analizar_url("www.tienda.example").dominio_registrable == "tienda.example"

    idn = analizar_url("https://café.cl")
    assert idn.usa_punycode
    assert idn.etiqueta_principal == "xn--caf-dma"
    assert idn.dominio_unicode == "café.cl"
    assert not idn.senales

    ip = analizar_url("http://[::1]/")
    assert ip.es_ip_literal
    assert ip.dominio_registrable is None
    assert ip.etiqueta_principal is None
    assert ip.url_captura is None


@pytest.mark.parametrize("host", [
    "noticias-bancolombia.example", "foro-paypal.example", "paypal.revista.example",
    "guia-paypal.example", "noticias-google-colombia.example",
])
def test_mencion_editorial_no_suma_puntos(host):
    marca = analizar(host).analisis_marca
    assert (marca.estado, marca.puntos_sugeridos, marca.coincidencias) == ("ausente", 0, ())


@pytest.mark.parametrize(("host", "nombre"), [
    ("paypa1.documentos.example", "PayPal"), ("servientega.documentos.example", "Servientrega"),
    ("guia-servientrega.example", "Servientrega"), ("paypal-login.zoom.us", "PayPal"),
    ("nequi.premios-clientes.example", "Nequi"), ("accounts.google.com.validacion.example", "Google"),
])
def test_evidencia_adicional_conserva_la_alerta(host, nombre):
    marca = analizar(host).analisis_marca
    assert (marca.estado, marca.marca, marca.puntos_sugeridos) == ("observado", nombre, 35)


@pytest.mark.parametrize(("host", "proveedor"), [
    ("nequi.slack.com", "Slack"), ("nequi.zoom.us", "Zoom"), ("nequi.zoom.com", "Zoom"),
    ("nequi.okta.com", "Okta"),
])
def test_plataforma_identificada_sin_atribuir_el_cliente(host, proveedor):
    marca = analizar(host).analisis_marca
    assert (marca.estado, marca.puntos_sugeridos, marca.marca) == ("ausente", 0, None)
    assert [(c.nombre, c.tipo) for c in marca.coincidencias] == [(proveedor, "infraestructura")]
    assert "sin verificar" in marca.explicacion


def test_host_exacto_prevalece_sobre_la_marca_del_dominio_matriz():
    marca = analizar("signin.aws.amazon.com").analisis_marca
    assert (marca.marca, marca.coincidencias[0].tipo) == ("Amazon Web Services", "autenticacion")


def test_cliente_documentado_en_plataforma_compartida_se_limita_al_host(tmp_path, monkeypatch):
    # Catálogo de prueba para una delegación exclusiva de un cliente.
    ficha = {"nombre": "Ejemplo", "categoria": "finanzas", "dominios": {"ejemplo.test": ""},
             "autenticacion": {"equipo.okta.test": ""}}
    datos = {"marcas": [ficha], "plataformas_autenticacion": [{"sufijo": "okta.test", "proveedor": "Okta"}]}
    (tmp_path / "marcas.json").write_text(json.dumps(datos), encoding="utf-8")
    monkeypatch.setattr(brand_analyzer, "DATOS", tmp_path)
    monkeypatch.setattr(brand_analyzer, "_catalogo", brand_analyzer._catalogo.__wrapped__)
    exacto = analizar("equipo.okta.test").analisis_marca
    assert (exacto.marca, exacto.coincidencias[0].tipo) == ("Ejemplo", "autenticacion")
    for host in ("otro.okta.test", "sub.equipo.okta.test", "equipo.okta.test.example"):
        assert all(c.nombre != "Ejemplo" for c in analizar(host).coincidencias_marca)


def test_cada_relacion_tiene_fuente_y_apunta_al_acceso_exacto_de_otro_proveedor():
    marcas = json.loads((DATOS / "marcas.json").read_text(encoding="utf-8"))["marcas"]
    for cliente in marcas:
        for host, fuente in cliente.get("proveedores_autenticacion", {}).items():
            origen = urlsplit(fuente)
            assert origen.scheme == "https"
            assert analizar(origen.hostname).analisis_marca.marca == cliente["nombre"]
            acceso = analizar(host).analisis_marca
            assert acceso.coincidencias[0].tipo == "autenticacion"
            assert acceso.marca != cliente["nombre"]
