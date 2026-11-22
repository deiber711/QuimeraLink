import socket

import pytest

from analisis import analizar
from analyzers.brand_analyzer import analizar_marca, normalizar_visual
from analyzers.url_analyzer import analizar_url


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
