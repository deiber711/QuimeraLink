from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO
import sqlite3
import sys
from urllib.error import HTTPError
from urllib.request import Request
from unittest.mock import Mock

import pytest

from analisis import analizar
from analyzers import reputation as rep
from inspeccion import describir, inspeccionar
from main import main
from test_inspeccion import redireccion, respuesta, simular


AHORA = datetime(2026, 11, 21, 20, 0, tzinfo=timezone.utc)
LISTA = AHORA - timedelta(minutes=5)
URL = "https://alerta.ejemplo.test/Acceso?token=privado&x=%2F#paso"


def csv_phishtank(url, *, verified="yes", online="yes"):
    return ("phish_id,url,verified,verification_time,online\n"
            f"123,{url},{verified},2026-11-20T23:00:00+00:00,{online}\n")


@pytest.fixture(autouse=True)
def cache_local(tmp_path, monkeypatch):
    ruta = tmp_path / "reputacion.sqlite3"
    monkeypatch.setattr(rep, "_base_local", lambda: ruta)
    monkeypatch.setattr(rep, "_ahora", lambda: AHORA)
    return ruta


def guardar(fuente, texto, fecha=LISTA):
    return rep._guardar(fuente, texto, fecha, AHORA)


def test_url_exacta_fecha_y_privacidad(monkeypatch):
    guardar(rep.PHISHTANK, csv_phishtank(URL))

    def sin_red(*_):
        pytest.fail("Un análisis local no abre conexiones.")

    monkeypatch.setattr("socket.getaddrinfo", sin_red)
    resultado = analizar("HTTPS://ALERTA.EJEMPLO.TEST:443/Acceso?token=privado&x=%2F#paso").reputacion
    evidencia = resultado.evidencias[0]
    assert evidencia.estado == "observado"
    assert evidencia.fuente.regla == "url_exacta"
    assert evidencia.fecha_consulta == AHORA
    assert evidencia.fecha_lista == LISTA
    assert evidencia.fecha_indicador == datetime(2026, 11, 20, 23, 0, tzinfo=timezone.utc)
    assert resultado.puntos_sugeridos == 70
    informe = "\n".join(rep.lineas_reputacion(resultado))
    assert "2026-11-21 19:55 UTC" in informe
    for privado in ("/Acceso", "privado", "#paso"):
        assert privado not in informe
    for distinta in (URL.replace("https://", "http://"), URL.replace("/Acceso", "/acceso"),
                     URL.replace("#paso", "#otro"), URL.replace("privado", "otro"),
                     URL.replace("token=privado&x=%2F", "x=%2F&token=privado"),
                     URL.replace(".test/", ".test:8080/"), "https://alerta.ejemplo.test/"):
        assert rep.analizar_reputacion(distinta).evidencias[0].estado == "ausente"


def test_dominio_y_subdominio_sin_ampliar_a_padres_o_vecinos():
    guardar(rep.CERT_POLSKA, "ALERTA.CAFÉ.TEST.\n")
    for host in ("alerta.café.test", "a.b.alerta.xn--caf-dma.test"):
        evidencia = rep.analizar_reputacion(f"https://{host}:8080/cualquier/ruta").evidencias[1]
        assert evidencia.estado == "observado"
        assert "alerta.xn--caf-dma.test" in evidencia.explicacion
    for host in ("café.test", "noalerta.café.test", "alerta.café.test.ejemplo.test", "vecino.café.test"):
        assert rep.analizar_reputacion(host).evidencias[1].estado == "ausente"
    assert rep.analizar_reputacion("https://192.0.2.1").evidencias[1].estado == "desconocido"


def test_coincidencia_fuerte_unica_y_marca_conservada():
    url = "https://paypa1.example/"
    guardar(rep.PHISHTANK, csv_phishtank(url))
    guardar(rep.CERT_POLSKA, "paypa1.example\n")
    resultado = analizar(url)
    assert all(e.estado == "observado" for e in resultado.reputacion.evidencias)
    assert resultado.reputacion.puntos_sugeridos == 70
    assert resultado.analisis_marca.puntos_sugeridos == 35
    assert any("PayPal" in senal for senal in resultado.senales)


def test_copia_ausente_corrupta_o_vencida(cache_local):
    assert all(e.estado == "desconocido" for e in rep.analizar_reputacion(URL).evidencias)
    guardar(rep.PHISHTANK, csv_phishtank(URL), AHORA - timedelta(hours=25))
    historico = rep.analizar_reputacion(URL)
    assert historico.evidencias[0].estado == "observado"
    assert not historico.evidencias[0].vigente
    assert historico.puntos_sugeridos == 0
    assert "desactualizada" in historico.evidencias[0].explicacion
    assert rep.analizar_reputacion("ejemplo.test").evidencias[0].estado == "desconocido"
    cache_local.write_bytes(b"archivo corrupto")
    assert all(e.estado == "error" for e in rep.analizar_reputacion(URL).evidencias)


def test_actualizacion_independiente_conserva_la_copia_anterior(monkeypatch):
    guardar(rep.PHISHTANK, csv_phishtank(URL))
    guardar(rep.CERT_POLSKA, "retirado.example\n")

    def descargar(fuente):
        if fuente == rep.PHISHTANK:
            raise HTTPError(fuente.descarga, 429, "Límite", None, None)
        return "alerta.ejemplo.test\n", AHORA, AHORA

    monkeypatch.setattr(rep, "_descargar", descargar)
    phishtank, cert = rep.actualizar_listas()
    assert "límite" in phishtank.error
    assert cert.cantidad == 1
    resultado = rep.analizar_reputacion(URL)
    assert [e.estado for e in resultado.evidencias] == ["observado", "observado"]
    assert resultado.evidencias[0].fecha_lista == LISTA
    assert rep.analizar_reputacion("retirado.example").evidencias[1].estado == "ausente"
    with pytest.raises(ValueError):
        guardar(rep.CERT_POLSKA, "<html>error</html>", AHORA)
    guardar(rep.CERT_POLSKA, "retirado.example\n")
    assert rep.analizar_reputacion(URL).evidencias[1].estado == "observado"


def test_phishtank_omite_registros_inactivos_y_credenciales(cache_local):
    datos = csv_phishtank(URL) + csv_phishtank("https://otra.example/", verified="no").split("\n", 1)[1]
    datos += csv_phishtank("https://caida.example/", online="no").split("\n", 1)[1]
    assert guardar(rep.PHISHTANK, datos) == 1
    for url in ("otra.example", "caida.example"):
        assert rep.analizar_reputacion(url).evidencias[0].estado == "ausente"
    url_con_credenciales = URL.replace("https://", "https://usuario:clave@")
    assert rep.analizar_reputacion(url_con_credenciales).evidencias[0].estado == "desconocido"
    with closing(sqlite3.connect(cache_local)) as conexion:
        (valor,) = conexion.execute("SELECT valor FROM indicadores").fetchone()
    assert valor == rep._huella(URL)


def test_descarga_truncada_y_redireccion_restringida(monkeypatch):
    clase = rep._RedireccionLista()
    solicitud = Request(rep.PHISHTANK.descarga)
    cdn = "https://cdn.phishtank.com/datadumps/verified_online.csv?firma=prueba"
    assert clase.redirect_request(solicitud, None, 302, "", {}, cdn).full_url == cdn
    for otro in ("http://", "https://externo.example/", "https://cdn.phishtank.com@externo.example/"):
        assert clase.redirect_request(solicitud, None, 302, "", {}, otro) is None
    assert clase.redirect_request(Request(cdn), None, 302, "", {}, cdn) is None

    respuesta_corta = BytesIO(b"alerta.example\n")
    respuesta_corta.status = 200
    respuesta_corta.headers = Message()
    respuesta_corta.headers["Content-Length"] = "80"
    monkeypatch.setattr(rep, "build_opener", Mock(return_value=Mock(open=Mock(return_value=respuesta_corta))))
    with pytest.raises(ValueError, match="incompleta"):
        rep._descargar(rep.CERT_POLSKA)


def test_consola_y_redireccion_muestran_evidencia_redactada(monkeypatch, capsys):
    guardar(rep.PHISHTANK, csv_phishtank(URL))
    monkeypatch.setattr(sys, "argv", ["main.py", URL])
    assert main() == 0
    salida = capsys.readouterr().out
    assert "Alto riesgo por reputación" in salida
    assert "no confirma la legitimidad" in salida
    assert "privado" not in salida

    with simular(redireccion(URL), respuesta(404)):
        informe = describir(inspeccionar("https://salto.example/"))
    assert "Destino anunciado · alerta.ejemplo.test · PhishTank" in informe
    assert "Coincidencia exacta" in informe
    assert "privado" not in informe
