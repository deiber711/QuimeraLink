import json
import socket
from time import monotonic, sleep

import pytest
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QCheckBox, QTextEdit

import revision
from analyzers import reputation
from escritorio import QApplication, Ventana
from informe import generar_informe
from test_inspeccion import html, simular


@pytest.fixture
def ventana(tmp_path, monkeypatch):
    monkeypatch.setattr(reputation, "_base_local", lambda: tmp_path / "listas.sqlite3")
    monkeypatch.setattr(revision, "_ultimo_intento", {})
    def sin_red(_):
        raise TimeoutError
    monkeypatch.setattr(reputation, "_descargar", sin_red)
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    ventana = Ventana(QSettings(str(tmp_path / "ajustes.ini"), QSettings.Format.IniFormat))
    ventana.show()
    yield ventana
    ventana.close()
    app.processEvents()


def analizar(ventana, enlace):
    ventana.entrada.setText(enlace)
    ventana.analizar.click()
    limite = monotonic() + 10
    while ventana.ocupado and monotonic() < limite:
        QApplication.processEvents()
        sleep(0.01)
    assert not ventana.ocupado


def test_un_click_dictamen_detalle_y_exportacion(ventana, monkeypatch, tmp_path):
    def captura_inesperada(*_):
        pytest.fail("La captura está desactivada al inicio.")
    monkeypatch.setattr("escritorio.imagen", captura_inesperada)
    with simular(html(b"<form><input type=password></form>")):
        analizar(ventana, "https://nequi-premios.example/ruta?token=privado")
    rev = ventana.revision
    assert rev.informe == generar_informe(rev.resultado, rev.inspeccion)
    assert rev.informe["inspeccion_solicitada"] and rev.informe["dns_rdap_solicitado"]
    assert ventana.nivel.text() == "Este enlace parece sospechoso"
    assert ventana.puntos.valor == 55
    assert "contraseña" in ventana.motivos.text()
    assert "listas" in ventana.pendiente.text()
    assert "RDAP" not in ventana.pendiente.text()
    contenido = []
    def leer_detalle():
        dialogo = QApplication.activeModalWidget()
        contenido.append(dialogo.findChild(QTextEdit).toPlainText())
        dialogo.accept()
    QTimer.singleShot(0, leer_detalle)
    ventana.detalle.click()
    assert "PhishTank" in contenido[0] and "privado" not in contenido[0]
    ruta = tmp_path / "dictamen.json"
    monkeypatch.setattr("escritorio.QFileDialog.getSaveFileName", lambda *_: (str(ruta), ""))
    ventana.guardar()
    assert json.loads(ruta.read_text(encoding="utf-8")) == rev.informe
    ventana.entrada.setText("otro.example")
    assert ventana.revision is None and ventana.panel.isHidden()


def test_entrada_invalida_y_visita_bloqueada(ventana):
    analizar(ventana, "https://")
    assert ventana.revision is None and ventana.estado.text()
    with simular() as solicitudes:
        analizar(ventana, "https://usuario:clave@ejemplo.test")
        solicitudes.assert_not_called()
    assert ventana.revision.inspeccion.limitacion
    assert ventana.puntos.valor == 0 and ventana.pendiente.text()


def test_captura_configurable_y_fallo_independiente(ventana, monkeypatch):
    def activar():
        dialogo = QApplication.activeModalWidget()
        dialogo.findChild(QCheckBox).click()
        dialogo.accept()
    QTimer.singleShot(0, activar)
    ventana.config.click()
    llamadas = []
    def fallar(url):
        llamadas.append(url)
        raise OSError
    monkeypatch.setattr("escritorio.imagen", fallar)
    with simular(html(b"<title>Inicio</title>")):
        analizar(ventana, "https://sitio.example")
    assert llamadas == ["https://sitio.example"]
    assert ventana.panel.isVisible()
    assert "captura opcional" in ventana.nota_foto.text()


def test_listas_automaticas_y_riesgo_con_pagina_inaccesible(ventana, monkeypatch):
    llamadas = []
    def descargar(fuente):
        llamadas.append(fuente)
        if fuente == reputation.PHISHTANK:
            raise TimeoutError
        fecha = reputation._ahora()
        return "portal.example", fecha, fecha
    monkeypatch.setattr(reputation, "_descargar", descargar)
    for _ in range(2):
        with simular(socket.gaierror(socket.EAI_NONAME, "DNS simulado")):
            analizar(ventana, "https://portal.example")
        assert ventana.puntos.valor == 70
        assert "probablemente no existe" in ventana.motivos.text()
    assert llamadas == list(reputation.FUENTES)


def test_registro_denuncias_y_direccion_se_combinan_en_el_mismo_click(ventana, monkeypatch):
    from analyzers.rdap_dns import ResultadoDNS, ResultadoDominio, ResultadoRDAP

    consultas = []
    def resolver(host, puerto, *, type):
        consultas.append(host)
        raise socket.gaierror(socket.EAI_AGAIN, "Prueba de fallo temporal")

    def registro(enlace):
        host = "nequi-premios.com"
        return ResultadoDominio(reputation._ahora(), ResultadoDNS(host, "resuelve", "Confirmado"),
                                ResultadoRDAP(host, "observado", antiguedad_dias=3))

    monkeypatch.setattr("red.socket.getaddrinfo", resolver)
    monkeypatch.setattr(revision, "analizar_dns_rdap", registro)
    with simular(html(b"<form><input type=password></form>")):
        analizar(ventana, "https://nequi-premios.com")
    assert consultas == ["nequi-premios.com."]
    assert ventana.puntos.valor == 65
    assert "menos de un mes" in ventana.motivos.text()


def test_resultado_visible_en_ventana_compacta(ventana):
    ventana.resize(530, 460)
    with simular(html(b"<title>Inicio</title>")):
        analizar(ventana, "https://portal.example")
    QApplication.processEvents()
    assert ventana.scroll.verticalScrollBar().value() > 0
    assert ventana.scroll.horizontalScrollBar().maximum() == 0
