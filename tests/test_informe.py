import json
import sqlite3
import sys
from dataclasses import replace
from datetime import timedelta

import pytest

from analisis import analizar
from analyzers import reputation as rep
from analyzers.rdap_dns import ResultadoDNS, ResultadoDominio, ResultadoRDAP
from informe import generar_informe
from inspeccion import inspeccionar
from main import main
from test_inspeccion import html, redireccion, simular


@pytest.fixture(autouse=True)
def cache_local(monkeypatch, tmp_path):
    monkeypatch.setattr(rep, "_base_local", lambda: tmp_path / "reputacion.sqlite3")


def cargar(host, *, horas=0):
    ahora = rep._ahora()
    fecha = ahora - timedelta(hours=horas)
    csv = "phish_id,url,verified,verification_time,online\n1,https://" + host + "/,yes,,yes\n"
    rep._guardar(rep.PHISHTANK, csv, fecha, ahora)
    rep._guardar(rep.CERT_POLSKA, host, fecha, ahora)


def test_json_local_inconcluso_y_privado(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "argv", ["main.py", "--json", "https://ejemplo.test/ruta?token=secreto#ancla"])
    assert main() == 0
    salida = capsys.readouterr().out
    informe = json.loads(salida)
    assert informe["nivel"] == "Inconcluso" and informe["puntos"] == 0
    assert len(informe["limitaciones"]) == 2
    assert not any(token in salida for token in ("/ruta", "secreto", "ancla"))
    assert not list(tmp_path.iterdir())


def test_cobertura_por_fuente_y_copia_danada():
    cargar("alerta.test")
    informe = generar_informe(analizar("ejemplo.test"))
    assert informe["nivel"] == "Sin indicadores detectados" and not informe["limitaciones"]
    with sqlite3.connect(rep._base_local()) as db:
        db.execute("UPDATE listas SET fecha_lista=NULL WHERE fuente='PhishTank'")
    informe = generar_informe(analizar("alerta.test"))
    assert informe["puntos"] == 70 and informe["cobertura"] == "parcial"
    assert [r["estado"] for r in informe["reputacion"]] == ["error", "observado"]


def test_copia_vencida():
    cargar("alerta.test", horas=25)
    informe = generar_informe(analizar("alerta.test"))
    assert informe["puntos"] == 0 and informe["cobertura"] == "parcial"
    assert all(e["estado"] == "observado" for e in informe["reputacion"])


def test_redireccion_repeticion_de_senales_y_limite():
    cargar("nequi-premios.example")
    formulario = b'<form action="http://otro.test/"><input type=password></form>'
    with simular(redireccion("https://nequi-premios.example"), html(formulario * 2)):
        inspeccion = inspeccionar("https://inicio.test")
    informe = generar_informe(analizar("inicio.test"), inspeccion)
    assert informe["puntos"] == 100 and informe["nivel"] == "Alto riesgo"
    assert {r["id"]: r["puntos"] for r in informe["reglas"]} == {
        "marca": 35, "reputacion": 70, "credenciales": 20,
        "formulario_externo": 20, "http_sensible": 10,
    }
    assert len(informe["reglas"]) == 5


def test_no_asocia_credenciales_de_otro_sitio_a_la_marca_inicial():
    with simular(redireccion("https://otro.test"), html(b'<form><input type=password></form>')):
        inspeccion = inspeccionar("https://nequi-premios.example")
    informe = generar_informe(analizar("nequi-premios.example"), inspeccion)
    assert [r["id"] for r in informe["reglas"]] == ["marca"]


@pytest.mark.parametrize("edad,plataforma,puntos", [(29, False, 10), (30, False, 0), (2, True, 0)])
def test_registro_reciente_solo_del_dominio_evaluado(edad, plataforma, puntos):
    local = analizar("ejemplo.test")
    datos = ResultadoDominio(rep._ahora(), ResultadoDNS(local.dominio, "resuelve", ""),
                             ResultadoRDAP(local.dominio, "observado", antiguedad_dias=edad), plataforma)
    informe = generar_informe(replace(local, dns_rdap=datos))
    assert informe["puntos"] == puntos


def test_proveedor_documentado_sin_puntos_por_formulario_externo():
    with simular(html(b'<form action="https://secure.login.gov/"><input type=password></form>')):
        inspeccion = inspeccionar("https://www.ssa.gov")
    informe = generar_informe(analizar("www.ssa.gov"), inspeccion)
    assert "formulario_externo" not in [r["id"] for r in informe["reglas"]]
