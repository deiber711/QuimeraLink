from datetime import date
import json
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from analisis import analizar
from dominios import DATOS, dominio_registrable, normalizar_dominio
from marcas import CoincidenciaMarca


class MarcasTests(unittest.TestCase):
    def test_alias_del_catalogo_con_menciones_y_solicitudes(self):
        datos = json.loads((DATOS / "marcas.json").read_text(encoding="utf-8"))
        for ficha in datos["marcas"]:
            for alias in [*ficha.get("distintivos", []), *ficha.get("contextuales", [])]:
                for host in (f"noticias-{alias}.example", f"{alias}.revista.example", f"{alias}.okta.com"):
                    with self.subTest(host=host, marca=ficha["nombre"]):
                        self.assertEqual(analizar(host).analisis_marca.puntos_sugeridos, 0)
                host = f"{alias}-verificacion.example"
                with self.subTest(host=host, marca=ficha["nombre"]):
                    marca = analizar(host).analisis_marca
                    self.assertEqual(marca.puntos_sugeridos, 35)
                    self.assertTrue(any(ficha["nombre"] in senal for senal in marca.senales))

    def test_referencias_del_catalogo(self):
        datos = json.loads((DATOS / "marcas.json").read_text(encoding="utf-8"))
        date.fromisoformat(datos["fecha_revision"])
        marcas = datos["marcas"]
        nombres = {ficha["nombre"] for ficha in marcas}
        self.assertEqual(len(nombres), len(marcas))
        self.assertEqual({ficha["categoria"] for ficha in marcas}, {
            "finanzas", "tramites", "envios", "telecomunicaciones", "cuentas_y_autenticacion",
        })
        campos = {"dominios": "dominio", "hosts": "dominio", "autenticacion": "autenticacion"}
        with patch("socket.getaddrinfo", side_effect=AssertionError("El catálogo es local")):
            for ficha in marcas:
                self.assertTrue(any(ficha.get(campo) for campo in campos))
                for campo, tipo in campos.items():
                    for host, fuente in ficha.get(campo, {}).items():
                        with self.subTest(marca=ficha["nombre"], campo=campo, host=host):
                            self.assertEqual(normalizar_dominio(host)[0], host)
                            self.assertEqual(urlsplit(fuente).scheme, "https")
                            self.assertTrue(urlsplit(fuente).hostname)
                            if campo == "dominios":
                                self.assertEqual(dominio_registrable(host), host)
                            resultado = analizar("https://" + host)
                            self.assertIn(CoincidenciaMarca(ficha["nombre"], tipo), resultado.coincidencias_marca)
                            self.assertFalse(resultado.senales)

    def test_senala_suplantacion_con_evidencia_en_el_host(self):
        casos = {
            "nequii.example": "Nequi",
            "www.bancol0mbia.example": "Bancolombia",
            "banc0lom1bia.com": "Bancolombia",
            "www.vancolmbia.com/personas": "Bancolombia",
            "movt4r-colombia.cc": "Movistar",
            "pse-pagos.example": "PSE",
            "dian.tramite.ejemplo.example": "DIAN",
            "www.fcm.org.co.multas.example": "SIMIT",
            "interrapidisimo-rastreo.example": "Inter Rapidísimo",
            "4-72-envios.example": "4-72",
            "efecty-giros.example": "Efecty",
            "claro-factura.example": "Claro",
            "falabella-ofertas.example": "Falabella",
            "accounts.google.com.acceso.example": "Google",
        }
        for host, marca in casos.items():
            with self.subTest(host=host):
                resultado = analizar(host)
                self.assertFalse(resultado.coincidencias_marca)
                self.assertTrue(any(marca in senal for senal in resultado.senales))

    def test_no_infiere_una_marca_por_una_palabra_suelta(self):
        for url in ("visa.example", "claro.example", "envia.example", "x.example", "pse.example",
                    "visa.foro.example", "canalpaypal.example", "googleapis.example", "cloud.example", "efecto.example",
                    "portal.example/informacion/paypal?tramite=dian"):
            with self.subTest(url=url):
                resultado = analizar(url)
                self.assertFalse(resultado.coincidencias_marca)
                self.assertFalse(resultado.senales)

    def test_autenticacion_verificada_respeta_el_host_exacto(self):
        casos = {
            "accounts.google.com": "Google",
            "login.microsoftonline.com": "Microsoft",
            "account.apple.com": "Apple",
            "autenticaciondigital.and.gov.co": "Portal GOV.CO",
            "www.banco.scotiabankcolpatria.com": "DAVIbank",
        }
        for host, marca in casos.items():
            with self.subTest(host=host):
                coincidencia = CoincidenciaMarca(marca, "autenticacion")
                self.assertIn(coincidencia, analizar(host).coincidencias_marca)
                self.assertNotIn(coincidencia, analizar("otro." + host).coincidencias_marca)
                self.assertNotIn(coincidencia, analizar(host + ".example").coincidencias_marca)
        self.assertTrue(any("HTTP" in senal for senal in analizar("http://accounts.google.com").senales))

    def test_infraestructura_compartida_no_atribuye_al_tenant(self):
        for host, proveedor in (("nequi.okta.com", "Okta"), ("paypa1.us.auth0.com", "Auth0"),
                                ("paypal.signin.aws.amazon.com", "AWS Sign-In"),
                                ("dian.b2clogin.com", "Microsoft Entra")):
            with self.subTest(host=host):
                resultado = analizar(host)
                self.assertEqual(resultado.coincidencias_marca, (CoincidenciaMarca(proveedor, "infraestructura"),))
                self.assertFalse(resultado.senales)
                self.assertFalse(analizar(host + ".example").coincidencias_marca)

        resultado = analizar("paypal-login.okta.com")
        self.assertEqual(resultado.coincidencias_marca, (CoincidenciaMarca("Okta", "infraestructura"),))
        self.assertTrue(any("PayPal" in senal for senal in resultado.senales))

    def test_sufijos_de_autenticacion_del_catalogo(self):
        datos = json.loads((DATOS / "marcas.json").read_text(encoding="utf-8"))
        for plataforma in datos["plataformas_autenticacion"]:
            host = "equipo-ejemplo." + plataforma["sufijo"]
            with self.subTest(host=host):
                self.assertEqual(urlsplit(plataforma["fuente"]).scheme, "https")
                self.assertEqual(analizar(host).coincidencias_marca,
                                 (CoincidenciaMarca(plataforma["proveedor"], "infraestructura"),))
                self.assertFalse(analizar(host + ".example").coincidencias_marca)


if __name__ == "__main__":
    unittest.main()
