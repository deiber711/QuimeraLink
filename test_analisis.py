import unittest
from unittest.mock import patch

from analisis import analizar
from captura import imagen


class AnalisisTests(unittest.TestCase):
    def test_dominio_y_privacidad(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError):
            resultado = analizar("https://paypal.com@destino.example/?clave=privada")
        self.assertEqual(resultado.dominio, "destino.example")
        self.assertIsNone(resultado.url_captura)
        self.assertTrue(resultado.senales)
        self.assertNotIn("privada", str(resultado.senales))

    def test_marca(self):
        for url in ("www.paypal.com", "personas.bancolombia.com.co"):
            with self.subTest(url=url):
                self.assertFalse(analizar(url).senales)
        for dominio in ("paypa1", "paypl", "payypal", "payapl", "pay-pal-soporte", "paypal.com.destino"):
            with self.subTest(dominio=dominio):
                self.assertTrue(any("PayPal" in s for s in analizar(dominio + ".example").senales))
        self.assertTrue(any("Bancolombia" in s for s in analizar("bancolornbia.example").senales))

    def test_dominio_registrable(self):
        casos = {
            "https://portal.entidad.COM.CO.": "entidad.com.co",
            "www.entidad.co.uk": "entidad.co.uk",
            "www.usuario.github.io": "usuario.github.io",
            "www.a.b.ck": "a.b.ck",
            "www.www.ck": "www.ck",
            "b.ck": None,
            "co.uk": None,
            "www.entidad.example": "entidad.example",
            "www.пример.рф": "xn--e1afmkfd.xn--p1ai",
        }
        for url, esperado in casos.items():
            with self.subTest(url=url):
                self.assertEqual(analizar(url).dominio_registrable, esperado)

    def test_idna_y_caracteres_confusos(self):
        unicode = analizar("p\u0430yp\u0430l.example")
        self.assertEqual(unicode.dominio, "xn--pypl-53dc.example")
        self.assertEqual(unicode.dominio_unicode, "p\u0430yp\u0430l.example")
        self.assertEqual(unicode, analizar(unicode.dominio))
        self.assertTrue(any("confundirse" in s for s in unicode.senales))
        self.assertTrue(any("PayPal" in s for s in unicode.senales))

        ancho_completo = analizar("ｅxample.com")
        self.assertEqual(ancho_completo.dominio, "example.com")
        self.assertTrue(any("confundirse" in s for s in ancho_completo.senales))

        for dominio in ("ѕсоре.example", "gοld.example"):
            with self.subTest(dominio=dominio):
                self.assertTrue(any("confundirse" in s for s in analizar(dominio).senales))
        for dominio, ascii_ in (("café.cl", "xn--caf-dma.cl"), ("faß.de", "xn--fa-hia.de")):
            with self.subTest(dominio=dominio):
                resultado = analizar(dominio)
                self.assertEqual(resultado.dominio, ascii_)
                self.assertEqual(resultado.dominio_unicode, dominio)
                self.assertFalse(resultado.senales)

    def test_ubicaciones_enganosas(self):
        casos = {
            "tienda.co.uk.acceso.example": "subdominio",
            "acceso.example/tienda.com/login": "ruta",
            "acceso.example/https%3A%2F%2Ftienda.dev/login?clave=privada": "ruta",
            "https://ac%63eso.example/": "codificados",
        }
        for url, mensaje in casos.items():
            with self.subTest(url=url):
                resultado = analizar(url)
                self.assertEqual(resultado.dominio_registrable, "acceso.example")
                self.assertTrue(any(mensaje in s for s in resultado.senales))
                self.assertNotIn("privada", str(resultado.senales))

        for url in ("acceso.example/?ir=https://tienda.com", "api.us.example.com", "tienda。example.com",
                    "www.ejemplo.com.ejemplo.com",
                    "ejemplo.com/www.ejemplo.com/", "acceso.example/index.html"):
            with self.subTest(url=url):
                self.assertFalse(analizar(url).senales)

    def test_ip_literal(self):
        for url, destino in (("https://192.0.2.1", "192.0.2.1"), ("https://[0:0::1]", "::1")):
            with self.subTest(url=url):
                resultado = analizar(url)
                self.assertEqual(resultado.dominio, destino)
                self.assertIsNone(resultado.dominio_registrable)
                self.assertIsNone(resultado.url_captura)
                self.assertTrue(any("IP literal" in s for s in resultado.senales))

        for url in ("http://127.1", "http://2130706433", "http://0x7f000001", "http://0177.0.0.1"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "IPv4"):
                analizar(url)

    def test_longitud_no_genera_senales(self):
        url = f"https://{'a' * 63}.{'b' * 63}.example.com/documentos/{'x' * 5000}"
        resultado = analizar(url)
        self.assertEqual(resultado.dominio_registrable, "example.com")
        self.assertFalse(resultado.senales)

    def test_invalidas(self):
        for url in ("", "file:///algo", "https://", "https://a.test:99999", "https://xn--a.example",
                    "https://[::1]acceso.example", "https://acceso.example..", "https://a%2fb.example"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                analizar(url)

    def test_limitaciones_de_captura(self):
        for url in ("http://127.0.0.1", "http://[::1]", "https://a.example:22"):
            self.assertIsNone(analizar(url).url_captura)
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                imagen("https://pagina.example")


if __name__ == "__main__":
    unittest.main()
