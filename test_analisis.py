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
        self.assertFalse(analizar("www.paypal.com").senales)
        self.assertTrue(analizar("paypa1.example").senales)
        self.assertTrue(analizar("paypal.com.destino.example").senales)

    def test_invalidas(self):
        for url in ("", "file:///algo", "https://", "http://127.1", "https://a.test:99999"):
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
