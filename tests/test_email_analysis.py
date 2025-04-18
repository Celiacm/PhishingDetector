import unittest
from unittest.mock import patch, MagicMock
from modules.email_analysis import (
    check_spf, check_dmarc, check_dkim,
    match_yara, analizar_contenido, es_enlace_sospechoso
)

class TestEmailAnalysis(unittest.TestCase):

    @patch("dns.resolver.resolve")
    def test_check_spf_valid(self, mock_resolve):
        mock_txt = MagicMock()
        mock_txt.__str__.return_value = '"v=spf1 include:_spf.google.com -all"'
        mock_resolve.return_value = [mock_txt]
        result = check_spf("test@gmail.com")
        self.assertTrue(result)

    @patch("dns.resolver.resolve")
    def test_check_spf_invalid(self, mock_resolve):
        mock_txt = MagicMock()
        mock_txt.__str__.return_value = '"v=spf1 include:_spf.google.com"'  # sin -all
        mock_resolve.return_value = [mock_txt]
        result = check_spf("test@gmail.com")
        self.assertFalse(result)

    @patch("dns.resolver.resolve")
    def test_check_dmarc_valid(self, mock_resolve):
        mock_txt = MagicMock()
        mock_txt.__str__.return_value = '"v=DMARC1; p=reject;"'
        mock_resolve.return_value = [mock_txt]
        result = check_dmarc("test@gmail.com")
        self.assertTrue(result)
        
        
    @patch("dns.resolver.resolve")
    def test_check_dmarc_invalid(self, mock_resolve):
        mock_txt = MagicMock()
        mock_txt.__str__.return_value = '"v=DMARC1; p=none;"'
        mock_resolve.return_value = [mock_txt]
        result = check_dmarc("test@gmail.com")
        self.assertFalse(result)

    @patch("modules.email_analysis.dkim.verify")
    def test_check_dkim_valid(self, mock_verify):
        mock_verify.return_value = True
        raw_email = b"From: test@example.com\r\n\r\nThis is a test email"
        result = check_dkim(raw_email)
        self.assertTrue(result)

    def test_match_yara_none(self):
        content = "este es un texto limpio"
        result = match_yara(content)
        self.assertFalse(result)

    def test_analizar_contenido_urgente_html(self):
        body = ("¡Tu cuenta será desactivada si no verificas! " + "<b>Haz clic aquí</b>" * 30)
        result = analizar_contenido(body)
        self.assertTrue(result["urgente"])
        self.assertTrue(result["html_excesivo"])

    def test_es_enlace_sospechoso_ip(self):
        href = "http://123.123.123.123"
        self.assertEqual(es_enlace_sospechoso(href), "Enlace apunta a IP directa")

    def test_es_enlace_sospechoso_ofuscado(self):
        href = "http://example.com/%20@malicious"
        self.assertEqual(es_enlace_sospechoso(href), "Enlace contiene codificación ofuscada o '@'")

    def test_es_enlace_sospechoso_punycode(self):
        href = "http://xn--phishing-abc.com"
        self.assertEqual(es_enlace_sospechoso(href), "Enlace usa Punycode (posible suplantación)")

    def test_es_enlace_sospechoso_legitimo(self):
        href = "http://example.com/login"
        self.assertIsNone(es_enlace_sospechoso(href))

if __name__ == '__main__':
    unittest.main()
