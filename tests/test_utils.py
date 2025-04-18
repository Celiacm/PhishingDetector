import unittest
from unittest.mock import patch, MagicMock
import modules.utils as utils


class TestUtils(unittest.TestCase):

    @patch("modules.utils.requests.post")
    @patch.dict("os.environ", {
        "TELEGRAM_BOT_TOKEN": "fake_token",
        "TELEGRAM_CHAT_ID": "fake_chat"
    })
    def test_send_telegram_alert(self, mock_post):
        email_data = {"from": "phisher@mal.com", "subject": "¡Alerta!"}
        utils.send_telegram_alert(email_data, "Phishing")
        
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("fake_token", args[0])
        self.assertEqual(kwargs["data"]["chat_id"], "fake_chat")
        self.assertIn("Phishing", kwargs["data"]["text"])

    @patch("modules.utils.db.get_email_by_message_id", return_value=False)
    @patch("modules.utils.db.existe_remitente", return_value=False)
    @patch("modules.utils.db.save_email_to_db")
    @patch("modules.utils.email_analysis.is_phishing")
    @patch("modules.utils.email_analysis.check_spf", return_value=True)
    @patch("modules.utils.email_analysis.check_dkim", return_value=True)
    @patch("modules.utils.email_analysis.check_dmarc", return_value=True)
    @patch("modules.utils.send_telegram_alert")
    @patch("imaplib.IMAP4_SSL")
    @patch.dict("os.environ", {
        "OAUTH_ACCESS_TOKEN": "token",
        "OAUTH_EMAIL": "correo@prueba.com"
    })
    def test_get_emails_without_session(self, mock_imap, mock_alert,
                                        mock_spf, mock_dkim, mock_dmarc,
                                        mock_is_phishing, mock_save, *_):

        # Simula correo en bytes
        mock_conn = MagicMock()
        mock_conn.search.return_value = ("OK", [b"1"])
        mock_conn.fetch.return_value = ("OK", [(b"1", b"From: test\r\nMessage-ID: <id1>\r\n\r\nBody")])
        mock_imap.return_value = mock_conn

        mock_is_phishing.return_value = {
            "estado": "Phishing (alto riesgo)",
            "motivos": ["Motivo simulado"],
            "score": 10
        }

        emails = utils.get_emails_without_session(limit=1)

        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]["estado"], "Phishing (alto riesgo)")
        mock_save.assert_called_once()
        mock_alert.assert_called_once()


if __name__ == '__main__':
    unittest.main()
