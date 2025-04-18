import unittest
from unittest.mock import patch, MagicMock
from modules.scheduler import auto_scan_emails, run

class TestAutoScanEmails(unittest.TestCase):

    @patch("modules.scheduler.send_telegram_alert")
    @patch("modules.scheduler.get_emails_without_session")
    def test_alert_sent_only_for_phishing(self, mock_get_emails, mock_send_alert):
        # Simula 3 correos, uno phishing, dos no
        mock_get_emails.return_value = [
            {"from": "bad@phish.com", "subject": "Hackeado", "is_phishing": "Phishing"},
            {"from": "safe@domain.com", "subject": "Hola", "is_phishing": "Seguro"},
            {"from": "maybe@doubt.com", "subject": "Hmm", "is_phishing": "Sospechoso"}
        ]

        auto_scan_emails()

        # Solo debe llamarse una vez para el phishing
        mock_send_alert.assert_called_once_with(
            {"from": "bad@phish.com", "subject": "Hackeado"},
            "Phishing"
        )

    @patch("modules.scheduler.schedule.every")
    @patch("modules.scheduler.threading.Thread")
    def test_run_starts_thread(self, mock_thread, mock_schedule):
        mock_instance = MagicMock()
        mock_thread.return_value = mock_instance

        run()

        mock_thread.assert_called_once()
        mock_instance.start.assert_called_once()

