from urllib.parse import parse_qs, urlparse

from django.test import TestCase

from Config.models import CI, Config
from core.providers import QitianProvider


class ConfigModelTests(TestCase):
    def test_update_and_read_value(self):
        Config.update_value(CI.QITIAN_APP_ID, "first")
        Config.update_value(CI.QITIAN_APP_ID, "second")
        self.assertEqual(Config.get_value_by_key(CI.QITIAN_APP_ID), "second")

    def test_missing_value_returns_default(self):
        self.assertEqual(Config.get_value_by_key("missing", "fallback"), "fallback")

    def test_qitian_provider_reads_database_config(self):
        Config.update_value(CI.QITIAN_OAUTH_HOST, "https://accounts.example.test/")
        Config.update_value(CI.QITIAN_APP_ID, "database-app-id")

        authorize_url = QitianProvider().authorize_url("state-value", "https://api.example.test/callback")
        parsed = urlparse(authorize_url)

        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", "https://accounts.example.test/oauth/")
        self.assertEqual(parse_qs(parsed.query)["app_id"], ["database-app-id"])
        self.assertEqual(parse_qs(parsed.query)["state"], ["state-value"])
