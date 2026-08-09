import base64
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from core.auth import issue_access
from core.models import MfaEntry, User, UserIdentity
from core.providers import ProviderProfile


class MfaEntryApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create(display_name="Test")
        self.other = User.objects.create(display_name="Other")
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {issue_access(self.user)}"}

    def test_create_list_and_delete_entry(self):
        payload = {"issuer": "Example", "accountName": "alice@example.com", "secret": "JBSWY3DPEHPK3PXP"}
        created = self.client.post("/mfa/entries", payload, content_type="application/json", **self.headers)
        self.assertEqual(created.status_code, 201)
        listed = self.client.get("/mfa/entries", **self.headers)
        self.assertEqual(listed.json()["entries"][0]["secret"], payload["secret"])
        deleted = self.client.delete(f"/mfa/entries/{created.json()['id']}", **self.headers)
        self.assertEqual(deleted.status_code, 204)

    def test_entries_are_isolated_by_user(self):
        MfaEntry.objects.create(user=self.other, issuer="Other", account_name="other", secret="JBSWY3DPEHPK3PXP")
        response = self.client.get("/mfa/entries", **self.headers)
        self.assertEqual(response.json()["entries"], [])

    def test_duplicate_factor_is_rejected(self):
        payload = {"issuer": "Example", "accountName": "alice", "secret": "JBSWY3DPEHPK3PXP"}
        self.client.post("/mfa/entries", payload, content_type="application/json", **self.headers)
        response = self.client.post("/mfa/entries", {**payload, "issuer": "Renamed"}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 409)

    def test_invalid_base32_is_rejected(self):
        response = self.client.post(
            "/mfa/entries",
            {"issuer": "Bad", "accountName": "bad", "secret": "NOT-BASE32"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_account_delete_requires_confirmation(self):
        rejected = self.client.delete("/me/account", {"confirmation": "NO"}, content_type="application/json", **self.headers)
        self.assertEqual(rejected.status_code, 400)
        accepted = self.client.delete("/me/account", {"confirmation": "DELETE"}, content_type="application/json", **self.headers)
        self.assertEqual(accepted.status_code, 204)
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())

    def test_ticket_exchange_is_rate_limited(self):
        for _ in range(20):
            response = self.client.post("/auth/ticket", {"ticket": "invalid"}, content_type="application/json", REMOTE_ADDR="192.0.2.4")
            self.assertEqual(response.status_code, 401)
        limited = self.client.post("/auth/ticket", {"ticket": "invalid"}, content_type="application/json", REMOTE_ADDR="192.0.2.4")
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited["Retry-After"], "60")


class OAuthCallbackTests(TestCase):
    @patch("core.views.PROVIDERS")
    def test_qitian_callback_accepts_missing_state(self, providers):
        providers.get.return_value.exchange.return_value = ProviderProfile(
            subject="qitian-user-app-id",
            username="jyonn",
            display_name="Jyonn",
        )

        response = self.client.get("/auth/qitian/callback", {"code": "fresh-code"})

        self.assertEqual(response.status_code, 302)
        self.assertIn("/#/auth/callback?ticket=", response["Location"])
        self.assertTrue(UserIdentity.objects.filter(provider="qitian", subject="qitian-user-app-id").exists())

    @patch("core.views.PROVIDERS")
    def test_github_callback_rejects_missing_state(self, providers):
        response = self.client.get("/auth/github/callback", {"code": "fresh-code"})

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].endswith("/#/auth/callback?error=oauth_failed"))
        providers.get.return_value.exchange.assert_not_called()
