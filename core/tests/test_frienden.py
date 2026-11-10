import base64
import hashlib
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.core.cache import cache
from django.test import Client, TestCase

from core.auth import issue_access
from core.models import MfaEntry, User, UserIdentity
from core.views import FRIENDEN_STATE_COOKIE


class FriendenOAuthTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create(display_name="Existing account")
        UserIdentity.objects.create(user=self.user, provider="qitian", subject="qitian-subject")
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {issue_access(self.user)}"}
        self.provider = self.enterContext(patch("core.providers.FriendenProvider.request"))
        self.provider.side_effect = self.provider_response

    @staticmethod
    def provider_response(method, endpoint, **kwargs):
        return {
            "token": {"access_token": "test-token"},
            "userinfo": {"sub": "sermo:1:123", "nickname": "友间昵称"},
            "revoke": {"revoked": True},
        }[endpoint]

    def begin(self, *, link=False):
        if link:
            response = self.client.get("/auth/frienden/link", secure=True, **self.headers)
            url = response.json()["authorizeUrl"]
        else:
            response = self.client.get("/auth/frienden/start", secure=True)
            url = response["Location"]
        self.assertEqual(urlsplit(url).netloc, "frienden.jyonn.space")
        self.assertTrue(response.cookies[FRIENDEN_STATE_COOKIE]["secure"])
        self.assertTrue(response.cookies[FRIENDEN_STATE_COOKIE]["httponly"])
        return {key: value[0] for key, value in parse_qs(urlsplit(url).query).items()}

    def callback(self, flow, client=None):
        response = (client or self.client).get(
            "/auth/frienden/callback", {"state": flow["state"], "code": "provider-code"}, secure=True,
        )
        return {key: value[0] for key, value in parse_qs(response["Location"].split("?", 1)[1]).items()}

    def exchange_ticket(self, result):
        response = self.client.post("/auth/ticket", {"ticket": result["ticket"]}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_link_then_sign_in_to_same_account_and_entries(self):
        entry = MfaEntry.objects.create(
            user=self.user, issuer="Example", account_name="existing", secret="JBSWY3DPEHPK3PXP",
        )
        flow = self.begin(link=True)
        self.assertEqual(flow["client_id"], settings.FRIENDEN_CLIENT_ID)
        self.assertEqual(flow["redirect_uri"], settings.FRIENDEN_REDIRECT_URI)
        self.assertEqual(flow["scope"], "profile")
        self.assertEqual(flow["code_challenge_method"], "S256")
        linked = self.callback(flow)
        self.assertEqual(linked["link"], "frienden")
        form = self.provider.call_args_list[0].kwargs["form"]
        self.assertEqual(form["redirect_uri"], flow["redirect_uri"])
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
        self.assertEqual(challenge, flow["code_challenge"])
        self.provider.assert_called_with("POST", "revoke", token="test-token")
        self.assertEqual(self.exchange_ticket(linked)["user"]["id"], str(self.user.pk))

        login = self.exchange_ticket(self.callback(self.begin()))
        self.assertEqual(login["user"]["id"], str(self.user.pk))
        self.assertEqual({identity["provider"] for identity in login["user"]["identities"]}, {"qitian", "frienden"})
        entries = self.client.get("/mfa/entries", HTTP_AUTHORIZATION=f"Bearer {login['accessToken']}")
        self.assertEqual([item["id"] for item in entries.json()["entries"]], [entry.pk])
        self.assertEqual(User.objects.count(), 1)

    def test_first_frienden_login_creates_account(self):
        login = self.exchange_ticket(self.callback(self.begin()))
        self.assertNotEqual(login["user"]["id"], str(self.user.pk))
        self.assertEqual(login["user"]["identities"], [{"provider": "frienden", "username": "友间昵称", "email": ""}])

    def test_cross_browser_callback_and_replay_are_rejected(self):
        flow = self.begin()
        self.assertEqual(self.callback(flow, Client()), {"error": "oauth_failed"})
        self.provider.assert_not_called()
        self.assertIn("ticket", self.callback(flow))

        self.client.cookies[FRIENDEN_STATE_COOKIE] = flow["state"]
        self.provider.reset_mock()
        self.assertEqual(self.callback(flow), {"error": "oauth_failed"})
        self.provider.assert_not_called()

    def test_cannot_link_frienden_identity_owned_by_another_account(self):
        other = User.objects.create()
        identity = UserIdentity.objects.create(user=other, provider="frienden", subject="sermo:1:123")
        self.assertEqual(self.callback(self.begin(link=True)), {"error": "identity_in_use", "link": "frienden"})
        identity.refresh_from_db()
        self.assertEqual(identity.user_id, other.pk)

    def test_cannot_replace_a_bound_frienden_identity(self):
        UserIdentity.objects.create(user=self.user, provider="frienden", subject="sermo:1:456")
        self.assertEqual(self.callback(self.begin(link=True)), {"error": "identity_in_use", "link": "frienden"})
        self.assertFalse(UserIdentity.objects.filter(provider="frienden", subject="sermo:1:123").exists())

    def test_frienden_link_requires_login_and_is_not_a_cli_provider(self):
        self.assertEqual(self.client.get("/auth/frienden/link").status_code, 401)
        self.assertEqual(self.client.get("/auth/frienden/cli").status_code, 404)
