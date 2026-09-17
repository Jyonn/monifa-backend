from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from core.auth import issue_access
from core.models import MfaEntry, MfaShare, User
from core.totp import generate_totp


class TotpTests(TestCase):
    def test_rfc_6238_sha1_vector(self):
        entry = MfaEntry(
            secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            algorithm="SHA1",
            digits=8,
            period=30,
        )
        self.assertEqual(generate_totp(entry, 59), ("94287082", 1))


class ShareApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create(display_name="Alice")
        self.entry = MfaEntry.objects.create(
            user=self.user,
            issuer="Example",
            account_name="alice@example.com",
            secret="JBSWY3DPEHPK3PXP",
        )
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {issue_access(self.user)}"}

    def test_create_read_and_revoke_share_without_exposing_secret(self):
        created = self.client.post(
            f"/mfa/entries/{self.entry.pk}/share",
            {"ttlSeconds": 3600},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(created.status_code, 201)
        token = created.json()["token"]
        self.assertNotIn(token, MfaShare.objects.get(entry=self.entry).token_hash)

        shared = self.client.get(f"/shares/{token}")
        self.assertEqual(shared.status_code, 200)
        self.assertEqual(shared.json()["issuer"], "Example")
        self.assertIn("code", shared.json())
        self.assertNotIn("secret", shared.json())
        self.assertEqual(shared["Cache-Control"], "no-store, private")

        revoked = self.client.delete(f"/mfa/entries/{self.entry.pk}/share", **self.headers)
        self.assertEqual(revoked.status_code, 204)
        self.assertEqual(self.client.get(f"/shares/{token}").status_code, 404)

    def test_new_share_invalidates_previous_url(self):
        first = self.client.post(f"/mfa/entries/{self.entry.pk}/share", {}, content_type="application/json", **self.headers).json()["token"]
        second = self.client.post(f"/mfa/entries/{self.entry.pk}/share", {}, content_type="application/json", **self.headers).json()["token"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.client.get(f"/shares/{first}").status_code, 404)
        self.assertEqual(self.client.get(f"/shares/{second}").status_code, 200)

    def test_expired_share_is_not_available(self):
        token = MfaShare.issue(self.entry, timezone.now() - timezone.timedelta(seconds=1))
        self.assertEqual(self.client.get(f"/shares/{token}").status_code, 404)
