import base64

from django.test import TestCase

from core.auth import issue_access
from core.models import MfaEntry, User


class MfaEntryApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(display_name="Test")
        self.other = User.objects.create(display_name="Other")
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {issue_access(self.user)}"}

    def test_create_list_and_delete_entry(self):
        payload = {"issuer": "Example", "accountName": "alice@example.com", "secret": "JBSWY3DPEHPK3PXP"}
        created = self.client.post("/api/mfa/entries", payload, content_type="application/json", **self.headers)
        self.assertEqual(created.status_code, 201)
        listed = self.client.get("/api/mfa/entries", **self.headers)
        self.assertEqual(listed.json()["entries"][0]["secret"], payload["secret"])
        deleted = self.client.delete(f"/api/mfa/entries/{created.json()['id']}", **self.headers)
        self.assertEqual(deleted.status_code, 204)

    def test_entries_are_isolated_by_user(self):
        MfaEntry.objects.create(user=self.other, issuer="Other", account_name="other", secret="JBSWY3DPEHPK3PXP")
        response = self.client.get("/api/mfa/entries", **self.headers)
        self.assertEqual(response.json()["entries"], [])

    def test_duplicate_factor_is_rejected(self):
        payload = {"issuer": "Example", "accountName": "alice", "secret": "JBSWY3DPEHPK3PXP"}
        self.client.post("/api/mfa/entries", payload, content_type="application/json", **self.headers)
        response = self.client.post("/api/mfa/entries", {**payload, "issuer": "Renamed"}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 409)

    def test_invalid_base32_is_rejected(self):
        response = self.client.post(
            "/api/mfa/entries",
            {"issuer": "Bad", "accountName": "bad", "secret": "NOT-BASE32"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 400)

