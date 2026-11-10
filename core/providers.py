import base64
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlencode

import requests
from django.conf import settings

from Config.models import CI, Config


@dataclass
class ProviderProfile:
    subject: str
    username: str = ""
    display_name: str = ""
    email: str = ""
    avatar_url: str = ""
    metadata: dict | None = None


class GitHubProvider:
    name = "github"

    def authorize_url(self, state, callback):
        return "https://github.com/login/oauth/authorize?" + urlencode(
            {"client_id": Config.get_value_by_key(CI.GITHUB_CLIENT_ID, ""), "redirect_uri": callback, "scope": "read:user user:email", "state": state}
        )

    def exchange(self, code, callback):
        response = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json={
                "client_id": Config.get_value_by_key(CI.GITHUB_CLIENT_ID, ""),
                "client_secret": Config.get_value_by_key(CI.GITHUB_CLIENT_SECRET, ""),
                "code": code,
                "redirect_uri": callback,
            },
            timeout=8,
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        return self.profile_from_token(token)

    def profile_from_token(self, token):
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        user = requests.get("https://api.github.com/user", headers=headers, timeout=8).json()
        emails = requests.get("https://api.github.com/user/emails", headers=headers, timeout=8).json()
        primary = next((item["email"] for item in emails if item.get("primary") and item.get("verified")), "")
        return ProviderProfile(str(user["id"]), user.get("login", ""), user.get("name") or user.get("login", ""), primary, user.get("avatar_url", ""), {"profile_url": user.get("html_url", "")})


class QitianProvider:
    name = "qitian"

    def authorize_url(self, state, callback):
        host = Config.get_value_by_key(CI.QITIAN_OAUTH_HOST, "https://qt.6-79.cn").rstrip("/")
        return host + "/oauth/?" + urlencode(
            {"app_id": Config.get_value_by_key(CI.QITIAN_APP_ID, ""), "redirect_uri": callback, "state": state}
        )

    def exchange(self, code, callback):
        host = Config.get_value_by_key(CI.QITIAN_HOST, "https://api.qt.6-79.cn").rstrip("/")
        response = requests.post(
            host + "/oauth/token",
            json={"code": code, "app_secret": Config.get_value_by_key(CI.QITIAN_APP_SECRET, "")},
            timeout=8,
        )
        response.raise_for_status()
        payload = response.json().get("body", response.json())
        token = payload["token"]
        subject = str(payload["user_app_id"])
        profile_response = requests.get(host + "/user/", headers={"token": token}, timeout=8)
        profile_response.raise_for_status()
        profile = profile_response.json().get("body", profile_response.json())
        return ProviderProfile(subject, profile.get("qitian", ""), profile.get("nickname", ""), profile.get("email", ""), profile.get("avatar", ""), {})


class FriendenProvider:
    api_url = "https://api.sermo.jyonn.space/users/oauth/"

    def authorize_url(self, state, verifier):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        return "https://frienden.jyonn.space/oauth/authorize?" + urlencode({
            "client_id": settings.FRIENDEN_CLIENT_ID,
            "redirect_uri": settings.FRIENDEN_REDIRECT_URI,
            "response_type": "code",
            "scope": "profile",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })

    def request(self, method, endpoint, *, form=None, token=None):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        with requests.request(method, self.api_url + endpoint, data=form, headers=headers, timeout=(4, 8), allow_redirects=False) as response:
            if response.status_code != 200:
                raise ValueError("Frienden OAuth request failed")
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid Frienden OAuth response")
            return payload

    def exchange(self, code, verifier):
        token = self.request("POST", "token", form={
            "grant_type": "authorization_code",
            "client_id": settings.FRIENDEN_CLIENT_ID,
            "redirect_uri": settings.FRIENDEN_REDIRECT_URI,
            "code": code,
            "code_verifier": verifier,
        }).get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("Missing Frienden access token")
        try:
            profile = self.request("GET", "userinfo", token=token)
        finally:
            try:
                self.request("POST", "revoke", token=token)
            except (requests.RequestException, ValueError):
                pass

        subject = profile.get("sub")
        if not isinstance(subject, str) or len(subject) > 255 or not re.fullmatch(r"sermo:[0-9]+:[0-9]+", subject):
            raise ValueError("Invalid Frienden subject")
        nickname = profile.get("nickname")
        nickname = nickname.strip() if isinstance(nickname, str) else ""
        return ProviderProfile(subject, username=nickname[:255], display_name=nickname[:120] or "友间用户")


PROVIDERS = {"github": GitHubProvider(), "qitian": QitianProvider(), "frienden": FriendenProvider()}
