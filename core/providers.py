from dataclasses import dataclass
from urllib.parse import urlencode

import requests

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
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        user = requests.get("https://api.github.com/user", headers=headers, timeout=8).json()
        emails = requests.get("https://api.github.com/user/emails", headers=headers, timeout=8).json()
        primary = next((item["email"] for item in emails if item.get("primary") and item.get("verified")), "")
        return ProviderProfile(str(user["id"]), user.get("login", ""), user.get("name") or user.get("login", ""), primary, user.get("avatar_url", ""), {"profile_url": user.get("html_url", "")})


class QitianProvider:
    name = "qitian"

    def authorize_url(self, state, callback):
        host = Config.get_value_by_key(CI.QITIAN_HOST, "https://sso.6-79.cn").rstrip("/")
        return host + "/oauth/?" + urlencode(
            {"app_id": Config.get_value_by_key(CI.QITIAN_APP_ID, ""), "redirect_uri": callback, "state": state}
        )

    def exchange(self, code, callback):
        host = Config.get_value_by_key(CI.QITIAN_HOST, "https://sso.6-79.cn").rstrip("/")
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


PROVIDERS = {"github": GitHubProvider(), "qitian": QitianProvider()}
