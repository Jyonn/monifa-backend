import base64
import hashlib
import json
from urllib.parse import urlencode

import jwt
from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from Config.models import CI, Config
from .auth import decode_token, issue_access, issue_refresh, rate_limit, require_access
from .models import AuditEvent, ExpiringCode, MfaEntry, RefreshSession, User, UserIdentity
from .providers import PROVIDERS


def body(request):
    try:
        return json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return None


def client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")).split(",")[0].strip() or None


def frontend_url():
    return Config.get_value_by_key(CI.FRONTEND_URL, settings.FRONTEND_URL).rstrip("/")


def consume_code(raw, kind):
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with transaction.atomic():
        code = ExpiringCode.objects.select_for_update().filter(code_hash=digest, kind=kind).first()
        if not code or code.used_at or code.expires_at <= timezone.now():
            return None
        code.used_at = timezone.now()
        code.save(update_fields=["used_at"])
        return code


def profile_json(user):
    return {
        "id": str(user.pk),
        "displayName": user.display_name,
        "avatarUrl": user.avatar_url,
        "identities": [
            {"provider": identity.provider, "username": identity.username, "email": identity.email}
            for identity in user.identities.all()
        ],
    }


def health(request):
    return JsonResponse({"status": "ok", "serverTime": int(timezone.now().timestamp())})


@require_http_methods(["GET"])
def oauth_start(request, provider):
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    link_user = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = decode_token(auth[7:], "access")
            link_user = User.objects.filter(pk=payload["sub"]).first()
        except jwt.PyJWTError:
            pass
    state = ExpiringCode.issue(ExpiringCode.Kind.OAUTH_STATE, settings.OAUTH_STATE_TTL_SECONDS, provider=provider, link_user=link_user)
    callback = request.build_absolute_uri(f"/api/auth/{provider}/callback")
    return redirect(adapter.authorize_url(state, callback))


@require_access
@require_http_methods(["GET"])
def oauth_link_start(request, provider):
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    state = ExpiringCode.issue(
        ExpiringCode.Kind.OAUTH_STATE,
        settings.OAUTH_STATE_TTL_SECONDS,
        provider=provider,
        link_user=request.monifa_user,
    )
    callback = request.build_absolute_uri(f"/api/auth/{provider}/callback")
    return JsonResponse({"authorizeUrl": adapter.authorize_url(state, callback)})


@require_http_methods(["GET"])
def oauth_callback(request, provider):
    adapter = PROVIDERS.get(provider)
    state = consume_code(request.GET.get("state", ""), ExpiringCode.Kind.OAUTH_STATE)
    if adapter is None or state is None or state.provider != provider or not request.GET.get("code"):
        return redirect(frontend_url() + "/#/auth/callback?error=oauth_failed")
    try:
        callback = request.build_absolute_uri(f"/api/auth/{provider}/callback")
        profile = adapter.exchange(request.GET["code"], callback)
        with transaction.atomic():
            identity = UserIdentity.objects.select_related("user").filter(provider=provider, subject=profile.subject).first()
            if state.link_user:
                if identity and identity.user_id != state.link_user_id:
                    return redirect(frontend_url() + "/#/auth/callback?error=identity_in_use")
                user = state.link_user
            elif identity:
                user = identity.user
            else:
                user = User.objects.create(display_name=profile.display_name, avatar_url=profile.avatar_url)
            UserIdentity.objects.update_or_create(
                provider=provider,
                subject=profile.subject,
                defaults={"user": user, "username": profile.username, "email": profile.email, "avatar_url": profile.avatar_url, "metadata": profile.metadata or {}},
            )
        ticket = ExpiringCode.issue(ExpiringCode.Kind.LOGIN_TICKET, settings.LOGIN_TICKET_TTL_SECONDS, user=user)
        AuditEvent.objects.create(user=user, action="auth.login", ip_address=client_ip(request), metadata={"provider": provider})
        return redirect(frontend_url() + "/#/auth/callback?" + urlencode({"ticket": ticket}))
    except Exception:
        return redirect(frontend_url() + "/#/auth/callback?error=oauth_failed")


@csrf_exempt
@require_http_methods(["POST"])
@rate_limit("ticket", 20)
def exchange_ticket(request):
    data = body(request)
    code = consume_code((data or {}).get("ticket", ""), ExpiringCode.Kind.LOGIN_TICKET)
    if code is None or code.user is None:
        return JsonResponse({"error": "invalid_ticket"}, status=401)
    return JsonResponse({"accessToken": issue_access(code.user), "refreshToken": issue_refresh(code.user), "user": profile_json(code.user)})


@csrf_exempt
@require_http_methods(["POST"])
@rate_limit("refresh", 30)
def refresh(request):
    token = (body(request) or {}).get("refreshToken", "")
    try:
        payload = decode_token(token, "refresh")
        with transaction.atomic():
            session = RefreshSession.objects.select_for_update().get(token_id=payload["jti"], user_id=payload["sub"])
            if session.revoked_at or session.expires_at <= timezone.now() or session.token_hash != RefreshSession.digest(token):
                raise RefreshSession.DoesNotExist
            session.revoked_at = timezone.now()
            session.save(update_fields=["revoked_at"])
            user = session.user
        return JsonResponse({"accessToken": issue_access(user), "refreshToken": issue_refresh(user), "user": profile_json(user)})
    except (jwt.PyJWTError, RefreshSession.DoesNotExist, KeyError, ValueError):
        return JsonResponse({"error": "invalid_refresh_token"}, status=401)


@csrf_exempt
@require_http_methods(["POST"])
def logout(request):
    token = (body(request) or {}).get("refreshToken", "")
    try:
        payload = decode_token(token, "refresh")
        RefreshSession.objects.filter(token_id=payload["jti"], token_hash=RefreshSession.digest(token)).update(revoked_at=timezone.now())
    except (jwt.PyJWTError, KeyError):
        pass
    return JsonResponse({}, status=204)


@require_access
@require_http_methods(["GET"])
def me(request):
    return JsonResponse(profile_json(request.monifa_user))


def validate_entry(data):
    try:
        secret = "".join(data["secret"].split()).upper().rstrip("=")
        base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
        algorithm = data.get("algorithm", "SHA1").upper()
        digits = int(data.get("digits", 6))
        period = int(data.get("period", 30))
        if algorithm not in MfaEntry.Algorithm.values or digits not in (6, 8) or period < 5 or period > 300:
            raise ValueError
        issuer = str(data.get("issuer", "")).strip()
        account_name = str(data.get("accountName", "")).strip()
        if not secret or not issuer or not account_name:
            raise ValueError
        return {"secret": secret, "algorithm": algorithm, "digits": digits, "period": period, "issuer": issuer, "account_name": account_name}
    except (KeyError, TypeError, ValueError, base64.binascii.Error):
        return None


def entry_json(entry):
    return {
        "id": entry.pk,
        "issuer": entry.issuer,
        "accountName": entry.account_name,
        "secret": entry.secret,
        "algorithm": entry.algorithm,
        "digits": entry.digits,
        "period": entry.period,
        "createdAt": entry.created_at.isoformat(),
    }


@csrf_exempt
@require_access
@require_http_methods(["GET", "POST"])
@rate_limit("mfa_entries", 120)
def entries(request):
    if request.method == "GET":
        AuditEvent.objects.create(
            user=request.monifa_user,
            action="mfa.read",
            ip_address=client_ip(request),
            metadata={"count": request.monifa_user.mfa_entries.count()},
        )
        response = JsonResponse({"entries": [entry_json(item) for item in request.monifa_user.mfa_entries.all()], "serverTime": int(timezone.now().timestamp())})
        response["Cache-Control"] = "no-store"
        return response
    values = validate_entry(body(request) or {})
    if values is None:
        return JsonResponse({"error": "invalid_totp_entry"}, status=400)
    try:
        entry = MfaEntry.objects.create(user=request.monifa_user, **values)
    except IntegrityError:
        return JsonResponse({"error": "duplicate_totp_entry"}, status=409)
    AuditEvent.objects.create(user=request.monifa_user, action="mfa.create", target_id=str(entry.pk), ip_address=client_ip(request), metadata={"issuer": entry.issuer})
    return JsonResponse(entry_json(entry), status=201)


@csrf_exempt
@require_access
@require_http_methods(["DELETE"])
@rate_limit("mfa_delete", 60)
def entry_detail(request, entry_id):
    entry = request.monifa_user.mfa_entries.filter(pk=entry_id).first()
    if entry is None:
        return JsonResponse({"error": "not_found"}, status=404)
    audit = {"issuer": entry.issuer}
    entry.delete()
    AuditEvent.objects.create(user=request.monifa_user, action="mfa.delete", target_id=str(entry_id), ip_address=client_ip(request), metadata=audit)
    return JsonResponse({}, status=204)


@csrf_exempt
@require_access
@require_http_methods(["DELETE"])
def unlink_identity(request, provider):
    identities = request.monifa_user.identities.all()
    if identities.count() <= 1:
        return JsonResponse({"error": "last_identity"}, status=409)
    deleted, _ = identities.filter(provider=provider).delete()
    if not deleted:
        return JsonResponse({"error": "not_found"}, status=404)
    AuditEvent.objects.create(user=request.monifa_user, action="identity.unlink", ip_address=client_ip(request), metadata={"provider": provider})
    return JsonResponse({}, status=204)


@csrf_exempt
@require_access
@require_http_methods(["DELETE"])
def delete_account(request):
    if (body(request) or {}).get("confirmation") != "DELETE":
        return JsonResponse({"error": "confirmation_required"}, status=400)
    user = request.monifa_user
    AuditEvent.objects.filter(user=user).delete()
    user.delete()
    return JsonResponse({}, status=204)
