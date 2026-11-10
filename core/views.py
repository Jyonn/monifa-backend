import base64
import hashlib
import json
import logging
import secrets
from urllib.parse import urlencode

import jwt
from django.conf import settings
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from Config.models import CI, Config
from .auth import decode_token, issue_access, issue_refresh, rate_limit, require_access
from .models import AuditEvent, ExpiringCode, MfaEntry, MfaShare, RefreshSession, User, UserIdentity
from .providers import PROVIDERS
from .totp import generate_totp


logger = logging.getLogger(__name__)
FRIENDEN_STATE_COOKIE = "__Host-monifa-frienden-state"


def body(request):
    try:
        return json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return None


def client_ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")).split(",")[0].strip() or None


def frontend_url():
    return Config.get_value_by_key(CI.FRONTEND_URL, settings.FRONTEND_URL).rstrip("/")


def consume_code(raw, kind, **filters):
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with transaction.atomic():
        code = ExpiringCode.objects.select_for_update().filter(code_hash=digest, kind=kind, **filters).first()
        if not code or code.used_at or code.expires_at <= timezone.now():
            return None
        code.used_at = timezone.now()
        ExpiringCode.objects.filter(pk=code.pk).update(used_at=code.used_at, pkce_verifier="")
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


def resolve_profile_user(provider, profile, link_user=None):
    if link_user:
        link_user = User.objects.select_for_update().get(pk=link_user.pk)
        if provider == UserIdentity.Provider.FRIENDEN and link_user.identities.filter(
            provider=provider,
        ).exclude(subject=profile.subject).exists():
            return None
    identity = UserIdentity.objects.select_related("user").filter(provider=provider, subject=profile.subject).first()
    if link_user:
        if identity and identity.user_id != link_user.pk:
            return None
        user = link_user
    elif identity:
        user = identity.user
    else:
        user = User.objects.create(display_name=profile.display_name, avatar_url=profile.avatar_url)
    details = {"username": profile.username, "email": profile.email, "avatar_url": profile.avatar_url, "metadata": profile.metadata or {}}
    if identity:
        for field, value in details.items():
            setattr(identity, field, value)
        identity.save(update_fields=[*details, "updated_at"])
    else:
        UserIdentity.objects.create(user=user, provider=provider, subject=profile.subject, **details)
    return user


def health(request):
    return JsonResponse({"status": "ok", "serverTime": int(timezone.now().timestamp())})


def begin_oauth(request, provider, adapter, link_user=None, *, return_url=False):
    frienden = provider == UserIdentity.Provider.FRIENDEN
    verifier = secrets.token_urlsafe(48) if frienden else ""
    state = ExpiringCode.issue(
        ExpiringCode.Kind.OAUTH_STATE,
        settings.OAUTH_STATE_TTL_SECONDS,
        provider=provider,
        link_user=link_user,
        pkce_verifier=verifier,
    )
    callback = request.build_absolute_uri(f"/auth/{provider}/callback")
    authorize_url = adapter.authorize_url(state, verifier if frienden else callback)
    response = JsonResponse({"authorizeUrl": authorize_url}) if return_url else redirect(authorize_url)
    if frienden:
        response.set_cookie(
            FRIENDEN_STATE_COOKIE, state, max_age=settings.OAUTH_STATE_TTL_SECONDS,
            secure=True, httponly=True, samesite="Lax",
        )
        response["Cache-Control"] = "no-store"
        response["Referrer-Policy"] = "no-referrer"
    return response


@require_http_methods(["GET"])
def oauth_start(request, provider):
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    link_user = None
    auth = request.headers.get("Authorization", "")
    if provider != UserIdentity.Provider.FRIENDEN and auth.startswith("Bearer "):
        try:
            payload = decode_token(auth[7:], "access")
            link_user = User.objects.filter(pk=payload["sub"]).first()
        except jwt.PyJWTError:
            pass
    return begin_oauth(request, provider, adapter, link_user)


@require_access
@require_http_methods(["GET"])
def oauth_link_start(request, provider):
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    return begin_oauth(request, provider, adapter, request.monifa_user, return_url=True)


@require_http_methods(["GET"])
def oauth_callback(request, provider):
    adapter = PROVIDERS.get(provider)
    raw_state = request.GET.get("state", "")
    frienden = provider == UserIdentity.Provider.FRIENDEN
    if frienden and (not raw_state or not constant_time_compare(raw_state, request.COOKIES.get(FRIENDEN_STATE_COOKIE, ""))):
        return redirect(frontend_url() + "/#/auth/callback?error=oauth_failed")
    state = consume_code(raw_state, ExpiringCode.Kind.OAUTH_STATE, provider=provider) if raw_state else None
    qitian_without_state = provider == UserIdentity.Provider.QITIAN and not raw_state
    invalid_state = not qitian_without_state and state is None
    link_user = state.link_user if state else None

    def finish(**params):
        if frienden and link_user:
            params["link"] = provider
        response = redirect(frontend_url() + "/#/auth/callback?" + urlencode(params))
        if frienden:
            response.delete_cookie(FRIENDEN_STATE_COOKIE, samesite="Lax")
            response["Cache-Control"] = "no-store"
            response["Referrer-Policy"] = "no-referrer"
        return response

    code = request.GET.get("code", "")
    if adapter is None or invalid_state or not code or (frienden and not state.pkce_verifier):
        return finish(error="oauth_failed")
    try:
        callback = request.build_absolute_uri(f"/auth/{provider}/callback")
        profile = adapter.exchange(code, state.pkce_verifier if frienden else callback)
        with transaction.atomic():
            user = resolve_profile_user(provider, profile, link_user)
            if user is None:
                return finish(error="identity_in_use")
            ticket = ExpiringCode.issue(ExpiringCode.Kind.LOGIN_TICKET, settings.LOGIN_TICKET_TTL_SECONDS, user=user)
            AuditEvent.objects.create(user=user, action="identity.link" if frienden and link_user else "auth.login", ip_address=client_ip(request), metadata={"provider": provider})
        return finish(ticket=ticket)
    except Exception:
        if frienden:
            logger.warning("Frienden OAuth callback failed")
        else:
            logger.exception("OAuth callback failed provider=%s", provider)
        return finish(error="oauth_failed")


@csrf_exempt
@require_http_methods(["GET", "POST"])
@rate_limit("provider_cli", 20)
def provider_cli_auth(request, provider):
    if provider not in (UserIdentity.Provider.QITIAN, UserIdentity.Provider.GITHUB):
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        return JsonResponse({"error": "unsupported_provider"}, status=404)
    if request.method == "GET":
        app_id = Config.get_value_by_key(CI.QITIAN_APP_ID, "") if provider == UserIdentity.Provider.QITIAN else Config.get_value_by_key(CI.GITHUB_CLIENT_ID, "")
        return JsonResponse({"appId": app_id})
    data = body(request) or {}
    try:
        if provider == UserIdentity.Provider.QITIAN:
            code = str(data.get("code", "")).strip()
            if not code:
                return JsonResponse({"error": "authorization_code_required"}, status=400)
            profile = adapter.exchange(code, "")
        elif provider == UserIdentity.Provider.GITHUB:
            access_token = str(data.get("accessToken", "")).strip()
            if not access_token:
                return JsonResponse({"error": "access_token_required"}, status=400)
            profile = adapter.profile_from_token(access_token)
        else:
            return JsonResponse({"error": "unsupported_provider"}, status=404)
        with transaction.atomic():
            user = resolve_profile_user(provider, profile)
        AuditEvent.objects.create(user=user, action="auth.login", ip_address=client_ip(request), metadata={"provider": provider, "client": "cli"})
        return JsonResponse({"accessToken": issue_access(user), "refreshToken": issue_refresh(user), "user": profile_json(user)})
    except Exception:
        logger.exception("CLI OAuth exchange failed provider=%s", provider)
        return JsonResponse({"error": "oauth_failed"}, status=401)


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
    try:
        share_active = entry.share.active
    except MfaShare.DoesNotExist:
        share_active = False
    return {
        "id": entry.pk,
        "issuer": entry.issuer,
        "accountName": entry.account_name,
        "secret": entry.secret,
        "algorithm": entry.algorithm,
        "digits": entry.digits,
        "period": entry.period,
        "createdAt": entry.created_at.isoformat(),
        "shareActive": share_active,
    }


@csrf_exempt
@require_access
@require_http_methods(["GET", "POST"])
@rate_limit("mfa_entries", 120)
def entries(request):
    if request.method == "GET":
        entry_list = list(request.monifa_user.mfa_entries.select_related("share"))
        AuditEvent.objects.create(
            user=request.monifa_user,
            action="mfa.read",
            ip_address=client_ip(request),
            metadata={"count": len(entry_list)},
        )
        response = JsonResponse({"entries": [entry_json(item) for item in entry_list], "serverTime": int(timezone.now().timestamp())})
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
@require_http_methods(["POST", "DELETE"])
@rate_limit("mfa_share_manage", 30)
def entry_share(request, entry_id):
    entry = request.monifa_user.mfa_entries.filter(pk=entry_id).first()
    if entry is None:
        return JsonResponse({"error": "not_found"}, status=404)
    if request.method == "DELETE":
        MfaShare.objects.filter(entry=entry, revoked_at__isnull=True).update(revoked_at=timezone.now())
        AuditEvent.objects.create(user=request.monifa_user, action="mfa.share.revoke", target_id=str(entry_id), ip_address=client_ip(request))
        return JsonResponse({}, status=204)

    data = body(request) or {}
    try:
        ttl_seconds = data.get("ttlSeconds", 86400)
        if ttl_seconds is not None:
            ttl_seconds = int(ttl_seconds)
            if ttl_seconds not in (3600, 86400, 604800):
                raise ValueError
            expires_at = timezone.now() + timezone.timedelta(seconds=ttl_seconds)
        else:
            expires_at = None
    except (TypeError, ValueError):
        return JsonResponse({"error": "invalid_share_expiry"}, status=400)

    token = MfaShare.issue(entry, expires_at)
    AuditEvent.objects.create(
        user=request.monifa_user,
        action="mfa.share.create",
        target_id=str(entry_id),
        ip_address=client_ip(request),
        metadata={"expiresAt": expires_at.isoformat() if expires_at else None},
    )
    return JsonResponse({"token": token, "expiresAt": expires_at.isoformat() if expires_at else None}, status=201)


@require_http_methods(["GET"])
@rate_limit("mfa_share_read", 120)
def shared_entry(request, token):
    share = MfaShare.objects.select_related("entry").filter(token_hash=MfaShare.digest(token)).first()
    if share is None or not share.active:
        return JsonResponse({"error": "share_not_found"}, status=404)
    now = timezone.now()
    code, remaining = generate_totp(share.entry, now.timestamp())
    MfaShare.objects.filter(pk=share.pk).update(last_accessed_at=now)
    response = JsonResponse(
        {
            "issuer": share.entry.issuer,
            "accountName": share.entry.account_name,
            "code": code,
            "remaining": remaining,
            "period": share.entry.period,
            "serverTime": int(now.timestamp()),
            "expiresAt": share.expires_at.isoformat() if share.expires_at else None,
        }
    )
    response["Cache-Control"] = "no-store, private"
    response["Referrer-Policy"] = "no-referrer"
    return response


@csrf_exempt
@require_access
@require_http_methods(["DELETE"])
@transaction.atomic
def unlink_identity(request, provider):
    user = User.objects.select_for_update().get(pk=request.monifa_user.pk)
    identities = user.identities.all()
    if not identities.exclude(provider=provider).exists():
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
