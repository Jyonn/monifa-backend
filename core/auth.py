import hashlib
import uuid
from functools import wraps

import jwt
from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone

from .models import RefreshSession, User


def _encode(payload, ttl):
    now = timezone.now()
    return jwt.encode({**payload, "iat": now, "exp": now + timezone.timedelta(seconds=ttl)}, settings.SECRET_KEY, algorithm="HS256")


def issue_access(user):
    return _encode({"sub": str(user.pk), "type": "access"}, settings.ACCESS_TOKEN_TTL_SECONDS)


def issue_refresh(user):
    token_id = uuid.uuid4()
    token = _encode({"sub": str(user.pk), "type": "refresh", "jti": str(token_id)}, settings.REFRESH_TOKEN_TTL_SECONDS)
    RefreshSession.objects.create(
        user=user,
        token_id=token_id,
        token_hash=RefreshSession.digest(token),
        expires_at=timezone.now() + timezone.timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS),
    )
    return token


def decode_token(token, expected_type):
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Wrong token type")
    return payload


def bearer_user(request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        payload = decode_token(header[7:], "access")
        return User.objects.get(pk=payload["sub"])
    except (jwt.PyJWTError, User.DoesNotExist, ValueError):
        return None


def require_access(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        request.monifa_user = bearer_user(request)
        if request.monifa_user is None:
            return JsonResponse({"error": "authentication_required"}, status=401)
        return view(request, *args, **kwargs)

    return wrapped

