import hashlib
import secrets
import uuid

from django.db import models
from django.utils import timezone


class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    display_name = models.CharField(max_length=120, blank=True)
    avatar_url = models.URLField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class UserIdentity(models.Model):
    class Provider(models.TextChoices):
        QITIAN = "qitian", "Qitian"
        GITHUB = "github", "GitHub"

    user = models.ForeignKey(User, related_name="identities", on_delete=models.CASCADE)
    provider = models.CharField(max_length=32, choices=Provider.choices)
    subject = models.CharField(max_length=255)
    username = models.CharField(max_length=255, blank=True)
    email = models.EmailField(blank=True)
    avatar_url = models.URLField(max_length=500, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["provider", "subject"], name="unique_provider_subject")]


class MfaEntry(models.Model):
    class Algorithm(models.TextChoices):
        SHA1 = "SHA1", "SHA-1"
        SHA256 = "SHA256", "SHA-256"
        SHA512 = "SHA512", "SHA-512"

    user = models.ForeignKey(User, related_name="mfa_entries", on_delete=models.CASCADE)
    issuer = models.CharField(max_length=160)
    account_name = models.CharField(max_length=255)
    secret = models.CharField(max_length=512)
    secret_fingerprint = models.CharField(max_length=64)
    algorithm = models.CharField(max_length=8, choices=Algorithm.choices, default=Algorithm.SHA1)
    digits = models.PositiveSmallIntegerField(default=6)
    period = models.PositiveSmallIntegerField(default=30)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["issuer", "account_name", "created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "secret_fingerprint", "algorithm", "digits", "period"],
                name="unique_user_totp_factor",
            )
        ]

    @staticmethod
    def fingerprint(secret):
        return hashlib.sha256("".join(secret.split()).upper().encode()).hexdigest()

    def save(self, *args, **kwargs):
        self.secret = "".join(self.secret.split()).upper().rstrip("=")
        self.secret_fingerprint = self.fingerprint(self.secret)
        super().save(*args, **kwargs)


class MfaShare(models.Model):
    entry = models.OneToOneField(MfaEntry, related_name="share", on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    @classmethod
    def issue(cls, entry, expires_at=None):
        token = secrets.token_urlsafe(32)
        cls.objects.update_or_create(
            entry=entry,
            defaults={
                "token_hash": cls.digest(token),
                "expires_at": expires_at,
                "revoked_at": None,
                "last_accessed_at": None,
            },
        )
        return token

    @property
    def active(self):
        return self.revoked_at is None and (self.expires_at is None or self.expires_at > timezone.now())


class RefreshSession(models.Model):
    user = models.ForeignKey(User, related_name="sessions", on_delete=models.CASCADE)
    token_id = models.UUIDField(default=uuid.uuid4, unique=True)
    token_hash = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()


class ExpiringCode(models.Model):
    class Kind(models.TextChoices):
        OAUTH_STATE = "oauth_state", "OAuth state"
        LOGIN_TICKET = "login_ticket", "Login ticket"

    kind = models.CharField(max_length=20, choices=Kind.choices)
    code_hash = models.CharField(max_length=64, unique=True)
    provider = models.CharField(max_length=32, blank=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    link_user = models.ForeignKey(User, null=True, blank=True, related_name="link_codes", on_delete=models.CASCADE)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def issue(cls, kind, ttl_seconds, **kwargs):
        raw = secrets.token_urlsafe(32)
        cls.objects.create(
            kind=kind,
            code_hash=hashlib.sha256(raw.encode()).hexdigest(),
            expires_at=timezone.now() + timezone.timedelta(seconds=ttl_seconds),
            **kwargs,
        )
        return raw


class AuditEvent(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=80)
    target_id = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
