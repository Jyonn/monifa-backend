# Monifa Backend

Django API for Monifa, a multi-SSO TOTP authenticator web app.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
.venv/bin/python manage.py migrate
.venv/bin/python manage.py runserver
```

When `MYSQL_DATABASE` is unset, development and tests use SQLite. Production is designed for MySQL 8 through PyMySQL.

## Authentication

Monifa supports Qitian and GitHub OAuth identities through a provider-neutral `UserIdentity` model. OAuth callbacks issue a short-lived, one-time login ticket. The frontend exchanges it for a 15-minute access JWT and rotating 30-day refresh JWT.

All API authentication uses `Authorization: Bearer`; cookies and CSRF authentication are intentionally disabled. Configure only exact frontend origins in `CORS_ALLOWED_ORIGINS`.

## Security note

The current product decision stores TOTP secrets in plaintext so the web client can generate codes and cache them offline. Never include secrets, generated codes, OAuth credentials, or JWTs in logs. Database and host access are therefore part of Monifa's security boundary.

## API

- `GET /api/auth/{qitian|github}/start`
- `GET /api/auth/{qitian|github}/link`
- `GET /api/auth/{provider}/callback`
- `POST /api/auth/ticket`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/me`
- `DELETE /api/me/account`
- `DELETE /api/me/identities/{provider}`
- `GET|POST /api/mfa/entries`
- `DELETE /api/mfa/entries/{id}`
