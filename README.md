# Monifa · 时符 Backend

Django API for Monifa · 时符, a multi-SSO TOTP authenticator web app.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
cp mysql.local.conf.example mysql.local.conf
.venv/bin/python manage.py migrate
.venv/bin/python manage.py runserver
```

Database credentials live in the ignored `mysql.local.conf`, matching the Disk application. Django passes that file to the MySQL client through `read_default_file`. When the file is absent, development and automated tests fall back to SQLite.

## Application configuration

OAuth credentials and runtime application URLs follow Disk's database-backed `Config`/`ConfigInstance` pattern. After migrating, configure production with:

```bash
.venv/bin/python manage.py setconfig frontend-url https://monifa.jyonn.space
.venv/bin/python manage.py setconfig qt-oauth-host https://qt.6-79.cn
.venv/bin/python manage.py setconfig qt-host https://api.qt.6-79.cn
.venv/bin/python manage.py setconfig qt-app-id YOUR_QITIAN_APP_ID
.venv/bin/python manage.py setconfig qt-app-secret YOUR_QITIAN_APP_SECRET
.venv/bin/python manage.py setconfig github-client-id YOUR_GITHUB_CLIENT_ID
.venv/bin/python manage.py setconfig github-client-secret YOUR_GITHUB_CLIENT_SECRET
```

The command values may appear in shell history. On a shared production host, use a protected deployment script or write the values through a Django shell reading protected files. Database connection settings, `DJANGO_SECRET_KEY`, allowed hosts and CORS remain startup configuration because Django needs them before it can query `Config`.

## Authentication

Monifa · 时符 supports Qitian and GitHub OAuth identities through a provider-neutral `UserIdentity` model. OAuth callbacks issue a short-lived, one-time login ticket. The frontend exchanges it for a 15-minute access JWT and rotating 30-day refresh JWT.

The companion `monifa-cli` uses `qt app oauth` for Qitian and GitHub's Device
Flow. It exchanges the resulting proof through `/auth/{provider}/cli`. These
endpoints publish only OAuth App IDs; provider secrets remain server-side.

API sessions use `Authorization: Bearer`. Frienden OAuth uses a short-lived, host-only cookie to bind the callback to the browser that started the flow. Configure exact frontend origins in `CORS_ALLOWED_ORIGINS` and serve the web frontend and API over HTTPS on the same site.

### Frienden

The registered client defaults to `monifa` with the exact callback `https://api.monifa.jyonn.space/auth/frienden/callback`. Approve both the `profile` and `phone` scopes in Frienden before deploying this version, then run `python manage.py migrate` before starting the updated backend. An alternate registration can set `FRIENDEN_CLIENT_ID` and `FRIENDEN_REDIRECT_URI` in the backend runtime environment.

Frienden sign-in resolves accounts by the verified mainland China phone number. Existing Qitian or GitHub users sign in as usual and link Frienden under account settings to associate their verified number with their existing Monifa account. Existing Frienden identities from before the migration obtain their phone mapping at their next authorization when the number is available. Accounts already associated with different Monifa users require separate handling when the same number is presented.

If an existing Frienden subject presents a changed number, sign in through an existing session or another linked identity and use the phone sync action in settings. Unlinking Frienden removes its phone association.

Login-ticket exchange, token refresh and MFA CRUD endpoints use a Django Cache-backed per-client rate limit. Production deployments with multiple Gunicorn workers should configure a shared cache backend such as Redis so limits apply across processes.

## Security note

The current product decision stores TOTP secrets in plaintext so the web client can generate codes and cache them offline. Never include secrets, generated codes, OAuth credentials, or JWTs in logs. Database and host access are therefore part of the application's security boundary.

## API

- `GET /auth/{qitian|github|frienden}/start`
- `GET /auth/{qitian|github|frienden}/link`
- `GET /auth/{provider}/callback`
- `GET|POST /auth/{qitian|github}/cli`
- `POST /auth/ticket`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /me`
- `DELETE /me/account`
- `DELETE /me/identities/{provider}`
- `GET|POST /mfa/entries`
- `DELETE /mfa/entries/{id}`
- `POST|DELETE /mfa/entries/{id}/share`
- `GET /shares/{token}` (public bearer-link access)

Creating a share accepts `ttlSeconds` as `3600`, `86400`, `604800`, or `null` for no expiry. Only one share is active per entry; creating another immediately invalidates the previous URL. The public response contains the current code and display metadata, never the TOTP secret. Share tokens are stored as SHA-256 digests and can be revoked by the entry owner.

After deploying a version that introduces sharing, run `python manage.py migrate` before restarting Gunicorn.
