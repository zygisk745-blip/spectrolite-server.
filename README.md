# Spectrolite Auth Server (starter)

A standalone key-authentication API intended for an app you own or are authorized to modify. It does not bypass or impersonate the original Spectrolite authentication service.

## Endpoints

- `GET /health` — database and service health check.
- `POST /auth/login` — validates a license key and binds it to the first device ID used.
- `GET /auth/me` — validates a session token.
- `POST /admin/keys` — creates a key (admin bearer token required).
- `POST /admin/keys/disable` — disables a key and prevents further session validation.

Interactive API docs are available at `/docs` after deployment.

## Deploy on Render + Neon

1. Create a PostgreSQL database on Neon and copy its connection string. Ensure it includes `sslmode=require`.
2. Upload this folder to a GitHub repository.
3. In Render, choose **New + → Blueprint**, connect the repository, and let Render read `render.yaml`.
4. When prompted, set `DATABASE_URL` to the Neon connection string. Render generates `ADMIN_TOKEN`; save it securely.
5. After deploy, open `https://YOUR-SERVICE.onrender.com/health` and confirm `{ "ok": true }`.

The free web service may spin down when idle. Free-tier availability and limits can change.

## Create a key

Use the deployed API's `/docs` page. Call `POST /admin/keys` with header `Authorization: Bearer YOUR_ADMIN_TOKEN` and JSON body such as:

```json
{"label":"Test user","expires_in_days":30}
```

The plaintext key is shown only once. Store it safely.

## Login request

```json
{"key":"SPX-your-key","device_id":"stable-device-id-from-your-app"}
```

A successful response contains `session_token`. Send it as `Authorization: Bearer SESSION_TOKEN` to `/auth/me`.

## Important before production

- This is a starter, not a complete production security review. Add rate limiting, audit logs, backups, admin UI, and key/session revocation management before public use.
- Never put `ADMIN_TOKEN` in the APK.
- Use a stable, privacy-reviewed device identifier; avoid collecting hardware identifiers unnecessarily.
- APK integration requires changing the app's legitimate authentication client and rebuilding/signing it. The server API alone does not modify the APK or preserve proprietary features automatically.
