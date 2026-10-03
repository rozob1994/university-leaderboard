# Private admin hosting setup

This repository can run as a password-protected Node web service.

## Important

- Do **not** put plaintext passwords in this repository.
- Use `admin-credential-generator.html` locally to generate password verifiers.
- Put the generated `ADMIN_USERS_JSON` value into your hosting provider's secret/environment-variable UI.
- `SESSION_SECRET` must also stay secret.
- Keep GitHub Pages enabled only until the protected deployment is tested. Then disable GitHub Pages so the public URL cannot bypass the login.

## Authentication

- Three independent usernames/passwords.
- Passwords are verified with PBKDF2-HMAC-SHA256 (310,000 iterations, per-user random salt).
- The server stores no plaintext passwords.
- Auth sessions use an HMAC-signed, HttpOnly, Secure, SameSite=Lax cookie.
- Five failed login attempts from one IP trigger a 15-minute temporary lockout.

## Render

The included `render.yaml` creates a Node web service and prompts for `ADMIN_USERS_JSON`. Render generates `SESSION_SECRET` automatically.

The current PWA's class data remains browser-local unless you explicitly link/import/sync a project. Authentication alone does not make three browsers share one project database.
